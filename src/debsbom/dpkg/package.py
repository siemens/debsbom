# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from abc import ABC, abstractmethod
from dataclasses import dataclass
import itertools
from debian.deb822 import Packages, PkgRelation
from debian.debian_support import Version
import logging
from packageurl import PackageURL
from typing import Iterator, List, Tuple, Type


logger = logging.getLogger(__name__)


@dataclass
class Dependency:
    """Representation of a dependency for a package."""

    name: str
    archqual: str | None = None
    version: Tuple[str, Version] | None = None
    arch: str | None = None
    restrictions: str | None = None

    @classmethod
    def from_pkg_relations(cls, relations: List[List[PkgRelation]]) -> List["Dependency"]:
        dependencies = []
        for relation in relations:
            for dep in relation:
                if dep.get("version"):
                    # make a proper Version out of it
                    dep["version"] = (dep["version"][0], Version(dep["version"][1]))
                dependencies.append(Dependency(**dep))
        return dependencies

    @classmethod
    def parse_depends_line(cls, line: str) -> List["Dependency"]:
        return Dependency.from_pkg_relations(PkgRelation.parse_relations(line))


@dataclass(init=False)
class Package(ABC):
    """Base class for binary and source packages."""

    name: str
    version: Version

    def __init__(self, name: str, version: str | Version):
        self.name = name
        self.version = Version(version)

    @classmethod
    def parse_status_file(cls, status_file: str) -> Iterator[Type["Package"]]:
        """
        Parse a dpkg status file and returns packages with their relations.
        """
        logger.info(f"Parsing status file '{status_file}'...")
        binpkgs_it = cls._parse_status_file_raw(status_file)
        return cls._unique_everseen(
            itertools.chain.from_iterable(map(lambda p: cls._resolve_sources(p, True), binpkgs_it))
        )

    @classmethod
    def _parse_status_file_raw(cls, status_file: str) -> Iterator[Type["BinaryPackage"]]:
        """
        Parse a dpkg status file and returns binary packages with their relations.
        The relations might contain links to packages that are not known yet (e.g.
        all source packages). These need to be resolved in a second pass.
        """
        with open(status_file, "r") as status_file:
            for package in Packages.iter_paragraphs(status_file, use_apt_pkg=False):
                if package.source:
                    srcdep = Dependency(package.source, None, ("=", package.source_version))
                else:
                    srcdep = None

                pdepends = package.relations["depends"] or []
                dependencies = Dependency.from_pkg_relations(pdepends)

                # static dependencies
                s_built_using = package.relations["built-using"] or []
                sdepends = Dependency.from_pkg_relations(s_built_using)

                bpkg = BinaryPackage(
                    name=package.get("Package"),
                    section=package.get("Section"),
                    maintainer=package.get("Maintainer"),
                    architecture=package.get("Architecture"),
                    source=srcdep,
                    version=package.get("Version"),
                    depends=dependencies,
                    built_using=sdepends,
                    description=package.get("Description"),
                    homepage=package.get("Homepage"),
                )
                logger.debug(f"Found binary package: '{bpkg.name}'")
                yield bpkg

    @classmethod
    def _unique_everseen(cls, iterable, key=None):
        """
        Yield unique elements, preserving order. Remember all elements ever seen.
        """
        seen = set()
        if key is None:
            for element in itertools.filterfalse(seen.__contains__, iterable):
                seen.add(element)
                yield element
        else:
            for element in iterable:
                k = key(element)
                if k not in seen:
                    seen.add(k)
                yield element

    @classmethod
    def _resolve_sources(
        cls, pkg: Type["BinaryPackage"], add_pkg=False
    ) -> Iterator[Type["Package"]]:
        """
        Returns an iterator to resolve the source package of a binary package.
        If add_pkg=True is set, the passed binary package is returned as well.
        """
        if pkg.source:
            logger.debug(f"Found source package: '{pkg.source.name}'")
            yield SourcePackage(pkg.source.name, pkg.source.version[1], pkg.maintainer)
        for bu in pkg.built_using:
            # When creating the source package from a built-depends, we don't know the maintainer.
            # If we now create a source package first via a built-using relation and later
            # re-create the same source package from a binary package, it still misses the
            # maintainer information, despite we would have it from the binary package.
            # Some tests on a rather large debian sid showed, that this situation is unlikely.
            logger.debug(f"Found built-using source package: '{bu.name}@{bu.version[1]}'")
            yield SourcePackage(bu.name, bu.version[1])
        if add_pkg:
            yield pkg

    @abstractmethod
    def purl(self) -> PackageURL:
        raise NotImplementedError


@dataclass(init=False)
class SourcePackage(Package):
    """Representation of a Debian Source package."""

    maintainer: str | None = None

    def __init__(self, name: str, version: str | Version, maintainer: str | None = None):
        self.name = name
        self.version = Version(version)
        self.maintainer = maintainer

    def __hash__(self):
        return hash(self.purl())

    def __eq__(self, other):
        # For compatibility reasons
        if isinstance(other, SourcePackage):
            return self.purl() == other.purl()
        return NotImplemented

    def purl(self) -> PackageURL:
        """Return the PURL of the package."""
        return PackageURL.from_string(
            "pkg:deb/debian/{}@{}?arch=source".format(self.name, self.version)
        )

    def dscfile(self) -> str:
        """Return the name of the .dsc file"""
        # TODO: find where this filename format is specified
        if self.version.debian_revision:
            version_wo_epoch = f"{self.version.upstream_version}-{self.version.debian_revision}"
        else:
            version_wo_epoch = self.version.upstream_version
        return f"{self.name}_{version_wo_epoch}.dsc"


@dataclass(init=False)
class BinaryPackage(Package):
    """Incomplete representation of a Debian binary package."""

    maintainer: str
    section: str
    architecture: str
    source: Dependency
    depends: List[Dependency]
    built_using: List[Dependency]
    description: str
    homepage: str

    def __init__(
        self,
        name: str,
        section: str,
        maintainer: str,
        architecture: str,
        source: Dependency,
        version: str | Version,
        depends: List[Dependency],
        built_using: List[Dependency],
        description: str,
        homepage: str,
    ):
        self.name = name
        self.section = section
        self.maintainer = maintainer
        self.architecture = architecture
        self.source = source
        self.version = Version(version)
        self.depends = depends
        self.built_using = built_using
        self.description = description
        self.homepage = homepage

    def __hash__(self):
        return hash(self.purl())

    def __eq__(self, other):
        if isinstance(other, BinaryPackage):
            return self.purl() == other.purl()
        return NotImplemented

    def purl(self) -> PackageURL:
        """Return the PURL of the package."""
        purl = "pkg:deb/debian/{}@{}".format(self.name, self.version)
        if self.architecture:
            purl = purl + "?arch={}".format(self.architecture)
        return PackageURL.from_string(purl)
