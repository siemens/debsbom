# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from abc import ABC, abstractmethod
from dataclasses import dataclass
from debian.deb822 import Packages, PkgRelation
from debian.debian_support import Version
import logging
from packageurl import PackageURL
from typing import Iterator, List, Tuple, Type

from ..sbom import Reference


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
        """Parse a dpkg status file."""
        logger.info(f"Parsing status file '{status_file}'...")
        with open(status_file, "r") as status_file:
            # track which source package ids we already added to
            # prevent duplicate entries
            source_packages = []
            for package in Packages.iter_paragraphs(status_file, use_apt_pkg=False):
                pdepends = package.relations["depends"]
                if pdepends:
                    dependencies = [
                        Reference(package_name=dep.name)
                        for dep in Dependency.from_pkg_relations(pdepends)
                    ]
                else:
                    dependencies = None

                spkg = SourcePackage(
                    name=package.source,
                    version=package.source_version,
                    maintainer=package.get("Maintainer"),
                )
                bpkg = BinaryPackage(
                    name=package.get("Package"),
                    section=package.get("Section"),
                    maintainer=package.get("Maintainer"),
                    architecture=package.get("Architecture"),
                    source=Reference(package_name=spkg.name, is_source=True),
                    version=package.get("Version"),
                    depends=dependencies,
                    description=package.get("Description"),
                    homepage=package.get("Homepage"),
                )
                logger.debug(f"Found binary package: '{bpkg.name}'")
                yield bpkg
                if spkg.name not in source_packages:
                    source_packages.append(spkg.name)
                    logger.debug(f"Found source package: '{spkg.name}'")
                    yield spkg

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
    source: Reference
    depends: List[Reference]
    description: str
    homepage: str

    def __init__(
        self,
        name: str,
        section: str,
        maintainer: str,
        architecture: str,
        source: SourcePackage,
        version: str | Version,
        depends: List[Dependency],
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
        self.description = description
        self.homepage = homepage

    def purl(self) -> PackageURL:
        """Return the PURL of the package."""
        purl = "pkg:deb/debian/{}@{}".format(self.name, self.version)
        if self.architecture:
            purl = purl + "?arch={}".format(self.architecture)
        return PackageURL.from_string(purl)
