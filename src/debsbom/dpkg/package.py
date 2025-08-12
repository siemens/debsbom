# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from dataclasses import dataclass
from debian.deb822 import Packages, PkgRelation
from debian.debian_support import Version
from packageurl import PackageURL
import re
from typing import Iterator, List, Tuple, Type
import functools

from ..sbom import CDX_REF_PREFIX, SBOMType, SPDX_REF_PREFIX

# SPDX IDs only allow alphanumeric, '.' and '-'
SPDX_ID_RE = re.compile(r"[^A-Za-z0-9.\-]+")


@dataclass
class SourcePackage:
    """Representation of a Debian Source package."""

    name: str
    version: Version | None

    def purl(self) -> PackageURL:
        """Return the PURL of the package."""
        return PackageURL.from_string(
            "pkg:deb/debian/{}@{}?arch=source".format(self.name, self.version)
        )

    def bom_ref(self, sbom_type: SBOMType) -> str:
        """Return a unique BOM reference."""
        if sbom_type == SBOMType.CycloneDX:
            return CDX_REF_PREFIX + "{}-srcpkg".format(self.name)
        elif sbom_type == SBOMType.SPDX:
            return SPDX_REF_PREFIX + "{}-srcpkg".format(re.sub(SPDX_ID_RE, ".", self.name))

    @functools.cache
    def parse(s: str) -> Type["SourcePackage"]:
        split = s.split(" ")
        name = split[0]
        try:
            version = " ".join(split[1:]).strip("()")
        except IndexError:
            version = None

        return SourcePackage(name=name, version=version)


@dataclass
class Dependency:
    """Representation of a dependency for a package."""

    name: str
    archqual: str | None = None
    version: Tuple[str, Version] | None = None
    arch: str | None = None
    restrictions: str | None = None

    def bom_ref(self, sbom_type: SBOMType) -> str:
        """Return a unique BOM reference."""
        if sbom_type == SBOMType.CycloneDX:
            return CDX_REF_PREFIX + "{}".format(self.name)
        elif sbom_type == SBOMType.SPDX:
            return SPDX_REF_PREFIX + re.sub(SPDX_ID_RE, ".", self.name)

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


@dataclass
class BinaryPackage:
    """Incomplete representation of a debian binary package."""

    name: str
    section: str
    maintainer: str
    architecture: str
    source: SourcePackage
    version: Version
    depends: List[Dependency]
    description: str
    homepage: str

    def purl(self) -> PackageURL:
        """Return the PURL of the package."""
        purl = "pkg:deb/debian/{}@{}".format(self.name, self.version)
        if self.architecture:
            purl = purl + "?arch={}".format(self.architecture)
        return PackageURL.from_string(purl)

    def bom_ref(self, sbom_type: SBOMType) -> str:
        """Return a unique BOM reference."""
        if sbom_type == SBOMType.CycloneDX:
            return CDX_REF_PREFIX + self.name
        elif sbom_type == SBOMType.SPDX:
            return SPDX_REF_PREFIX + re.sub(SPDX_ID_RE, ".", self.name)

    @classmethod
    def parse_status_file(cls, status_file: str) -> Iterator[Type["BinaryPackage"]]:
        """Parse a dpkg status file."""
        with open(status_file, "r") as status_file:
            for package in Packages.iter_paragraphs(status_file, use_apt_pkg=False):
                pdepends = package.relations["depends"]
                if pdepends:
                    dependencies = Dependency.from_pkg_relations(pdepends)
                else:
                    dependencies = None

                bpkg = BinaryPackage(
                    name=package.get("Package"),
                    section=package.get("Section"),
                    maintainer=package.get("Maintainer"),
                    architecture=package.get("Architecture"),
                    source=SourcePackage(name=package.source, version=package.source_version),
                    version=package.get("Version"),
                    depends=dependencies,
                    description=package.get("Description"),
                    homepage=package.get("Homepage"),
                )
                yield bpkg
