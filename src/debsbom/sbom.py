# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Set
from dataclasses import dataclass
from enum import Enum
import re

from .dpkg.package import BinaryPackage, Dependency, Package, SourcePackage

CDX_REF_PREFIX = "CDXRef-"
CDX_PACKAGE_EXTREF_TYPE_WEBSITE = "website"

SPDX_REF_PREFIX = "SPDXRef-"
SPDX_REF_DOCUMENT = SPDX_REF_PREFIX + "DOCUMENT"
SPDX_REFERENCE_TYPE_PURL = "purl"
SPDX_REFERENCE_TYPE_DISTRIBUTION = "distribution"
# SPDX IDs only allow alphanumeric, '.' and '-'
SPDX_ID_RE = re.compile(r"[^A-Za-z0-9.\-]+")

# cues for an organization in the maintainer name
SPDX_SUPPLIER_ORG_CUE = [
    "maintainers",
    "group",
    "developers",
    "team",
    "project",
    "task force",
    "strike force",
    "packagers",
    "users",
]


# pattern to match the common "John Doe <john@doe.com>"
SUPPLIER_PATTERN = re.compile("(?P<supplier_name>^[^<]+)(\\<(?P<supplier_email>.+)\\>)?")


class SBOMType(Enum):
    """Supported SBOM types"""

    CycloneDX = (0,)
    """CycloneDX"""
    SPDX = (1,)
    """SPDX"""

    def from_str(bomtype: str):
        if bomtype.lower() == "cdx":
            return SBOMType.CycloneDX
        if bomtype.lower() == "spdx":
            return SBOMType.SPDX
        raise RuntimeError(f"Unknown SBOM type '{bomtype}'")


class BOM_Standard(Enum):
    """Controls the data representation and added values in the SBOM"""

    DEFAULT = (0,)
    STANDARD_BOM = (1,)


@dataclass
class Reference:
    """Generic reference in a SBOM."""

    target: str
    is_source: bool = False

    def as_str(self, sbom_type: SBOMType) -> str:
        """Return a string representation for the given SBOM type."""
        if sbom_type == SBOMType.CycloneDX:
            s = CDX_REF_PREFIX + self.target
        elif sbom_type == SBOMType.SPDX:
            s = SPDX_REF_PREFIX + re.sub(SPDX_ID_RE, ".", self.target)

        if self.is_source:
            s += "-srcpkg"
        return s

    @classmethod
    def lookup(
        cls, pkg: BinaryPackage, dep: Dependency, sbom_type: SBOMType, known_refs: Set[str]
    ) -> str | None:
        """
        For imprecise references (without architecture), locate the matching
        reference id within the id passed as known_refs. Returns None if
        not found. To avoid downstream double caching of IDs in two formats, we pass the
        known_refs as a string set.
        """
        if dep.arch:
            return Reference.make_from_dep(dep).as_str(sbom_type)
        candidates = map(
            lambda a: Reference.make_from_dep(dep, a).as_str(sbom_type),
            set([pkg.architecture, "all"]),
        )
        return next(filter(lambda d: d in known_refs, candidates), None)

    @staticmethod
    def make_from_pkg(pkg: Package) -> "Reference":
        """
        Return a reference to a package in the list of all packages.
        This representation must match the one returned by ``make_from_dep``.
        """
        if isinstance(pkg, SourcePackage):
            return Reference(target=f"{pkg.name}-{pkg.version}", is_source=True)
        elif isinstance(pkg, BinaryPackage):
            return Reference(target=f"{pkg.name}-{pkg.architecture}", is_source=False)
        raise NotImplementedError()

    @staticmethod
    def make_from_dep(dep: Dependency, to_arch: str | None = None) -> "Reference":
        """
        Return a reference to a package from a dependency. If the dependency does
        not specify an architecture, the caller is responsible for providing this
        in ``to_arch``.
        """
        if "source" in [dep.arch, to_arch]:
            return Reference(target=f"{dep.name}-{dep.version[1]}", is_source=True)
        else:
            to_arch = to_arch or dep.arch
            return Reference(target=f"{dep.name}-{to_arch}", is_source=False)


class BomSpecific:
    """Mixin to denote that a class processes bom type specific data"""

    @classmethod
    def sbom_type(cls) -> SBOMType:
        """Type of SBOM this class can handle"""
        return cls._sbom_type


class CDXType(BomSpecific):
    """CycloneDX type mixin"""

    _sbom_type = SBOMType.CycloneDX


class SPDXType(BomSpecific):
    """SPDX type mixin"""

    _sbom_type = SBOMType.SPDX
