# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from dataclasses import dataclass
from enum import Enum
import re
from typing import Type

from .dpkg.package import BinaryPackage, Dependency, Package, SourcePackage

CDX_REF_PREFIX = "CDXRef-"
CDX_PACKAGE_EXTREF_TYPE_WEBSITE = "website"

SPDX_REF_PREFIX = "SPDXRef-"
SPDX_REF_DOCUMENT = SPDX_REF_PREFIX + "DOCUMENT"
SPDX_REFERENCE_TYPE_PURL = "purl"
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
    CycloneDX = (0,)
    SPDX = (1,)


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

    @staticmethod
    def make_from_pkg(pkg: Package) -> Type["Reference"]:
        """
        Return a unique string to reference a package in the list of all packages.
        This representation must match the one returned by make_from_dep.
        """
        if isinstance(pkg, SourcePackage):
            return Reference(target=f"{pkg.name}-{pkg.version}", is_source=True)
        elif isinstance(pkg, BinaryPackage):
            return Reference(target=f"{pkg.name}", is_source=False)
        raise NotImplementedError()

    @staticmethod
    def make_from_dep(dep: Dependency, to_source=False) -> type["Reference"]:
        if to_source:
            return Reference(target=f"{dep.name}-{dep.version[1]}", is_source=True)
        else:
            return Reference(target=f"{dep.name}", is_source=False)
