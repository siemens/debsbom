# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from dataclasses import dataclass
from enum import Enum
import re

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

    package_name: str
    is_source: bool = False

    def as_str(self, sbom_type: SBOMType) -> str:
        """Return a string representation for the given SBOM type."""
        if sbom_type == SBOMType.CycloneDX:
            s = CDX_REF_PREFIX + self.package_name
        elif sbom_type == SBOMType.SPDX:
            s = SPDX_REF_PREFIX + re.sub(SPDX_ID_RE, ".", self.package_name)

        if self.is_source:
            s += "-srcpkg"
        return s
