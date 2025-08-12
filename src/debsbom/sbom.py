# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from enum import Enum
import re

CDX_REF_PREFIX = "CDXRef-"
CDX_PACKAGE_EXTREF_TYPE_WEBSITE = "website"

SPDX_REF_PREFIX = "SPDXRef-"
SPDX_REF_DOCUMENT = SPDX_REF_PREFIX + "DOCUMENT"
SPDX_REFERENCE_TYPE_PURL = "purl"

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
SUPPLIER_PATTERN = re.compile("(?P<supplier_name>^[^<]*)(\\<(?P<supplier_email>.*)\\>)?")


class SBOMType(Enum):
    CycloneDX = (0,)
    SPDX = (1,)
