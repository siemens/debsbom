# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import json
from pathlib import Path

__all__ = [
    "download",
]


__DOWNLOAD_SCHEMA_PATH = Path(__file__).parent / "schema-download.json"

with open(__DOWNLOAD_SCHEMA_PATH) as f:
    download = json.load(f)
