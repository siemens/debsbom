# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import json
from pathlib import Path

__all__ = [
    "download",
    "tracepath",
]


__DOWNLOAD_SCHEMA_PATH = Path(__file__).parent / "schema-download.json"
__TRACEPATH_SCHEMA_PATH = Path(__file__).parent / "schema-trace-path.json"

with open(__DOWNLOAD_SCHEMA_PATH) as f:
    download = json.load(f)
with open(__TRACEPATH_SCHEMA_PATH) as f:
    tracepath = json.load(f)
