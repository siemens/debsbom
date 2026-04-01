# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import json
from pathlib import Path

__all__ = [
    "download",
    "secscan",
    "tracepath",
]


__DOWNLOAD_SCHEMA_PATH = Path(__file__).parent / "schema-download.json"
__SECSCAN_SCHEMA_PATH = Path(__file__).parent / "schema-sec-scan.json"
__TRACEPATH_SCHEMA_PATH = Path(__file__).parent / "schema-trace-path.json"

with open(__DOWNLOAD_SCHEMA_PATH) as f:
    download = json.load(f)
with open(__SECSCAN_SCHEMA_PATH) as f:
    secscan = json.load(f)
with open(__TRACEPATH_SCHEMA_PATH) as f:
    tracepath = json.load(f)
