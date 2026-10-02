# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import json
from pathlib import Path

__all__ = [
    "download",
    "filter_report",
    "secscan",
    "tracepath",
]


__DOWNLOAD_SCHEMA_PATH = Path(__file__).parent / "schema-download.json"
__FILTER_REPORT_SCHEMA_PATH = Path(__file__).parent / "schema-filter-report.json"
__SECSCAN_SCHEMA_PATH = Path(__file__).parent / "schema-sec-scan.json"
__TRACEPATH_SCHEMA_PATH = Path(__file__).parent / "schema-trace-path.json"

with open(__DOWNLOAD_SCHEMA_PATH) as f:
    download = json.load(f)
with open(__FILTER_REPORT_SCHEMA_PATH) as f:
    filter_report = json.load(f)
with open(__SECSCAN_SCHEMA_PATH) as f:
    secscan = json.load(f)
with open(__TRACEPATH_SCHEMA_PATH) as f:
    tracepath = json.load(f)
