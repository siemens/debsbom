# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from typing import IO

from .bomreader import BomReader
from ..sbom import CDXType

import json
from pathlib import Path
from cyclonedx.model.bom import Bom


class CdxBomReader(BomReader, CDXType):
    """Import an CycloneDX SBOM"""

    @classmethod
    def read_file(cls, filename: Path) -> Bom:
        with open(filename, "r") as f:
            return cls.read_stream(f)

    @classmethod
    def read_stream(cls, stream: IO[str]) -> Bom:
        return Bom.from_json(json.load(stream))
