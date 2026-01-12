# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from io import TextIOBase

from .bomreader import BomReader
from ..sbom import CDXType

import json
from pathlib import Path
from cyclonedx.model.bom import Bom


class CdxBomFileReader(BomReader, CDXType):
    """Import a CycloneDX SBOM from a file"""

    def __init__(self, filename: Path):
        self.filename = filename

    def read(self) -> Bom:
        with open(self.filename, "r") as f:
            return CdxBomStreamReader(f).read()


class CdxBomStreamReader(BomReader, CDXType):
    """Import a CycloneDX SBOM from a file stream"""

    def __init__(self, stream: TextIOBase):
        self.stream = stream

    def read(self) -> Bom:
        return CdxBomJsonReader(json.load(self.stream)).read()


class CdxBomJsonReader(BomReader, CDXType):
    """Import a CycloneDX SBOM from a json object"""

    def __init__(self, json_obj):
        self.json_obj = json_obj

    def read(self) -> Bom:
        return Bom.from_json(self.json_obj)
