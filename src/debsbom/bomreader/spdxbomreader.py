# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import json
from pathlib import Path
from io import TextIOBase

from spdx_tools.spdx.parser.parse_anything import parse_file as spdx_parse_file
from spdx_tools.spdx.parser.jsonlikedict.json_like_dict_parser import JsonLikeDictParser
from spdx_tools.spdx.model.document import Document

from .bomreader import BomReader
from ..sbom import SPDXType


class SpdxBomFileReader(BomReader, SPDXType):
    """Import a CycloneDX SBOM from a file"""

    def __init__(self, filename: Path):
        self.filename = filename

    def read(self) -> Document:
        return spdx_parse_file(str(self.filename))


class SpdxBomStreamReader(BomReader, SPDXType):
    """Import a CycloneDX SBOM from a file stream"""

    def __init__(self, stream: TextIOBase):
        self.stream = stream

    def read(self) -> Document:
        return SpdxBomJsonReader(json.load(self.stream)).read()


class SpdxBomJsonReader(BomReader, SPDXType):
    """Import a CycloneDX SBOM from a json object"""

    def __init__(self, json_obj):
        self.json_obj = json_obj

    def read(self) -> Document:
        return JsonLikeDictParser().parse(self.json_obj)
