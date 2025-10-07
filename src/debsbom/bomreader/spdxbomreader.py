# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import json
from pathlib import Path
from typing import IO

from pathlib import Path
from spdx_tools.spdx.parser.parse_anything import parse_file as spdx_parse_file
from spdx_tools.spdx.parser.jsonlikedict.json_like_dict_parser import JsonLikeDictParser
from spdx_tools.spdx.model.document import Document

from .bomreader import BomReader
from ..sbom import SPDXType


class SpdxBomReader(BomReader, SPDXType):
    """Import an SPDX SBOM"""

    @classmethod
    def read_file(cls, filename: Path) -> Document:
        return spdx_parse_file(str(filename))

    @classmethod
    def read_stream(cls, stream: IO[str]) -> Document:
        return JsonLikeDictParser().parse(json.load(stream))
