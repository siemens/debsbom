# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from io import TextIOWrapper
from pathlib import Path
import spdx_tools.spdx.writer.json.json_writer as spdx_json_writer

from .bomwriter import BomWriter
from ..sbom import CDXType


class SpdxBomWriter(BomWriter, CDXType):
    @staticmethod
    def write_to_file(bom, outfile: Path, validate: bool):
        spdx_json_writer.write_document_to_file(bom, str(outfile), validate)

    @staticmethod
    def write_to_stream(bom, f: TextIOWrapper, validate: bool):
        spdx_json_writer.write_document_to_stream(bom, f, validate)
        f.write("\n")
