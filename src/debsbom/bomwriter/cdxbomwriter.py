# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from io import TextIOWrapper
from pathlib import Path
import cyclonedx.output as cdx_output
import cyclonedx.schema as cdx_schema

from .bomwriter import BomWriter
from ..sbom import CDXType


class CdxBomWriter(BomWriter, CDXType):
    @staticmethod
    def write_to_file(bom, outfile: Path, validate: bool):
        cdx_output.make_outputter(
            bom, cdx_schema.OutputFormat.JSON, cdx_schema.SchemaVersion.V1_6
        ).output_to_file(str(outfile), allow_overwrite=True, indent=4)

    @staticmethod
    def write_to_stream(bom, f: TextIOWrapper, validate: bool):
        f.write(
            cdx_output.make_outputter(
                bom, cdx_schema.OutputFormat.JSON, cdx_schema.SchemaVersion.V1_6
            ).output_as_string(indent=4)
        )
