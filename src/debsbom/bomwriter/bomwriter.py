# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import cyclonedx.output as cdx_output
import cyclonedx.schema as cdx_schema
from io import TextIOWrapper
from pathlib import Path
import spdx_tools.spdx.writer.json.json_writer as spdx_json_writer

from ..sbom import SBOMType


class BomWriter:
    @staticmethod
    def write_to_file(bom, bomtype: SBOMType, outfile: Path, validate: bool):
        if bomtype == SBOMType.CycloneDX:
            cdx_output.make_outputter(
                bom, cdx_schema.OutputFormat.JSON, cdx_schema.SchemaVersion.V1_6
            ).output_to_file(str(outfile), allow_overwrite=True, indent=4)
        elif bomtype == SBOMType.SPDX:
            spdx_json_writer.write_document_to_file(bom, str(outfile), validate)

    @staticmethod
    def write_to_stream(bom, bomtype: SBOMType, f: TextIOWrapper, validate: bool):
        if bomtype == SBOMType.CycloneDX:
            f.write(
                cdx_output.make_outputter(
                    bom, cdx_schema.OutputFormat.JSON, cdx_schema.SchemaVersion.V1_6
                ).output_as_string(indent=4)
            )
        elif bomtype == SBOMType.SPDX:
            spdx_json_writer.write_document_to_stream(bom, f, validate)
        f.write("\n")
