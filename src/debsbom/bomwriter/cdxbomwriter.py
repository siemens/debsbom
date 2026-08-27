# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from io import TextIOWrapper
from pathlib import Path
import cyclonedx.output as cdx_output
import cyclonedx.schema as cdx_schema

from .bomwriter import BomWriter, SerializerOpts
from ..sbom import CDXType


class CdxSerializerOpts(SerializerOpts):
    """
    Options for the SBOM serializer
    """

    def __init__(self, cdx_schema_version: str):
        try:
            match cdx_schema_version:
                case "latest":
                    self.cdx_schema_version = max(cdx_schema.SchemaVersion)
                case _:
                    self.cdx_schema_version = cdx_schema.SchemaVersion.from_version(
                        cdx_schema_version
                    )
        except ValueError:
            raise ValueError(f"Invalid CycloneDX schema version: {cdx_schema_version}")


class CdxBomWriter(BomWriter, CDXType):
    @staticmethod
    def write_to_file(bom, outfile: Path, validate: bool, opts: CdxSerializerOpts | None = None):
        opts = opts or CdxSerializerOpts("latest")
        cdx_output.make_outputter(
            bom, cdx_schema.OutputFormat.JSON, opts.cdx_schema_version
        ).output_to_file(str(outfile), allow_overwrite=True, indent=4)

    @staticmethod
    def write_to_stream(
        bom, f: TextIOWrapper, validate: bool, opts: CdxSerializerOpts | None = None
    ):
        opts = opts or CdxSerializerOpts("latest")
        f.write(
            cdx_output.make_outputter(
                bom, cdx_schema.OutputFormat.JSON, opts.cdx_schema_version
            ).output_as_string(indent=4)
        )
