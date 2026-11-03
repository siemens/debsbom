# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

import logging
from pathlib import Path
import sys


from ..sbom import SBOMType
from ..bomwriter.bomwriter import BomWriter, SerializerOpts

logger = logging.getLogger(__name__)


class SbomOutput:
    """
    Mixin that writes an SBOM based on an output argument
    """

    @classmethod
    def write_out_arg(
        cls,
        bom,
        bomtype: SBOMType,
        out: str,
        validate: bool,
        opts: SerializerOpts | None = None,
    ):
        writer = BomWriter.create(bomtype)
        if out == "-":
            logger.info("Emit SBOM on stdout")
            writer.write_to_stream(bom, sys.stdout, validate=validate, opts=opts)
        else:
            file_format = None
            if opts is not None:
                try:
                    from ..bomwriter.spdxbomwriter import SpdxSerializerOpts

                    if isinstance(opts, SpdxSerializerOpts):
                        import spdx_tools.spdx.formats
                        from spdx_tools.spdx.parser.error import SPDXParsingError

                        if opts.output_format is None:
                            try:
                                file_format = spdx_tools.spdx.formats.file_name_to_format(out)
                            except SPDXParsingError:
                                pass
                        else:
                            file_format = opts.output_format
                except ImportError:
                    pass

                try:
                    from ..bomwriter.cdxbomwriter import CdxSerializerOpts

                    if isinstance(opts, CdxSerializerOpts):
                        file_format = opts.output_format
                except ImportError:
                    pass
            if file_format is None and not out.endswith(f".{bomtype}.json"):
                out += f".{bomtype}.json"
            logger.info(f"Write SBOM to file {out}")
            writer.write_to_file(bom, Path(out), validate=validate, opts=opts)
