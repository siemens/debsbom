# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

import logging
from pathlib import Path
import sys

from ..sbom import SBOMType
from ..bomwriter.bomwriter import BomWriter

logger = logging.getLogger(__name__)


class SbomOutput:
    """
    Mixin that writes an SBOM based on an output argument
    """

    @classmethod
    def write_out_arg(cls, bom, bomtype: SBOMType, out: str, validate: bool):
        writer = BomWriter.create(bomtype)
        if out == "-":
            logger.info("Emit SBOM on stdout")
            writer.write_to_stream(bom, sys.stdout, validate=validate)
        else:
            if not out.endswith(f".{bomtype}.json"):
                out += f".{bomtype}.json"
            logger.info(f"Write SBOM to file {out}")
            writer.write_to_file(bom, Path(out), validate=validate)
