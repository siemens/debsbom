# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import logging
from pathlib import Path
import spdx_tools.spdx.writer.json.json_writer as spdx_json_writer

from ..bomreader.spdxbomreader import SpdxBomReader
from .input import GenerateInput
from ..merge.spdx import SpdxSbomMerger

logger = logging.getLogger(__name__)


class MergeCmd(GenerateInput):
    """Merge multiple SBOMs into a single one."""

    @staticmethod
    def run(args):
        # TODO: CDX
        # TODO: input SBOM type parsing
        docs = []
        for sbom in args.sboms:
            docs.append(SpdxBomReader.read_file(Path(sbom)))
        sbom_merger = SpdxSbomMerger(
            distro_name=args.distro_name,
            distro_supplier=args.distro_supplier,
            distro_version=args.distro_version,
            base_distro_vendor=args.base_distro_vendor,
            spdx_namespace=args.spdx_namespace,
            cdx_serialnumber=args.cdx_serialnumber,
            timestamp=args.timestamp,
        )
        bom = sbom_merger.merge_sboms(docs)
        spdx_json_writer.write_document_to_file(bom, "merged.spdx.json", validate=True)

    @classmethod
    def setup_parser(cls, parser):
        cls.parser_add_generate_input_args(parser, default_out="merged")
        parser.add_argument(
            "sboms",
            metavar="SBOM",
            nargs="+",
            help="SBOMs to merge",
        )
