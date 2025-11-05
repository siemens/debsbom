# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import logging
import json
from pathlib import Path
import sys

from ..bomreader.cdxbomreader import CdxBomReader
from ..bomreader.spdxbomreader import SpdxBomReader
from ..bomwriter import BomWriter
from .input import GenerateInput, warn_if_tty
from ..compare.spdx import SpdxSbomCompare
from ..compare.cdx import CdxSbomCompare
from ..sbom import SBOMType


logger = logging.getLogger(__name__)


class CompareCmd(GenerateInput):
    """
    Compare two SBOMs and generate a new SBOM containing only the additional components found in the target
    """

    @classmethod
    def run(cls, args):
        if args.base_sbom == "-" or args.target_sbom == "-":
            warn_if_tty()
            if args.sbom_type is None:
                raise ValueError("option --sbom-type is required when reading SBOMs from stdin")
            decoder = json.JSONDecoder()
        else:
            base_sbom_fmt = None
            target_sbom_fmt = None
            base_sbom_path = Path(args.base_sbom)
            target_sbom_path = Path(args.target_sbom)

            if ".spdx" in base_sbom_path.suffixes:
                base_sbom_fmt = "spdx"
            elif ".cdx" in target_sbom_path.suffixes:
                base_sbom_fmt = "cdx"

            if ".spdx" in target_sbom_path.suffixes:
                target_sbom_fmt = "spdx"
            elif ".cdx" in target_sbom_path.suffixes:
                target_sbom_fmt = "cdx"

        if not base_sbom_fmt or not target_sbom_fmt:
            raise ValueError("can not detect SBOM format for one or both files")

        if base_sbom_fmt != target_sbom_fmt:
            raise ValueError("can not compare mixed SPDX and CycloneDX documents")

        if target_sbom_fmt == "spdx":
            base_sbom_obj = SpdxBomReader.read_file(args.base_sbom)
            target_sbom_obj = SpdxBomReader.read_file(args.target_sbom)
            sbom_compare = SpdxSbomCompare(
                distro_name=args.distro_name,
                distro_supplier=args.distro_supplier,
                distro_version=args.distro_version,
                base_distro_vendor=args.base_distro_vendor,
                spdx_namespace=args.spdx_namespace,
                cdx_serialnumber=args.cdx_serialnumber,
                timestamp=args.timestamp,
            )
            bom = sbom_compare.compare(base_sbom_obj, target_sbom_obj)
            if args.out == "-":
                BomWriter.write_to_stream(bom, SBOMType.SPDX, sys.stdout, args.validate)
            else:
                out = args.out
                if not out.endswith(".spdx.json"):
                    out += ".spdx.json"
                BomWriter.write_to_file(bom, SBOMType.SPDX, Path(out), args.validate)

        if target_sbom_fmt == "cdx":
            base_sbom_obj = CdxBomReader.read_file(args.base_sbom)
            target_sbom_obj = CdxBomReader.read_file(args.target_sbom)
            sbom_compare = CdxSbomCompare(
                distro_name=args.distro_name,
                distro_supplier=args.distro_supplier,
                distro_version=args.distro_version,
                base_distro_vendor=args.base_distro_vendor,
                spdx_namespace=args.spdx_namespace,
                cdx_serialnumber=args.cdx_serialnumber,
                timestamp=args.timestamp,
            )
            bom = sbom_compare.compare(base_sbom_obj, target_sbom_obj)
            if args.out == "-":
                BomWriter.write_to_stream(bom, SBOMType.CycloneDX, sys.stdout, args.validate)
            else:
                out = args.out
                if not out.endswith(".cdx.json"):
                    out += ".cdx.json"
                BomWriter.write_to_file(bom, SBOMType.CycloneDX, Path(out), args.validate)

    @classmethod
    def setup_parser(cls, parser):
        cls.parser_add_generate_input_args(parser, default_out="extras")
        parser.add_argument(
            "-b",
            "--base-sbom",
            required=True,
            help="Path to the base (reference) SBOM file"
        )

        parser.add_argument(
            "-n",
            "--target-sbom",
            required=True,
            help="Path to the target (new) SBOM file"
        )
