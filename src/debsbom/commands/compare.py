# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import json
from pathlib import Path
import sys

from ..bomwriter import BomWriter
from .input import GenerateInput, warn_if_tty
from ..sbom import SBOMType


class CompareCmd(GenerateInput):
    """
    Compare two SBOMs and generate a new SBOM containing only the additional components found in the target
    """

    @classmethod
    def run(cls, args):
        base_sbom_fmt = None
        target_sbom_fmt = None

        base_json_obj = None
        target_json_obj = None

        base_path = None
        target_path = None

        base_sbom_obj = None
        target_sbom_obj = None

        inputs = [
            ("base", args.base_sbom),
            ("target", args.target_sbom),
        ]

        for kind, sbom_arg in inputs:
            # read from stdin
            if sbom_arg == "-" or sbom_arg.startswith("/dev/fd/"):
                warn_if_tty()
                if args.sbom_type is None:
                    raise ValueError("option --sbom-type is required when reading SBOMs from stdin")
                # determine file descriptor
                if sbom_arg == "-":
                    fd = sys.stdin
                else:
                    fd = open(sbom_arg, "r")

                s = fd.read()
                decoder = json.JSONDecoder()
                json_obj, _ = decoder.raw_decode(s)

                fmt = args.sbom_type

                if kind == "base":
                    base_json_obj = json_obj
                else:
                    target_json_obj = json_obj

            else:
                sbom_path = Path(sbom_arg)
                if ".spdx" in sbom_path.suffixes:
                    SBOMType.SPDX.validate_dependency_availability()
                    fmt = "spdx"
                elif ".cdx" in sbom_path.suffixes:
                    SBOMType.CycloneDX.validate_dependency_availability()
                    fmt = "cdx"
                else:
                    raise ValueError(f"cannot detect SBOM format for {sbom_arg}")

                if kind == "base":
                    base_path = sbom_path
                else:
                    target_path = sbom_path

            if kind == "base":
                base_sbom_fmt = fmt
            else:
                target_sbom_fmt = fmt

        if base_sbom_fmt != target_sbom_fmt:
            raise ValueError("can not compare mixed SPDX and CycloneDX documents")

        if target_sbom_fmt == "spdx":
            from ..bomreader.spdxbomreader import SpdxBomReader
            from ..compare.spdx import SpdxSbomCompare

            if base_json_obj is not None:
                base_sbom_obj = SpdxBomReader.from_json(base_json_obj)
            else:
                base_sbom_obj = SpdxBomReader.read_file(base_path)

            if target_json_obj is not None:
                target_sbom_obj = SpdxBomReader.from_json(target_json_obj)
            else:
                target_sbom_obj = SpdxBomReader.read_file(target_path)

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
            from ..bomreader.cdxbomreader import CdxBomReader
            from ..compare.cdx import CdxSbomCompare

            if base_json_obj is not None:
                base_sbom_obj = CdxBomReader.from_json(base_json_obj)
            else:
                base_sbom_obj = CdxBomReader.read_file(base_path)

            if target_json_obj is not None:
                target_sbom_obj = CdxBomReader.from_json(target_json_obj)
            else:
                target_sbom_obj = CdxBomReader.read_file(target_path)

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
            "-t",
            "--sbom-type",
            choices=["cdx", "spdx"],
            help="expected SBOM type when reading SBOMs from stdin, required when reading from stdin",
        )
        parser.add_argument(
            "-b",
            "--base-sbom",
            required=True,
            help="Path to the base (reference) SBOM file",
        )
        parser.add_argument(
            "-n",
            "--target-sbom",
            required=True,
            help="Path to the target (new) SBOM file",
        )
