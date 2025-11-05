# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import json
from pathlib import Path
import sys


from ..bomwriter import BomWriter
from .input import GenerateInput, SbomInput, warn_if_tty
from ..sbom import SBOMType


class CompareCmd(GenerateInput, SbomInput):
    """
    Compare two SBOMs and generate a new SBOM containing only the additional components found in the target
    """

    @classmethod
    def run(cls, args):
        inputs = [
            ("base", args.base_sbom),
            ("target", args.target_sbom),
        ]

        base_json_obj = target_json_obj = None
        base_path = target_path = None
        base_sbom_fmt = target_sbom_fmt = None
        base_sbom_obj = target_sbom_obj = None

        json_sboms = []
        stdin_consumed = False

        for kind, sbom_arg in inputs:
            # read from stdin
            if sbom_arg == "-":
                warn_if_tty()
                if args.sbom_type is None:
                    raise ValueError("option --sbom-type is required when reading SBOMs from stdin")

                if not stdin_consumed:
                    decoder = json.JSONDecoder()
                    s = sys.stdin.read()
                    json_obj, _ = decoder.raw_decode(s)
                    len_s = len(s)
                    read_total = 0
                    while read_total < len_s:
                        json_obj, read = decoder.raw_decode(s[read_total:])
                        read_total += read
                        json_sboms.append(json_obj)

                    stdin_consumed = True

                # Pop the next object for this argument
                try:
                    json_obj = json_sboms.pop(0)
                except IndexError:
                    raise ValueError("Not enough SBOMs provided on stdin")

                fmt = args.sbom_type

                if kind == "base":
                    base_json_obj = json_obj
                    base_sbom_fmt = fmt
                else:
                    target_json_obj = json_obj
                    target_sbom_fmt = fmt

            else:
                sbom_path = Path(sbom_arg)
                if ".spdx" in sbom_path.suffixes:
                    fmt = "spdx"
                elif ".cdx" in sbom_path.suffixes:
                    fmt = "cdx"
                else:
                    raise ValueError(f"cannot detect SBOM format for {sbom_arg}")

                if kind == "base":
                    base_path = sbom_path
                    base_sbom_fmt = fmt
                else:
                    target_path = sbom_path
                    target_sbom_fmt = fmt

        if base_sbom_fmt != target_sbom_fmt:
            raise ValueError("can not compare mixed SPDX and CycloneDX documents")

        SBOMType.from_str(target_sbom_fmt).validate_dependency_availability()

        from ..compare.compare import SbomCompare

        bom = SbomCompare.run_compare(
            fmt=target_sbom_fmt,
            args=args,
            base_json_obj=base_json_obj,
            target_json_obj=target_json_obj,
            base_path=base_path,
            target_path=target_path,
        )

        sbom_type = SBOMType.SPDX if target_sbom_fmt == "spdx" else SBOMType.CycloneDX

        if args.out == "-":
            BomWriter.write_to_stream(bom, sbom_type, sys.stdout, args.validate)
        else:
            out = args.out
            suffix = ".spdx.json" if target_sbom_fmt == "spdx" else ".cdx.json"
            if not out.endswith(suffix):
                out += suffix
            BomWriter.write_to_file(bom, sbom_type, Path(out), args.validate)

    @classmethod
    def setup_parser(cls, parser):
        cls.parser_add_generate_input_args(parser, default_out="extras")
        cls.parser_add_sbom_input_args(
            parser, required=True, sbom_args=["base_sbom", "target_sbom"]
        )
