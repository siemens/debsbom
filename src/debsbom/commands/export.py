# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import sys
from .input import SbomInput


class ExportCmd(SbomInput):
    """
    Processes an SBOM and converts it to various graph formats.
    Note, that SPDX SBOMs lead to better results, as they describes inter
    package relations more precisely.
    """

    @classmethod
    def run(cls, args):
        from ..export.exporter import GraphExporter
        from ..export.exporter import GraphOutputFormat

        exporters = cls.create_sbom_processors(
            args, GraphExporter, format=GraphOutputFormat.from_str(args.format)
        )
        for exporter in exporters:
            if args.out and args.out != "-":
                with open(args.out, "w") as f:
                    exporter.export(f)
            else:
                exporter.export(sys.stdout)

    @classmethod
    def setup_parser(cls, parser):
        cls.parser_add_sbom_input_args(parser)
        parser.add_argument("out", nargs="?", help="output file (optional)")
        parser.add_argument(
            "--format",
            help="graph output format (default: %(default)s)",
            choices=["graphml"],
            default="graphml",
        )
