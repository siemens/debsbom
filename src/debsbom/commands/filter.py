# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from .output import SbomOutput
from .input import SbomInput, SourceBinaryInput


class FilterCmd(SbomInput, SourceBinaryInput):
    """Filter SBOM by sources or binaries."""

    @classmethod
    def run(cls, args):
        resolvers = cls.get_sbom_resolvers(args)

        for resolver in resolvers:
            cls.filter_sbom(resolver, args.sources, args.binaries)
            SbomOutput.write_out_arg(
                resolver.document, resolver.sbom_type(), args.bomout, args.validate
            )

    @classmethod
    def setup_parser(cls, parser):
        cls.parser_add_sbom_input_args(parser, required=True)
        cls.parser_add_source_binary_args(parser)
        parser.add_argument("bomout", help="sbom output file. Use '-' to write to stdout")
        parser.add_argument(
            "--validate",
            help="validate generated SBOM (only for SPDX)",
            action="store_true",
        )
