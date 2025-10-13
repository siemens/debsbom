# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import logging
from pathlib import Path
import sys

from ..resolver.resolver import PackageResolver, PackageStreamResolver
from ..sbom import SBOMType


logger = logging.getLogger(__name__)


def warn_if_tty() -> None:
    if sys.stdin.isatty():
        logger.warning("Expecting data via stdin, but connected to TTY.")


class SbomInput:
    """
    Mixin that needs an SBOM as input
    """

    @classmethod
    def parser_add_sbom_input_args(cls, parser, required=False):
        parser.add_argument(
            "bomin",
            help="sbom file to process. Use '-' to read SBOM from stdin",
            nargs=None if required else "?",
        )
        parser.add_argument(
            "-t",
            "--sbom-type",
            choices=["cdx", "spdx"],
            help="SBOM type to process (default: auto-detect)",
        )

    @classmethod
    def create_sbom_processor(cls, args, processor_cls, *proc_args):
        if args.bomin == "-":
            if not args.sbom_type:
                raise RuntimeError("If reading from stdin, the '--sbom-type' needs to be set")
            return processor_cls.from_stream(
                sys.stdin, SBOMType.from_str(args.sbom_type), *proc_args
            )
        return processor_cls.create(Path(args.bomin), *proc_args)

    @classmethod
    def get_sbom_resolver(cls, args) -> PackageResolver:
        return cls.create_sbom_processor(args, PackageResolver)

    @classmethod
    def has_bomin(cls, args):
        return args.bomin is not None


class PkgStreamInput:
    """
    Mixin that takes a pkgstream as input. A pkgstream is either a stream
    of newline separated tuples "<pkg-name> <pkg-version> <pkg-arch>" or a
    stream of newline separated debian PURLs.
    """

    @classmethod
    def get_pkgstream_resolver(cls):
        warn_if_tty()
        return PackageStreamResolver(sys.stdin)
