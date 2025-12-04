# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from datetime import datetime
import logging
from pathlib import Path
import sys
from urllib.parse import urlparse
from uuid import UUID

from ..util.compression import Compression
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


class GenerateInput:
    """
    Mixin for SBOM generating commands.

    Provides options for SBOM output and root component metadata.
    """

    @classmethod
    def parser_add_generate_input_args(cls, parser, default_out):
        parser.add_argument(
            "-o",
            "--out",
            type=str,
            help="filename for output (default: %(default)s). Use '-' to write to stdout",
            default=default_out,
        )
        parser.add_argument(
            "--distro-name",
            type=str,
            help="distro name (default: %(default)s)",
            default="Debian",
        )
        parser.add_argument(
            "--distro-supplier",
            type=str,
            help="supplier for the root component",
            default=None,
        )
        parser.add_argument(
            "--distro-version",
            type=str,
            help="version for the root component",
            default=None,
        )
        parser.add_argument(
            "--base-distro-vendor",
            choices=["debian", "ubuntu"],
            help="vendor of debian distribution (debian or ubuntu)",
            default="debian",
        )
        parser.add_argument(
            "--cdx-standard",
            choices=["default", "standard-bom"],
            help="generate SBOM according to this spec (only for CDX)",
            default="default",
        )
        parser.add_argument(
            "--spdx-namespace",
            type=urlparse,
            help="document namespace, must be a valid URI (only for SPDX)",
            default=None,
        )
        parser.add_argument(
            "--cdx-serialnumber",
            type=UUID,
            help="document serial number, must be a UUID in 8-4-4-4-12 format (only for CDX)",
            default=None,
        )
        parser.add_argument(
            "--timestamp",
            type=datetime.fromisoformat,
            help="document timestamp in ISO 8601 format",
            default=None,
        )
        parser.add_argument(
            "--add-meta-data",
            action="append",
            metavar="key=value",
            help="add arbitrary metadata properties to the SBOM",
        )
        parser.add_argument(
            "--validate",
            help="validate generated SBOM (only for SPDX)",
            action="store_true",
        )


class RepackInput:
    """
    Mixin for SBOM repacking commands.
    """

    @classmethod
    def parser_add_repack_input_args(cls, parser):
        parser.add_argument(
            "--compress",
            help="compress merged tarballs (default: gzip)",
            choices=["no"] + [c.tool for c in Compression.formats()],
            default="gzip",
        )
        parser.add_argument(
            "--apply-patches",
            help="apply debian patches",
            action="store_true",
        )
        parser.add_argument(
            "--mtime",
            type=datetime.fromisoformat,
            help="set mtime for creating tar archives in ISO 8601 format. If this option is not set,"
            " the timestamp from the most recent changelog entry is used for reproducible builds.",
        )
