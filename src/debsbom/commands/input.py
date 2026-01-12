# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from datetime import datetime
import logging
from pathlib import Path
import sys
from urllib.parse import urlparse
from uuid import UUID

from ..dpkg import package
from ..util.compression import Compression
from ..util.sbom_processor import SbomProcessor
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
    def parser_add_sbom_input_args(cls, parser, required=False, sbom_args=None, multi_input=False):
        sbom_args = sbom_args or ["bomin"]

        if multi_input:
            nargs = "+" if required else "*"
        else:
            nargs = None if required else "?"

        for arg in sbom_args:
            parser.add_argument(
                arg,
                help=f"sbom file(s) to process for '{arg}'. Use '-' to read from stdin",
                nargs=nargs,
                metavar=arg.upper(),
            )
        parser.add_argument(
            "-t",
            "--sbom-type",
            choices=["cdx", "spdx"],
            help="SBOM type to process (default: auto-detect), required when reading from stdin",
        )

    @classmethod
    def create_sbom_processors(
        cls, args, processor_cls, sbom_args=None, **proc_args
    ) -> list[SbomProcessor]:
        sbom_args = sbom_args or ["bomin"]
        processors = []

        for arg_name in sbom_args:
            arg_value = getattr(args, arg_name, None)
            if not arg_value:
                continue
            # Wrap single value in a list for uniform iteration
            sbom_files = arg_value if isinstance(arg_value, list) else [arg_value]

            for sbom_file in sbom_files:
                if sbom_file == "-":
                    if not args.sbom_type:
                        raise RuntimeError(
                            "If reading from stdin, the '--sbom-type' needs to be set"
                        )
                    processors.append(
                        processor_cls.from_stream(
                            sys.stdin, bomtype=SBOMType.from_str(args.sbom_type), **proc_args
                        )
                    )
                else:
                    processors.append(
                        processor_cls.create(Path(sbom_file), bomtype=args.sbom_type, **proc_args)
                    )

        return processors

    @classmethod
    def get_sbom_resolvers(cls, args) -> list[PackageResolver]:
        return cls.create_sbom_processors(args, PackageResolver)

    @classmethod
    def has_sboms(cls, args, sbom_args=None) -> bool:
        sbom_args = sbom_args or ["bomin"]
        return any(getattr(args, arg, None) is not None for arg in sbom_args)

    @classmethod
    def has_bomin(cls, args) -> bool:
        return cls.has_sboms(args)


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


class SourceBinaryInput:
    """
    Mixin for SBOM download and repack commands.
    """

    @classmethod
    def parser_add_source_binary_args(cls, parser):
        parser.add_argument(
            "--sources",
            help="operate only on source packages (skip binaries)",
            action="store_true",
        )
        parser.add_argument(
            "--binaries",
            help="operate only on binary packages (skip sources)",
            action="store_true",
        )

    @staticmethod
    def _filter_pkg(
        p: package.Package, sources: bool, binaries: bool, skip: list[package.Package] | None = None
    ) -> bool:
        if skip and p in skip:
            return False

        if not sources and not binaries:
            return True
        if sources and p.is_source():
            return True
        if binaries and p.is_binary():
            return True
        return False


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
