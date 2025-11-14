# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import logging
from pathlib import Path
import sys

from ..bomwriter import BomWriter
from .input import SbomInput, RepackInput
from ..generate.generate import Debsbom
from ..repack.packer import BomTransformer, Packer
from ..resolver.resolver import PackageStreamResolver
from ..util.compression import Compression


logger = logging.getLogger(__name__)


class RepackCmd(SbomInput, RepackInput):
    """
    Repacks the downloaded files into a uniform source archive, merging the
    referenced source packages into a single archive and optionally applying
    patches.
    The layout of the source archive is controlled by the 'format' argument.
    If an input SBOM is provided and data is passed via stdin, only the packages passed via
    stdin are resolved and updated in the final SBOM.

    Note: The files have to be downloaded first and need to be in the directory specified by 'dldir'.
    """

    @classmethod
    def run(cls, args):
        compress = Compression.from_tool(args.compress if args.compress != "no" else None)
        linkonly = not args.copy

        if cls.has_bomin(args) and not sys.stdin.isatty():
            logger.info("run in partial-repack mode")
            pkg_subset = set(PackageStreamResolver(sys.stdin))
        else:
            pkg_subset = None

        packer = Packer.from_format(
            fmt=args.format,
            dldir=Path(args.dldir),
            outdir=Path(args.outdir),
            compress=compress,
            apply_patches=args.apply_patches,
        )
        resolver = cls.get_sbom_resolver(args)
        bt = BomTransformer.create(args.format, resolver.sbom_type(), resolver.document)
        if pkg_subset:
            pkgs = filter(lambda p: p in pkg_subset, resolver)
        else:
            pkgs = resolver
        repacked = filter(
            lambda p: p,
            map(
                lambda p: packer.repack(p, symlink=linkonly, mtime=args.mtime),
                pkgs,
            ),
        )
        bom = packer.rewrite_sbom(bt, repacked)
        if args.bomout == "-":
            BomWriter.write_to_stream(bom, resolver.sbom_type(), sys.stdout, validate=args.validate)
        else:
            BomWriter.write_to_file(
                bom, resolver.sbom_type(), Path(args.bomout), validate=args.validate
            )

    @classmethod
    def setup_parser(cls, parser):
        cls.parser_add_sbom_input_args(parser, required=True)
        cls.parser_add_repack_input_args(parser)
        parser.add_argument("bomout", help="sbom output file. Use '-' to write to stdout")
        parser.add_argument(
            "--dldir", default="downloads", help="download directory from 'download'"
        )
        parser.add_argument(
            "--outdir", default="packed", help="directory to repack into (default: %(default)s)"
        )
        parser.add_argument("--format", default="standard-bom", choices=["standard-bom"])
        parser.add_argument(
            "--copy",
            help="copy artifacts into deploy tree instead of symlinking",
            action="store_true",
        )
        parser.add_argument(
            "--validate",
            help="validate generated SBOM (only for SPDX)",
            action="store_true",
        )
