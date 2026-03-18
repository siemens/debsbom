# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import logging
from pathlib import Path
import sys

from .output import SbomOutput
from .input import SbomInput, RepackInput, SourceBinaryInput
from ..repack.packer import BomTransformer, Packer
from ..resolver.resolver import PackageStreamResolver
from ..util.compression import Compression
from .download import DownloadCmd
from ..sbom import SBOMType, SPDX_REF_DOCUMENT

logger = logging.getLogger(__name__)


class RepackCmd(SbomInput, RepackInput, SourceBinaryInput):
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

        if args.format == "standard-bom":
            logger.warning(
                "format 'standard-bom' is deprecated, use 'standard-bom-package' instead"
            )
            args.format = "standard-bom-package"

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
        resolvers = cls.get_sbom_resolvers(args)
        for resolver in resolvers:
            filtered_pkgs = list(
                filter(lambda p: DownloadCmd._filter_pkg(p, args.sources, args.binaries), resolver)
            )
            cls.filter_sbom(resolver, args.sources, args.binaries)
            bt = BomTransformer.create(args.format, resolver.sbom_type(), resolver.document)
            if pkg_subset:
                pkgs = filter(lambda p: p in pkg_subset, filtered_pkgs)
            else:
                pkgs = filtered_pkgs
            repacked = filter(
                lambda p: p,
                map(
                    lambda p: packer.repack(p, symlink=linkonly, mtime=args.mtime),
                    pkgs,
                ),
            )
            bom = packer.rewrite_sbom(bt, repacked)
            SbomOutput.write_out_arg(bom, resolver.sbom_type(), args.bomout, args.validate)

    @classmethod
    def setup_parser(cls, parser):
        from ..cli import arg_mark_as_file, arg_mark_as_dir

        cls.parser_add_sbom_input_args(parser, required=True)
        cls.parser_add_repack_input_args(parser)
        arg_mark_as_file(
            parser.add_argument("bomout", help="sbom output file. Use '-' to write to stdout")
        )
        arg_mark_as_dir(
            parser.add_argument(
                "--dldir", default="downloads", help="download directory from 'download'"
            )
        )
        arg_mark_as_dir(
            parser.add_argument(
                "--outdir", default="packed", help="directory to repack into (default: %(default)s)"
            )
        )
        parser.add_argument(
            "--format",
            default="standard-bom-package",
            choices=["standard-bom", "standard-bom-package"],
        )
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
        cls.parser_add_source_binary_args(parser)
