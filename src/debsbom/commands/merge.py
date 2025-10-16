# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import logging
from pathlib import Path

from .input import PkgStreamInput, SbomInput
from ..dpkg import package
from ..repack.merger import DscFileNotFoundError, SourceArchiveMerger
from ..util.compression import Compression
from ..util.progress import progress_cb


logger = logging.getLogger(__name__)


class MergeCmd(SbomInput, PkgStreamInput):
    """
    Processes an SBOM and merges the .orig and .debian tarballs. The tarballs have to be
    downloaded first.
    """

    @classmethod
    def run(cls, args):
        pkgdir = Path(args.pkgdir)
        outdir = Path(args.outdir or args.pkgdir)
        compress = Compression.from_tool(args.compress if args.compress != "no" else None)
        if cls.has_bomin(args):
            resolver = cls.get_sbom_resolver(args)
        else:
            resolver = cls.get_pkgstream_resolver()
        merger = SourceArchiveMerger(pkgdir, outdir, compress)
        pkgs = list(package.filter_sources(resolver))

        logger.info("Merging...")
        for idx, pkg in enumerate(pkgs):
            if args.progress:
                progress_cb(idx, len(pkgs), f"{pkg.name}@{pkg.version}")
            try:
                merger.merge(pkg, apply_patches=args.apply_patches)
            except DscFileNotFoundError:
                logger.warning(f"dsc file not found: {pkg.name}@{pkg.version}")

    @classmethod
    def setup_parser(cls, parser):
        cls.parser_add_sbom_input_args(parser)
        parser.add_argument(
            "--pkgdir", default="downloads/sources", help="directory with downloaded packages"
        )
        parser.add_argument(
            "--outdir", default="downloads/sources", help="directory to store the merged files"
        )
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
