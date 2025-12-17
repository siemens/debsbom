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
from .download import DownloadCmd
from ..sbom import SBOMType

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
        filtered_pkgs = list(
            filter(lambda p: DownloadCmd._filter_pkg(p, args.sources, args.binaries), resolver)
        )
        if not (args.sources and args.binaries):
            if resolver.sbom_type() == SBOMType.CycloneDX:
                if args.sources:
                    resolver.document.components = [
                        comp
                        for comp in resolver.document.components
                        if "arch=source" in str(comp.bom_ref.value)
                    ]
                    resolver.document.dependencies = []
                elif args.binaries:
                    resolver.document.components = [
                        comp
                        for comp in resolver.document.components
                        if "arch=source" not in str(comp.bom_ref.value)
                    ]
                    resolver.document.dependencies = [
                        dep
                        for dep in resolver.document.dependencies
                        if "arch=source" not in str(dep.ref.value)
                    ]
                    for dep in resolver.document.dependencies:
                        dep.dependencies = [
                            deps
                            for deps in dep.dependencies
                            if "arch=source" not in str(deps.ref.value)
                        ]
            elif resolver.sbom_type() == SBOMType.SPDX:
                if args.sources:
                    resolver.document.packages = [
                        pkg
                        for pkg in resolver.document.packages
                        if any(
                            "arch=source" in ref.locator
                            for ref in pkg.external_references
                            if ref.reference_type == "purl"
                        )
                    ]
                    resolver.document.relationships = []
                elif args.binaries:
                    resolver.document.packages = [
                        pkg
                        for pkg in resolver.document.packages
                        if any(
                            "arch=source" not in ref.locator
                            for ref in pkg.external_references
                            if ref.reference_type == "purl"
                        )
                    ]
                    binary_ids = {pkg.spdx_id for pkg in resolver.document.packages}
                    resolver.document.relationships = [
                        rel
                        for rel in resolver.document.relationships
                        if rel.spdx_element_id in binary_ids
                        and rel.related_spdx_element_id in binary_ids
                    ]
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
        parser.add_argument(
            "--sources",
            help="repack only source components (skip binaries)",
            action="store_true",
        )
        parser.add_argument(
            "--binaries",
            help="repack only binary components (skip sources)",
            action="store_true",
        )
