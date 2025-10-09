#!/usr/bin/env python3

# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import argparse
from datetime import datetime
from importlib.metadata import version
import itertools
import logging
import sys
import traceback
from uuid import UUID
from urllib.parse import urlparse
from pathlib import Path

from .sbom import BOM_Standard
from .dpkg import package
from .generate import Debsbom, SBOMType
from . import HAS_PYTHON_APT

# Keep the set of required deps to a bare minimum, needed for SBOM generation
try:
    import requests
    from .download import (
        PackageDownloader,
        PackageResolver,
        PackageStreamResolver,
        PersistentResolverCache,
        SourceArchiveMerger,
        DscFileNotFoundError,
    )
    from .snapshot import client as sdlclient
    from .repack import Packer, BomTransformer
    from .util import Compression

    HAS_DOWNLOAD_DEPS = True
except ModuleNotFoundError:
    HAS_DOWNLOAD_DEPS = False

logger = logging.getLogger(__name__)


def progress_cb(i: int, n: int, name: str):
    clear = "\r\033[K"
    sys.stdout.write(f"{clear}processing {i+1}/{n} ({name})")
    if i + 1 == n:
        sys.stdout.write("\n")
    sys.stdout.flush()


def warn_if_tty() -> None:
    if sys.stdin.isatty():
        logger.warning("Expecting data via stdin, but connected to TTY.")


class SbomInput:
    """
    Mixin that needs an SBOM as input
    """

    @classmethod
    def parser_add_sbom_input_args(cls, parser):
        parser.add_argument(
            "bomin", help="sbom file to process ('-' to read SBOM from stdin)", nargs="?"
        )
        parser.add_argument(
            "-t",
            "--sbom-type",
            choices=["cdx", "spdx"],
            help="SBOM type to process (default: auto-detect)",
        )

    @classmethod
    def get_sbom_resolver(cls, args):
        if args.bomin == "-":
            if not args.sbom_type:
                raise RuntimeError("If reading from stdin, the '--sbom-type' needs to be set")
            return PackageResolver.from_stream(sys.stdin, SBOMType.from_str(args.sbom_type))
        return PackageResolver.create(Path(args.bomin))

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


class GenerateCmd:
    """
    Generate SBOMs from the dpkg package list
    """

    @staticmethod
    def run(args):
        if args.sbom_type is None:
            sbom_types = [SBOMType.SPDX, SBOMType.CycloneDX]
        else:
            sbom_types = [SBOMType.from_str(stype) for stype in args.sbom_type]

        cdx_standard = BOM_Standard.DEFAULT
        if args.cdx_standard == "standard-bom":
            cdx_standard = BOM_Standard.STANDARD_BOM

        debsbom = Debsbom(
            distro_name=args.distro_name,
            sbom_types=sbom_types,
            root=args.root,
            distro_supplier=args.distro_supplier,
            distro_version=args.distro_version,
            base_distro_vendor=args.base_distro_vendor,
            spdx_namespace=args.spdx_namespace,
            cdx_serialnumber=args.cdx_serialnumber,
            timestamp=args.timestamp,
            cdx_standard=cdx_standard,
        )
        if args.from_pkglist:
            warn_if_tty()

        debsbom.generate(
            args.out,
            progress_cb=progress_cb if args.progress else None,
            validate=args.validate,
            pkgs_stream=sys.stdin if args.from_pkglist else None,
        )

    @staticmethod
    def setup_parser(parser):
        parser.add_argument(
            "-t",
            "--sbom-type",
            choices=["cdx", "spdx"],
            action="append",
            help="SBOM type to generate, can be passed multiple times (default: all)",
        )
        parser.add_argument(
            "-r",
            "--root",
            type=str,
            help="root directory to look for dpkg status file",
            default="/",
        )
        parser.add_argument(
            "-o",
            "--out",
            type=str,
            help="filename for output (default: %(default)s). Use '-' to write to stdout",
            default="sbom",
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
            "--validate",
            help="validate generated SBOM (only for SPDX)",
            action="store_true",
        )
        parser.add_argument(
            "--from-pkglist",
            help="create SBOM from a package list passed via stdin instead of dpkg data",
            action="store_true",
        )


class DownloadCmd(SbomInput, PkgStreamInput):
    """
    Processes a SBOM and downloads the referenced packages.
    If no SBOM is provided, it reads line separated entries (name version arch)
    from stdin to define what shall be downloaded.
    """

    @staticmethod
    def human_readable_bytes(size):
        if size < 1024 * 1024:
            return f"{int(size / 1024):d} KiB"
        elif size < 1024 * 1024 * 1024:
            return f"{int(size / 1024 / 1024):d} MiB"
        else:
            return f"{size / 1024 / 1024 / 1024:.2f} GiB"

    @staticmethod
    def _check_for_dsc(p, files):
        """
        all source packages should have a .dsc file. Warn if it is missing
        """
        if isinstance(p, package.SourcePackage) and not any(
            f.filename == p.dscfile() for f in files
        ):
            logger.warning(f"no .dsc file found for {p.name}@{p.version}")

    @staticmethod
    def _filter_pkg(p: package.Package, sources: bool, binaries: bool) -> bool:
        if sources and isinstance(p, package.SourcePackage):
            return True
        if binaries and isinstance(p, package.BinaryPackage):
            return True
        return False

    @classmethod
    def run(cls, args):
        outdir = Path(args.outdir)
        outdir.mkdir(exist_ok=True)
        cache = PersistentResolverCache(outdir / ".cache")
        if cls.has_bomin(args):
            resolver = cls.get_sbom_resolver(args)
        else:
            resolver = cls.get_pkgstream_resolver()
        rs = requests.Session()
        rs.headers.update({"User-Agent": f"debsbom/{version('debsbom')}"})
        sdl = sdlclient.SnapshotDataLake(session=rs)
        downloader = PackageDownloader(args.outdir, session=rs)
        pkgs = list(filter(lambda p: cls._filter_pkg(p, args.sources, args.binaries), resolver))

        logger.info("Resolving upstream packages...")
        for idx, pkg in enumerate(pkgs):
            if args.progress:
                progress_cb(idx, len(pkgs), pkg.name)
            try:
                files = list(resolver.resolve(sdl, pkg, cache))
                DownloadCmd._check_for_dsc(pkg, files)
                downloader.register(files, pkg)
            except sdlclient.NotFoundOnSnapshotError:
                logger.warning(f"not found upstream: {pkg.name}@{pkg.version}")

        nfiles, nbytes, cfiles, cbytes = downloader.stat()
        print(
            f"downloading {nfiles} files, {DownloadCmd.human_readable_bytes(nbytes)} "
            f"(cached: {cfiles}, {DownloadCmd.human_readable_bytes(cbytes)})"
        )
        dl_files = downloader.download(progress_cb=progress_cb if args.progress else None)
        for p in dl_files:
            logger.debug(f"downloaded {p}")

    @classmethod
    def setup_parser(cls, parser):
        cls.parser_add_sbom_input_args(parser)
        parser.add_argument(
            "--outdir", default="downloads", help="directory to store downloaded files"
        )
        parser.add_argument("--sources", help="download source packages", action="store_true")
        parser.add_argument("--binaries", help="download binary packages", action="store_true")


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
        pkgs = list(resolver.sources())

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


class RepackCmd(SbomInput):
    """
    Repacks the downloaded files into a uniform source archive.
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
            fmt=args.format, dldir=Path(args.dldir), outdir=Path(args.outdir), compress=compress
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
                lambda p: packer.repack(p, symlink=linkonly),
                pkgs,
            ),
        )
        bom = packer.rewrite_sbom(bt, repacked)
        if args.bomout == "-":
            Debsbom.write_to_stream(bom, resolver.sbom_type(), sys.stdout, validate=args.validate)
        else:
            Debsbom.write_to_file(
                bom, resolver.sbom_type(), Path(args.bomout), validate=args.validate
            )

    @classmethod
    def setup_parser(cls, parser):
        cls.parser_add_sbom_input_args(parser)
        parser.add_argument("bomout", help="sbom output file. Use '-' to write to stdout")
        parser.add_argument(
            "--dldir", default="downloads", help="download directory from 'download'"
        )
        parser.add_argument("--outdir", default="packed", help="directory to repack into'")
        parser.add_argument("--format", default="standard-bom", choices=["standard-bom"])
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
            "--copy",
            help="copy artifacts into deploy tree instead of symlinking",
            action="store_true",
        )
        parser.add_argument(
            "--validate",
            help="validate generated SBOM (only for SPDX)",
            action="store_true",
        )


def setup_parser():
    parser = argparse.ArgumentParser(
        prog="debsbom",
        description="SBOM tool for Debian systems.",
    )
    parser.add_argument(
        "--version", action="version", version="%(prog)s {}".format(version("debsbom"))
    )
    parser.add_argument("-v", "--verbose", action="count", default=0, help="be more verbose")
    parser.add_argument(
        "--progress",
        help="report progress",
        action="store_true",
    )
    subparser = parser.add_subparsers(help="sub command help", dest="cmd")
    GenerateCmd.setup_parser(
        subparser.add_parser("generate", help="generate a SBOM for a Debian system")
    )

    if HAS_DOWNLOAD_DEPS:
        DownloadCmd.setup_parser(
            subparser.add_parser("download", help="download referenced packages")
        )
        MergeCmd.setup_parser(
            subparser.add_parser("source-merge", help="merge referenced source packages")
        )
        RepackCmd.setup_parser(subparser.add_parser("repack", help="repack sources and sbom"))

    return parser


def main():
    parser = setup_parser()
    args = parser.parse_args()

    if args.verbose == 0:
        level = logging.WARNING
    elif args.verbose == 1:
        level = logging.INFO
    elif args.verbose == 2:
        level = logging.DEBUG

    logging.basicConfig(level=level)

    if not HAS_PYTHON_APT:
        logger.info("Module 'apt' from 'python-apt' missing. Using slower internal parser.")

    try:
        if args.cmd == "generate":
            GenerateCmd.run(args)
        elif args.cmd == "download":
            DownloadCmd.run(args)
        elif args.cmd == "source-merge":
            MergeCmd.run(args)
        elif args.cmd == "repack":
            RepackCmd.run(args)
    except Exception as e:
        logger.error(e)
        print(f"debsbom: error: {e}", file=sys.stderr)
        if args.verbose >= 1:
            print(traceback.format_exc(), file=sys.stderr, end="")
        sys.exit(-1)


if __name__ == "__main__":
    main()
