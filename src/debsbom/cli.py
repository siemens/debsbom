#!/usr/bin/env python3

# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import argparse
from datetime import datetime
from importlib.metadata import version
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
        PersistentResolverCache,
        Compression,
        SourceArchiveMerger,
        DscFileNotFoundError,
    )
    from .snapshot import client as sdlclient

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


class GenerateCmd:
    """
    Generate SBOMs from the dpkg package list
    """

    @staticmethod
    def run(args):
        if args.sbom_type is None:
            sbom_types = [SBOMType.SPDX, SBOMType.CycloneDX]
        else:
            sbom_types = []
            for stype in args.sbom_type:
                if stype == "cdx":
                    sbom_types.append(SBOMType.CycloneDX)
                elif stype == "spdx":
                    sbom_types.append(SBOMType.SPDX)

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
        if args.from_pkglist and sys.stdin.isatty():
            logger.warning("Expecting data via stdin, but connected to TTY.")

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
            help="filename for output (default: %(default)s)",
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


class DownloadCmd:
    """
    Processes a SBOM and downloads the referenced packages
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
    def run(args):
        outdir = Path(args.outdir)
        outdir.mkdir(exist_ok=True)
        cache = PersistentResolverCache(outdir / ".cache")
        resolver = PackageResolver.create(Path(args.bomfile))
        rs = requests.Session()
        rs.headers.update({"User-Agent": f"debsbom/{version('debsbom')}"})
        sdl = sdlclient.SnapshotDataLake(session=rs)
        downloader = PackageDownloader(args.outdir, session=rs)

        pkgs = []
        if args.sources:
            pkgs.extend(resolver.sources())

        if args.binaries:
            pkgs.extend(resolver.binaries())

        logger.info("Resolving upstream packages...")
        for idx, pkg in enumerate(pkgs):
            if args.progress:
                progress_cb(idx, len(pkgs), pkg.name)
            try:
                files = list(resolver.resolve(sdl, pkg, cache))
                DownloadCmd._check_for_dsc(pkg, files)
            except sdlclient.NotFoundOnSnapshotError:
                logger.warning(f"not found upstream: {pkg.name}@{pkg.version}")
            downloader.register(files)

        nfiles, nbytes, cfiles, cbytes = downloader.stat()
        print(
            f"downloading {nfiles} files, {DownloadCmd.human_readable_bytes(nbytes)} "
            f"(cached: {cfiles}, {DownloadCmd.human_readable_bytes(cbytes)})"
        )
        dl_files = downloader.download(progress_cb=progress_cb if args.progress else None)
        for p in dl_files:
            logger.debug(f"downloaded {p}")

    @staticmethod
    def setup_parser(parser):
        parser.add_argument("bomfile", help="sbom file to process")
        parser.add_argument(
            "--outdir", default="downloads", help="directory to store downloaded files"
        )
        parser.add_argument("--sources", help="download source packages", action="store_true")
        parser.add_argument("--binaries", help="download binary packages", action="store_true")


class MergeCmd:
    """
    Processes an SBOM and merges the .orig and .debian tarballs. The tarballs have to be
    downloaded first.
    """

    @staticmethod
    def run(args):
        pkgdir = Path(args.pkgdir)
        outdir = Path(args.outdir or args.pkgdir)
        compress = Compression.from_tool(args.compress if args.compress != "no" else None)
        resolver = PackageResolver.create(Path(args.bomfile))
        merger = SourceArchiveMerger(pkgdir, outdir, compress)
        pkgs = list(resolver.sources())

        logger.info("Merging...")
        for idx, pkg in enumerate(pkgs):
            if args.progress:
                progress_cb(idx, len(pkgs), f"{pkg.name}@{pkg.version}")
            try:
                merger.merge(pkg)
            except DscFileNotFoundError:
                logger.warning(f"dsc file not found: {pkg.name}@{pkg.version}")

    @staticmethod
    def setup_parser(parser):
        parser.add_argument("bomfile", help="sbom file to process")
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


def main():
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

    args = parser.parse_args()

    if args.verbose == 0:
        level = logging.WARNING
    elif args.verbose == 1:
        level = logging.INFO
    elif args.verbose == 2:
        level = logging.DEBUG

    logging.basicConfig(level=level)

    if not HAS_PYTHON_APT:
        logging.info("Module 'apt' from 'python-apt' missing. Using slower internal parser.")

    try:
        if args.cmd == "generate":
            GenerateCmd.run(args)
        elif args.cmd == "download":
            DownloadCmd.run(args)
        elif args.cmd == "source-merge":
            MergeCmd.run(args)
    except Exception as e:
        logger.error(e)
        print(f"debsbom: error: {e}", file=sys.stderr)
        if args.verbose >= 1:
            print(traceback.format_exc(), file=sys.stderr, end="")
        sys.exit(-1)


if __name__ == "__main__":
    main()
