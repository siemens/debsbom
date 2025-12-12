#!/usr/bin/env python3

# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import argparse
from importlib.metadata import version
import logging
import sys
import traceback

from .generate.generate import DistroArchUnknownError

from .commands.generate import GenerateCmd
from .commands.download import DownloadCmd
from .commands.merge import MergeCmd
from .commands.source_merge import SourceMergeCmd
from .commands.repack import RepackCmd
from .commands.export import ExportCmd
from .commands.compare import CompareCmd

# Attempt to import optional download dependencies to check their availability.
# The success or failure of these imports determines if download features are enabled.
try:
    import requests
    from zstandard import ZstdCompressor, ZstdDecompressor

    HAS_DOWNLOAD_DEPS = True
except ModuleNotFoundError as e:
    HAS_DOWNLOAD_DEPS = False
    MISSING_MODULE = e

logger = logging.getLogger(__name__)


def setup_parser():
    parser = argparse.ArgumentParser(
        prog="debsbom",
        description="SBOM tool for Debian systems.",
    )
    parser.add_argument(
        "--version", action="version", version="%(prog)s {}".format(version("debsbom"))
    )
    parser.add_argument("-v", "--verbose", action="count", default=0, help="be more verbose")
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--progress",
        help="report progress",
        action="store_true",
    )
    group.add_argument(
        "--json",
        help="make output machine readable",
        action="store_true",
    )
    subparser = parser.add_subparsers(help="sub command help", dest="cmd", required=True)
    GenerateCmd.setup_parser(
        subparser.add_parser("generate", help="generate a SBOM for a Debian system")
    )
    MergeCmd.setup_parser(subparser.add_parser("merge", help="merge multiple SBOMs"))
    DownloadCmd.setup_parser(subparser.add_parser("download", help="download referenced packages"))
    SourceMergeCmd.setup_parser(
        subparser.add_parser("source-merge", help="merge referenced source packages")
    )
    RepackCmd.setup_parser(subparser.add_parser("repack", help="repack sources and sbom"))
    ExportCmd.setup_parser(subparser.add_parser("export", help="export SBOM as graph"))
    CompareCmd.setup_parser(
        subparser.add_parser("compare", help="compare SBOMs and list new components")
    )

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

    try:
        if args.cmd == "generate":
            GenerateCmd.run(args)
        elif args.cmd == "download":
            if HAS_DOWNLOAD_DEPS:
                DownloadCmd.run(args)
            else:
                raise RuntimeError(f"{MISSING_MODULE}. {args.cmd} not available")
        elif args.cmd == "source-merge":
            SourceMergeCmd.run(args)
        elif args.cmd == "repack":
            RepackCmd.run(args)
        elif args.cmd == "export":
            ExportCmd.run(args)
        elif args.cmd == "merge":
            MergeCmd.run(args)
        elif args.cmd == "compare":
            CompareCmd.run(args)
    except DistroArchUnknownError as e:
        logger.error(f"debsbom: error: {e}. Set --distro-arch to dpkg architecture (e.g. amd64)")
        sys.exit(-2)
    except Exception as e:
        logger.error(e)
        if not args.json:
            print(f"debsbom: error: {e}", file=sys.stderr)
            if args.verbose >= 1:
                print(traceback.format_exc(), file=sys.stderr, end="")
        sys.exit(-1)


if __name__ == "__main__":
    main()
