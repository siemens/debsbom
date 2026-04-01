#!/usr/bin/env python3

# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import argparse
from importlib.metadata import version
import logging
import os
import sys
import traceback

from .generate.generate import DistroArchUnknownError

from .commands.generate import GenerateCmd
from .commands.download import DownloadCmd
from .commands.merge import MergeCmd
from .commands.source_merge import SourceMergeCmd
from .commands.repack import RepackCmd
from .commands.export import ExportCmd
from .commands.delta import DeltaCmd
from .commands.tracepath import TracePathCmd
from .commands.filter import FilterCmd
from .commands.security_scan import SecurityScanCmd

# Attempt to import optional download dependencies to check their availability.
# The success or failure of these imports determines if download features are enabled.
try:
    import requests
    from zstandard import ZstdCompressor, ZstdDecompressor

    HAS_DOWNLOAD_DEPS = True
except ModuleNotFoundError as e:
    HAS_DOWNLOAD_DEPS = False
    MISSING_MODULE_DOWNLOAD = e

try:
    import networkx

    HAS_TRACEPATH_DEPS = True
except ModuleNotFoundError as e:
    HAS_TRACEPATH_DEPS = False
    MISSING_MODULE_TRACEPATH = e

try:
    import shtab

    HAS_SHTAB_DEPS = True
except ModuleNotFoundError:
    HAS_SHTAB_DEPS = False

logger = logging.getLogger(__name__)


def arg_mark_as_file(arg):
    """
    If we have shtab, mark the argument as a file path
    """
    if HAS_SHTAB_DEPS:
        arg.complete = shtab.FILE


def arg_mark_as_dir(arg):
    """
    If we have shtab, mark the argument as a directory path
    """
    if HAS_SHTAB_DEPS:
        arg.complete = shtab.DIRECTORY


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
    if HAS_SHTAB_DEPS:
        shtab.add_argument_to(parser, "--print-completion")
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
    DeltaCmd.setup_parser(
        subparser.add_parser("delta", help="list components changed in target SBOM")
    )
    TracePathCmd.setup_parser(
        subparser.add_parser("trace-path", help="trace path between components")
    )
    FilterCmd.setup_parser(
        subparser.add_parser("filter", help="filter SBOM by sources or binaries")
    )
    SecurityScanCmd.setup_parser(
        subparser.add_parser("sec-scan", help="check SBOM for security vulnerabilities")
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
                raise RuntimeError(f"{MISSING_MODULE_DOWNLOAD}. {args.cmd} not available")
        elif args.cmd == "source-merge":
            SourceMergeCmd.run(args)
        elif args.cmd == "repack":
            RepackCmd.run(args)
        elif args.cmd == "export":
            ExportCmd.run(args)
        elif args.cmd == "merge":
            MergeCmd.run(args)
        elif args.cmd == "delta":
            DeltaCmd.run(args)
        elif args.cmd == "trace-path":
            if HAS_TRACEPATH_DEPS:
                TracePathCmd.run(args)
            else:
                raise RuntimeError(f"{MISSING_MODULE_TRACEPATH}. {args.cmd} not available")
        elif args.cmd == "filter":
            FilterCmd.run(args)
        elif args.cmd == "sec-scan":
            SecurityScanCmd.run(args)
    except DistroArchUnknownError as e:
        logger.error(f"debsbom: error: {e}. Set --distro-arch to dpkg architecture (e.g. amd64)")
        sys.exit(-2)
    except BrokenPipeError:
        # https://docs.python.org/3/library/signal.html#note-on-sigpipe
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(1)
    except Exception as e:
        logger.error(e)
        if not args.json:
            print(f"debsbom: error: {e}", file=sys.stderr)
            if args.verbose >= 1:
                print(traceback.format_exc(), file=sys.stderr, end="")
        sys.exit(-1)


if __name__ == "__main__":
    main()
