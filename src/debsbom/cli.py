#!/usr/bin/env python3

# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import argparse
from datetime import datetime
from importlib.metadata import version
import sys
import traceback
from uuid import UUID
from urllib.parse import urlparse

from .generate import Debsbom, SBOMType


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

        debsbom = Debsbom(
            distro_name=args.distro_name,
            sbom_types=set(sbom_types),
            root=args.root,
            distro_supplier=args.distro_supplier,
            distro_version=args.distro_version,
            spdx_namespace=args.spdx_namespace,
            cdx_serialnumber=args.cdx_serialnumber,
            timestamp=args.timestamp,
        )
        debsbom.generate(
            args.out,
            progress_cb=progress_cb if args.progress else None,
            validate=args.validate,
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
            "--progress",
            help="report progress",
            action="store_true",
        )
        parser.add_argument(
            "--validate",
            help="validate generated SBOM (only for SPDX)",
            action="store_true",
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
    subparser = parser.add_subparsers(help="sub command help", dest="cmd")
    GenerateCmd.setup_parser(
        subparser.add_parser("generate", help="generate a SBOM for a Debian system")
    )
    args = parser.parse_args()

    try:
        if args.cmd == "generate":
            GenerateCmd.run(args)
    except Exception as e:
        print("debsbom: error: {}".format(e))
        if args.verbose >= 1:
            print(traceback.format_exc(), end="")
        sys.exit(-1)


if __name__ == "__main__":
    main()
