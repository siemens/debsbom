# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from datetime import datetime
import logging
import sys
from urllib.parse import urlparse
from uuid import UUID

from debsbom import HAS_PYTHON_APT
from .input import warn_if_tty
from ..generate.generate import Debsbom
from ..sbom import BOM_Standard, SBOMType
from ..util.progress import progress_cb


logger = logging.getLogger(__name__)


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

        if not HAS_PYTHON_APT:
            logger.info("Module 'apt' from 'python-apt' missing. Using slower internal parser.")

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
