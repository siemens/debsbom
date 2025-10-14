# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import logging
import sys

from debsbom import HAS_PYTHON_APT
from .input import GenerateInput, warn_if_tty
from ..generate.generate import Debsbom
from ..sbom import BOM_Standard, SBOMType
from ..util.progress import progress_cb


logger = logging.getLogger(__name__)


class GenerateCmd(GenerateInput):
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

    @classmethod
    def setup_parser(cls, parser):
        cls.parser_add_generate_input_args(parser, default_out="sbom")
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
            help="root directory to look for dpkg status file and apt cache",
            default="/",
        )
        parser.add_argument(
            "--from-pkglist",
            help="create SBOM from a package list passed via stdin",
            action="store_true",
        )
