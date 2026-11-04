# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from collections import defaultdict
import logging
from pathlib import Path

from .download import DownloadInput

try:
    # Do not crash when we fail to import download dependencies
    from ..download.download import PackageDownloader, DownloadStatus, DownloadResult
except ModuleNotFoundError:
    pass
from ..enrich import Enricher
from .input import SbomValidationInput
from .output import SbomOutput
from ..resolver.resolver import PackageResolver
from ..util.progress import progress_cb

import argparse
from itertools import chain

logger = logging.getLogger(__name__)


class EnrichCmd(DownloadInput, SbomOutput, SbomValidationInput):
    """
    Processes an SBOM and enriches all its package information.
    """

    @classmethod
    def setup_parser(cls, parser):
        from ..cli import arg_mark_as_file

        cls.parser_add_download_args(parser, input_required=True)
        cls.parser_add_validation_input_arg(parser)
        arg_mark_as_file(
            parser.add_argument(
                dest="out",
                metavar="bomout",
                nargs="?",
                type=str,
                help="filename for output (default: %(default)s). Use '-' to write to stdout",
                default="enriched",
            )
        )
        parser.add_argument(
            "--checksums",
            action=argparse.BooleanOptionalAction,
            help="add checksums to packages (default: %(default)s)",
            default=True,
        )
        parser.add_argument(
            "--download-location",
            action=argparse.BooleanOptionalAction,
            help="add download location to packages (default: %(default)s)",
            default=True,
        )
        parser.add_argument(
            "--omnibor-id",
            action=argparse.BooleanOptionalAction,
            help="add omnibor artifact IDs to packages (default: %(default)s)",
            default=True,
        )
        parser.add_argument(
            "--swh-id",
            action=argparse.BooleanOptionalAction,
            help="add swh IDs to packages (default: %(default)s)",
            default=True,
        )

    @classmethod
    def run(cls, args):
        outdir = Path(args.outdir)
        outdir.mkdir(exist_ok=True)

        pkg_resolver = PackageResolver.create(Path(args.bomin))
        sbom_type = pkg_resolver.sbom_type()

        rs = cls._create_default_session()
        cache = cls._create_default_resolver(args, rs, outdir)
        downloader = PackageDownloader(args.outdir, session=rs)

        enricher = Enricher.create_from_reader(
            pkg_resolver,
            args.checksums,
            args.omnibor_id,
            args.swh_id,
            args.download_location,
        )

        incomplete_pkgs = enricher.incomplete_components()
        pkgs = dict(
            map(
                lambda p: (pkg_resolver.create_package(p), p),
                filter(pkg_resolver.is_debian_pkg, incomplete_pkgs),
            )
        )
        pkg_paths = defaultdict(list)
        download_results = cls._download_packages(
            downloader, cache, pkgs.keys(), args.progress, args.json
        )
        for res in download_results:
            pkg_paths[res.package].append((res.path, res.source))

        for pkg, paths in pkg_paths.items():
            enricher.enrich_component(pkgs[pkg], paths)

        SbomOutput.write_out_arg(enricher.document, sbom_type, args.out, args.validate)
