# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

import logging
from pathlib import Path

from ..dpkg.package import filter_sources
from ..commands.input import PkgStreamInput, SbomInput
from ..securityscan.scanner import SecurityScanner, CveUrgency
from ..securityscan.writer import ScanResultWriter

try:
    import requests

    HAS_REQUESTS_DEP = True
except ModuleNotFoundError:
    HAS_REQUESTS_DEP = False


try:
    from ..tracepath.walker import GraphWalker

    HAS_TRACEPATH_DEPS = True
except ModuleNotFoundError as e:
    HAS_TRACEPATH_DEPS = False
    MISSING_MODULE_TRACEPATH = e


DEBIAN_BUGTRACKER_URL = "https://bugs.debian.org/cgi-bin/bugreport.cgi"
SECURITY_TRACKER_URL = "https://security-tracker.debian.org/tracker"
SECURITY_DB_URL_PATH = "data/json"
# delay path expansion to make help message and docs reproducible
SECURITY_DB_PATH_DEFAULT = Path("~") / ".cache" / "debsbom" / "security-tracker.json"


logger = logging.getLogger(__name__)


class SecurityScanCmd(SbomInput, PkgStreamInput):
    """
    Scans packages from an SBOM for security vulnerabilities.
    """

    @classmethod
    def download_db(cls, url: str, db_path: Path) -> None:
        """Download the Debian security tracker JSON database."""
        if not HAS_REQUESTS_DEP:
            raise RuntimeError('Missing "requests" dependency')

        logger.info(f"Downloading security tracker database from {url}")
        # if the default path is used, create it
        if db_path.expanduser() == SECURITY_DB_PATH_DEFAULT.expanduser():
            db_path.parent.mkdir(parents=True, exist_ok=True)
        response = requests.get(url, stream=True)
        response.raise_for_status()

        with open(db_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        logger.info(f"Database downloaded to {db_path}")

    @classmethod
    def run(cls, args):
        db_path = args.db.expanduser()
        if args.update_db or not db_path.exists():
            cls.download_db(f"{args.tracker}/{SECURITY_DB_URL_PATH}", db_path)

        graph_walker = None
        if cls.has_bomin(args):
            resolver = cls.get_sbom_resolvers(args)[0]
            if args.with_paths_to_root:
                if not HAS_TRACEPATH_DEPS:
                    raise RuntimeError(
                        f"{MISSING_MODULE_TRACEPATH}, required for --with-paths-to-root"
                    )

                graph_walker = GraphWalker.from_document(resolver.document, resolver.sbom_type())
        else:
            resolver = cls.get_pkgstream_resolver()
        input_filename = Path(args.bomin) if args.bomin not in [None, "-"] else None

        if args.product:
            product = args.product
        elif args.default_product == "distribution":
            product = resolver.root_component_name()
        else:
            product = None

        pkgs = list(resolver)
        scanner = SecurityScanner(db_path, distro=args.distro)
        vulns_it = scanner.scan(
            filter_sources(pkgs), CveUrgency.from_string(args.min_urgency), args.filter
        )
        with ScanResultWriter.create(
            "json" if args.json else args.format,
            sdo_url=args.tracker,
            bdo_url=DEBIAN_BUGTRACKER_URL,
            author=args.author,
            input_filename=input_filename,
            packages=pkgs,
            graph_walker=graph_walker,
            product=product,
        ) as f:
            for v in vulns_it:
                f.write(v)

    @classmethod
    def setup_parser(cls, parser):
        from ..cli import arg_mark_as_dir

        cls.parser_add_sbom_input_args(parser)
        parser.add_argument(
            "--author",
            type=str,
            help="author of the document (-f vex only)",
        )
        parser.add_argument(
            "--default-product",
            choices=["component", "distribution"],
            default="component",
            help="controls whether the component or distribution is used as the product in VEX statements (-f vex only, default: %(default)s)",
        )
        parser.add_argument(
            "--product",
            type=str,
            help="product to use in VEX statements, overwrites the behavior of --default-product (-f vex only)",
        )
        arg_mark_as_dir(
            parser.add_argument(
                "--db",
                type=Path,
                default=SECURITY_DB_PATH_DEFAULT,
                help="path to Debian security tracker JSON database (default: %(default)s)",
            )
        )
        parser.add_argument(
            "--distro", default="trixie", help="Debian distribution to check (default: %(default)s)"
        )
        parser.add_argument(
            "--update-db",
            action="store_true",
            help=f"download the security tracker database (from --tracker) "
            "and store it at the path specified by --db",
        )
        parser.add_argument("--filter", type=str, help="limit search to a specific package name")
        parser.add_argument(
            "-f",
            "--format",
            choices=["text", "json", "sarif", "vex"],
            default="text",
            help="output format (default: %(default)s)",
        )
        parser.add_argument(
            "--min-urgency",
            type=str,
            choices=[str(c) for c in CveUrgency],
            default=str(CveUrgency.NOT_YET_ASSIGNED),
            help="filter CVEs by urgency (default: %(default)s)",
        )
        parser.add_argument(
            "--tracker",
            type=str,
            help="URL of upstream debian security tracker (default: %(default)s)",
            default=SECURITY_TRACKER_URL,
        )
        parser.add_argument(
            "--with-paths-to-root",
            action="store_true",
            help="emit path from component to root per affected package (-f json only)",
            default=False,
        )
        return parser
