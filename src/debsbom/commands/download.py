# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from importlib.metadata import entry_points, version

from io import BytesIO
import logging
from pathlib import Path

from .input import PkgStreamInput, SbomInput
from ..dpkg import package
from ..resolver.resolver import PackageStreamResolver
from ..util.progress import progress_cb

try:
    # Attempt to import unused zstandard dependency to check their availability.
    # If it is missing, dependent modules are skipped to prevent import errors.
    from zstandard import ZstdCompressor, ZstdDecompressor
    import requests
    from ..snapshot import client as sdlclient
    from ..download.adapters import LocalFileAdapter
    from ..download.download import PackageDownloader, DownloadStatus, DownloadResult
    from ..download.resolver import PackageResolverCache, PersistentResolverCache, ResolveError
except ModuleNotFoundError:
    pass


logger = logging.getLogger(__name__)


def setup_snapshot_resolver(session):
    sdl = sdlclient.SnapshotDataLake(session=session)
    return sdlclient.UpstreamResolver(sdl)


RESOLVERS = {"debian-snapshot": setup_snapshot_resolver}

resolver_endpoints = entry_points(group="debsbom.download.resolver")
for ep in resolver_endpoints:
    setup_fn = ep.load()
    RESOLVERS[ep.name] = setup_fn


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
        if p.is_source() and not any(f.filename == p.dscfile() for f in files):
            logger.warning(f"no .dsc file found for {p}")

    @staticmethod
    def _filter_pkg(
        p: package.Package, sources: bool, binaries: bool, skip: list[package.Package] | None = None
    ) -> bool:
        if skip and p in skip:
            return False

        if not sources and not binaries:
            return True
        if sources and p.is_source():
            return True
        if binaries and p.is_binary():
            return True
        return False

    @classmethod
    def run(cls, args):
        outdir = Path(args.outdir)
        outdir.mkdir(exist_ok=True)
        if cls.has_bomin(args):
            resolver = cls.get_sbom_resolver(args)
        else:
            resolver = cls.get_pkgstream_resolver()
        rs = requests.Session()
        rs.mount("file:///", LocalFileAdapter())
        rs.headers.update({"User-Agent": f"debsbom/{version('debsbom')}"})
        u_resolver = RESOLVERS[args.resolver](rs)
        if type(u_resolver.cache) is PackageResolverCache:
            cachedir = outdir / ".cache"
            cachedir.mkdir(exist_ok=True)
            cache = PersistentResolverCache(cachedir / args.resolver)
            u_resolver.cache = cache
        downloader = PackageDownloader(args.outdir, session=rs)

        if args.skip_pkgs:
            skip = list(PackageStreamResolver(BytesIO(args.skip_pkgs.encode())))
        else:
            skip = None
        pkgs = list(
            filter(lambda p: cls._filter_pkg(p, args.sources, args.binaries, skip), resolver)
        )

        logger.info("Resolving upstream packages...")
        for idx, pkg in enumerate(pkgs):
            if args.progress:
                progress_cb(idx, len(pkgs), pkg.name)
            try:
                files = list(u_resolver._resolve_pkg(pkg))
                DownloadCmd._check_for_dsc(pkg, files)
                downloader.register(files, pkg)
            except ResolveError:
                pkg_type = "source" if pkg.is_source() else "binary"
                logger.warning(f"failed to resolve {pkg_type} package: {pkg}")
                if args.json:
                    print(
                        DownloadResult(
                            path=None, status=DownloadStatus.NOT_FOUND, package=pkg, filename=""
                        ).json()
                    )

        if not args.json:
            nfiles, nbytes, cfiles, cbytes = downloader.stat()
            print(
                f"downloading {nfiles} files, {DownloadCmd.human_readable_bytes(nbytes)} "
                f"(cached: {cfiles}, {DownloadCmd.human_readable_bytes(cbytes)})"
            )

        dl_results = downloader.download(progress_cb=progress_cb if args.progress else None)

        for r in dl_results:
            if args.json:
                print(r.json())
            logger.debug(f"{r.status}: {r.filename}")

    @classmethod
    def setup_parser(cls, parser):
        cls.parser_add_sbom_input_args(parser)
        parser.add_argument(
            "--outdir", default="downloads", help="directory to store downloaded files"
        )
        parser.add_argument("--sources", help="download source packages", action="store_true")
        parser.add_argument("--binaries", help="download binary packages", action="store_true")
        parser.add_argument(
            "--skip-pkgs",
            metavar="SKIP",
            help="packages to exclude from the download, in package-list format",
        )
        parser.add_argument(
            "--resolver",
            choices=RESOLVERS.keys(),
            default="debian-snapshot",
            help="resolver to use to find upstream packages (default: %(default)s)",
        )
