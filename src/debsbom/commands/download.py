# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from importlib.metadata import version
import logging
from pathlib import Path

from .input import PkgStreamInput, SbomInput
from ..dpkg import package
from ..util.progress import progress_cb

try:
    import requests
    from ..snapshot import client as sdlclient
    from ..download.download import PackageDownloader
    from ..download.resolver import PersistentResolverCache, UpstreamResolver
except ModuleNotFoundError:
    pass


logger = logging.getLogger(__name__)


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
        if not sources and not binaries:
            return True
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
        u_resolver = UpstreamResolver(sdl, cache)
        downloader = PackageDownloader(args.outdir, session=rs)
        pkgs = list(filter(lambda p: cls._filter_pkg(p, args.sources, args.binaries), resolver))

        logger.info("Resolving upstream packages...")
        for idx, pkg in enumerate(pkgs):
            if args.progress:
                progress_cb(idx, len(pkgs), pkg.name)
            try:
                files = list(u_resolver.resolve(pkg))
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
