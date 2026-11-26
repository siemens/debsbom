# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import argparse
from importlib.metadata import entry_points, version

from collections import deque
from collections.abc import Iterable
from io import BytesIO
import logging
from pathlib import Path

from .input import PkgStreamInput, SbomInput, SourceBinaryInput
from ..dpkg.package import Package
from ..resolver.resolver import PackageStreamResolver
from ..util.progress import progress_cb

try:
    # Attempt to import unused zstandard dependency to check their availability.
    # If it is missing, dependent modules are skipped to prevent import errors.
    from zstandard import ZstdCompressor, ZstdDecompressor
    import requests
    from ..apt.remote import RemoteRepository
    from ..snapshot import client as sdlclient
    from ..download.adapters import LocalFileAdapter
    from ..download.download import PackageDownloader, DownloadStatus, DownloadResult
    from ..download.mirror import MirrorResolver
    from ..download.resolver import (
        FallbackResolver,
        PackageResolverCache,
        PersistentResolverCache,
        ResolveError,
        Resolver,
    )
except ModuleNotFoundError:
    pass


logger = logging.getLogger(__name__)


def setup_snapshot_resolver(session):
    sdl = sdlclient.SnapshotDataLake(session=session)
    return sdlclient.UpstreamResolver(sdl)


def setup_mirror_resolver(session, url=None, suites=(), components=(), architectures=()):
    """
    Create the resolver of an APT repository. Unlike the other resolvers, it needs a
    configuration, see :py:class:`debsbom.apt.remote.RemoteRepository`.
    """
    if not url:
        raise ValueError("the debian-mirror resolver requires --mirror-url")
    if not suites:
        raise ValueError("the debian-mirror resolver requires --mirror-suite")
    return MirrorResolver(RemoteRepository(session, url, suites, components, architectures))


RESOLVERS = {
    "debian-snapshot": setup_snapshot_resolver,
    "debian-mirror": setup_mirror_resolver,
}

#: options of the built-in debian-mirror resolver
MIRROR_OPTIONS = (
    "mirror_url",
    "mirror_suite",
    "mirror_component",
    "mirror_architecture",
    "snapshot_fallback",
)

resolver_endpoints = entry_points(group="debsbom.download.resolver")
for ep in resolver_endpoints:
    setup_fn = ep.load()
    RESOLVERS[ep.name] = setup_fn


class DownloadInput(SbomInput):
    """
    Abstract class for download commands.
    Does not live in the inputs module as the dependency import logic depends on
    it being imported from here.
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
    def _create_default_session() -> requests.Session:
        rs = requests.Session()
        rs.mount("file:///", LocalFileAdapter())
        rs.headers.update({"User-Agent": f"debsbom/{version('debsbom')}"})
        return rs

    @staticmethod
    def _resolver_cache(outdir: Path, name: str) -> PersistentResolverCache:
        cachedir = outdir / ".cache"
        cachedir.mkdir(exist_ok=True)
        return PersistentResolverCache(cachedir / name)

    @staticmethod
    def _create_default_resolver(args, session, outdir) -> Resolver:
        """
        Create the configured resolver. It does not make any request, so that its
        configuration is validated before the input is read.
        """
        setup = RESOLVERS[args.resolver]
        if setup is setup_mirror_resolver:
            return DownloadInput._create_mirror_resolver(args, session, outdir)
        options = [
            f"--{'no-' if value is False else ''}{name.replace('_', '-')}"
            for name in MIRROR_OPTIONS
            if (value := getattr(args, name, None)) is not None
        ]
        if options:
            raise ValueError(
                f"{', '.join(options)} can only be used with the built-in debian-mirror resolver"
            )
        u_resolver = setup(session)
        if type(u_resolver.cache) is PackageResolverCache:
            u_resolver.cache = DownloadInput._resolver_cache(outdir, args.resolver)
        return u_resolver

    @staticmethod
    def _create_mirror_resolver(args, session, outdir) -> Resolver:
        """
        The results of the mirror are not cached, as it can change. Packages which are not
        found are only resolved on snapshot.debian.org if requested, as this discloses
        their names and versions.
        """
        mirror = setup_mirror_resolver(
            session,
            args.mirror_url,
            args.mirror_suite or (),
            args.mirror_component or (),
            args.mirror_architecture or (),
        )
        if not args.snapshot_fallback:
            return mirror
        snapshot = setup_snapshot_resolver(session)
        # use the cache of the built-in resolver only, not the one of a plugin replacing it
        if RESOLVERS.get("debian-snapshot") is setup_snapshot_resolver:
            snapshot.cache = DownloadInput._resolver_cache(outdir, "debian-snapshot")
        logger.info(
            f"Packages not found in '{mirror.repository.url}' are resolved on snapshot.debian.org"
        )
        return FallbackResolver(mirror, snapshot)

    @staticmethod
    def _download_packages(
        downloader: PackageDownloader,
        resolver_cache: Resolver,
        pkgs: list[Package],
        progress: bool | None,
        json: bool | None,
    ) -> Iterable[DownloadResult]:
        logger.info("Resolving upstream packages...")
        for idx, pkg in enumerate(pkgs):
            if progress:
                progress_cb(idx, len(pkgs), pkg.name)
            try:
                files = list(resolver_cache._resolve_pkg(pkg))
                DownloadCmd._check_for_dsc(pkg, files)
                downloader.register(files, pkg)
            except ResolveError as e:
                pkg_type = "source" if pkg.is_source() else "binary"
                reason = f": {e}" if str(e) else ""
                logger.warning(f"failed to resolve {pkg_type} package: {pkg}{reason}")
                if json:
                    print(
                        DownloadResult(
                            path=None,
                            status=DownloadStatus.NOT_FOUND,
                            package=pkg,
                            filename=None,
                            source=None,
                        ).json()
                    )

        if not json:
            nfiles, nbytes, cfiles, cbytes = downloader.stat()
            print(
                f"downloading {nfiles} files, {DownloadCmd.human_readable_bytes(nbytes)} "
                f"(cached: {cfiles}, {DownloadCmd.human_readable_bytes(cbytes)})"
            )

        dl_results = downloader.download(progress_cb=progress_cb if progress else None)

        for r in dl_results:
            if json:
                print(r.json())
            logger.debug(f"{r.status}: {r.filename}")
            yield r

    @classmethod
    def parser_add_download_args(cls, parser, input_required: bool = False):
        from ..cli import arg_mark_as_dir

        cls.parser_add_sbom_input_args(parser, required=input_required)
        arg_mark_as_dir(
            parser.add_argument(
                "--outdir", default="downloads", help="directory to store downloaded files"
            )
        )
        parser.add_argument(
            "--resolver",
            choices=RESOLVERS.keys(),
            default="debian-snapshot",
            help="resolver to use to find upstream packages (default: %(default)s)",
        )
        mirror = parser.add_argument_group(
            "debian-mirror resolver",
            "resolve packages from an APT repository, like a Debian mirror",
        )
        mirror.add_argument(
            "--mirror-url",
            metavar="URL",
            help="URL of the archive root (http, https or file), e.g. https://deb.debian.org/debian",
        )
        mirror.add_argument(
            "--mirror-suite",
            action="append",
            metavar="SUITE",
            help="suite to search, can be repeated (in order of priority). A path ending "
            "with '/' (e.g. './') is the exact path of the indexes of a flat repository",
        )
        mirror.add_argument(
            "--mirror-component",
            action="append",
            metavar="COMPONENT",
            help="component to search in each suite, can be repeated (in order of priority). "
            "Required, except for flat repositories",
        )
        mirror.add_argument(
            "--mirror-architecture",
            action="append",
            metavar="ARCH",
            help="architecture whose indexes are searched for 'Architecture: all' packages, "
            "can be repeated (default: the ones of the Release file). 'all' selects the "
            "binary-all indexes",
        )
        mirror.add_argument(
            "--snapshot-fallback",
            action=argparse.BooleanOptionalAction,
            help="resolve packages which are not found in the mirror on snapshot.debian.org, "
            "which receives their names and versions (default: no)",
        )


class DownloadCmd(DownloadInput, SourceBinaryInput, PkgStreamInput):
    """
    Processes a SBOM and downloads the referenced packages.
    If no SBOM is provided, it reads line separated entries (name version arch)
    from stdin to define what shall be downloaded.
    """

    @classmethod
    def run(cls, args):
        outdir = Path(args.outdir)
        outdir.mkdir(exist_ok=True)
        rs = DownloadCmd._create_default_session()
        u_resolver = cls._create_default_resolver(args, rs, outdir)
        if cls.has_bomin(args):
            resolvers = cls.get_sbom_resolvers(args)
        else:
            resolvers = [cls.get_pkgstream_resolver()]
        downloader = PackageDownloader(args.outdir, session=rs)

        if args.skip_pkgs:
            skip = list(PackageStreamResolver(BytesIO(args.skip_pkgs.encode())))
        else:
            skip = None

        pkgs = []
        for resolver in resolvers:
            pkgs.extend(
                list(
                    filter(
                        lambda p: cls._filter_pkg(p, args.sources, args.binaries, skip), resolver
                    )
                )
            )

        # immediately drop the results, we just need to exhaust the iterator
        deque(
            cls._download_packages(downloader, u_resolver, pkgs, args.progress, args.json), maxlen=0
        )

    @classmethod
    def setup_parser(cls, parser):
        cls.parser_add_download_args(parser)
        cls.parser_add_source_binary_args(parser)
        parser.add_argument(
            "--skip-pkgs",
            metavar="SKIP",
            help="packages to exclude from the download, in package-list format",
        )
