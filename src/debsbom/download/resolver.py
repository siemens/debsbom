# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Iterable
import dataclasses
import hashlib
import io
import json
import logging
from pathlib import Path

from ..dpkg import package
from ..snapshot.client import RemoteFile
from .dscfilter import RemoteDscFile

from zstandard import ZstdCompressor, ZstdDecompressor
from ..snapshot import client as sdlclient


logger = logging.getLogger(__name__)

UPSTREAM_ARCHIVE_ORDER = ["debian", "debian-security", "debian-debug", "debian-ports"]


class PackageResolverCache:
    """
    Maps packages to RemoteFile instances to avoid expensive calls to the upstream mirror.
    This dummy implementation can be used to not cache.
    """

    def lookup(self, p: package.SourcePackage | package.BinaryPackage) -> list["RemoteFile"] | None:
        """Lookup package files in cache"""
        return None

    def insert(
        self, p: package.SourcePackage | package.BinaryPackage, files: list["RemoteFile"]
    ) -> None:
        """Insert package files into cache"""
        pass


class PersistentResolverCache(PackageResolverCache):
    """
    Trivial implementation of a file-backed cache. Each cache entry is stored as individual file
    in the cachedir.
    """

    def __init__(self, cachedir: Path):
        self.cachedir = cachedir
        self.cctx = ZstdCompressor(level=10)
        self.dctx = ZstdDecompressor()
        cachedir.mkdir(exist_ok=True)

    @staticmethod
    def _package_hash(p: package.Package) -> str:
        return hashlib.sha256(
            json.dumps(
                {
                    "purl": p.purl().to_string(),
                    "checksums": p.checksums,
                },
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()

    def _entry_path(self, hash: str) -> Path:
        return self.cachedir / f"{hash}.json.zst"

    def lookup(self, p: package.SourcePackage | package.BinaryPackage) -> list["RemoteFile"] | None:
        hash = self._package_hash(p)
        entry = self._entry_path(hash)
        if not entry.is_file():
            logger.debug(f"Package '{p.name}' is not cached")
            return None
        with (
            open(entry, "rb") as _f,
            self.dctx.stream_reader(_f) as f,
        ):
            try:
                data = json.load(f)
            except json.decoder.JSONDecodeError:
                logger.warning(f"cache file {entry.name} ({p.name}@{p.version}) is corrupted")
                return None
        logger.debug(f"Package '{p.name}' already cached")
        return [RemoteFile(**d) for d in data]

    def insert(
        self, p: package.SourcePackage | package.BinaryPackage, files: list["RemoteFile"]
    ) -> None:
        hash = self._package_hash(p)
        entry = self._entry_path(hash)
        with (
            open(entry.with_suffix(".tmp"), "wb") as _f,
            self.cctx.stream_writer(_f) as cf,
            io.TextIOWrapper(cf, encoding="utf-8") as f,
        ):
            json.dump([dataclasses.asdict(rf) for rf in files], f)
        entry.with_suffix(".tmp").rename(entry)


class UpstreamResolver:
    """
    Helper to lookup packages on an upstream snapshot server.
    """

    def __init__(
        self, sdl: sdlclient.SnapshotDataLake, cache: PackageResolverCache = PackageResolverCache()
    ):
        self.sdl = sdl
        self.cache = cache

    @classmethod
    def _sort_by_archive(
        cls,
        files: Iterable["RemoteFile"] | Iterable["RemoteDscFile"],
    ) -> list["RemoteFile"] | list["RemoteDscFile"]:
        """
        Sort the input list by priority of the upstream archives. By that, we can iterate
        the items in the most likely order to have checksum matches more likely early.
        """
        priority = {name: i for i, name in enumerate(UPSTREAM_ARCHIVE_ORDER)}
        default_prio = len(UPSTREAM_ARCHIVE_ORDER)
        return sorted(
            files,
            key=lambda f: priority.get(f.archive_name, default_prio),
        )

    @classmethod
    def _resolve_dsc_files(
        cls, pkg: sdlclient.SourcePackage, archive: str | None = None
    ) -> Iterable["RemoteDscFile"]:
        """
        Locate all .dsc files associated with the source package and lazily create
        RemoteDscFile instances to lookup associated artifacts.
        """
        files = cls._sort_by_archive(pkg.srcfiles(archive=archive))
        for f in files:
            if f.filename.endswith(".dsc"):
                yield RemoteDscFile(sdl=pkg.sdl, dscfile=f, allfiles=files)

    def _filter_rel_sources(
        self, srcpkg: package.SourcePackage, sdlpkg: sdlclient.SourcePackage
    ) -> Iterable[RemoteFile]:
        """
        A debian source package can be found in multiple snapshot archives with varying
        content and checksum. In case we have a checksum, download all .dsc files until
        we find the one with a matching checksum. Then use the .dsc file to locate all other
        referenced artifacts.
        """
        if not srcpkg.checksums.get(package.ChecksumAlgo.SHA256SUM):
            logger.warning(
                f"no sha256 digest for {srcpkg.name}@{srcpkg.version}. Lookup will be imprecise"
            )
            yield from self._sort_by_archive(sdlpkg.srcfiles())
            return

        dscfiles = self._resolve_dsc_files(sdlpkg, archive=None)
        for d in dscfiles:
            if d.sha256 == srcpkg.checksums[package.ChecksumAlgo.SHA256SUM]:
                yield d.dscfile
                yield from d.srcfiles()
                return

    def resolve(self, p: package.Package) -> list["RemoteFile"]:
        """
        Resolve a local package to references on the upstream snapshot mirror
        """
        cached_files = self.cache.lookup(p)
        if cached_files:
            return cached_files

        # Determine which type of package and fetch files
        if p.is_source():
            files = self._filter_rel_sources(
                p, sdlclient.SourcePackage(self.sdl, p.name, str(p.version))
            )
        else:
            files = sdlclient.BinaryPackage(self.sdl, p.name, str(p.version), None, None).files(
                arch=p.architecture
            )
        files_list = list(files)
        self.cache.insert(p, files_list)
        logger.debug(f"Resolved '{p.name}': {files_list}")
        return files_list
