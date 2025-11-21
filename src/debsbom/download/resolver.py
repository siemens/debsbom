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

from ..util.checksum import ChecksumAlgo
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
                logger.warning(f"cache file {entry.name} ({p}) is corrupted")
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
    Helper to lookup packages on an upstream snapshot server. The lookup works as following:

    Binary package: ask the snapshot client for files of a binary package with name, version
    and architecture

    Source package (with checksum): ask the snapshot client for all files related to the source
    package identified by name and version. Then, sort the list by to sorting order and
    filter all .dsc files in the returned list. For each dsc file, fetch it and compute the
    checksum. If the checksum is not matching, ignore it. If it is matching, yield it and yield
    all referenced source files of the .dsc file.

    Source package (without checksum): ask the snapshot client for all files related to the
    source package identified by name and version. Then, sort the list by to sorting order and
    deduplicate based on (archive_name, filename). Note, that each deduplication contains the
    most recent file.

    Sorting order: First by archive_name (priority), then by first_seen (descending).

    Checksum computation: The checksums of the returned files are not checked at this stage
    (except for the .dsc files for source packages with checksum information). This operation is
    left to the caller (usually the downloader), as it creates potentially a lot of traffic
    between the snapshot mirror and the downloader. The resolving operations itself are cached
    in the cache, but the download artifacts have to be cached by the caller.
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
            key=lambda f: (
                # Primary: archive priority
                priority.get(f.archive_name, default_prio),
                # Secondary: most recent “first_seen” first (descending)
                -f.first_seen,
            ),
        )

    @classmethod
    def _distinct_by_archive_filename(cls, files: Iterable[RemoteFile]) -> Iterable[RemoteFile]:
        """
        Return a list of RemoteFiles that is made unique on archive and filename key.
        If multiple elements share the same keys, the first seen is returned.
        """
        seen: set[tuple[str, str]] = set()
        for file in files:
            key = (file.archive_name, file.filename)
            if key not in seen:
                seen.add(key)
                yield file

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
        if not srcpkg.checksums.get(ChecksumAlgo.SHA256SUM):
            # a source package should be uniquely identifiable by just its name + version,
            # so we do not want to emit a warning here;
            # see https://lists.debian.org/debian-devel/2025/10/msg00236.html
            logger.info(
                f"no sha256 digest for {srcpkg.name}@{srcpkg.version}. Lookup will be imprecise"
            )
            yield from self._distinct_by_archive_filename(self._sort_by_archive(sdlpkg.srcfiles()))
            return

        dscfiles = self._resolve_dsc_files(sdlpkg, archive=None)
        for d in dscfiles:
            if d.checksums.get(ChecksumAlgo.SHA256SUM) == srcpkg.checksums[ChecksumAlgo.SHA256SUM]:
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
