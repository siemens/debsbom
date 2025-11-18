# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from abc import ABC
import dataclasses
import hashlib
import io
import json
import logging
from pathlib import Path

from ..util.checksum import ChecksumAlgo
from ..dpkg import package

from zstandard import ZstdCompressor, ZstdDecompressor


logger = logging.getLogger(__name__)


@dataclasses.dataclass
class RemoteFile:
    #: Available checksums for the remote file.
    checksums: dict[ChecksumAlgo, str]
    #: Is used to determine the filename of the downloaded file.
    filename: str
    #: Debian archive name where the associated package comes from. If unsure use "debian".
    archive_name: str
    #: Full URL to where the file can be downloaded.
    downloadurl: str
    #: Size of the file, if available.
    size: int | None = None


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


class Resolver(ABC):
    """Base class for resolvers."""

    def __init__(self, cache: PackageResolverCache = PackageResolverCache()):
        self._cache = cache

    @property
    def cache(self):
        return self._cache

    @cache.setter
    def cache(self, cache: PackageResolverCache):
        self._cache = cache

    def _resolve_pkg(self, p: package.Package) -> list[RemoteFile]:
        cached_files = self.cache.lookup(p)
        if cached_files:
            return cached_files

        files = self.resolve(p)

        files_list = list(files)
        self.cache.insert(p, files_list)
        logger.debug(f"Resolved '{p.name}': {files_list}")
        return files_list

    def resolve(self, p: package.Package) -> list[RemoteFile]:
        """
        Resolve a package to a list of remote files to download.
        """
        raise NotImplementedError
