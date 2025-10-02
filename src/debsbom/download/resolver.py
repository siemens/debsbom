# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from abc import abstractmethod
from collections.abc import Iterable
import dataclasses
import hashlib
import io
import json
import logging
from pathlib import Path
from typing import IO
from packageurl import PackageURL
from zstandard import ZstdCompressor, ZstdDecompressor

from ..sbom import SBOMType
from ..dpkg import package
from ..snapshot import client as sdlclient
from ..snapshot.client import RemoteFile


logger = logging.getLogger(__name__)


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
    def _package_hash(p: package.SourcePackage | package.BinaryPackage) -> str:
        return hashlib.sha256(
            json.dumps(p.purl().to_string(), sort_keys=True).encode("utf-8")
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


class PackageResolver:
    """
    Creates internal package representations of an arbitrary
    package input. The packages are iteratively resolved.
    Iterable class.
    """

    def __iter__(self):
        return self

    @abstractmethod
    def __next__(self) -> package.Package:
        """Return next package"""
        raise NotImplementedError()

    @staticmethod
    def resolve(
        sdl: sdlclient.SnapshotDataLake,
        p: package.SourcePackage | package.BinaryPackage,
        cache: PackageResolverCache = PackageResolverCache(),
    ) -> list["RemoteFile"]:
        """
        Resolve a local package to references on the upstream snapshot mirror
        """
        cached_files = cache.lookup(p)
        if cached_files:
            return cached_files

        # Determine which type of package and fetch files
        if isinstance(p, package.SourcePackage):
            files = sdlclient.SourcePackage(sdl, p.name, str(p.version)).srcfiles()
        else:
            files = sdlclient.BinaryPackage(sdl, p.name, str(p.version), None, None).files(
                arch=p.architecture
            )
        files_list = list(files)
        cache.insert(p, files_list)
        logger.debug(f"Resolved '{p.name}': {files_list}")
        return files_list

    @staticmethod
    def create(filename: Path) -> "PackageResolver":
        """
        Factory to create a PackageResolver for the given SBOM type (based on the filename extension).
        """
        if filename.name.endswith("spdx.json"):
            from .spdx import SpdxPackageResolver

            return SpdxPackageResolver.from_file(filename)
        elif filename.name.endswith("cdx.json"):
            from .cdx import CdxPackageResolver

            return CdxPackageResolver.from_file(filename)
        else:
            raise RuntimeError("Cannot determine file format")

    @staticmethod
    def from_stream(stream: IO, bomtype=SBOMType) -> "PackageResolver":
        """
        Factory to create a PackageResolver for the given SBOM type that parses a stream.
        """
        if bomtype == SBOMType.SPDX:
            from .spdx import SpdxPackageResolver

            return SpdxPackageResolver.from_stream(stream)
        else:
            from .cdx import CdxPackageResolver

            return CdxPackageResolver.from_stream(stream)


class PackageStreamResolver(PackageResolver):
    """
    Iterates a list of pkg-list entries (name version architecture) and
    resolves them.
    """

    def __init__(self, pkgstream: Iterable[str]):
        self.packages = package.Package.parse_pkglist_stream(pkgstream)

    def __next__(self) -> package.Package:
        return next(self.packages)
