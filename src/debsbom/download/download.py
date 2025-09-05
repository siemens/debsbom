# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from abc import abstractmethod
import dataclasses
from functools import reduce
import hashlib
import json
import sys
from typing import Generator, Tuple, Type
from pathlib import Path
from urllib.request import urlretrieve
from packageurl import PackageURL

from ..dpkg import package
from ..snapshot import client as sdlclient


class PackageResolverCache:
    """
    Maps packages to RemoteFile instances to avoid expensive calls to the upstream mirror.
    This dummy implementation can be used to not cache.
    """

    def lookup(
        self, p: package.SourcePackage | package.BinaryPackage
    ) -> list["sdlclient.RemoteFile"] | None:
        return None

    def insert(
        self, p: package.SourcePackage | package.BinaryPackage, files: list["sdlclient.RemoteFile"]
    ) -> None:
        pass


class PersistentResolverCache(PackageResolverCache):
    """
    Trivial implementation of a file-backed cache. Each cache entry is stored as individual file
    in the cachedir.
    """

    def __init__(self, cachedir: Path):
        self.cachedir = cachedir
        cachedir.mkdir(exist_ok=True)

    @staticmethod
    def _package_hash(p: package.SourcePackage | package.BinaryPackage) -> str:
        return hashlib.sha256(
            json.dumps({"name": p.name, "version": p.version}, sort_keys=True).encode("utf-8")
        ).hexdigest()

    def _entry_path(self, hash: str) -> Path:
        return self.cachedir / f"{hash}.json"

    def lookup(
        self, p: package.SourcePackage | package.BinaryPackage
    ) -> list["sdlclient.RemoteFile"] | None:
        hash = self._package_hash(p)
        entry = self._entry_path(hash)
        if not entry.is_file():
            return None
        with open(entry, "r") as f:
            data = json.load(f)
        return [sdlclient.RemoteFile(**d) for d in data]

    def insert(
        self, p: package.SourcePackage | package.BinaryPackage, files: list["sdlclient.RemoteFile"]
    ) -> None:
        hash = self._package_hash(p)
        entry = self._entry_path(hash)
        with open(entry.with_suffix(".tmp"), "w") as f:
            json.dump([dataclasses.asdict(rf) for rf in files], f)
        entry.with_suffix(".tmp").rename(entry)


class PackageResolver:
    @abstractmethod
    def debian_pkgs(self) -> Generator:
        """
        Return Debian package instances
        """
        pass

    def sources(self) -> Generator[package.SourcePackage, None, None]:
        return filter(lambda p: isinstance(p, package.SourcePackage), self.debian_pkgs())

    def binaries(self) -> Generator[package.BinaryPackage, None, None]:
        return filter(lambda p: isinstance(p, package.BinaryPackage), self.debian_pkgs())

    def package_from_purl(self, purl: str) -> Tuple[str, str, str]:
        purl = PackageURL.from_string(purl)
        if not purl.type == "deb":
            raise RuntimeError("Not a debian purl", purl)
        if purl.qualifiers.get("arch") == "source":
            return package.SourcePackage(purl.name, purl.version)
        else:
            return package.BinaryPackage(
                name=purl.name,
                section=None,
                maintainer=None,
                architecture=purl.qualifiers.get("arch"),
                source=None,
                version=purl.version,
                depends=None,
                description=None,
                homepage=None,
            )

    @staticmethod
    def resolve(
        sdl: sdlclient.SnapshotDataLake,
        p: package.SourcePackage | package.BinaryPackage,
        cache: PackageResolverCache = PackageResolverCache(),
    ) -> list["sdlclient.RemoteFile"]:
        """
        Resolve a local package to references on the upstream snapshot mirror
        """
        cached_files = cache.lookup(p)
        if cached_files:
            return cached_files

        # Determine which type of package and fetch files
        if isinstance(p, package.SourcePackage):
            files = sdlclient.SourcePackage(sdl, p.name, p.version).srcfiles()
        else:
            files = sdlclient.BinaryPackage(sdl, p.name, p.version, None, None).files(
                arch=p.architecture
            )
        files_list = list(files)
        cache.insert(p, files_list)
        return files_list

    @staticmethod
    def create(filename: Path) -> Type["PackageResolver"]:
        if filename.name.endswith("spdx.json"):
            from .spdx import SpdxPackageResolver

            return SpdxPackageResolver(filename)
        elif filename.name.endswith("cdx.json"):
            from .cdx import CdxPackageResolver

            return CdxPackageResolver(filename)
        else:
            raise RuntimeError("Cannot determine file format")


class PackageDownloader:
    def __init__(self, outdir: Path | str = "downloads"):
        self.dldir = Path(outdir)
        self.dldir.mkdir(exist_ok=True)
        self.to_download: list["sdlclient.RemoteFile"] = []

    def register(self, files: list["sdlclient.RemoteFile"]):
        self.to_download.extend(list(files))

    def stat(self):
        """
        Returns a tuple (files to download, total size)
        """
        nbytes = reduce(lambda acc, x: acc + x.size, self.to_download, 0)
        return (len(self.to_download), nbytes)

    def download(self, progress_cb):
        for idx, f in enumerate(self.to_download):
            if progress_cb:
                progress_cb(idx, len(self.to_download), f.filename)
            target = Path(self.dldir / f.filename)
            if target.is_file():
                with open(target, "rb") as fd:
                    digest = hashlib.file_digest(fd, "sha1")
                if digest.hexdigest() == f.hash:
                    continue
                else:
                    print(f"Checksum mismatch on {f.filename}. Download again.", file=sys.stderr)
            fdst = target.with_suffix(target.suffix + ".tmp")
            urlretrieve(f.downloadurl, fdst)
            fdst.rename(target)
