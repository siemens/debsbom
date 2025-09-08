# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from abc import abstractmethod
from collections import namedtuple
import dataclasses
from functools import reduce
import hashlib
import json
import shutil
import sys
from typing import Generator, Iterator, Tuple, Type
from pathlib import Path
from urllib.request import urlretrieve
from packageurl import PackageURL
import requests

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
            json.dumps(p.purl().to_string(), sort_keys=True).encode("utf-8")
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
            try:
                data = json.load(f)
            except json.decoder.JSONDecodeError:
                print(
                    f"cache file {entry.name} ({p.name}@{p.version}) is corrupted", file=sys.stderr
                )
                return None
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
    StatisticsType = namedtuple("statistics", "files bytes cfiles cbytes")

    def __init__(
        self, outdir: Path | str = "downloads", session: requests.Session = requests.Session()
    ):
        self.dldir = Path(outdir)
        self.dldir.mkdir(exist_ok=True)
        self.to_download: list["sdlclient.RemoteFile"] = []
        self.rs = session
        self.known_hashes = {}

    def register(self, files: list["sdlclient.RemoteFile"]):
        self.to_download.extend(list(files))

    def stat(self) -> Type["StatisticsType"]:
        """
        Returns a tuple (files to download, total size, cached files, cached bytes)
        """
        unique_dl = list({v.hash: v for v in self.to_download}.values())
        nbytes = reduce(lambda acc, x: acc + x.size, unique_dl, 0)
        cfiles = list(filter(lambda f: Path(self.dldir / f.filename).is_file(), unique_dl))
        cbytes = reduce(lambda acc, x: acc + x.size, cfiles, 0)
        return self.StatisticsType(len(unique_dl), nbytes, len(cfiles), cbytes)

    def download(self, progress_cb=None) -> Iterator[Path]:
        """
        Download all files and yield the file paths to the on-disk
        object. Files that are already there are not downloaded again,
        but still reported.
        """
        for idx, f in enumerate(self.to_download):
            if progress_cb:
                progress_cb(idx, len(self.to_download), f.filename)
            target = Path(self.dldir / f.filename)
            # check if we have the file under the exact filename
            if target.is_file():
                with open(target, "rb") as fd:
                    digest = hashlib.file_digest(fd, "sha1")
                if digest.hexdigest() == f.hash:
                    self.known_hashes[f.hash] = f.filename
                    yield target
                    continue
                else:
                    print(f"Checksum mismatch on {f.filename}. Download again.", file=sys.stderr)
                    self.known_hashes.pop(f.hash, None)
                    target.unlink()
            # check if we have a file with the same hash and link to it
            o_filename = self.known_hashes.get(f.hash)
            if o_filename:
                o_path = Path(self.dldir / o_filename).resolve()
                target.symlink_to(o_path.relative_to(self.dldir.resolve()))
                yield target
                continue

            fdst = target.with_suffix(target.suffix + ".tmp")
            with self.rs.get(f.downloadurl, stream=True) as r:
                r.raise_for_status()
                with open(fdst, "wb") as fp:
                    shutil.copyfileobj(r.raw, fp)
            fdst.rename(target)
            self.known_hashes[f.hash] = f.filename
            yield target
        self.to_download = []
