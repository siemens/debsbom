# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from abc import abstractmethod
from collections import namedtuple
from collections.abc import Iterable
import dataclasses
from functools import reduce
import hashlib
import json
import logging
import shutil
from pathlib import Path
from packageurl import PackageURL
import requests

from ..dpkg import package
from ..snapshot import client as sdlclient
from ..snapshot.client import RemoteFile


logger = logging.getLogger(__name__)
StatisticsType = namedtuple("statistics", "files bytes cfiles cbytes")


class PackageResolverCache:
    """
    Maps packages to RemoteFile instances to avoid expensive calls to the upstream mirror.
    This dummy implementation can be used to not cache.
    """

    def lookup(self, p: package.SourcePackage | package.BinaryPackage) -> list["RemoteFile"] | None:
        return None

    def insert(
        self, p: package.SourcePackage | package.BinaryPackage, files: list["RemoteFile"]
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

    def lookup(self, p: package.SourcePackage | package.BinaryPackage) -> list["RemoteFile"] | None:
        hash = self._package_hash(p)
        entry = self._entry_path(hash)
        if not entry.is_file():
            logger.debug(f"Package '{p.name}' is not cached")
            return None
        with open(entry, "r") as f:
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
        with open(entry.with_suffix(".tmp"), "w") as f:
            json.dump([dataclasses.asdict(rf) for rf in files], f)
        entry.with_suffix(".tmp").rename(entry)


class PackageResolver:
    @abstractmethod
    def debian_pkgs(self) -> Iterable[package.Package]:
        """
        Return Debian package instances
        """
        pass

    def sources(self) -> Iterable[package.SourcePackage]:
        return filter(lambda p: isinstance(p, package.SourcePackage), self.debian_pkgs())

    def binaries(self) -> Iterable[package.BinaryPackage]:
        return filter(lambda p: isinstance(p, package.BinaryPackage), self.debian_pkgs())

    def package_from_purl(self, purl: str) -> "package.Package":
        purl = PackageURL.from_string(purl)
        if not purl.type == "deb":
            raise RuntimeError("Not a debian purl", purl)
        if purl.qualifiers.get("arch") == "source":
            return package.SourcePackage(purl.name, purl.version)
        else:
            return package.BinaryPackage(
                name=purl.name,
                architecture=purl.qualifiers.get("arch"),
                version=purl.version,
            )

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
        if filename.name.endswith("spdx.json"):
            from .spdx import SpdxPackageResolver

            return SpdxPackageResolver(filename)
        elif filename.name.endswith("cdx.json"):
            from .cdx import CdxPackageResolver

            return CdxPackageResolver(filename)
        else:
            raise RuntimeError("Cannot determine file format")


class PackageDownloader:
    def __init__(
        self, outdir: Path | str = "downloads", session: requests.Session = requests.Session()
    ):
        outdir = Path(outdir)
        self.sources_dir = outdir / "sources"
        self.binaries_dir = outdir / "binaries"
        self.to_download: list[RemoteFile] = []
        self.rs = session
        self.known_hashes = {}

        outdir.mkdir(exist_ok=True)
        for p in [self.sources_dir, self.binaries_dir]:
            p.mkdir(exist_ok=True)

    def _target_path(self, f: RemoteFile):
        if f.architecture == "source":
            return Path(self.sources_dir / f.filename)
        else:
            return Path(self.binaries_dir / f.filename)

    def register(self, files: list[RemoteFile]):
        self.to_download.extend(list(files))

    def stat(self) -> StatisticsType:
        """
        Returns a tuple (files to download, total size, cached files, cached bytes)
        """
        unique_dl = list({v.hash: v for v in self.to_download}.values())
        nbytes = reduce(lambda acc, x: acc + x.size, unique_dl, 0)
        cfiles = list(filter(lambda f: self._target_path(f).is_file(), unique_dl))
        cbytes = reduce(lambda acc, x: acc + x.size, cfiles, 0)
        return StatisticsType(len(unique_dl), nbytes, len(cfiles), cbytes)

    def download(self, progress_cb=None) -> Iterable[Path]:
        """
        Download all files and yield the file paths to the on-disk
        object. Files that are already there are not downloaded again,
        but still reported.
        """
        logger.info("Starting download...")
        for idx, f in enumerate(self.to_download):
            if progress_cb:
                progress_cb(idx, len(self.to_download), f.filename)
            target = self._target_path(f)
            # check if we have the file under the exact filename
            if target.is_file():
                with open(target, "rb") as fd:
                    digest = hashlib.file_digest(fd, "sha1")
                if digest.hexdigest() == f.hash:
                    self.known_hashes[f.hash] = f.filename
                    yield target
                    continue
                else:
                    logger.warning(f"Checksum mismatch on {f.filename}. Download again.")
                    self.known_hashes.pop(f.hash, None)
                    target.unlink()
            # check if we have a file with the same hash and link to it
            o_filename = self.known_hashes.get(f.hash)
            if o_filename:
                basepath = target.parent
                o_path = basepath / o_filename
                target.symlink_to(o_path.relative_to(basepath))
                yield target
                continue

            fdst = target.with_suffix(target.suffix + ".tmp")
            logger.debug(f"Downloading '{f.downloadurl}' to '{target}'...")
            with self.rs.get(f.downloadurl, stream=True) as r:
                r.raise_for_status()
                with open(fdst, "wb") as fp:
                    shutil.copyfileobj(r.raw, fp)
            fdst.rename(target)
            self.known_hashes[f.hash] = f.filename
            yield target
        self.to_download = []
        self.known_hashes.clear()
