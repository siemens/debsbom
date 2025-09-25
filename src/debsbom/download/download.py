# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from abc import abstractmethod
from collections import namedtuple
from collections.abc import Iterable
import dataclasses
from functools import reduce
import hashlib
from hmac import compare_digest
import json
import logging
import shutil
from pathlib import Path
from packageurl import PackageURL
import requests

from ..dpkg import package
from ..dpkg.package import ChecksumAlgo
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
    @property
    def document(self):
        """get the parsed SBOM document"""
        return self._document

    @abstractmethod
    def is_debian_pkg(package) -> bool:
        """Return true if provided SBOM package is a Debian package"""
        raise NotImplementedError()

    @abstractmethod
    def debian_pkgs(self) -> Iterable[package.Package]:
        """
        Return Debian package instances
        """
        pass

    def sources(self) -> Iterable[package.SourcePackage]:
        """Iterate Debian source packages"""
        return filter(lambda p: isinstance(p, package.SourcePackage), self.debian_pkgs())

    def binaries(self) -> Iterable[package.BinaryPackage]:
        """Iterate Debian binary packages"""
        return filter(lambda p: isinstance(p, package.BinaryPackage), self.debian_pkgs())

    @classmethod
    def package_from_purl(cls, purl: str) -> "package.Package":
        """
        Create a package from a PURL. Note, that the package only encodes
        information that can be derived from the PURL.
        """
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


class PackageDownloader:
    """
    Retrieve package artifacts from upstream. Files are only retrieved once by comparison
    with the data in the local downloads directory.
    """

    def __init__(
        self, outdir: Path | str = "downloads", session: requests.Session = requests.Session()
    ):
        outdir = Path(outdir)
        self.sources_dir = outdir / "sources"
        self.binaries_dir = outdir / "binaries"
        self.to_download: list[tuple[package.Package, RemoteFile]] = []
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

    def register(self, files: list[RemoteFile], package: package.Package | None = None) -> None:
        """Register a list of files corresponding to a package for download."""
        self.to_download.extend([(package, f) for f in files])

    def stat(self) -> StatisticsType:
        """
        Returns a tuple (files to download, total size, cached files, cached bytes)
        """
        unique_dl = list({v.hash: v for _, v in self.to_download}.values())
        nbytes = reduce(lambda acc, x: acc + x.size, unique_dl, 0)
        cfiles = list(filter(lambda f: self._target_path(f).is_file(), unique_dl))
        cbytes = reduce(lambda acc, x: acc + x.size, cfiles, 0)
        return StatisticsType(len(unique_dl), nbytes, len(cfiles), cbytes)

    @classmethod
    def checksum_ok(cls, pkg: package.Package, file: Path) -> bool:
        """
        Check if the checksum of a file matches the checksums of the package.
        If no checksums are provided, return true.
        """
        if not pkg.checksums:
            return True

        dig_exp = None
        hl_algo = None
        pkg_algs = pkg.checksums.keys()
        if ChecksumAlgo.SHA256SUM in pkg_algs:
            dig_exp = pkg.checksums[ChecksumAlgo.SHA256SUM]
            hl_algo = "sha256"
        elif ChecksumAlgo.SHA1SUM in pkg_algs:
            dig_exp = pkg.checksums[ChecksumAlgo.SHA1SUM]
            hl_algo = "sha1"
        elif ChecksumAlgo.MD5SUM in pkg_algs:
            dig_exp = pkg.checksums[ChecksumAlgo.MD5SUM]
            hl_algo = "md5"
        else:
            logger.debug(f"No supported checksum on {pkg.name}@{pkg.version}")
            return True

        with open(file, "rb") as fd:
            logger.debug(f"compute checksum on {file.name}")
            digest = hashlib.file_digest(fd, hl_algo).hexdigest()
        if compare_digest(dig_exp, digest):
            return True
        logger.error(f"Checksums mismatch on '{file.name}': {dig_exp} != {digest}")
        return False

    def download(self, progress_cb=None) -> Iterable[Path]:
        """
        Download all files and yield the file paths to the on-disk
        object. Files that are already there are not downloaded again,
        but still reported.
        """
        logger.info("Starting download...")
        for idx, (pkg, f) in enumerate(self.to_download):
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
            if pkg and not self.checksum_ok(pkg, fdst):
                fdst.unlink()
                continue
            fdst.rename(target)
            self.known_hashes[f.hash] = f.filename
            yield target
        self.to_download = []
        self.known_hashes.clear()
