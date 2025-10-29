# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from collections import namedtuple
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from functools import reduce
import hashlib
from hmac import compare_digest
import json
import logging
import shutil
from pathlib import Path
import sys
import os

from ..dpkg import package
from ..dpkg.package import ChecksumAlgo, Package
from ..snapshot.client import RemoteFile

import requests


logger = logging.getLogger(__name__)
StatisticsType = namedtuple("statistics", "files bytes cfiles cbytes")


class DownloadStatus(str, Enum):
    OK = "ok"
    CHECKSUM_MISMATCH = "checksum_mismatch"
    NOT_FOUND = "not_found"

    def __str__(self) -> str:
        return self.value


@dataclass
class DownloadResult:
    path: Path | None
    status: DownloadStatus
    package: Package | None
    filename: str

    def json(self) -> str:
        result = {
            "status": str(self.status),
            "package": {
                "name": self.package.name if self.package else "",
                "version": str(self.package.version) if self.package else "",
            },
            "filename": self.filename,
        }
        if self.path:
            result["path"] = str(self.path.absolute())
        return json.dumps(result)


class PackageDownloader:
    """
    Retrieve package artifacts from upstream. Files are only retrieved once by comparison
    with the data in the local downloads directory.
    """

    def __init__(
        self,
        outdir: Path | str = "downloads",
        session: requests.Session = requests.Session(),
    ):
        self.outdir = Path(outdir)
        self.sources_dir = self.outdir / "sources"
        self.binaries_dir = self.outdir / "binaries"
        self.to_download: list[tuple[package.Package, RemoteFile]] = []
        self.rs = session
        self.known_hashes = {}

        self.outdir.mkdir(exist_ok=True)
        for p in [self.sources_dir, self.binaries_dir]:
            p.mkdir(exist_ok=True)

    def _target_path(self, f: RemoteFile):
        if f.architecture == "source":
            return Path(self.sources_dir / f.archive_name / f.filename)
        else:
            return Path(self.binaries_dir / f.archive_name / f.filename)

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
    def checksum_ok(cls, pkg: package.Package, file: Path, remotefile: RemoteFile) -> bool:
        """
        Check if the checksum of a file matches the checksums of the package.
        If no checksums are provided, return true.
        """
        if not pkg.checksums:
            return True
        if pkg.is_source() and not remotefile.filename.endswith(".dsc"):
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
            logger.debug(f"No supported checksum on {pkg}")
            return True

        with open(file, "rb") as fd:
            logger.debug(f"compute checksum on {file.name}")
            digest = hashlib.file_digest(fd, hl_algo).hexdigest()
        if compare_digest(dig_exp, digest):
            return True
        logger.error(f"Checksums mismatch on '{file.name}': {dig_exp} != {digest}")
        return False

    def download(self, progress_cb=None) -> Iterable[DownloadResult]:
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
            if not target.parent.is_dir():
                target.parent.mkdir()
            # check if we have the file under the exact filename
            if target.is_file():
                with open(target, "rb") as fd:
                    digest = hashlib.file_digest(fd, "sha1")
                if digest.hexdigest() == f.hash:
                    logger.debug(f"File '{target}' already downloaded.")
                    self.known_hashes[f.hash] = target
                    yield DownloadResult(
                        path=target, status=DownloadStatus.OK, package=pkg, filename=f.filename
                    )
                    continue
                else:
                    logger.warning(f"Checksum mismatch on {f.filename}. Download again.")
                    self.known_hashes.pop(f.hash, None)
                    target.unlink()
            # check if we have a file with the same hash and link to it
            o_target = self.known_hashes.get(f.hash)
            if o_target:
                if sys.version_info < (3, 12):
                    o_target_rel = os.path.relpath(o_target, start=target.parent)
                else:
                    o_target_rel = o_target.relative_to(target.parent, walk_up=True)
                target.symlink_to(o_target_rel)
                logger.debug(f"Linking '{target}' to already downloaded '{o_target_rel}'")
                yield DownloadResult(
                    path=target, status=DownloadStatus.OK, package=pkg, filename=f.filename
                )
                continue

            fdst = target.with_suffix(target.suffix + ".tmp")
            logger.debug(f"Downloading '{f.downloadurl}' to '{target}'...")
            with self.rs.get(f.downloadurl, stream=True) as r:
                r.raise_for_status()
                with open(fdst, "wb") as fp:
                    shutil.copyfileobj(r.raw, fp)
            if pkg and not self.checksum_ok(pkg, fdst, f):
                logger.warning(f"Checksum mismatch on downloaded file '{fdst}'")
                fdst.unlink()
                yield DownloadResult(
                    path=None,
                    status=DownloadStatus.CHECKSUM_MISMATCH,
                    package=pkg,
                    filename=f.filename,
                )
                continue
            logger.debug(f"Downloaded '{f.downloadurl}'")
            fdst.rename(target)
            self.known_hashes[f.hash] = target
            yield DownloadResult(
                path=target, status=DownloadStatus.OK, package=pkg, filename=f.filename
            )
        self.to_download = []
        self.known_hashes.clear()
