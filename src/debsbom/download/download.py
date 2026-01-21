# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from collections import namedtuple
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from functools import reduce
import json
import logging
import shutil
from pathlib import Path
import sys
import os

from ..util.checksum import check_hash_from_path
from .resolver import RemoteFile
from ..dpkg import package
from ..dpkg.package import Package

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
    package: Package
    filename: str | None

    def json(self) -> str:
        result = {
            "status": str(self.status),
            "package": {
                "name": self.package.name,
                "version": str(self.package.version),
                "purl": str(self.package.purl()),
            },
        }
        if self.filename:
            result["filename"] = self.filename
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

    def _target_path(self, pkg: package.Package, f: RemoteFile):
        if pkg.is_source():
            return Path(self.sources_dir / f.archive_name / f.filename)
        else:
            return Path(self.binaries_dir / f.archive_name / f.filename)

    def register(self, files: list[RemoteFile], package: package.Package) -> None:
        """Register a list of files corresponding to a package for download."""
        self.to_download.extend([(package, f) for f in files])

    def stat(self) -> StatisticsType:
        """
        Returns a tuple (files to download, total size, cached files, cached bytes)
        """
        unique_dl = list(
            {frozenset(v.checksums.items()): (pkg, v) for pkg, v in self.to_download}.values()
        )
        nbytes = reduce(lambda acc, x: acc + x[1].size if x[1].size else 0, unique_dl, 0)
        cfiles = list(filter(lambda x: self._target_path(x[0], x[1]).is_file(), unique_dl))
        cbytes = reduce(lambda acc, x: acc + x[1].size if x[1].size else 0, cfiles, 0)
        return StatisticsType(len(unique_dl), nbytes, len(cfiles), cbytes)

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
            target = self._target_path(pkg, f)
            if not target.parent.is_dir():
                target.parent.mkdir()
            hashable_file_checksums = frozenset(f.checksums.items())
            # check if we have the file under the exact filename
            if target.is_file():
                if check_hash_from_path(target, f.checksums):
                    logger.debug(f"File '{target}' already downloaded.")
                    self.known_hashes[hashable_file_checksums] = target
                    yield DownloadResult(
                        path=target, status=DownloadStatus.OK, package=pkg, filename=f.filename
                    )
                    continue
                logger.warning(f"Checksum mismatch on {f.filename}. Download again.")
                self.known_hashes.pop(hashable_file_checksums, None)
                target.unlink()
            # check if we have a file with the same hash and link to it
            o_target = self.known_hashes.get(hashable_file_checksums)
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
            if pkg.checksums:
                if (
                    not pkg.is_source() or f.filename.endswith(".dsc")
                ) and not check_hash_from_path(fdst, pkg.checksums):
                    logger.warning(f"Checksum mismatch on downloaded file '{fdst}'")
                    fdst.unlink()
                    yield DownloadResult(
                        path=None,
                        status=DownloadStatus.CHECKSUM_MISMATCH,
                        package=pkg,
                        filename=f.filename,
                    )
                    continue
            else:
                logger.debug(f"No supported checksum on {pkg}")

            logger.debug(f"Downloaded '{f.downloadurl}'")
            fdst.rename(target)
            self.known_hashes[hashable_file_checksums] = target
            yield DownloadResult(
                path=target, status=DownloadStatus.OK, package=pkg, filename=f.filename
            )
        self.to_download = []
        self.known_hashes.clear()
