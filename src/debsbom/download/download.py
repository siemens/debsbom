# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from collections import namedtuple
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from functools import reduce
import hashlib
from hmac import compare_digest
import json
import logging
from pathlib import Path
import sys
import os

from ..util.checksum import ChecksumAlgo, best_digest, calculate_checksums
from .resolver import RemoteFile
from ..dpkg import package
from ..dpkg.package import Package

import requests

logger = logging.getLogger(__name__)
StatisticsType = namedtuple("statistics", "files bytes cfiles cbytes")

#: Read size when streaming a download to disk
_CHUNK_SIZE = 1024 * 1024


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
    source: str

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
        result["source"] = self.source
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
            base = self.sources_dir
        else:
            base = self.binaries_dir
        base = base.resolve()
        target = (base / f.archive_name / f.filename).resolve()
        if not target.is_relative_to(base):
            purl = pkg.purl()
            raise ValueError(
                f"{purl}: malicious path in remote file detected: '{f.archive_name}/{f.filename}'"
            )
        else:
            return target

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

    @staticmethod
    def _package_checksums(pkg: package.Package, f: RemoteFile) -> Mapping[ChecksumAlgo, str]:
        """
        The checksums of a package identify the .deb file of a binary package and the .dsc
        file of a source package. All other files of a source package are only identified
        by the checksums of the remote file (and transitively by the .dsc file).
        """
        if pkg.is_source() and not f.filename.endswith(".dsc"):
            return {}
        return pkg.checksums

    @classmethod
    def _algorithms(cls, pkg: package.Package, f: RemoteFile) -> set[ChecksumAlgo]:
        """Return the algorithms to verify: the strongest one of each expectation."""
        return {max(c) for c in (f.checksums, cls._package_checksums(pkg, f)) if c}

    @staticmethod
    def _digest_mismatch(
        expected: Mapping[ChecksumAlgo, str], digests: Mapping[ChecksumAlgo, str]
    ) -> str | None:
        """
        Compare the strongest expected digest. The result is final: on a mismatch,
        weaker digests are not consulted.
        """
        if not expected:
            return None
        algo, digest = best_digest(expected)
        if compare_digest(digest.lower(), digests[algo]):
            return None
        return f"{algo} is {digests[algo]}, expected {digest}"

    @classmethod
    def _verify(
        cls,
        size: int,
        digests: Mapping[ChecksumAlgo, str],
        pkg: package.Package,
        f: RemoteFile,
    ) -> tuple[str | None, str | None]:
        """
        Verify file data independently against the expectations of the remote file and the
        expectations of the package. Returns the remote file and the package problem, if any.
        """
        if f.size is not None and size > f.size:
            return f"size exceeds {f.size} bytes", None
        if f.size is not None and size < f.size:
            return f"size is {size} bytes, expected {f.size}", None
        return (
            cls._digest_mismatch(f.checksums, digests),
            cls._digest_mismatch(cls._package_checksums(pkg, f), digests),
        )

    @classmethod
    def _verify_path(
        cls, path: Path, pkg: package.Package, f: RemoteFile
    ) -> tuple[str | None, str | None]:
        """Verify a file on disk, see :py:meth:`_verify`."""
        size = path.stat().st_size
        if f.size is not None and size != f.size:
            digests = {}
        else:
            digests = calculate_checksums(path, cls._algorithms(pkg, f))
        return cls._verify(size, digests, pkg, f)

    def _fetch(
        self, f: RemoteFile, dst: Path, algorithms: set[ChecksumAlgo]
    ) -> tuple[int, dict[ChecksumAlgo, str]]:
        """
        Stream the remote file to ``dst`` and hash the stored bytes on the fly.
        Stops reading as soon as the data exceeds the expected size.
        """
        hashes = {algo: hashlib.new(str(algo)) for algo in algorithms}
        size = 0
        # request the file as is, as a content-coding would alter the stored bytes
        with self.rs.get(f.downloadurl, stream=True, headers={"Accept-Encoding": "identity"}) as r:
            r.raise_for_status()
            with open(dst, "wb") as fp:
                while chunk := r.raw.read(_CHUNK_SIZE):
                    size += len(chunk)
                    if f.size is not None and size > f.size:
                        break
                    fp.write(chunk)
                    for h in hashes.values():
                        h.update(chunk)
        return size, {algo: h.hexdigest() for algo, h in hashes.items()}

    @staticmethod
    def _result(
        pkg: package.Package, f: RemoteFile, status: DownloadStatus, path: Path | None = None
    ) -> DownloadResult:
        return DownloadResult(
            path=path, status=status, package=pkg, filename=f.filename, source=f.downloadurl
        )

    def download(self, progress_cb=None) -> Iterable[DownloadResult]:
        """
        Download all files and yield the file paths to the on-disk
        object. Files that are already there are not downloaded again,
        but still reported. Before a file is reported as available, its size
        and checksum are verified against the ones of the remote file, if
        provided. Independently, the checksum of a binary package or of the
        .dsc file of a source package is verified.
        """
        logger.info("Starting download...")
        for idx, (pkg, f) in enumerate(self.to_download):
            if progress_cb:
                progress_cb(idx, len(self.to_download), f.filename)
            target = self._target_path(pkg, f)
            if not target.parent.is_dir():
                target.parent.mkdir()
            # only files with checksums can be identified by them
            hashable_file_checksums = frozenset(f.checksums.items()) if f.checksums else None
            # check if we have the file under the exact filename
            if target.is_file():
                if f.checksums:
                    file_problem, pkg_problem = self._verify_path(target, pkg, f)
                else:
                    file_problem, pkg_problem = "no checksum to verify it", None
                if not file_problem:
                    if pkg_problem:
                        # keep the file, it is valid but not the one of this package
                        logger.warning(f"Checksum mismatch on '{target}' for {pkg}: {pkg_problem}")
                        yield self._result(pkg, f, DownloadStatus.CHECKSUM_MISMATCH)
                        continue
                    logger.debug(f"File '{target}' already downloaded.")
                    self.known_hashes[hashable_file_checksums] = target
                    yield self._result(pkg, f, DownloadStatus.OK, target)
                    continue
                logger.warning(
                    f"Existing file '{target}' is invalid: {file_problem}. Download again."
                )
                self.known_hashes.pop(hashable_file_checksums, None)
                target.unlink()
            # check if we have a file with the same hash and link to it
            o_target = self.known_hashes.get(hashable_file_checksums)
            if o_target:
                file_problem, pkg_problem = self._verify_path(o_target, pkg, f)
                if file_problem or pkg_problem:
                    logger.warning(
                        f"Checksum mismatch on '{o_target}' for {pkg}: {file_problem or pkg_problem}"
                    )
                    yield self._result(pkg, f, DownloadStatus.CHECKSUM_MISMATCH)
                    continue
                if sys.version_info < (3, 12):
                    o_target_rel = os.path.relpath(o_target, start=target.parent)
                else:
                    o_target_rel = o_target.relative_to(target.parent, walk_up=True)
                target.symlink_to(o_target_rel)
                logger.debug(f"Linking '{target}' to already downloaded '{o_target_rel}'")
                yield self._result(pkg, f, DownloadStatus.OK, target)
                continue

            fdst = target.with_suffix(target.suffix + ".tmp")
            logger.debug(f"Downloading '{f.downloadurl}' to '{target}'...")
            try:
                size, digests = self._fetch(f, fdst, self._algorithms(pkg, f))
            except BaseException:
                fdst.unlink(missing_ok=True)
                raise
            file_problem, pkg_problem = self._verify(size, digests, pkg, f)
            if file_problem or pkg_problem:
                problem = file_problem or f"{pkg_problem} for {pkg}"
                logger.warning(f"Checksum mismatch on downloaded file '{f.downloadurl}': {problem}")
                fdst.unlink()
                yield self._result(pkg, f, DownloadStatus.CHECKSUM_MISMATCH)
                continue
            if not pkg.checksums:
                logger.debug(f"No supported checksum on {pkg}")

            logger.debug(f"Downloaded '{f.downloadurl}'")
            fdst.rename(target)
            if hashable_file_checksums:
                self.known_hashes[hashable_file_checksums] = target
            yield self._result(pkg, f, DownloadStatus.OK, target)
        self.to_download = []
        self.known_hashes.clear()
