# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from collections import namedtuple
from collections.abc import Iterable, Mapping
from requests.exceptions import RequestException
from requests import Response
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass
from enum import Enum
from functools import reduce
import json
import logging
from pathlib import Path
import sys
import os

from ..util.checksum import (
    ChecksumAlgo,
    ChecksumMismatchError,
    best_digest,
    NoMatchingDigestError,
    calculate_checksums,
    verify_best_matching_digest,
)
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


class VerificationError(ValueError):
    """A file does not match its expectations."""


class InvalidFileError(VerificationError):
    """The file does not match the remote file."""


class PackageMismatchError(VerificationError):
    """The file is a valid remote file, but does not match the package."""


class UnsafeRedirectError(RequestException):
    """A redirect to a location with an unsupported scheme was refused."""

    def __init__(self, src: str, target: str, response: Response | None = None):
        message = f"refusing redirect from '{src}' to '{target}'"
        super().__init__(message, response=response)


def redirect_guard(response: Response, *args, **kwargs) -> Response:
    """
    Response hook which refuses to follow redirects to anything but HTTP(S) URLs,
    e.g. to local files.
    """
    if response.is_redirect:
        target = urljoin(response.url, response.headers["Location"])
        if urlparse(target).scheme not in ("http", "https"):
            response.close()
            raise UnsafeRedirectError(response.url, target, response)
    return response


@dataclass
class DownloadResult:
    path: Path | None
    status: DownloadStatus
    package: Package
    filename: str | None
    source: str | None

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
        if self.source:
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
        return {best_digest(c)[0] for c in (f.checksums, cls._package_checksums(pkg, f)) if c}

    @staticmethod
    def _verify_digest(expected: Mapping[ChecksumAlgo, str], digests: Mapping[ChecksumAlgo, str]):
        """
        Verify the strongest expected digest, if any. A mismatch is final: weaker digests
        are not consulted.
        """
        try:
            verify_best_matching_digest({a: d.lower() for a, d in expected.items()}, digests)
        except NoMatchingDigestError:
            pass

    @classmethod
    def _verify(cls, path: Path, pkg: package.Package, f: RemoteFile, size: int | None = None):
        """
        Verify a file against the expectations of the remote file and, if it is valid,
        against the expectations of the package. ``size`` overrides the on-disk size,
        e.g. the number of bytes received.

        Raises :py:class:`InvalidFileError` or :py:class:`PackageMismatchError`.
        """
        if size is None:
            size = path.stat().st_size
        if f.size is not None and size > f.size:
            raise InvalidFileError(f"size exceeds {f.size} bytes")
        if f.size is not None and size < f.size:
            raise InvalidFileError(f"size is {size} bytes, expected {f.size}")
        digests = calculate_checksums(path, cls._algorithms(pkg, f))
        try:
            cls._verify_digest(f.checksums, digests)
        except ChecksumMismatchError as e:
            raise InvalidFileError(str(e)) from e
        try:
            cls._verify_digest(cls._package_checksums(pkg, f), digests)
        except ChecksumMismatchError as e:
            raise PackageMismatchError(str(e)) from e

    def _fetch(self, f: RemoteFile, dst: Path) -> int:
        """
        Stream the remote file to ``dst`` and return the number of bytes received.
        Stops reading as soon as the data exceeds the expected size. Redirects are
        only followed to HTTP(S) URLs.
        """
        size = 0
        # hooks of the request replace the ones of the session
        hooks = {"response": [*self.rs.hooks["response"], redirect_guard]}
        with self.rs.get(f.downloadurl, stream=True, hooks=hooks) as r:
            r.raise_for_status()
            with open(dst, "wb") as fp:
                for chunk in r.iter_content(_CHUNK_SIZE):
                    size += len(chunk)
                    if f.size is not None and size > f.size:
                        break
                    fp.write(chunk)
        return size

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
                try:
                    if not f.checksums:
                        raise InvalidFileError("no checksum to verify it")
                    self._verify(target, pkg, f)
                except PackageMismatchError as e:
                    # keep the file, it is valid but not the one of this package
                    logger.warning(f"Checksum mismatch on '{target}' for {pkg}: {e}")
                    yield DownloadResult(
                        path=None,
                        status=DownloadStatus.CHECKSUM_MISMATCH,
                        package=pkg,
                        filename=f.filename,
                        source=f.downloadurl,
                    )
                    continue
                except InvalidFileError as e:
                    logger.warning(f"Existing file '{target}' is invalid: {e}. Download again.")
                    self.known_hashes.pop(hashable_file_checksums, None)
                    target.unlink()
                else:
                    logger.debug(f"File '{target}' already downloaded.")
                    self.known_hashes[hashable_file_checksums] = target
                    yield DownloadResult(
                        path=target,
                        status=DownloadStatus.OK,
                        package=pkg,
                        filename=f.filename,
                        source=f.downloadurl,
                    )
                    continue
            # check if we have a file with the same hash and link to it
            o_target = self.known_hashes.get(hashable_file_checksums)
            if o_target:
                try:
                    self._verify(o_target, pkg, f)
                except VerificationError as e:
                    logger.warning(f"Checksum mismatch on '{o_target}' for {pkg}: {e}")
                    yield DownloadResult(
                        path=None,
                        status=DownloadStatus.CHECKSUM_MISMATCH,
                        package=pkg,
                        filename=f.filename,
                        source=f.downloadurl,
                    )
                    continue
                if sys.version_info < (3, 12):
                    o_target_rel = os.path.relpath(o_target, start=target.parent)
                else:
                    o_target_rel = o_target.relative_to(target.parent, walk_up=True)
                target.symlink_to(o_target_rel)
                logger.debug(f"Linking '{target}' to already downloaded '{o_target_rel}'")
                yield DownloadResult(
                    path=target,
                    status=DownloadStatus.OK,
                    package=pkg,
                    filename=f.filename,
                    source=f.downloadurl,
                )
                continue

            fdst = target.with_suffix(target.suffix + ".tmp")
            logger.debug(f"Downloading '{f.downloadurl}' to '{target}'...")
            try:
                size = self._fetch(f, fdst)
            except BaseException:
                fdst.unlink(missing_ok=True)
                raise
            try:
                self._verify(fdst, pkg, f, size)
            except VerificationError as e:
                logger.warning(
                    f"Checksum mismatch on downloaded file '{f.downloadurl}' for {pkg}: {e}"
                )
                fdst.unlink()
                yield DownloadResult(
                    path=None,
                    status=DownloadStatus.CHECKSUM_MISMATCH,
                    package=pkg,
                    filename=f.filename,
                    source=f.downloadurl,
                )
                continue
            if not pkg.checksums:
                logger.debug(f"No supported checksum on {pkg}")

            logger.debug(f"Downloaded '{f.downloadurl}'")
            fdst.rename(target)
            if hashable_file_checksums:
                self.known_hashes[hashable_file_checksums] = target
            yield DownloadResult(
                path=target,
                status=DownloadStatus.OK,
                package=pkg,
                filename=f.filename,
                source=f.downloadurl,
            )
        self.to_download = []
        self.known_hashes.clear()
