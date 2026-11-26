# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

"""
Resolver for the packages of a remote APT repository, like a Debian mirror.
"""

import hashlib
import logging
import re
from urllib.parse import urlsplit

from debian import deb822

from ..apt.remote import (
    RemoteRepository,
    RepositoryError,
    RepositoryFile,
    RepositoryMetadataError,
    SourceRecord,
    parse_manifest,
)
from ..dpkg import package
from ..util.checksum import (
    ChecksumAlgo,
    ChecksumMismatchError,
    NoMatchingDigestError,
    calculate_checksums,
    verify_best_matching_digest,
)
from .resolver import NotFoundError, RemoteFile, ResolveError, Resolver

logger = logging.getLogger(__name__)

#: Maximum size of a .dsc file, which is retrieved to resolve a source package.
MAX_DSC_SIZE = 4 * 1024 * 1024

_LABEL_LENGTH = 64


class MirrorResolveError(ResolveError):
    """A package cannot be resolved because of a problem of the repository."""


class MirrorNotFoundError(MirrorResolveError, NotFoundError):
    """The package is not available in the repository."""


class MirrorIntegrityError(MirrorResolveError):
    """A file of the repository contradicts its metadata."""


def archive_label(url: str) -> str:
    """
    Name of the download directory of the files of a repository, derived from its URL,
    e.g. ``mirror_deb.debian.org_debian``. It groups the files, but does not establish
    their origin.
    """
    parts = urlsplit(url)
    name = re.sub(r"[^A-Za-z0-9.-]+", "_", parts.netloc + parts.path).strip("_.")
    if len(name) > _LABEL_LENGTH:
        digest = hashlib.sha256(url.encode()).hexdigest()[:8]
        name = f"{name[: _LABEL_LENGTH - 9]}_{digest}"
    return f"mirror_{name}" if name else "mirror"


def _describe(p: package.Package) -> str:
    if p.is_source():
        return f"source package {p.name} {p.version}"
    return f"binary package {p.name} {p.version} {p.architecture}"


class MirrorResolver(Resolver):
    """
    Resolve packages to the files of a remote APT repository, like a Debian mirror.

    A package is looked up by its exact name, version and (for binary packages)
    architecture, in the order of the configured suites and components. If the package has
    checksums, candidates are skipped if the strongest checksum they have in common differs.

    Binary package: the file of the ``Packages`` index is used. If it has no checksum in
    common with the package, the downloaded file is verified against both independently.

    Source package: the files of the ``Sources`` index are used. The .dsc file is retrieved
    and verified against the index. Its source name, version and list of files must match
    the index, and the other files are verified against its checksums. The checksums of the
    package identify the complete .dsc file, including its OpenPGP signature (which is not
    verified). Without checksums, the first candidate is used.

    A package which is not listed (or only with different checksums) is not found, see
    :py:class:`MirrorNotFoundError`. Other problems, like access errors, invalid metadata
    or files contradicting the metadata, raise a :py:class:`MirrorResolveError`.

    The repository is not authenticated. As it can change, the results should not be
    cached across runs.
    """

    def __init__(self, repository: RemoteRepository):
        super().__init__()
        self.repository = repository
        self.archive_name = archive_label(repository.url)

    def resolve(self, p: package.Package) -> list[RemoteFile]:
        try:
            if p.is_source():
                return self._resolve_source(p)
            return self._resolve_binary(p)
        except RepositoryError as e:
            raise MirrorResolveError(str(e)) from e

    def _remote_file(self, f: RepositoryFile) -> RemoteFile:
        return RemoteFile(
            checksums=dict(f.checksums),
            filename=f.name,
            archive_name=self.archive_name,
            downloadurl=self.repository.url_for(f.path),
            size=f.size,
        )

    def _not_found(self, skipped: int) -> MirrorNotFoundError:
        reason = f" (skipped {skipped} with different checksums)" if skipped else ""
        return MirrorNotFoundError(f"not found in '{self.repository.url}'{reason}")

    @staticmethod
    def _checksums(p: package.Package) -> dict[ChecksumAlgo, str]:
        # the checksums of the repository are normalized to lowercase
        return {algo: digest.lower() for algo, digest in p.checksums.items()}

    def _resolve_binary(self, p: package.Package) -> list[RemoteFile]:
        if not p.architecture:
            raise MirrorNotFoundError(
                f"cannot be looked up in '{self.repository.url}' without architecture"
            )
        expected = self._checksums(p)
        skipped = 0
        for record in self.repository.find_binaries(p.name, str(p.version), p.architecture):
            try:
                verify_best_matching_digest(record.file.checksums, expected)
            except ChecksumMismatchError as e:
                logger.debug(f"Skipping {_describe(p)} of '{record.index}': {e}")
                skipped += 1
                continue
            except NoMatchingDigestError:
                if expected:
                    logger.debug(
                        f"No checksum of {_describe(p)} in common with '{record.index}', "
                        "the downloaded file is verified independently"
                    )
            return [self._remote_file(record.file)]
        raise self._not_found(skipped)

    def _resolve_source(self, p: package.Package) -> list[RemoteFile]:
        expected = self._checksums(p)
        if not expected:
            # see UpstreamResolver, a source package should be identified by name and version
            logger.info(
                f"no digest for {p}. Lookup will be imprecise, "
                f"the first package found in '{self.repository.url}' is used"
            )
        skipped = 0
        for record in self.repository.find_sources(p.name, str(p.version)):
            try:
                verify_best_matching_digest(record.dsc.checksums, expected)
            except ChecksumMismatchError as e:
                logger.debug(f"Skipping {_describe(p)} of '{record.index}': .dsc {e}")
                skipped += 1
                continue
            except NoMatchingDigestError:
                pass
            digests, files = self._fetch_dsc(record)
            try:
                verify_best_matching_digest(digests, expected)
            except ChecksumMismatchError as e:
                logger.debug(f"Skipping {_describe(p)} of '{record.index}': .dsc {e}")
                skipped += 1
                continue
            except NoMatchingDigestError:
                pass
            return [self._remote_file(f) for f in (record.dsc, *files)]
        raise self._not_found(skipped)

    def _fetch_dsc(
        self, record: SourceRecord
    ) -> tuple[dict[ChecksumAlgo, str], list[RepositoryFile]]:
        """
        Retrieve the .dsc file of a source package and verify it against the index.
        Returns the checksums of the file and the other files with the checksums it lists.
        """
        dsc = record.dsc
        url = self.repository.url_for(dsc.path)
        if dsc.size > MAX_DSC_SIZE:
            raise MirrorResolveError(
                f"'{url}' exceeds the size limit of {MAX_DSC_SIZE} bytes of .dsc files"
            )
        try:
            data = self.repository.fetch(dsc.path, dsc.size)
        except RepositoryMetadataError as e:
            raise MirrorIntegrityError(
                f"'{url}' is larger than the {dsc.size} bytes listed in '{record.index}'"
            ) from e
        if len(data) != dsc.size:
            raise MirrorIntegrityError(
                f"'{url}' has {len(data)} bytes, but '{record.index}' lists {dsc.size}"
            )
        digests = calculate_checksums(data)
        try:
            verify_best_matching_digest(dsc.checksums, digests)
        except ChecksumMismatchError as e:
            raise MirrorIntegrityError(f"'{url}' does not match '{record.index}': {e}") from e
        return digests, self._check_dsc(record, url, data)

    @staticmethod
    def _check_dsc(record: SourceRecord, url: str, data: bytes) -> list[RepositoryFile]:
        """
        Verify that a .dsc file describes the source package of the record: its name,
        version and files, with their sizes and strongest common checksums. Returns the
        other files with the checksums of the .dsc file, as it identifies them and the
        index may only list weaker ones.
        """
        try:
            # an OpenPGP signature is removed, but not verified
            dsc = deb822.Deb822(data.decode("utf-8"))
        except UnicodeDecodeError as e:
            raise MirrorIntegrityError(f"'{url}' is not valid UTF-8: {e}") from e
        source, version = dsc.get("Source"), dsc.get("Version")
        if (source, version) != (record.name, record.version):
            raise MirrorIntegrityError(
                f"'{url}' describes {source} {version}, but '{record.index}' lists it for "
                f"{record.name} {record.version}"
            )
        listed = {f.name: f for f in parse_manifest(dsc, f"'{url}'")}
        indexed = {f.name: f for f in record.files if f is not record.dsc}
        if listed.keys() != indexed.keys():
            raise MirrorIntegrityError(
                f"'{url}' lists the files {sorted(listed)}, but '{record.index}' lists "
                f"{sorted(indexed)}"
            )
        for name, f in indexed.items():
            if f.size != listed[name].size:
                raise MirrorIntegrityError(
                    f"'{url}' lists {name!r} with {listed[name].size} bytes, but "
                    f"'{record.index}' with {f.size} bytes"
                )
            try:
                verify_best_matching_digest(listed[name].checksums, f.checksums)
            except (ChecksumMismatchError, NoMatchingDigestError) as e:
                raise MirrorIntegrityError(
                    f"'{url}' does not match '{record.index}' for {name!r}: {e}"
                ) from e
        return [
            RepositoryFile(f.path, f.size, listed[name].checksums) for name, f in indexed.items()
        ]
