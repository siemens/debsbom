# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

"""
Client for the package indexes of a remote APT repository, like a Debian mirror or a
repository created by tools such as reprepro.

The indexes (``Sources`` and ``Packages``) are retrieved on demand, parsed once per run
and looked up by package identity. The metadata used to locate a package is validated
(identity, paths, sizes, checksums and their consistency), but it is **not
authenticated**: signatures of the repository are not verified. The ``Release`` file is
only used to discover which indexes list ``Architecture: all`` packages.
"""

import codecs
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from io import BytesIO
import logging
import lzma
import posixpath
import re
from urllib.parse import quote, urlsplit
import zlib

from debian import deb822
import requests
import urllib3

from ..download.download import redirect_guard
from ..util.checksum import (
    ChecksumAlgo,
    checksums_from_package,
    deb882_table,
)

logger = logging.getLogger(__name__)

#: Connect and read timeouts (in seconds) of metadata requests. The read timeout limits
#: the time between received data, not the total duration of a request.
METADATA_TIMEOUT = (10, 60)
#: Maximum size of an index file, after decoding the HTTP content coding.
MAX_INDEX_FILE_SIZE = 128 * 1024 * 1024
#: Maximum size of the text of an index, after decompressing the index file.
MAX_INDEX_SIZE = 512 * 1024 * 1024
#: Maximum size of a ``Release`` or ``InRelease`` file.
MAX_RELEASE_SIZE = 16 * 1024 * 1024
#: Maximum memory used to decompress xz data.
XZ_MEMORY_LIMIT = 256 * 1024 * 1024

_CHUNK_SIZE = 64 * 1024
#: A single path segment or file name in repository metadata and configuration
_SEGMENT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~-]*")
_ARCH_RE = re.compile(r"[a-z0-9][a-z0-9-]*")
_TOKEN_RE = re.compile(r"\S+")
_SIZE_RE = re.compile(r"[0-9]{1,20}")
_HEX_RE = re.compile(r"[0-9a-fA-F]+")
_NON_BLANK_RE = re.compile(rb"\S")
_DIGEST_LENGTH = {
    ChecksumAlgo.MD5SUM: 32,
    ChecksumAlgo.SHA1SUM: 40,
    ChecksumAlgo.SHA256SUM: 64,
    ChecksumAlgo.SHA512SUM: 128,
}
# The fields are stored with lowercase names, which the checksum helpers expect.
#: Fields of a Packages paragraph which are needed to locate a binary package
_BINARY_FIELDS = ("filename", "size") + tuple(field for _, _, field in deb882_table)
#: Fields of a Sources paragraph which are needed to locate a source package
_SOURCE_FIELDS = ("directory",) + tuple(field.lower() for _, field, _ in deb882_table)


class RepositoryError(Exception):
    """Base class of all errors of a remote repository."""


class RepositoryAccessError(RepositoryError):
    """The repository could not be accessed: transport, authentication or server error."""


class RepositoryMetadataError(RepositoryError):
    """The repository metadata is malformed, unsafe or exceeds a size limit."""


class RepositoryConfigurationError(RepositoryError, ValueError):
    """The configuration is invalid or insufficient to locate the requested indexes."""


@dataclass(frozen=True)
class RepositoryFile:
    """A file listed in the repository metadata."""

    #: Normalized path relative to the archive root (a plain file name in a manifest)
    path: str
    size: int
    #: Validated checksums with lowercase digests
    checksums: dict[ChecksumAlgo, str]

    @property
    def name(self) -> str:
        return posixpath.basename(self.path)


@dataclass(frozen=True)
class BinaryRecord:
    """A binary package listed in a ``Packages`` index."""

    name: str
    version: str
    architecture: str
    file: RepositoryFile
    #: URL of the index listing the package
    index: str


@dataclass(frozen=True)
class SourceRecord:
    """A source package listed in a ``Sources`` index."""

    name: str
    version: str
    #: All files of the source package, including the .dsc file
    files: tuple[RepositoryFile, ...]
    #: URL of the index listing the package
    index: str

    @property
    def dsc(self) -> RepositoryFile:
        return next(f for f in self.files if f.name.endswith(".dsc"))


@dataclass(frozen=True)
class ReleaseInfo:
    """
    Information of a ``Release`` file. It is only used to discover indexes, as its
    signature is not verified.
    """

    architectures: tuple[str, ...]
    no_support_for_architecture_all: tuple[str, ...]

    @property
    def native_architectures(self) -> tuple[str, ...]:
        return tuple(a for a in self.architectures if a not in ("all", "source"))

    @property
    def has_all_packages_index(self) -> bool:
        """
        True, if ``Architecture: all`` packages are listed in a separate ``binary-all``
        index instead of the architecture-specific ones.
        """
        if self.architectures and "all" not in self.architectures:
            return False
        return "Packages" not in self.no_support_for_architecture_all


def _check_no_substitution(value: str, what: str) -> None:
    if "$(" in value:
        raise RepositoryConfigurationError(
            f"{what} {value!r}: substitution variables like $(ARCH) are not supported"
        )


def _check_segments(value: str, what: str) -> str:
    """Validate a suite or component name of the configuration."""
    _check_no_substitution(value, what)
    if not all(_SEGMENT_RE.fullmatch(s) for s in value.split("/")):
        raise RepositoryConfigurationError(f"invalid {what} {value!r}")
    return value


def _normalize(value: str) -> str | None:
    """
    Lexically resolve the ``.`` and ``..`` segments of a relative path. Returns None if
    the path is absolute, leaves its base or has an unsafe segment, and '' for the base.
    """
    if value.startswith("/") or not all(
        s in ("", ".", "..") or _SEGMENT_RE.fullmatch(s) for s in value.split("/")
    ):
        return None
    path = posixpath.normpath(value) if value else "."
    if path == ".." or path.startswith("../"):
        return None
    return "" if path == "." else path


def _relative_path(value: str, what: str, directory: bool = False) -> str:
    """
    Validate a path from repository metadata, which is relative to the archive root, and
    return it normalized. The archive root itself is only valid for a directory.
    """
    path = _normalize(value)
    if path is None or not (path or directory):
        raise RepositoryMetadataError(f"unsafe path {value!r} in {what}")
    return path


def _exact_path(suite: str) -> str:
    """Normalize the exact path of a suite ending with '/', the archive root is ''."""
    _check_no_substitution(suite, "exact path")
    path = _normalize(suite[:-1])
    if path is None:
        raise RepositoryConfigurationError(f"invalid exact path {suite!r}")
    return path


def _root_url(url: str) -> str:
    """Validate and normalize the configured URL of the archive root."""
    if not url or "\\" in url or any(c.isspace() or not c.isprintable() for c in url):
        raise RepositoryConfigurationError(f"invalid repository URL {url!r}")
    if "?" in url or "#" in url:
        raise RepositoryConfigurationError(
            f"repository URL {url!r} must not contain a query or fragment"
        )
    parts = urlsplit(url)
    if "@" in parts.netloc:
        raise RepositoryConfigurationError("repository URL must not contain credentials")
    if parts.scheme in ("http", "https"):
        try:
            port = parts.port
        except ValueError as e:
            raise RepositoryConfigurationError(f"invalid repository URL {url!r}: {e}") from e
        if not parts.hostname:
            raise RepositoryConfigurationError(f"repository URL {url!r} has no host")
        host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
        netloc = host if port is None else f"{host}:{port}"
    elif parts.scheme == "file":
        if parts.netloc.lower() not in ("", "localhost") or not parts.path.startswith("/"):
            raise RepositoryConfigurationError(
                f"repository URL {url!r} is not an absolute local file URL"
            )
        netloc = ""
    else:
        raise RepositoryConfigurationError(f"repository URL {url!r} must use http, https or file")
    # remove dot segments like RFC 3986
    segments: list[str] = []
    for s in parts.path.split("/"):
        if s == "..":
            segments = segments[:-1]
        elif s not in ("", "."):
            segments.append(s)
    return f"{parts.scheme}://{netloc}" + "".join(f"/{s}" for s in segments)


def _join(*parts: str) -> str:
    return "/".join(p for p in parts if p)


def _size(value: str, what: str) -> int:
    if not _SIZE_RE.fullmatch(value):
        raise RepositoryMetadataError(f"invalid size {value!r} in {what}")
    return int(value)


def _digest(value: str, algo: ChecksumAlgo, what: str) -> str:
    if len(value) != _DIGEST_LENGTH[algo] or not _HEX_RE.fullmatch(value):
        raise RepositoryMetadataError(f"invalid {algo} checksum {value!r} in {what}")
    return value.lower()


def parse_manifest(paragraph: deb822.Deb822, what: str) -> list[RepositoryFile]:
    """
    Parse and validate the file lists (``Files`` and ``Checksums-*``) of a ``Sources``
    paragraph or of a .dsc file, as parsed by :py:class:`debian.deb822.Deb822`.
    File-list fields must be raw strings, not pre-parsed lists. The paths of the
    returned files are plain file names.

    Each list must name a file at most once, with a valid checksum and a size consistent
    with the other lists. If ``Files`` is present, the other lists must not add files.
    Otherwise, the files of all supported lists are combined.
    """
    sizes: dict[str, int] = {}
    checksums: dict[str, dict[ChecksumAlgo, str]] = {}
    has_files = paragraph.get("Files") is not None
    for algo, field, _ in deb882_table:
        entries = paragraph.get(field)
        if entries is None:
            continue
        if not isinstance(entries, str) or not paragraph.is_multi_line(entries):
            raise RepositoryMetadataError(f"invalid {field} of {what}")
        listed = set()
        for line in filter(None, entries.splitlines()):
            parts = line.split(maxsplit=2)
            if len(parts) != 3:
                raise RepositoryMetadataError(f"invalid {field} entry in {what}")
            digest, size, name = parts
            if not _SEGMENT_RE.fullmatch(name):
                raise RepositoryMetadataError(f"unsafe file name {name!r} in {field} of {what}")
            if name in listed:
                raise RepositoryMetadataError(f"{field} of {what} lists {name!r} twice")
            listed.add(name)
            size = _size(size, f"{field} of {what}")
            if name not in sizes:
                if has_files and field != "Files":
                    raise RepositoryMetadataError(
                        f"{field} of {what} lists {name!r}, which is not listed in Files"
                    )
                sizes[name] = size
            elif sizes[name] != size:
                raise RepositoryMetadataError(f"conflicting sizes of {name!r} in {what}")
            checksums.setdefault(name, {})[algo] = digest
    if not sizes:
        raise RepositoryMetadataError(f"no files listed in {what}")
    return [
        RepositoryFile(
            path=name,
            size=size,
            checksums={algo: _digest(d, algo, what) for algo, d in checksums[name].items()},
        )
        for name, size in sizes.items()
    ]


def _read(response: requests.Response, limit: int, url: str) -> bytearray:
    """
    Read at most ``limit`` bytes of the response body, after decoding the HTTP content
    coding. The Content-Length is only checked upfront if there is no content coding,
    as it is the length of the encoded data otherwise.
    """
    if response.headers.get("Content-Encoding", "identity").lower() == "identity":
        length = response.headers.get("Content-Length", "")
        if length.isdigit() and int(length) > limit:
            raise RepositoryMetadataError(f"'{url}' exceeds the size limit of {limit} bytes")
    data = bytearray()
    for chunk in response.iter_content(_CHUNK_SIZE):
        data += chunk
        if len(data) > limit:
            raise RepositoryMetadataError(f"'{url}' exceeds the size limit of {limit} bytes")
    return data


def _decompress(data: bytes | bytearray, limit: int, url: str, new_decompressor: Callable) -> bytes:
    """
    Decompress all (concatenated) streams in ``data``, but at most ``limit`` bytes.
    Zero bytes between and after the streams (padding) are ignored, truncated data is
    an error.
    """
    chunks = []
    size = 0
    while True:
        decompressor = new_decompressor()
        chunks.append(decompressor.decompress(data, limit - size + 1))
        size += len(chunks[-1])
        if size > limit:
            raise RepositoryMetadataError(
                f"'{url}' exceeds the size limit of {limit} bytes after decompression"
            )
        if not decompressor.eof:
            raise RepositoryMetadataError(f"'{url}' is truncated")
        data = decompressor.unused_data.lstrip(b"\0")
        if not data:
            # a single stream is not copied
            return b"".join(chunks)


def _decompress_xz(data: bytes | bytearray, limit: int, url: str) -> bytes:
    try:
        return _decompress(
            data,
            limit,
            url,
            lambda: lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=XZ_MEMORY_LIMIT),
        )
    except lzma.LZMAError as e:
        raise RepositoryMetadataError(f"'{url}' is not valid xz data: {e}") from e


def _decompress_gzip(data: bytes | bytearray, limit: int, url: str) -> bytes:
    try:
        return _decompress(data, limit, url, lambda: zlib.decompressobj(wbits=zlib.MAX_WBITS | 16))
    except zlib.error as e:
        raise RepositoryMetadataError(f"'{url}' is not valid gzip data: {e}") from e


#: Index variants in order of preference
_INDEX_VARIANTS = ((".xz", _decompress_xz), (".gz", _decompress_gzip), ("", None))


def _check_utf8(data: bytes | bytearray, url: str) -> None:
    decoder = codecs.getincrementaldecoder("utf-8")()
    try:
        for pos in range(0, len(data), _CHUNK_SIZE):
            decoder.decode(data[pos : pos + _CHUNK_SIZE])
        decoder.decode(b"", final=True)
    except UnicodeDecodeError as e:
        raise RepositoryMetadataError(f"'{url}' is not valid UTF-8: {e}") from e


def _parse_index(
    data: bytes, binary: bool, url: str
) -> dict[tuple[str, ...], list[dict[str, str]]]:
    """
    Parse an index into its records, keyed by (name, version) for sources and
    (name, version, architecture) for binaries. Only the fields needed to locate the
    files are kept. They are validated when a record is looked up.
    """
    _check_utf8(data, url)
    keys = ("Package", "Version", "Architecture") if binary else ("Package", "Version")
    fields = _BINARY_FIELDS if binary else _SOURCE_FIELDS
    records: dict[tuple[str, ...], list[dict[str, str]]] = {}
    stream = BytesIO(data)
    parsed = 0
    for paragraph in deb822.Deb822.iter_paragraphs(stream, use_apt_pkg=False, encoding="utf-8"):
        parsed = stream.tell()
        key = tuple(paragraph.get(k, "") for k in keys)
        if not all(_TOKEN_RE.fullmatch(k) for k in key):
            raise RepositoryMetadataError(
                f"'{url}' lists a package without valid {', '.join(keys)}: {key!r}"
            )
        record = {f: v for f in fields if (v := paragraph.get(f)) is not None}
        records.setdefault(key, []).append(record)
    # the parser silently stops at data without fields, e.g. at an HTML error page
    if unparsed := _NON_BLANK_RE.search(data, parsed):
        line = data.count(b"\n", 0, unparsed.start()) + 1
        raise RepositoryMetadataError(f"'{url}' is not a valid index: cannot parse line {line}")
    return records


class RemoteRepository:
    """
    The package indexes of a remote APT repository.

    :param session: session used for all requests
    :param url: archive root (``http``, ``https`` or absolute ``file`` URL)
    :param suites: suites to search, in order. Suites ending with ``/`` are exact paths
        relative to the archive root (flat repositories), e.g. ``./``.
    :param components: components to search in each (normal) suite, in order
    :param architectures: architectures of the indexes which are searched for
        ``Architecture: all`` packages. If not set, they are taken from the
        ``Release`` file of the suite.

    The configuration is validated on construction (raising
    :py:exc:`RepositoryConfigurationError`), no request is made until a package is
    looked up.
    """

    def __init__(
        self,
        session: requests.Session,
        url: str,
        suites: Iterable[str],
        components: Iterable[str] = (),
        architectures: Iterable[str] = (),
    ):
        self.session = session
        self.url = _root_url(url)
        self.suites = tuple(dict.fromkeys(suites))
        self.components = tuple(dict.fromkeys(components))
        self.architectures = tuple(dict.fromkeys(architectures))
        if not self.suites:
            raise RepositoryConfigurationError("at least one suite is required")
        flat = [s.endswith("/") for s in self.suites]
        if any(flat) and not all(flat):
            raise RepositoryConfigurationError(
                "suites with an exact path (ending with '/') cannot be combined "
                "with normal suites, as they do not use components"
            )
        self.flat = all(flat)
        if self.flat:
            self._paths = tuple(dict.fromkeys(_exact_path(s) for s in self.suites))
            if self.components:
                raise RepositoryConfigurationError(
                    "suites with an exact path (ending with '/') have no components"
                )
            if self.architectures:
                raise RepositoryConfigurationError(
                    "architectures cannot be configured for suites with an exact path, "
                    "their index lists all architectures"
                )
        else:
            self._paths = tuple(_check_segments(s, "suite") for s in self.suites)
            if not self.components:
                raise RepositoryConfigurationError(
                    "at least one component is required for normal suites"
                )
            for c in self.components:
                _check_segments(c, "component")
        for a in self.architectures:
            self._check_architecture(a)
        #: memoized indexes (or their error) by index path
        self._indexes: dict[str, dict | RepositoryError] = {}
        #: memoized Release information (or their error) by suite
        self._releases: dict[str, ReleaseInfo | None | RepositoryError] = {}

    @staticmethod
    def _check_architecture(arch: str) -> None:
        _check_no_substitution(arch, "architecture")
        if arch == "any" or arch.startswith("any-") or arch.endswith("-any"):
            raise RepositoryConfigurationError(f"architecture wildcard {arch!r} is not supported")
        if arch == "source" or not _ARCH_RE.fullmatch(arch):
            raise RepositoryConfigurationError(f"invalid architecture {arch!r}")

    def url_for(self, path: str) -> str:
        """URL of a validated path relative to the archive root."""
        # like apt, encode '+' as some servers (e.g. S3) do not decode it properly
        return f"{self.url}/{quote(path, safe='/')}"

    def _get(self, url: str, limit: int) -> bytearray | None:
        """Retrieve at most ``limit`` bytes from ``url``. Returns None on a 404."""
        # hooks of the request replace the ones of the session
        hooks = {"response": [*self.session.hooks["response"], redirect_guard]}
        try:
            with self.session.get(url, stream=True, timeout=METADATA_TIMEOUT, hooks=hooks) as r:
                if r.status_code == requests.codes.not_found:
                    return None
                if r.status_code != requests.codes.ok:
                    raise RepositoryAccessError(
                        f"cannot retrieve '{url}': {r.status_code} {r.reason}"
                    )
                return _read(r, limit, url)
        except (requests.RequestException, urllib3.exceptions.HTTPError, OSError) as e:
            raise RepositoryAccessError(f"cannot retrieve '{url}': {e}") from e

    def fetch(self, path: str, limit: int) -> bytes:
        """Retrieve a small file listed in the metadata, like a .dsc file."""
        url = self.url_for(path)
        data = self._get(url, limit)
        if data is None:
            raise RepositoryAccessError(f"'{url}' is listed in the metadata, but not available")
        return bytes(data)

    def _load_index(self, path: str, binary: bool) -> dict[tuple[str, ...], list[dict[str, str]]]:
        for suffix, decompress in _INDEX_VARIANTS:
            url = self.url_for(path + suffix)
            data = self._get(url, MAX_INDEX_FILE_SIZE)
            if data is None:
                continue
            # parsing reads bytes without copying them, unlike a bytearray
            data = decompress(data, MAX_INDEX_SIZE, url) if decompress else bytes(data)
            logger.debug(f"Parsing index '{url}'")
            return _parse_index(data, binary, url)
        logger.debug(f"Index '{self.url_for(path)}' is not available")
        return {}

    def _index(self, path: str, binary: bool) -> dict[tuple[str, ...], list[dict[str, str]]]:
        """Get an index, which is retrieved and parsed only once (also on errors)."""
        index = self._indexes.get(path)
        if index is None:
            try:
                index = self._load_index(path, binary)
            except RepositoryError as e:
                index = e
            self._indexes[path] = index
        if isinstance(index, RepositoryError):
            raise index
        return index

    def _load_release(self, suite: str) -> ReleaseInfo | None:
        for name in ("Release", "InRelease"):
            url = self.url_for(f"dists/{suite}/{name}")
            data = self._get(url, MAX_RELEASE_SIZE)
            if data is None:
                continue
            _check_utf8(data, url)
            # the signature of an InRelease file is stripped, but not verified
            release = deb822.Deb822(bytes(data).splitlines(), encoding="utf-8")
            info = ReleaseInfo(
                architectures=tuple(release.get("Architectures", "").split()),
                no_support_for_architecture_all=tuple(
                    release.get("No-Support-for-Architecture-all", "").split()
                ),
            )
            if not all(_ARCH_RE.fullmatch(a) for a in info.architectures):
                raise RepositoryMetadataError(f"invalid Architectures in '{url}'")
            logger.debug(f"Using '{url}' (not authenticated) to discover indexes")
            return info
        return None

    def release(self, suite: str) -> ReleaseInfo | None:
        """Release information of a normal suite (or None if there is no Release file)."""
        if suite not in self._releases:
            try:
                self._releases[suite] = self._load_release(suite)
            except RepositoryError as e:
                self._releases[suite] = e
        release = self._releases[suite]
        if isinstance(release, RepositoryError):
            raise release
        return release

    def _all_architectures(self, suite: str) -> list[str]:
        """
        Architectures of the indexes which list ``Architecture: all`` packages, like apt:
        a separate ``binary-all`` index is only used if the Release file announces it
        (``all`` in Architectures, unless ``No-Support-for-Architecture-all: Packages``),
        if there is no Release file or if ``all`` is configured explicitly. The native
        indexes are searched as well, as they may also list these packages.
        """
        if "all" in self.architectures:
            return list(self.architectures)
        release = self.release(suite)
        if self.architectures:
            natives = list(self.architectures)
        elif release is not None and release.architectures:
            natives = list(release.native_architectures)
        else:
            raise RepositoryConfigurationError(
                f"cannot determine the indexes of 'Architecture: all' packages in suite "
                f"'{suite}', as there is no Release file listing its architectures: "
                "configure the architectures to search"
            )
        archs = (["all"] if release is None or release.has_all_packages_index else []) + natives
        if not archs:
            raise RepositoryConfigurationError(
                f"the Release file of suite '{suite}' lists no index of 'Architecture: all' packages"
            )
        return archs

    def _source_indexes(self) -> Iterator[str]:
        for path in self._paths:
            if self.flat:
                yield _join(path, "Sources")
                continue
            for component in self.components:
                yield f"dists/{path}/{component}/source/Sources"

    def _binary_indexes(self, architecture: str) -> Iterator[str]:
        for path in self._paths:
            if self.flat:
                yield _join(path, "Packages")
                continue
            archs = [architecture] if architecture != "all" else self._all_architectures(path)
            for component in self.components:
                for arch in archs:
                    yield f"dists/{path}/{component}/binary-{arch}/Packages"

    def find_sources(self, name: str, version: str) -> Iterator[SourceRecord]:
        """
        Find a source package by its exact name and version. The indexes are searched
        in the configured order and only retrieved when needed.
        """
        for path in self._source_indexes():
            for record in self._index(path, binary=False).get((name, version), []):
                yield self._source_record(name, version, record, self.url_for(path))

    def find_binaries(self, name: str, version: str, architecture: str) -> Iterator[BinaryRecord]:
        """
        Find a binary package by its exact name, version and architecture. The indexes
        are searched in the configured order and only retrieved when needed.
        """
        if not _ARCH_RE.fullmatch(architecture):
            raise RepositoryError(f"invalid architecture {architecture!r} of {name} {version}")
        for path in self._binary_indexes(architecture):
            for record in self._index(path, binary=True).get((name, version, architecture), []):
                yield self._binary_record(name, version, architecture, record, self.url_for(path))

    @staticmethod
    def _source_record(name: str, version: str, record: dict, index: str) -> SourceRecord:
        what = f"source package {name} {version} in '{index}'"
        if "directory" not in record:
            raise RepositoryMetadataError(f"no Directory for {what}")
        directory = _relative_path(record["directory"], f"Directory of {what}", directory=True)
        files = parse_manifest(deb822.Deb822(record), what)
        if len([f for f in files if f.name.endswith(".dsc")]) != 1:
            raise RepositoryMetadataError(f"{what} does not list exactly one .dsc file")
        return SourceRecord(
            name=name,
            version=version,
            files=tuple(
                RepositoryFile(_join(directory, f.path), f.size, f.checksums) for f in files
            ),
            index=index,
        )

    @staticmethod
    def _binary_record(
        name: str, version: str, architecture: str, record: dict, index: str
    ) -> BinaryRecord:
        what = f"binary package {name} {version} {architecture} in '{index}'"
        if "filename" not in record or "size" not in record:
            raise RepositoryMetadataError(f"no Filename or Size for {what}")
        checksums = {
            algo: _digest(digest, algo, what)
            for algo, digest in checksums_from_package(record).items()
        }
        if not checksums:
            raise RepositoryMetadataError(f"no supported checksum for {what}")
        return BinaryRecord(
            name=name,
            version=version,
            architecture=architecture,
            file=RepositoryFile(
                path=_relative_path(record["filename"], f"Filename of {what}"),
                size=_size(record["size"], what),
                checksums=checksums,
            ),
            index=index,
        )
