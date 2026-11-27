# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from collections import Counter
import gzip
from http import HTTPStatus
import io
import lzma
import subprocess
import sys
from unittest import mock

import pytest
import requests
from requests.adapters import BaseAdapter
from requests.structures import CaseInsensitiveDict
import urllib3
from debian import deb822

from debsbom.apt import remote
from debsbom.apt.remote import (
    METADATA_TIMEOUT,
    RemoteRepository,
    RepositoryAccessError,
    RepositoryConfigurationError,
    RepositoryError,
    RepositoryMetadataError,
)
from debsbom.download.adapters import LocalFileAdapter
from debsbom.download.download import UnsafeRedirectError
from debsbom.util.checksum import ChecksumAlgo, calculate_checksums

ROOT = "https://mirror.example/debian"
DEB = b"binary package\n"
LISTS = {
    "Files": ChecksumAlgo.MD5SUM,
    "Checksums-Sha1": ChecksumAlgo.SHA1SUM,
    "Checksums-Sha256": ChecksumAlgo.SHA256SUM,
    "Checksums-Sha512": ChecksumAlgo.SHA512SUM,
}
COMPRESS = {".xz": lzma.compress, ".gz": gzip.compress, "": bytes}


def paragraph(values: dict) -> str:
    """A deb822 paragraph, fields set to None are omitted."""
    return "".join(
        f"{k}:{v if v.startswith(chr(10)) else ' ' + v}\n"
        for k, v in values.items()
        if v is not None
    )


def binary(name="foo", version="1.0", arch="amd64", data=DEB, **fields) -> str:
    """Paragraph of a Packages index."""
    sums = calculate_checksums(data)
    return paragraph(
        {
            "Package": name,
            "Version": version,
            "Architecture": arch,
            "Filename": f"pool/main/f/{name}/{name}_{version}_{arch}.deb",
            "Size": str(len(data)),
            "MD5sum": sums[ChecksumAlgo.MD5SUM],
            "SHA256": sums[ChecksumAlgo.SHA256SUM],
        }
        | fields
    )


def file_list(files: dict[str, bytes], algo: ChecksumAlgo) -> str:
    return "".join(
        f"\n {calculate_checksums(data, [algo])[algo]} {len(data)} {name}"
        for name, data in files.items()
    )


def source(
    name="foo", version="1.0", files=None, lists=("Files", "Checksums-Sha256"), **fields
) -> str:
    """Paragraph of a Sources index."""
    files = files or {f"{name}_{version}.dsc": b"dsc\n", f"{name}_{version}.tar.xz": b"tar\n"}
    values = {"Package": name, "Version": version, "Directory": f"pool/main/f/{name}"}
    values |= {field: file_list(files, LISTS[field]) for field in lists}
    return paragraph(values | fields)


class LocalRepository:
    """A repository in a local directory, accessed by file URLs."""

    def __init__(self, root):
        self.root = root
        self.adapter = mock.Mock(wraps=LocalFileAdapter())
        self.session = requests.Session()
        self.session.mount("file:///", self.adapter)

    @property
    def url(self) -> str:
        return self.root.as_uri()

    def write(self, path: str, data: bytes) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def index(self, path: str, *paragraphs: str, variant=".xz") -> None:
        self.write(path + variant, COMPRESS[variant]("\n".join(paragraphs).encode()))

    def packages(self, *paragraphs, suite="trixie", component="main", arch="amd64", **kw):
        self.index(f"dists/{suite}/{component}/binary-{arch}/Packages", *paragraphs, **kw)

    def sources(self, *paragraphs, suite="trixie", component="main", **kw):
        self.index(f"dists/{suite}/{component}/source/Sources", *paragraphs, **kw)

    def repository(self, suites=("trixie",), components=("main",), architectures=()):
        return RemoteRepository(self.session, self.url, suites, components, architectures)

    @property
    def requested(self) -> Counter:
        return Counter(c.args[0].url for c in self.adapter.send.call_args_list)


@pytest.fixture
def local(tmp_path):
    repo = LocalRepository(tmp_path / "mirror")
    yield repo
    repo.session.close()


class HTTPResponses(BaseAdapter):
    """Serves fixed responses by URL like an HTTP server, including content coding."""

    def __init__(self):
        super().__init__()
        self.responses = {}
        self.sent = []
        self.raws = []

    def add(self, path, body=b"", status=200, headers=None):
        self.responses[f"{ROOT}/{path}"] = (status, body, headers or {})

    def send(self, request, **kwargs):
        self.sent.append((request.url, kwargs))
        status, body, headers = self.responses.get(request.url, (404, b"", {}))
        if isinstance(body, Exception):
            raise body
        raw = urllib3.HTTPResponse(
            body=io.BytesIO(body),
            headers=headers,
            status=status,
            preload_content=False,
            decode_content=False,
        )
        self.raws.append(raw)
        response = requests.Response()
        response.request = request
        response.url = request.url
        response.status_code = status
        response.reason = HTTPStatus(status).phrase
        response.raw = raw
        response.headers = CaseInsensitiveDict(raw.headers)
        return response

    def close(self):
        pass


@pytest.fixture
def http():
    adapter = HTTPResponses()
    with requests.Session() as rs:
        rs.mount("https://", adapter)
        adapter.session = rs
        yield adapter


def http_repository(http, **kwargs) -> RemoteRepository:
    return RemoteRepository(http.session, ROOT, ["trixie"], ["main"], **kwargs)


PACKAGES = "dists/trixie/main/binary-amd64/Packages"


@pytest.fixture
def offline_session():
    """A session which fails on any request."""
    with requests.Session() as rs:
        adapter = mock.Mock(spec=BaseAdapter, send=mock.Mock(side_effect=AssertionError))
        for prefix in ("http://", "https://", "file://"):
            rs.mount(prefix, adapter)
        yield rs


@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://mirror.example/debian/", ROOT),
        ("HTTPS://Mirror.Example:8443/debian", "https://mirror.example:8443/debian"),
        ("http://[::1]/debian", "http://[::1]/debian"),
        ("https://mirror.example", "https://mirror.example"),
        ("https://mirror.example/a/./b/../debian//", "https://mirror.example/a/debian"),
        ("file:///srv/mirror/", "file:///srv/mirror"),
        ("file://localhost/srv/mirror", "file:///srv/mirror"),
    ],
)
def test_valid_configuration(offline_session, url, expected):
    repo = RemoteRepository(offline_session, url, ["trixie", "trixie-updates"], ["main"])
    assert repo.url == expected
    assert repo.url_for("pool/main/f/foo/foo_1.0+b1_amd64.deb") == (
        f"{expected}/pool/main/f/foo/foo_1.0%2Bb1_amd64.deb"
    )
    assert not repo.flat


@pytest.mark.parametrize(
    "config, match",
    [
        (dict(url="ftp://mirror.example/debian"), "must use http, https or file"),
        (dict(url="mirror.example/debian"), "must use http, https or file"),
        (dict(url="https://user:secret@mirror.example/debian"), "credentials"),
        (dict(url="https://mirror.example/debian?token=1"), "query or fragment"),
        (dict(url="https://mirror.example/debian#main"), "query or fragment"),
        (dict(url="https:///debian"), "has no host"),
        (dict(url="https://mirror.example:99999/debian"), "invalid repository URL"),
        (dict(url="https://mirror.example/de bian"), "invalid repository URL"),
        (dict(url="https://mirror.example\\debian"), "invalid repository URL"),
        (dict(url="file://host/srv/mirror"), "absolute local file URL"),
        (dict(suites=[]), "at least one suite"),
        (dict(suites=["trixie", "./"]), "cannot be combined"),
        (dict(suites=["./"]), "have no components"),
        (dict(suites=["./"], components=[], architectures=["amd64"]), "architectures"),
        (dict(components=[]), "at least one component"),
        (dict(suites=["../trixie"]), "invalid suite"),
        (dict(suites=["trixie updates"]), "invalid suite"),
        (dict(suites=["$(ARCH)/"], components=[]), "substitution"),
        (dict(suites=["sub/../../"], components=[]), "invalid exact path"),
        (dict(suites=["/srv/"], components=[]), "invalid exact path"),
        (dict(components=["main/../contrib"]), "invalid component"),
        (dict(architectures=["linux-any"]), "wildcard"),
        (dict(architectures=["any"]), "wildcard"),
        (dict(architectures=["source"]), "invalid architecture"),
        (dict(architectures=["AMD64"]), "invalid architecture"),
        (dict(architectures=["$(ARCH)"]), "substitution"),
    ],
)
def test_invalid_configuration(offline_session, config, match):
    config = dict(url=ROOT, suites=["trixie"], components=["main"]) | config
    with pytest.raises(RepositoryConfigurationError, match=match) as e:
        RemoteRepository(offline_session, **config)
    assert isinstance(e.value, ValueError)


@pytest.mark.parametrize("variant", [".xz", ".gz", ""])
def test_index_variants(local, variant):
    local.packages(binary(), binary("bar"), variant=variant)
    local.sources(source(), variant=variant)
    repo = local.repository()
    (record,) = repo.find_binaries("foo", "1.0", "amd64")
    assert record.file.path == "pool/main/f/foo/foo_1.0_amd64.deb"
    assert record.file.size == len(DEB)
    assert record.file.checksums == {
        ChecksumAlgo.MD5SUM: calculate_checksums(DEB)[ChecksumAlgo.MD5SUM],
        ChecksumAlgo.SHA256SUM: calculate_checksums(DEB)[ChecksumAlgo.SHA256SUM],
    }
    assert record.index == f"{local.url}/{PACKAGES}"
    (src,) = repo.find_sources("foo", "1.0")
    assert [f.path for f in src.files] == [
        "pool/main/f/foo/foo_1.0.dsc",
        "pool/main/f/foo/foo_1.0.tar.xz",
    ]
    assert src.dsc.name == "foo_1.0.dsc"


def test_index_variant_preference(local):
    local.packages(binary(version="xz"), variant=".xz")
    local.packages(binary(version="gz"), variant=".gz")
    local.packages(binary(version="plain"), variant="")
    repo = local.repository()
    assert len(list(repo.find_binaries("foo", "xz", "amd64"))) == 1
    assert not list(repo.find_binaries("foo", "gz", "amd64"))


def test_only_missing_variants_are_skipped(local):
    """A malformed index is an error, even if another variant is available."""
    local.write(PACKAGES + ".xz", b"not xz")
    local.packages(binary(), variant=".gz")
    with pytest.raises(RepositoryMetadataError, match="truncated|not valid xz data"):
        list(local.repository().find_binaries("foo", "1.0", "amd64"))


def test_concatenated_streams(local):
    first, second = binary().encode(), ("\n" + binary("bar")).encode()
    local.write(PACKAGES + ".xz", lzma.compress(first) + b"\0" * 4 + lzma.compress(second))
    local.write(
        "dists/trixie/main/source/Sources.gz",
        gzip.compress(source().encode()) + gzip.compress(("\n" + source("bar")).encode()) + b"\0",
    )
    repo = local.repository()
    assert len(list(repo.find_binaries("bar", "1.0", "amd64"))) == 1
    assert len(list(repo.find_sources("bar", "1.0"))) == 1


@pytest.mark.parametrize(
    "variant, data, match",
    [
        (".xz", lzma.compress(binary().encode())[:-8], "truncated|not valid xz"),
        (".gz", gzip.compress(binary().encode())[:-8], "truncated"),
        (".gz", gzip.compress(binary().encode()) + b"trailing", "not valid gzip"),
        (".xz", binary().encode(), "not valid xz"),
        ("", binary().encode() + b"Description: \xff\n", "not valid UTF-8"),
        ("", b"Package: foo\nArchitecture: amd64\n", "without valid Package"),
        ("", b"Package: foo bar\nVersion: 1.0\nArchitecture: amd64\n", "without valid"),
        # not an index, e.g. an error page served instead of it
        ("", b"<html>Service unavailable</html>\n", "not a valid index: cannot parse line 1"),
        ("", b"not an index\n\n" + binary().encode(), "cannot parse line 1"),
        (
            "",
            binary().encode() + b"\nnot an index\n\n" + binary("bar").encode(),
            "cannot parse line 9",
        ),
    ],
)
def test_malformed_index(local, variant, data, match):
    local.write(PACKAGES + variant, data)
    with pytest.raises(RepositoryMetadataError, match=match):
        list(local.repository().find_binaries("foo", "1.0", "amd64"))


def test_size_limits(local, monkeypatch):
    text = "\n".join(binary(f"pkg{i}") for i in range(100)).encode()
    local.write(PACKAGES + ".xz", lzma.compress(text))
    local.write("dists/trixie/main/binary-arm64/Packages", text)
    monkeypatch.setattr(remote, "MAX_INDEX_SIZE", len(text) - 1)
    repo = local.repository()
    with pytest.raises(RepositoryMetadataError, match="after decompression"):
        list(repo.find_binaries("foo", "1.0", "amd64"))

    # the limit of the index file applies to uncompressed indexes as well
    monkeypatch.setattr(remote, "MAX_INDEX_SIZE", len(text))
    monkeypatch.setattr(remote, "MAX_INDEX_FILE_SIZE", len(text) - 1)
    with pytest.raises(RepositoryMetadataError, match="exceeds the size limit"):
        list(repo.find_binaries("foo", "1.0", "arm64"))


def test_xz_memory_limit(local, monkeypatch):
    local.packages(binary())
    monkeypatch.setattr(remote, "XZ_MEMORY_LIMIT", 1024)
    with pytest.raises(RepositoryMetadataError, match="Memory usage limit"):
        list(local.repository().find_binaries("foo", "1.0", "amd64"))


@pytest.mark.parametrize("variant", [".xz", ".gz", ""])
def test_http_content_coding(http, variant):
    """
    The HTTP content coding is decoded before an index file is decompressed. The limits
    apply to the decoded data, not to the Content-Length.
    """
    packages = "\n".join([binary(), binary("data", arch="all")])
    files = {
        PACKAGES + variant: COMPRESS[variant](packages.encode()),
        f"dists/trixie/main/source/Sources{variant}": COMPRESS[variant](source().encode()),
        "dists/trixie/Release": b"Architectures: amd64\n",
        "pool/main/f/foo/foo_1.0.dsc": b"dsc\n",
    }
    for path, data in files.items():
        coded = gzip.compress(data)
        http.add(
            path, coded, headers={"Content-Encoding": "gzip", "Content-Length": str(len(coded))}
        )
    repo = http_repository(http)
    (record,) = repo.find_binaries("foo", "1.0", "amd64")
    assert record.file.size == len(DEB)
    assert len(list(repo.find_binaries("data", "1.0", "all"))) == 1
    (src,) = repo.find_sources("foo", "1.0")
    # the Content-Length of the coded .dsc file exceeds its size
    assert repo.fetch(src.dsc.path, src.dsc.size) == b"dsc\n"
    assert all(
        kwargs["stream"] and kwargs["timeout"] == METADATA_TIMEOUT for _, kwargs in http.sent
    )


def test_http_malformed_content_coding(http):
    """Data which cannot be decoded is an error, not a missing index variant."""
    http.add(PACKAGES + ".xz", b"not gzip", headers={"Content-Encoding": "gzip"})
    http.add(PACKAGES + ".gz", gzip.compress(binary().encode()))
    with pytest.raises(RepositoryAccessError) as e:
        list(http_repository(http).find_binaries("foo", "1.0", "amd64"))
    assert isinstance(e.value.__cause__, requests.exceptions.ContentDecodingError)


def test_http_content_length(http, monkeypatch):
    """The Content-Length is checked upfront, unless it is the length of encoded data."""
    text = binary().encode()
    encoded = gzip.compress(text, compresslevel=0)
    assert len(encoded) > len(text)
    monkeypatch.setattr(remote, "MAX_INDEX_FILE_SIZE", len(text))
    http.add(
        PACKAGES,
        encoded,
        headers={"Content-Encoding": "gzip", "Content-Length": str(len(encoded))},
    )
    assert len(list(http_repository(http).find_binaries("foo", "1.0", "amd64"))) == 1

    http.add(PACKAGES, text, headers={"Content-Length": str(len(text) + 1)})
    with pytest.raises(RepositoryMetadataError, match="exceeds the size limit"):
        list(http_repository(http).find_binaries("foo", "1.0", "amd64"))
    assert http.raws[-1].tell() == 0


def test_http_decoded_size_limit(http, monkeypatch):
    monkeypatch.setattr(remote, "MAX_INDEX_FILE_SIZE", 1024 * 1024)
    http.add(
        PACKAGES,
        gzip.compress(binary().encode() + b"\0" * (4 * 1024 * 1024)),
        headers={"Content-Encoding": "gzip"},
    )
    with pytest.raises(RepositoryMetadataError, match="exceeds the size limit"):
        list(http_repository(http).find_binaries("foo", "1.0", "amd64"))
    assert http.raws[-1].closed


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
def test_access_errors(http, status):
    http.add(PACKAGES + ".xz", status=status)
    with pytest.raises(RepositoryAccessError, match=str(status)):
        list(http_repository(http).find_binaries("foo", "1.0", "amd64"))


@pytest.mark.parametrize("error", [requests.ConnectionError("down"), requests.Timeout("slow")])
def test_transport_errors(http, error):
    http.add(PACKAGES + ".xz", error)
    with pytest.raises(RepositoryAccessError, match=str(error)):
        list(http_repository(http).find_binaries("foo", "1.0", "amd64"))


def test_redirects(http, tmp_path):
    http.add(PACKAGES + ".xz", status=302, headers={"Location": f"{ROOT}/moved/Packages.xz"})
    http.add(
        "moved/Packages.xz",
        gzip.compress(lzma.compress(binary().encode())),
        headers={"Content-Encoding": "gzip"},
    )
    assert len(list(http_repository(http).find_binaries("foo", "1.0", "amd64"))) == 1

    local_file = tmp_path / "Packages"
    local_file.write_text(binary("bar"))
    local_files = mock.Mock(wraps=LocalFileAdapter())
    http.session.mount("file:///", local_files)
    http.add(PACKAGES + ".xz", status=302, headers={"Location": local_file.as_uri()})
    with pytest.raises(RepositoryAccessError) as e:
        list(http_repository(http).find_binaries("bar", "1.0", "amd64"))
    assert isinstance(e.value.__cause__, UnsafeRedirectError)
    local_files.send.assert_not_called()


def test_session_hooks(http):
    seen = []
    http.session.hooks["response"].append(lambda r, *args, **kwargs: seen.append(r.url))
    list(http_repository(http).find_binaries("foo", "1.0", "amd64"))
    assert f"{ROOT}/{PACKAGES}.xz" in seen


def test_index_memoization(local, monkeypatch):
    calls = Counter()
    parse_index = remote._parse_index

    def counting_parse_index(data, binary, url):
        calls[url] += 1
        return parse_index(data, binary, url)

    monkeypatch.setattr(remote, "_parse_index", counting_parse_index)
    local.packages(binary(), binary("bar"))
    repo = local.repository()
    for name in ("foo", "bar", "foo", "baz"):
        list(repo.find_binaries(name, "1.0", "amd64"))
    assert list(calls.values()) == [1]
    assert set(local.requested.values()) == {1}

    # missing indexes and errors are memoized as well
    local.write("dists/trixie/main/source/Sources.xz", b"broken")
    for _ in range(2):
        with pytest.raises(RepositoryMetadataError):
            list(repo.find_sources("foo", "1.0"))
        assert not list(repo.find_binaries("foo", "1.0", "arm64"))
    assert set(local.requested.values()) == {1}


def test_missing_indexes(local):
    """Missing and empty indexes are empty, like in incomplete repositories."""
    local.packages(binary(), component="contrib")
    local.packages(arch="arm64", variant=".gz")
    local.sources(variant="")
    repo = local.repository(components=["main", "contrib", "non-free"])
    assert len(list(repo.find_binaries("foo", "1.0", "amd64"))) == 1
    assert not list(repo.find_binaries("foo", "1.0", "arm64"))
    assert not list(repo.find_sources("foo", "1.0"))


def test_lookup_order(local):
    local.packages(binary(Filename="pool/updates.deb"), suite="trixie-updates")
    local.packages(binary(Filename="pool/main.deb"))
    local.packages(binary(Filename="pool/contrib.deb"), component="contrib")
    repo = local.repository(suites=["trixie-updates", "trixie"], components=["contrib", "main"])
    assert [r.file.path for r in repo.find_binaries("foo", "1.0", "amd64")] == [
        "pool/updates.deb",
        "pool/contrib.deb",
        "pool/main.deb",
    ]


@pytest.mark.parametrize(
    "name, version, arch",
    [
        ("Foo", "1.0", "amd64"),
        ("foo", "1.0-1", "amd64"),
        ("foo", "1", "amd64"),
        ("foo", "1.0", "i386"),
    ],
)
def test_exact_matching(local, name, version, arch):
    local.packages(binary())
    # a misplaced record is only found by its own architecture
    local.packages(binary(), arch="i386")
    local.sources(source())
    repo = local.repository()
    assert not list(repo.find_binaries(name, version, arch))
    assert arch == "i386" or not list(repo.find_sources(name, version))


@pytest.mark.parametrize("suite, path", [("./", ""), ("/", ""), ("sub/./dir/", "sub/dir/")])
def test_flat_repository(local, suite, path):
    """A flat index lists all architectures, its paths are relative to the archive root."""
    local.index(
        f"{path}Packages",
        binary(Filename=f"{path}foo_1.0_amd64.deb"),
        binary(arch="arm64", Filename="foo_1.0_arm64.deb"),
        binary("data", arch="all"),
        variant=".gz",
    )
    local.index(f"{path}Sources", source(Directory="."), variant="")
    repo = local.repository(suites=[suite], components=[])
    assert repo.flat
    (amd64,) = repo.find_binaries("foo", "1.0", "amd64")
    (arm64,) = repo.find_binaries("foo", "1.0", "arm64")
    assert len(list(repo.find_binaries("data", "1.0", "all"))) == 1
    assert repo.url_for(amd64.file.path) == f"{local.url}/{path}foo_1.0_amd64.deb"
    # not relative to the directory of the index
    assert repo.url_for(arm64.file.path) == f"{local.url}/foo_1.0_arm64.deb"
    (src,) = repo.find_sources("foo", "1.0")
    assert src.dsc.path == "foo_1.0.dsc"


@pytest.mark.parametrize(
    "filename, expected",
    [
        ("./pool/main/f/foo/foo_1.0_amd64.deb", "pool/main/f/foo/foo_1.0_amd64.deb"),
        ("pool/./main//f/foo/foo_1.0_amd64.deb", "pool/main/f/foo/foo_1.0_amd64.deb"),
        ("pool/main/x/../f/foo/foo_1.0_amd64.deb", "pool/main/f/foo/foo_1.0_amd64.deb"),
    ],
)
def test_path_normalization(local, filename, expected):
    local.packages(binary(Filename=filename))
    local.sources(source(Directory="pool/./main/x/../f/foo/"))
    repo = local.repository()
    (record,) = repo.find_binaries("foo", "1.0", "amd64")
    assert record.file.path == expected
    assert repo.url_for(record.file.path) == f"{local.url}/{expected}"
    (src,) = repo.find_sources("foo", "1.0")
    assert src.dsc.path == "pool/main/f/foo/foo_1.0.dsc"


@pytest.mark.parametrize(
    "filename",
    [
        "../foo_1.0_amd64.deb",
        "pool/../../foo_1.0_amd64.deb",
        "/srv/foo_1.0_amd64.deb",
        "https://evil.example/foo_1.0_amd64.deb",
        "pool/%2e%2e/foo_1.0_amd64.deb",
        "pool\\foo_1.0_amd64.deb",
        "pool/foo\x01_1.0_amd64.deb",
        "pool/$(ARCH)/foo_1.0_amd64.deb",
        "pool/.hidden/foo_1.0_amd64.deb",
        ".",
    ],
)
def test_unsafe_paths(local, filename):
    local.packages(binary(Filename=filename))
    local.sources(source(Directory=filename))
    repo = local.repository()
    with pytest.raises(RepositoryMetadataError, match="unsafe path"):
        list(repo.find_binaries("foo", "1.0", "amd64"))
    if filename != ".":
        with pytest.raises(RepositoryMetadataError, match="unsafe path"):
            list(repo.find_sources("foo", "1.0"))


@pytest.mark.parametrize(
    "fields, match",
    [
        (dict(Filename=None), "no Filename or Size"),
        (dict(Size=None), "no Filename or Size"),
        (dict(Size="12a"), "invalid size"),
        (dict(Size="-1"), "invalid size"),
        (dict(SHA256="00" * 31), "invalid sha256 checksum"),
        (dict(MD5sum="zz" * 16), "invalid md5 checksum"),
        (dict(MD5sum=None, SHA256=None, SHA384="00" * 48), "no supported checksum"),
    ],
)
def test_invalid_binary_record(local, fields, match):
    local.packages(binary(**fields))
    with pytest.raises(RepositoryMetadataError, match=match):
        list(local.repository().find_binaries("foo", "1.0", "amd64"))


def test_records_are_validated_when_used(local):
    local.packages(binary(), binary("bar", Filename="../bar.deb", Size="x"))
    local.sources(source(), source("bar", Directory="../.."))
    repo = local.repository()
    assert len(list(repo.find_binaries("foo", "1.0", "amd64"))) == 1
    assert len(list(repo.find_sources("foo", "1.0"))) == 1
    with pytest.raises(RepositoryMetadataError):
        list(repo.find_binaries("bar", "1.0", "amd64"))


def test_checksums_are_normalized(local):
    sha256 = calculate_checksums(DEB)[ChecksumAlgo.SHA256SUM]
    local.packages(binary(SHA256=sha256.upper()))
    (record,) = local.repository().find_binaries("foo", "1.0", "amd64")
    assert record.file.checksums[ChecksumAlgo.SHA256SUM] == sha256


@pytest.mark.parametrize(
    "lists",
    [
        ("Files", "Checksums-Sha256"),
        ("Checksums-Sha256",),
        ("Files",),
        ("Checksums-Sha1", "Checksums-Sha512"),
        tuple(LISTS),
    ],
)
def test_source_checksum_lists(local, lists):
    files = {
        "foo_1.0.dsc": b"dsc\n",
        "foo_1.0.orig.tar.gz": b"orig\n",
        "foo_1.0-1.debian.tar.xz": b"debian\n",
    }
    local.sources(source(files=files, lists=lists))
    (src,) = local.repository().find_sources("foo", "1.0")
    assert {f.name: f.size for f in src.files} == {n: len(d) for n, d in files.items()}
    for f in src.files:
        algos = [LISTS[field] for field in lists]
        assert f.checksums == calculate_checksums(files[f.name], algos)


def entry(algo: ChecksumAlgo, data: bytes, name: str, size=None) -> str:
    return (
        f"\n {calculate_checksums(data, [algo])[algo]} {len(data) if size is None else size} {name}"
    )


MD5, SHA256 = ChecksumAlgo.MD5SUM, ChecksumAlgo.SHA256SUM


@pytest.mark.parametrize(
    "fields, match",
    [
        (dict(Directory=None), "no Directory"),
        (dict(Files=entry(MD5, b"x", "foo.dsc") * 2), "lists 'foo.dsc' twice"),
        (
            {"Checksums-Sha256": entry(SHA256, b"dsc\n", "foo_1.0.dsc", size=5)},
            "conflicting sizes",
        ),
        (
            {"Checksums-Sha256": entry(SHA256, b"x", "extra.tar.xz")},
            "not listed in Files",
        ),
        (dict(Files=entry(MD5, b"x", "foo.tar.xz"), lists=()), "exactly one .dsc"),
        (
            dict(Files=entry(MD5, b"x", "a.dsc") + entry(MD5, b"x", "b.dsc"), lists=()),
            "exactly one",
        ),
        (dict(Files=entry(MD5, b"x", "../foo.dsc"), lists=()), "unsafe file name"),
        *[
            (
                {field: entry(algo, b"x", "foo.dsc") + suffix, "lists": ()},
                "unsafe file name",
            )
            for field, algo in LISTS.items()
            for suffix in (" extra", "\textra")
        ],
        (dict(Files="\n 0123", lists=()), "invalid Files entry"),
        (dict(Files="d41d8cd98f00b204e9800998ecf8427e 0 foo.dsc", lists=()), "invalid Files of"),
        (dict(Files=entry(MD5, b"x", "foo.dsc", size="1x"), lists=()), "invalid size"),
        (dict(lists=()), "no files listed"),
    ],
)
def test_invalid_source_record(local, fields, match):
    fields = dict(fields)
    lists = fields.pop("lists", ("Files", "Checksums-Sha256"))
    local.sources(source(lists=lists, **fields))
    with pytest.raises(RepositoryMetadataError, match=match):
        list(local.repository().find_sources("foo", "1.0"))


@pytest.mark.parametrize(
    "release, hints, listed_in, found",
    [
        # binary-all is used if it is announced
        ("Architectures: all amd64", (), "all", True),
        ("Architectures: all amd64", (), "amd64", True),
        # ... but not if the native indexes list the packages
        ("Architectures: amd64 arm64", (), "all", False),
        ("Architectures: amd64 arm64", (), "arm64", True),
        ("Architectures: all amd64\nNo-Support-for-Architecture-all: Packages", (), "all", False),
        ("Architectures: all amd64\nNo-Support-for-Architecture-all: Packages", (), "amd64", True),
        # configured architectures replace the ones of the Release file
        ("Architectures: amd64", ("arm64",), "amd64", False),
        ("Architectures: amd64", ("arm64",), "arm64", True),
        (None, ("arm64",), "all", True),
        (None, ("arm64",), "arm64", True),
        # with 'all', exactly the configured indexes are searched
        ("Architectures: amd64", ("all",), "all", True),
        (None, ("all",), "amd64", False),
        (None, ("all", "amd64"), "amd64", True),
    ],
)
def test_architecture_all_routing(local, release, hints, listed_in, found):
    if release is not None:
        local.write("dists/trixie/Release", f"Suite: trixie\n{release}\n".encode())
    local.packages(binary("data", arch="all"), arch=listed_in)
    repo = local.repository(architectures=hints)
    assert bool(list(repo.find_binaries("data", "1.0", "all"))) == found


def test_architecture_all_from_inrelease(local):
    local.write(
        "dists/trixie/InRelease",
        b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nArchitectures: all amd64\n"
        b"-----BEGIN PGP SIGNATURE-----\n\nnot verified\n-----END PGP SIGNATURE-----\n",
    )
    local.packages(binary("data", arch="all"), arch="all")
    assert len(list(local.repository().find_binaries("data", "1.0", "all"))) == 1


@pytest.mark.parametrize(
    "release",
    [None, "Suite: trixie", "Architectures: all\nNo-Support-for-Architecture-all: Packages"],
)
def test_architecture_all_unknown(local, release):
    if release is not None:
        local.write("dists/trixie/Release", release.encode())
    repo = local.repository()
    with pytest.raises(RepositoryConfigurationError, match="Architecture: all"):
        list(repo.find_binaries("data", "1.0", "all"))
    # native packages do not need the Release file
    assert not list(repo.find_binaries("data", "1.0", "amd64"))


def test_release_errors(local, http, monkeypatch):
    http.add("dists/trixie/Release", status=500)
    with pytest.raises(RepositoryAccessError, match="500"):
        list(http_repository(http, architectures=["amd64"]).find_binaries("data", "1.0", "all"))

    local.write("dists/trixie/Release", b"Architectures: amd64 AMD64\n")
    with pytest.raises(RepositoryMetadataError, match="invalid Architectures"):
        list(local.repository().find_binaries("data", "1.0", "all"))

    monkeypatch.setattr(remote, "MAX_RELEASE_SIZE", 10)
    local.write("dists/trixie/Release", b"Architectures: all amd64\n")
    with pytest.raises(RepositoryMetadataError, match="exceeds the size limit"):
        list(local.repository().find_binaries("data", "1.0", "all"))


@pytest.mark.parametrize("arch", ["", "AMD64", "amd64 ", "../all"])
def test_invalid_package_architecture(local, arch):
    with pytest.raises(RepositoryError, match="invalid architecture"):
        list(local.repository().find_binaries("foo", "1.0", arch))
    assert not local.requested


def test_fetch(local, monkeypatch):
    local.write("pool/main/f/foo/foo_1.0.dsc", b"dsc\n")
    repo = local.repository()
    assert repo.fetch("pool/main/f/foo/foo_1.0.dsc", 4) == b"dsc\n"
    with pytest.raises(RepositoryMetadataError, match="exceeds the size limit"):
        repo.fetch("pool/main/f/foo/foo_1.0.dsc", 3)
    with pytest.raises(RepositoryAccessError, match="not available"):
        repo.fetch("pool/main/f/foo/foo_1.1.dsc", 4)


def test_no_apt_needed(local, monkeypatch):
    """Neither python-apt nor APT tools are needed to read a repository."""
    monkeypatch.setitem(sys.modules, "apt_pkg", None)
    # pretend python-apt is available, but fail if it is used
    monkeypatch.setattr(deb822, "_have_apt_pkg", True)
    monkeypatch.setattr(deb822, "apt_pkg", mock.Mock(side_effect=AssertionError), raising=False)
    monkeypatch.setattr(subprocess, "Popen", mock.Mock(side_effect=AssertionError))
    local.packages(binary())
    local.sources(source())
    repo = local.repository()
    assert len(list(repo.find_binaries("foo", "1.0", "amd64"))) == 1
    assert len(list(repo.find_sources("foo", "1.0"))) == 1
