# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import io
import json
from pathlib import Path
import jsonschema

import pytest
from debsbom.download.adapters import LocalFileAdapter
from debsbom.download import (
    PackageDownloader,
    PersistentResolverCache,
)
from debsbom.download.download import DownloadResult, DownloadStatus
from debsbom.download.resolver import NotFoundError, RemoteFile
from debsbom.resolver import PackageResolver, PackageStreamResolver
from debsbom import schema
from debsbom.dpkg.package import (
    BinaryPackage,
    SourcePackage,
    ChecksumAlgo,
    filter_binaries,
    filter_sources,
)
from debsbom.repack.packer import Packer, StandardBomTransformer
from debsbom.snapshot.client import SnapshotRemoteFile, UpstreamResolver
from debsbom.util.checksum import calculate_checksums
import debsbom.snapshot.client as sdlclient

import requests
from requests import Session

from unittest import mock


@pytest.fixture()
def spdx_bomfile(tmpdir):
    """
    Return the path to a minimal spdx sbom file
    """
    _spdx_tools = pytest.importorskip("spdx_tools")

    from debsbom.generate.spdx import spdx_bom

    import spdx_tools.spdx.writer.json.json_writer as spdx_json_writer

    pkgs = BinaryPackage.inject_src_packages(
        BinaryPackage.parse_status_file(Path("tests/data/dpkg-status-minimal"))
    )
    bom = spdx_bom(set(pkgs), "debian", "amd64")
    outfile = Path(tmpdir) / "bom.spdx.json"
    spdx_json_writer.write_document_to_file(bom, outfile, False)
    return outfile


@pytest.fixture()
def cdx_bomfile(tmpdir):
    """
    Return the path to a cdx minimal sbom file
    """
    _cyclonedx = pytest.importorskip("cyclonedx")

    from debsbom.generate.cdx import cyclonedx_bom

    import cyclonedx.output as cdx_output
    import cyclonedx.schema as cdx_schema

    pkgs = BinaryPackage.inject_src_packages(
        BinaryPackage.parse_status_file(Path("tests/data/dpkg-status-minimal"))
    )
    bom = cyclonedx_bom(set(pkgs), "debian", "amd64")
    outfile = Path(tmpdir) / "bom.cdx.json"
    cdx_output.make_outputter(
        bom, cdx_schema.OutputFormat.JSON, cdx_schema.SchemaVersion.V1_6
    ).output_to_file(outfile)
    return outfile


@pytest.mark.online
def test_download(tmpdir, http_session):
    dl = PackageDownloader(Path(tmpdir), session=http_session)
    test_file = SnapshotRemoteFile(
        checksums={ChecksumAlgo.SHA1SUM: "1f3a43c181b81e3578d609dc0931ff147623eb38"},
        filename="pytest_8.4.2-1.dsc",
        size=2757,
        archive_name="debian",
        path="/pool/main/p/pytest",
        first_seen=1757270199,
        downloadurl="https://snapshot.debian.org/file/1f3a43c181b81e3578d609dc0931ff147623eb38/pytest_8.4.2-1.dsc",
        architecture=None,
    )
    pkg = BinaryPackage("foo", "1.0")
    dl.register([test_file], pkg)
    assert dl.stat() == (1, 2757, 0, 0)
    mock_cb = mock.Mock()
    downloaded = list(dl.download(mock_cb))
    mock_cb.assert_called_once_with(0, 1, test_file.filename)

    assert len(downloaded) == 1
    assert downloaded[0].path.is_file()
    assert downloaded[0].path.is_relative_to(Path(tmpdir))
    stat_orig = downloaded[0].path.stat()
    assert downloaded[0].status == DownloadStatus.OK

    # now download again (which should not actually download)
    dl.register([test_file], pkg)
    downloaded = list(dl.download(None))
    assert int(downloaded[0].path.stat().st_mtime_ns) == int(stat_orig.st_mtime_ns)
    assert downloaded[0].status == DownloadStatus.OK

    # tamper the checksum of the downloaded file. Must result in re-download
    with open(downloaded[0].path, "w+") as f:
        f.write("append")
    dl.register([test_file], pkg)
    downloaded = list(dl.download(None))
    assert int(downloaded[0].path.stat().st_mtime_ns) != int(stat_orig.st_mtime_ns)
    assert downloaded[0].status == DownloadStatus.OK


def test_package_resolver_parse_spdx(spdx_bomfile):
    rs = PackageResolver.create(spdx_bomfile)
    pkgs = list(rs)
    assert any(filter(lambda p: p.name == "binutils", filter_sources(pkgs)))
    assert any(filter(lambda p: p.architecture == "amd64", filter_binaries(pkgs)))


def test_package_resolver_parse_cdx(cdx_bomfile):
    rs = PackageResolver.create(cdx_bomfile)
    assert any(filter(lambda p: p.architecture == "amd64", rs))


def test_package_resolver_parse_stream():
    data = [
        "binutils 2.40-2 amd64",
        "guestfs-tools 1.52.3-1 source",
    ]
    stream = io.BytesIO("\n".join(data).encode())
    rs = PackageStreamResolver(stream)
    pkgs = list(rs)
    assert any(filter(lambda p: p.name == "guestfs-tools", filter_sources(pkgs)))
    assert any(filter(lambda p: p.name == "binutils", filter_binaries(pkgs)))


@pytest.mark.online
def test_package_resolver_resolve_spdx(spdx_bomfile, tmpdir, sdl):
    cachedir = Path(tmpdir) / ".cache"
    prs = PackageResolver.create(spdx_bomfile)
    rs_cache = PersistentResolverCache(cachedir)
    urs = UpstreamResolver(sdl, rs_cache)

    files = list(urs.resolve(next(filter(lambda p: p.name == "binutils", prs))))
    assert "binutils" in files[0].filename

    # resolve with cache
    prs = PackageResolver.create(spdx_bomfile)
    files = list(urs.resolve(next(filter(lambda p: p.name == "binutils", prs))))
    assert "binutils" in files[0].filename


def test_resolver_cache_negative(tmpdir):
    """
    404s (and only those) are cached as negative result
    """
    pkg = BinaryPackage(name="does-not-exist", architecture="amd64", version="1.0")

    class _Resolver(sdlclient.Resolver):
        def resolve(self, p):
            self.calls += 1
            raise self.exc

    urs = _Resolver(PersistentResolverCache(Path(tmpdir) / ".cache"))
    urs.calls = 0

    # transient errors are not cached
    urs.exc = sdlclient.SnapshotResolveError("boom")
    for _ in range(2):
        with pytest.raises(sdlclient.SnapshotResolveError):
            urs._resolve_pkg(pkg)
    assert urs.calls == 2

    # 404s are cached
    urs.exc = sdlclient.SnapshotNotFoundError("gone")
    with pytest.raises(sdlclient.SnapshotNotFoundError):
        urs._resolve_pkg(pkg)
    with pytest.raises(NotFoundError):
        urs._resolve_pkg(pkg)
    assert urs.calls == 3


@pytest.mark.online
def test_file_checksum(sdl, tmpdir, http_session):
    bpkg = BinaryPackage(
        name="binutils-arm-none-eabi", architecture="amd64", version="2.40-2+18+b1"
    )
    bpkg.checksums[ChecksumAlgo.SHA256SUM] = (
        "c8f9da2a434366bfe5a66a8267cb3b1df028f1d95278715050c222b43e1c221c"
    )
    s_bpkg = sdlclient.BinaryPackage(sdl, bpkg.name, str(bpkg.version), None, None)
    files = list(s_bpkg.files(arch=bpkg.architecture))

    dl = PackageDownloader(Path(tmpdir), session=http_session)

    # test matching checksum case
    dl.register(files, bpkg)
    stats = dl.stat()
    assert stats.files == 1
    local_files = list(dl.download())
    assert local_files[0].status == DownloadStatus.OK

    # test invalid checksum
    local_files[0].path.unlink()
    # tamper checksum (sha256sum of '42')
    bpkg.checksums[ChecksumAlgo.SHA256SUM] = (
        "084c799cd551dd1d8d5c5f9a5d593b2e931f5e36122ee5c793c1d08a19839cc0"
    )
    dl.register(files, bpkg)
    stats = dl.stat()
    assert stats.files == 1
    local_files = list(dl.download())
    # no file was successfully downloaded
    assert local_files[0].status == DownloadStatus.CHECKSUM_MISMATCH


@pytest.mark.online
def test_repack(tmpdir, spdx_bomfile, cdx_bomfile, http_session, sdl):
    tmpdir = Path(tmpdir)

    dl_dir = tmpdir / "downloads"
    out_dir = tmpdir / "outdir"
    dl_dir.mkdir()
    out_dir.mkdir()

    packer = Packer.from_format(
        fmt="standard-bom-package",
        dldir=dl_dir,
        outdir=out_dir,
    )

    found_spdx = False
    found_cdx = False
    urs = UpstreamResolver(sdl)
    for bom in [spdx_bomfile, cdx_bomfile]:
        resolver = PackageResolver.create(bom)
        pkgs = list(resolver)

        # download a single package
        dl = PackageDownloader(dl_dir, session=http_session)
        for p in filter(lambda p: p.name == "binutils", filter_sources(pkgs)):
            dl.register(urs.resolve(p), p)
        files = list(dl.download())
        assert len(files) == 3

        # merge the source package
        bt = StandardBomTransformer.create(
            "standard-bom-package", resolver.sbom_type(), resolver.document
        )
        repacked = list(filter(lambda p: p, map(lambda p: packer.repack(p, symlink=True), pkgs)))
        assert len(repacked) == 1
        assert ".merged.tar" in repacked[0].filename
        bom_out = packer.rewrite_sbom(bt, repacked)

        # check if the sbom is updated
        if "spdx" in bom.name:
            found_spdx = True
            found_updated_locator = False
            for p in bom_out.packages:
                if p.external_references:
                    if any([ref.locator.startswith("file:///") for ref in p.external_references]):
                        found_updated_locator = True
                        break
            assert found_updated_locator
        if "cdx" in bom.name:
            found_cdx = True
            for c in bom_out.components:
                if c.external_references:
                    if any([str(ref.url).startswith("file:///") for ref in c.external_references]):
                        found_updated_locator = True
                        break
            assert found_updated_locator

    assert found_spdx
    assert found_cdx


@pytest.mark.online
def test_srcpkg_with_checksum(sdl):
    rs = UpstreamResolver(sdl)
    # package with multiple src packages with equal version number
    sratom = SourcePackage("sratom", "0.6.14-1")

    # resolve without further information
    files = list(rs.resolve(sratom))
    for e in [".dsc", ".debian.tar.xz", ".orig.tar.xz", "orig.tar.xz.asc"]:
        assert len(list(filter(lambda f: f.filename.endswith(e), files))) == 3
    assert files[0].archive_name == "debian"

    # resolve with checksum of debian-ports hurd-amd64 variant
    sratom.checksums[ChecksumAlgo.SHA256SUM] = (
        "4619ccf1ad73f96d08b7709ea768523f16c60ecac68eb269614c1950ba776508"
    )
    files = list(rs.resolve(sratom))
    assert len(files) == 4
    assert files[0].archive_name == "debian-ports"


@pytest.mark.parametrize(
    "dlresult",
    [
        DownloadResult(
            Path("/tmp/foo.tar"),
            DownloadStatus.OK,
            SourcePackage("foo", "1.0"),
            "foo.tar",
            "file:///foo.tar",
        ),
        DownloadResult(
            None,
            DownloadStatus.NOT_FOUND,
            SourcePackage("foo", "1.0"),
            "bar.tar",
            "file:///foo.tar",
        ),
        DownloadResult(
            None,
            DownloadStatus.CHECKSUM_MISMATCH,
            BinaryPackage("bar", "1.0"),
            "bar.tar",
            "file:///foo.tar",
        ),
    ],
)
def test_download_result_format(dlresult):
    data = json.loads(dlresult.json())
    if data["status"] == DownloadStatus.OK:
        assert data["status"] == "ok"

    jsonschema.validate(data, schema=schema.download)


def test_download_result_invalid():
    data = {
        "status": "unknown",
        "package": {"name": "foo", "version": "1.0"},
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, schema=schema.download)


def test_local_file():
    session = Session()
    session.mount("file:///", LocalFileAdapter())
    with session.get("file://" + str(Path("tests/data/local-download").absolute())) as r:
        assert r.status_code == 200
        assert r.content == b"This is a test file for the local file adapter test.\n"


def test_local_file_404():
    session = Session()
    session.mount("file:///", LocalFileAdapter())
    with session.get("file:///does-not-exist") as r:
        assert r.status_code == 404


@pytest.mark.online
def test_malicious_path_download(tmpdir, http_session):
    dl = PackageDownloader(Path(tmpdir), session=http_session)
    test_file = SnapshotRemoteFile(
        checksums={ChecksumAlgo.SHA1SUM: "1f3a43c181b81e3578d609dc0931ff147623eb38"},
        # this filename would lead to a path traversal attack
        filename="../../../pytest_8.4.2-1.dsc",
        size=1234,
        archive_name="debian",
        path="/pool/main/p/pytest",
        first_seen=1757270199,
        downloadurl="https://snapshot.debian.org/file/1f3a43c181b81e3578d609dc0931ff147623eb38/pytest_8.4.2-1.dsc",
        architecture=None,
    )
    pkg = BinaryPackage("foo", "1.0")
    dl.register([test_file], pkg)
    with pytest.raises(ValueError):
        dl.stat()

    test_file2 = SnapshotRemoteFile(
        checksums={ChecksumAlgo.SHA1SUM: "1f3a43c181b81e3578d609dc0931ff147623eb38"},
        filename="pytest_8.4.2-1.dsc",
        size=1234,
        # this filename would lead to a path traversal attack
        archive_name="../debian",
        path="/pool/main/p/pytest",
        first_seen=1757270199,
        downloadurl="https://snapshot.debian.org/file/1f3a43c181b81e3578d609dc0931ff147623eb38/pytest_8.4.2-1.dsc",
        architecture=None,
    )
    dl.register([test_file2], pkg)
    with pytest.raises(ValueError):
        dl.stat()


MD5 = ChecksumAlgo.MD5SUM
SHA1 = ChecksumAlgo.SHA1SUM
SHA256 = ChecksumAlgo.SHA256SUM
WRONG_SHA256 = "084c799cd551dd1d8d5c5f9a5d593b2e931f5e36122ee5c793c1d08a19839cc0"


def _upstream_file(tmp_path, name, data=None) -> Path:
    path = tmp_path / "upstream" / name
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(data if data is not None else f"content of {name}\n".encode())
    return path


def _remote(path: Path, checksums=None, size=-1, filename=None, url=None) -> RemoteFile:
    """RemoteFile for a local file, with correct expectations unless overridden."""
    data = path.read_bytes()
    return RemoteFile(
        checksums=calculate_checksums(data, [SHA256]) if checksums is None else checksums,
        filename=filename or path.name,
        archive_name="debian",
        downloadurl=url or path.as_uri(),
        size=len(data) if size == -1 else size,
    )


def _tmp_files(dl: PackageDownloader) -> list[Path]:
    return list(dl.outdir.rglob("*.tmp"))


@pytest.mark.parametrize(
    "expect,status",
    [
        ({}, DownloadStatus.OK),
        ({"size": None}, DownloadStatus.OK),
        ({"checksums": {SHA256: WRONG_SHA256}}, DownloadStatus.CHECKSUM_MISMATCH),
        ({"size": 1}, DownloadStatus.CHECKSUM_MISMATCH),
        ({"size": 1000}, DownloadStatus.CHECKSUM_MISMATCH),
        # a mismatch of the strongest digest is final
        ({"checksums": "md5-ok-sha256-bad"}, DownloadStatus.CHECKSUM_MISMATCH),
    ],
)
def test_download_verifies_remote_file(tmp_path, fake_http, expect, status):
    rs, _ = fake_http
    path = _upstream_file(tmp_path, "foo_1.0_amd64.deb")
    if expect.get("checksums") == "md5-ok-sha256-bad":
        expect["checksums"] = calculate_checksums(path, [MD5]) | {SHA256: WRONG_SHA256}
    dl = PackageDownloader(tmp_path / "dl", session=rs)
    dl.register([_remote(path, **expect)], BinaryPackage("foo", "1.0", architecture="amd64"))
    (result,) = dl.download()

    assert result.status == status
    target = dl.binaries_dir / "debian" / path.name
    if status == DownloadStatus.OK:
        assert result.path == target.resolve()
        assert target.read_bytes() == path.read_bytes()
    else:
        assert result.path is None
        assert not target.exists()
    assert not _tmp_files(dl)


@pytest.mark.parametrize(
    "pkg_checksums,status",
    [
        ("sha256-ok", DownloadStatus.OK),
        ({SHA256: WRONG_SHA256}, DownloadStatus.CHECKSUM_MISMATCH),
        # a mismatch of the strongest digest is final
        ("sha1-ok-sha256-bad", DownloadStatus.CHECKSUM_MISMATCH),
    ],
)
def test_download_verifies_binary_package(tmp_path, fake_http, pkg_checksums, status):
    rs, _ = fake_http
    path = _upstream_file(tmp_path, "foo_1.0_amd64.deb")
    if pkg_checksums == "sha256-ok":
        pkg_checksums = calculate_checksums(path, [SHA256])
    elif pkg_checksums == "sha1-ok-sha256-bad":
        pkg_checksums = calculate_checksums(path, [SHA1]) | {SHA256: WRONG_SHA256}
    pkg = BinaryPackage("foo", "1.0", architecture="amd64", checksums=pkg_checksums)
    dl = PackageDownloader(tmp_path / "dl", session=rs)
    # the remote file expectations are correct, the package ones are verified independently
    dl.register([_remote(path)], pkg)
    (result,) = dl.download()
    assert result.status == status
    assert (dl.binaries_dir / "debian" / path.name).exists() == (status == DownloadStatus.OK)
    assert not _tmp_files(dl)


def test_download_source_package_checksums(tmp_path, fake_http):
    """
    The checksums of a source package refer to the .dsc file only. The other
    source files are verified against the remote file expectations.
    """
    rs, _ = fake_http
    dsc = _upstream_file(tmp_path, "foo_1.0-1.dsc")
    orig = _upstream_file(tmp_path, "foo_1.0.orig.tar.xz")
    debian = _upstream_file(tmp_path, "foo_1.0-1.debian.tar.xz")
    pkg = SourcePackage("foo", "1.0-1", checksums=calculate_checksums(dsc, [SHA256]))
    dl = PackageDownloader(tmp_path / "dl", session=rs)
    dl.register(
        [_remote(dsc), _remote(orig), _remote(debian, checksums={SHA256: WRONG_SHA256})], pkg
    )
    results = {r.filename: r.status for r in dl.download()}
    assert results == {
        dsc.name: DownloadStatus.OK,
        orig.name: DownloadStatus.OK,
        debian.name: DownloadStatus.CHECKSUM_MISMATCH,
    }

    # a .dsc not matching the source package is rejected
    other = SourcePackage("foo", "1.0-1", checksums={SHA256: WRONG_SHA256})
    dl.register([_remote(dsc)], other)
    assert [r.status for r in dl.download()] == [DownloadStatus.CHECKSUM_MISMATCH]
    # but the valid file of the first package is kept
    assert (dl.sources_dir / "debian" / dsc.name).is_file()


def test_download_existing_files(tmp_path, fake_http):
    rs, adapter = fake_http
    path = _upstream_file(tmp_path, "foo_1.0_amd64.deb")
    url = "https://mirror.example/pool/main/f/foo/foo_1.0_amd64.deb"
    adapter.add(url, path.read_bytes())
    pkg = BinaryPackage("foo", "1.0", architecture="amd64")
    dl = PackageDownloader(tmp_path / "dl", session=rs)
    target = dl.binaries_dir / "debian" / path.name
    target.parent.mkdir()

    # valid existing file is not downloaded again
    target.write_bytes(path.read_bytes())
    dl.register([_remote(path, url=url)], pkg)
    assert [r.status for r in dl.download()] == [DownloadStatus.OK]
    assert adapter.requests == []

    # corrupted existing file (same size) is downloaded again
    target.write_bytes(path.read_bytes().upper())
    dl.register([_remote(path, url=url)], pkg)
    assert [r.status for r in dl.download()] == [DownloadStatus.OK]
    assert target.read_bytes() == path.read_bytes()
    assert adapter.urls == [url]

    # a valid file is not deleted if it does not match another package
    other = BinaryPackage("foo", "1.0", architecture="amd64", checksums={SHA256: WRONG_SHA256})
    dl.register([_remote(path, url=url)], other)
    assert [r.status for r in dl.download()] == [DownloadStatus.CHECKSUM_MISMATCH]
    assert target.read_bytes() == path.read_bytes()
    assert len(adapter.requests) == 1

    # without checksums (e.g. from a plugin), existing files are downloaded again
    dl.register([_remote(path, url=url, checksums={}, size=None)], pkg)
    assert [r.status for r in dl.download()] == [DownloadStatus.OK]
    assert len(adapter.requests) == 2

    # existing file of another size (e.g. truncated) is downloaded again
    target.write_bytes(path.read_bytes()[:-1])
    dl.register([_remote(path, url=url)], pkg)
    assert [r.status for r in dl.download()] == [DownloadStatus.OK]
    assert target.read_bytes() == path.read_bytes()
    assert len(adapter.requests) == 3


def test_download_deduplication(tmp_path, fake_http):
    rs, _ = fake_http
    data = b"same content\n"
    first = _upstream_file(tmp_path, "foo_1.0_amd64.deb", data)
    second = _upstream_file(tmp_path, "foo_1.0_arm64.deb", data)
    pkg = BinaryPackage("foo", "1.0", architecture="amd64")
    pkg_bad = BinaryPackage("foo", "1.0", architecture="arm64", checksums={SHA256: WRONG_SHA256})
    dl = PackageDownloader(tmp_path / "dl", session=rs)
    dl.register([_remote(first)], pkg)
    dl.register([_remote(second)], pkg_bad)
    dl.register([_remote(second)], pkg)
    results = list(dl.download())
    assert [r.status for r in results] == [
        DownloadStatus.OK,
        DownloadStatus.CHECKSUM_MISMATCH,
        DownloadStatus.OK,
    ]
    linked = dl.binaries_dir / "debian" / second.name
    assert linked.is_symlink() and linked.read_bytes() == data

    # the size of a file with the same checksums is verified as well
    conflicting = _upstream_file(tmp_path, "foo_1.0_i386.deb", data)
    dl.register([_remote(first)], pkg)
    dl.register([_remote(conflicting, size=len(data) + 1)], pkg)
    assert [r.status for r in dl.download()] == [
        DownloadStatus.OK,
        DownloadStatus.CHECKSUM_MISMATCH,
    ]
    assert not (dl.binaries_dir / "debian" / conflicting.name).exists()

    # files without checksums cannot be identified and are not deduplicated
    third = _upstream_file(tmp_path, "bar_1.0_amd64.deb", b"bar\n")
    fourth = _upstream_file(tmp_path, "baz_1.0_amd64.deb", b"baz\n")
    for f in [third, fourth]:
        dl.register([_remote(f, checksums={}, size=None)], BinaryPackage(f.name, "1.0"))
    assert [r.status for r in dl.download()] == [DownloadStatus.OK] * 2
    for f in [third, fourth]:
        stored = dl.binaries_dir / "debian" / f.name
        assert not stored.is_symlink() and stored.read_bytes() == f.read_bytes()


class _FailingStream(io.RawIOBase):
    """Stream that fails after returning some data."""

    def __init__(self):
        self.calls = 0

    def readable(self):
        return True

    def read(self, size=-1):
        self.calls += 1
        if self.calls > 1:
            raise ConnectionResetError("connection reset")
        return b"partial"


@pytest.mark.parametrize(
    "body,status,exc",
    [
        (b"not found", 404, requests.HTTPError),
        (_FailingStream, 200, ConnectionResetError),
        (requests.ConnectionError("unreachable"), 200, requests.ConnectionError),
    ],
)
def test_download_transport_failure(tmp_path, fake_http, body, status, exc):
    rs, adapter = fake_http
    path = _upstream_file(tmp_path, "foo_1.0_amd64.deb")
    url = "https://mirror.example/foo_1.0_amd64.deb"
    adapter.add(url, body() if body is _FailingStream else body, status=status)
    dl = PackageDownloader(tmp_path / "dl", session=rs)
    dl.register([_remote(path, url=url)], BinaryPackage("foo", "1.0", architecture="amd64"))
    with pytest.raises(exc):
        list(dl.download())
    assert not (dl.binaries_dir / "debian" / path.name).exists()
    assert not _tmp_files(dl)


def test_download_requests_identity_encoding(tmp_path, fake_http):
    """Artifacts are requested without content-coding, as the stored bytes are verified."""
    rs, adapter = fake_http
    path = _upstream_file(tmp_path, "foo_1.0-1.dsc")
    url = "https://mirror.example/foo_1.0-1.dsc"
    adapter.add(url, path.read_bytes())
    dl = PackageDownloader(tmp_path / "dl", session=rs)
    dl.register([_remote(path, url=url)], SourcePackage("foo", "1.0-1"))
    assert [r.status for r in dl.download()] == [DownloadStatus.OK]
    assert adapter.requests[0].headers["Accept-Encoding"] == "identity"
