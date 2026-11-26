# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import gzip
import io
import json
from pathlib import Path
import subprocess
import sys
import textwrap
import jsonschema
import urllib3

import pytest
from debsbom.cli import setup_parser
from debsbom.commands import download
from debsbom.commands.download import DownloadCmd
from debsbom.download.adapters import LocalFileAdapter
from debsbom.download import (
    PackageDownloader,
    PersistentResolverCache,
)
from debsbom.download.download import (
    DownloadResult,
    DownloadStatus,
    UnsafeRedirectError,
)
from debsbom.download.resolver import (
    FallbackResolver,
    NotFoundError,
    PackageResolverCache,
    RemoteFile,
    ResolveError,
    Resolver,
)
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
from requests.adapters import BaseAdapter
from requests.structures import CaseInsensitiveDict
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


def test_download_result_missing_source():
    data = {
        "status": "ok",
        "package": {"name": "foo", "version": "1.0", "purl": "pkg:deb/debian/foo@1.0"},
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, schema=schema.download)


def test_download_not_found_json(tmp_path, monkeypatch, capsys):
    def resolve(pkg):
        raise NotFoundError(f"{pkg} not found")

    resolver = sdlclient.UpstreamResolver(mock.MagicMock())
    monkeypatch.setattr(resolver, "resolve", resolve)
    monkeypatch.setitem(download.RESOLVERS, "debian-snapshot", lambda session: resolver)
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(b"no-such-package 1.0-1 amd64\n")))
    args = setup_parser().parse_args(["--json", "download", "--outdir", str(tmp_path)])
    DownloadCmd.run(args)

    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])
    jsonschema.validate(data, schema=schema.download)
    assert data["status"] == DownloadStatus.NOT_FOUND
    assert data["package"]["name"] == "no-such-package"


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


def test_cli_without_download_dependencies():
    """
    The CLI, and by that the offline generate command, must work without the optional
    download dependencies. Before Python 3.14, annotations are evaluated eagerly, so
    they must not refer to the guarded imports at class definition time.
    """
    code = textwrap.dedent("""
        import sys

        # simulate that the optional download dependencies are not installed
        for mod in ("requests", "zstandard"):
            sys.modules[mod] = None

        from debsbom import cli

        assert not cli.HAS_DOWNLOAD_DEPS
        args = cli.setup_parser().parse_args(["generate", "--root", "does-not-exist"])
        assert args.cmd == "generate"
        """)
    subprocess.run([sys.executable, "-c", code], check=True)


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
DATA = b"package content\n"
DIGESTS = calculate_checksums(DATA, [MD5, SHA1, SHA256])
BAD_SHA256 = "0" * 64
OK = DownloadStatus.OK
MISMATCH = DownloadStatus.CHECKSUM_MISMATCH


@pytest.fixture
def downloader(tmp_path):
    with requests.Session() as rs:
        rs.mount("file:///", LocalFileAdapter())
        yield PackageDownloader(tmp_path / "dl", session=rs)


def _upstream(tmp_path, name, data=DATA) -> Path:
    path = tmp_path / "upstream" / name
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(data)
    return path


def _remote(path: Path, **expect) -> RemoteFile:
    """RemoteFile for an upstream file, with correct expectations unless overridden."""
    data = path.read_bytes()
    return RemoteFile(
        checksums=expect.get("checksums", calculate_checksums(data, [SHA256])),
        filename=path.name,
        archive_name="debian",
        downloadurl=path.as_uri(),
        size=expect.get("size", len(data)),
    )


def _binary(checksums=None) -> BinaryPackage:
    return BinaryPackage("foo", "1.0", architecture="amd64", checksums=checksums)


def _stored(dl: PackageDownloader) -> set[str]:
    return {p.name for p in dl.outdir.rglob("*") if p.is_file()}


@pytest.mark.parametrize(
    "expect,pkg_checksums,ok",
    [
        pytest.param({}, None, True, id="valid"),
        pytest.param({"size": None}, None, True, id="unknown-size"),
        pytest.param({"size": len(DATA) - 1}, None, False, id="too-large"),
        pytest.param({"size": len(DATA) + 1}, None, False, id="truncated"),
        pytest.param({"checksums": {SHA256: BAD_SHA256}}, None, False, id="remote-mismatch"),
        pytest.param(
            {"checksums": {MD5: DIGESTS[MD5], SHA256: BAD_SHA256}},
            None,
            False,
            id="remote-strongest-mismatch",
        ),
        pytest.param({}, {SHA256: DIGESTS[SHA256]}, True, id="package-match"),
        pytest.param({}, {SHA256: BAD_SHA256}, False, id="package-mismatch"),
        pytest.param(
            {}, {SHA1: DIGESTS[SHA1], SHA256: BAD_SHA256}, False, id="package-strongest-mismatch"
        ),
    ],
)
def test_download_verifies_file(tmp_path, downloader, expect, pkg_checksums, ok):
    path = _upstream(tmp_path, "foo_1.0_amd64.deb")
    downloader.register([_remote(path, **expect)], _binary(pkg_checksums))
    (result,) = downloader.download()

    if ok:
        assert result.status == OK
        assert result.path.read_bytes() == DATA
        assert _stored(downloader) == {path.name}
    else:
        assert result.status == MISMATCH
        assert result.path is None
        assert _stored(downloader) == set()


def test_download_source_package_checksums(tmp_path, downloader):
    """The checksums of a source package only refer to its .dsc file."""
    dsc = _upstream(tmp_path, "foo_1.0-1.dsc", b"dsc\n")
    orig = _upstream(tmp_path, "foo_1.0.orig.tar.xz", b"orig\n")
    debian = _upstream(tmp_path, "foo_1.0-1.debian.tar.xz", b"debian\n")
    pkg = SourcePackage("foo", "1.0-1", checksums=calculate_checksums(dsc, [SHA256]))
    downloader.register(
        [_remote(dsc), _remote(orig), _remote(debian, checksums={SHA256: BAD_SHA256})], pkg
    )
    assert {r.filename: r.status for r in downloader.download()} == {
        dsc.name: OK,
        orig.name: OK,
        debian.name: MISMATCH,
    }


def test_download_existing_file(tmp_path, downloader):
    path = _upstream(tmp_path, "foo_1.0_amd64.deb")
    remote = _remote(path)
    target = downloader.binaries_dir / "debian" / path.name
    target.parent.mkdir()

    # invalid existing files are replaced
    for invalid in [DATA.upper(), DATA[:-1]]:
        target.write_bytes(invalid)
        downloader.register([remote], _binary())
        assert [r.status for r in downloader.download()] == [OK]
        assert target.read_bytes() == DATA

    # a valid file is kept, even if it does not match another package
    downloader.register([remote], _binary({SHA256: BAD_SHA256}))
    assert [r.status for r in downloader.download()] == [MISMATCH]
    assert target.read_bytes() == DATA

    # a valid file is not downloaded again
    path.unlink()
    downloader.register([remote], _binary())
    assert [r.status for r in downloader.download()] == [OK]

    # a file without checksums cannot be verified and is downloaded again
    _upstream(tmp_path, path.name, b"new content\n")
    downloader.register([_remote(path, checksums={}, size=None)], _binary())
    assert [r.status for r in downloader.download()] == [OK]
    assert target.read_bytes() == b"new content\n"


def test_download_deduplication(tmp_path, downloader):
    first = _remote(_upstream(tmp_path, "foo_1.0_amd64.deb"))
    second_path = _upstream(tmp_path, "foo_1.0_arm64.deb")
    second = _remote(second_path)
    # files with the same checksums are only downloaded once
    second_path.unlink()

    downloader.register([first], _binary())
    downloader.register([second], _binary({SHA256: BAD_SHA256}))
    downloader.register([second], _binary())
    downloader.register(
        [_remote(_upstream(tmp_path, "foo_1.0_i386.deb"), size=len(DATA) + 1)], _binary()
    )
    results = list(downloader.download())
    assert [r.status for r in results] == [OK, MISMATCH, OK, MISMATCH]
    assert results[2].path.read_bytes() == DATA

    # files without checksums are not deduplicated
    for name, data in [("bar_1.0_amd64.deb", b"bar\n"), ("baz_1.0_amd64.deb", b"baz\n")]:
        downloader.register([_remote(_upstream(tmp_path, name, data), checksums={})], _binary())
    results = list(downloader.download())
    assert [r.path.read_bytes() for r in results] == [b"bar\n", b"baz\n"]


def test_download_failure_leaves_no_files(tmp_path, downloader):
    path = _upstream(tmp_path, "foo_1.0_amd64.deb")
    remote = _remote(path)
    path.unlink()
    downloader.register([remote], _binary())
    with pytest.raises(requests.HTTPError):
        list(downloader.download())
    assert _stored(downloader) == set()


class _GzipAdapter(BaseAdapter):
    """Serves the given data with gzip content-coding."""

    def __init__(self, data):
        super().__init__()
        self.data = data

    def send(self, request, **kwargs):
        response = requests.Response()
        response.request = request
        response.url = request.url
        response.status_code = 200
        response.raw = urllib3.HTTPResponse(
            body=io.BytesIO(gzip.compress(self.data)),
            headers={"Content-Encoding": "gzip"},
            preload_content=False,
            decode_content=False,
        )
        response.headers = CaseInsensitiveDict(response.raw.headers)
        return response

    def close(self):
        pass


def test_download_decodes_content_encoding(tmp_path):
    remote = _remote(_upstream(tmp_path, "foo_1.0-1.dsc"))
    remote.downloadurl = "https://mirror.example/foo_1.0-1.dsc"
    with requests.Session() as rs:
        rs.mount("https://", _GzipAdapter(DATA))
        dl = PackageDownloader(tmp_path / "dl", session=rs)
        dl.register([remote], SourcePackage("foo", "1.0-1"))
        (result,) = dl.download()
    assert result.status == OK
    assert result.path.read_bytes() == DATA


class _RedirectAdapter(BaseAdapter):
    """Redirects every request to the given location."""

    def __init__(self, location):
        super().__init__()
        self.location = location

    def send(self, request, **kwargs):
        response = requests.Response()
        response.request = request
        response.url = request.url
        response.status_code = 302
        response.headers["Location"] = self.location
        response.raw = io.BytesIO()
        return response

    def close(self):
        pass


@pytest.mark.parametrize(
    "location",
    [
        "HTTP://cdn.example/foo_1.0_amd64.deb",
        "/pool/foo_1.0_amd64.deb",
        "https://next.example/foo_1.0_amd64.deb",
    ],
)
def test_download_follows_http_redirects(tmp_path, downloader, location):
    """HTTP(S) redirects are followed, including relative ones, chains and downgrades to HTTP."""
    remote = _remote(_upstream(tmp_path, "foo_1.0_amd64.deb"))
    remote.downloadurl = "https://mirror.example/foo_1.0_amd64.deb"
    downloader.rs.mount("https://mirror.example/", _RedirectAdapter(location))
    downloader.rs.mount("https://mirror.example/pool/", _GzipAdapter(DATA))
    downloader.rs.mount(
        "https://next.example/", _RedirectAdapter("http://cdn.example/foo_1.0_amd64.deb")
    )
    downloader.rs.mount("http://cdn.example/", _GzipAdapter(DATA))
    downloader.register([remote], _binary())
    (result,) = downloader.download()
    assert result.status == OK
    assert result.path.read_bytes() == DATA


@pytest.mark.parametrize(
    "location", ["file://{}", "FILE://{}", "ftp://mirror.example{}", "https://next.example{}"]
)
def test_download_rejects_redirects_to_other_transports(tmp_path, downloader, location):
    """Redirects to anything but HTTP(S) are refused before the location is requested."""
    local = _upstream(tmp_path, "foo_1.0_amd64.deb")
    remote = _remote(local, checksums={})
    remote.downloadurl = "https://mirror.example/foo_1.0_amd64.deb"
    local_files = mock.Mock(wraps=LocalFileAdapter())
    downloader.rs.mount("file:///", local_files)
    downloader.rs.mount("https://mirror.example/", _RedirectAdapter(location.format(local)))
    downloader.rs.mount("https://next.example/", _RedirectAdapter(local.as_uri()))
    downloader.register([remote], _binary())
    with pytest.raises(UnsafeRedirectError):
        list(downloader.download())
    local_files.send.assert_not_called()
    assert _stored(downloader) == set()


def test_download_applies_session_hooks(tmp_path, downloader):
    """Response hooks of the session also apply to downloads."""
    hook = mock.Mock(return_value=None)
    downloader.rs.hooks["response"].append(hook)
    downloader.register([_remote(_upstream(tmp_path, "foo_1.0_amd64.deb"))], _binary())
    (result,) = downloader.download()
    assert result.status == OK
    hook.assert_called_once()


class _StaticResolver(Resolver):
    """Yields fixed files and raises the exceptions among them."""

    def __init__(self, result, cache=None):
        super().__init__(cache)
        self.result = result
        self.calls = 0

    def resolve(self, p):
        self.calls += 1
        for item in self.result:
            if isinstance(item, Exception):
                raise item
            yield item


PRIMARY = RemoteFile(
    {}, "foo_1.0_amd64.deb", "primary", "https://primary.example/foo_1.0_amd64.deb"
)
FALLBACK = RemoteFile(
    {}, "foo_1.0_amd64.deb", "debian", "https://fallback.example/foo_1.0_amd64.deb"
)


@pytest.mark.parametrize(
    "primary, fallback, expected",
    [
        ([PRIMARY], [FALLBACK], [PRIMARY]),
        # only packages which are not found are resolved by the fallback
        ([NotFoundError("gone")], [FALLBACK], [FALLBACK]),
        ([], [FALLBACK], [FALLBACK]),
        ([ResolveError("boom")], [FALLBACK], ResolveError),
        # the files of a resolver are used completely or not at all
        ([PRIMARY, NotFoundError("gone")], [FALLBACK], [FALLBACK]),
        ([PRIMARY, ResolveError("boom")], [FALLBACK], ResolveError),
        ([NotFoundError("gone")], [FALLBACK, NotFoundError("gone")], NotFoundError),
        ([NotFoundError("gone")], [], NotFoundError),
        ([NotFoundError("gone")], [ResolveError("boom")], ResolveError),
    ],
)
def test_fallback_resolver(primary, fallback, expected):
    resolvers = _StaticResolver(primary), _StaticResolver(fallback)
    resolver = FallbackResolver(*resolvers)
    if isinstance(expected, list):
        assert resolver._resolve_pkg(_binary()) == expected
    else:
        with pytest.raises(expected) as e:
            resolver._resolve_pkg(_binary())
        assert type(e.value) is expected
    fallback_used = any(isinstance(i, NotFoundError) for i in primary) or not primary
    assert [r.calls for r in resolvers] == [1, int(fallback_used)]


def test_fallback_resolver_reasons():
    resolver = FallbackResolver(
        _StaticResolver([NotFoundError("not in the mirror")]),
        _StaticResolver([sdlclient.SnapshotNotFoundError(sdlclient.NotFoundOnSnapshotError())]),
    )
    with pytest.raises(
        NotFoundError, match="^not in the mirror, and not by the fallback resolver$"
    ):
        resolver._resolve_pkg(_binary())


def test_fallback_resolver_caches(tmp_path):
    """
    The resolvers use their own caches, the combined results are not cached. Packages are
    always resolved by the primary resolver first.
    """
    primary = _StaticResolver([NotFoundError("gone")])
    fallback = _StaticResolver([FALLBACK], PersistentResolverCache(tmp_path / "cache"))
    resolver = FallbackResolver(primary, fallback)
    assert type(resolver.cache) is PackageResolverCache
    for _ in range(2):
        assert resolver._resolve_pkg(_binary()) == [FALLBACK]
    assert (primary.calls, fallback.calls) == (2, 1)

    primary.result = [PRIMARY]
    assert resolver._resolve_pkg(_binary()) == [PRIMARY]
    assert (primary.calls, fallback.calls) == (3, 1)
