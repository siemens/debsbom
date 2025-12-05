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
from debsbom.resolver import PackageResolver, PackageStreamResolver
from debsbom.dpkg.package import (
    BinaryPackage,
    SourcePackage,
    ChecksumAlgo,
    filter_binaries,
    filter_sources,
)
from debsbom.repack.packer import BomTransformer, Packer
from debsbom.snapshot.client import SnapshotRemoteFile, UpstreamResolver
import debsbom.snapshot.client as sdlclient

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

    pkgs = BinaryPackage.parse_status_file(Path("tests/data/dpkg-status-minimal"))
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

    pkgs = BinaryPackage.parse_status_file(Path("tests/data/dpkg-status-minimal"))
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

    files = list(urs.resolve(next(prs)))
    assert "binutils" in files[0].filename

    # resolve with cache
    prs = PackageResolver.create(spdx_bomfile)
    files = list(urs.resolve(next(prs)))
    assert "binutils" in files[0].filename


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
        fmt="standard-bom",
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
        for p in filter_sources(pkgs):
            dl.register(urs.resolve(p), p)
        files = list(dl.download())
        assert len(files) == 3

        # merge the source package
        bt = BomTransformer.create("standard-bom", resolver.sbom_type(), resolver.document)
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


@pytest.fixture(scope="session")
def dlschema():
    schemapath = Path(__file__).parent / "../src/debsbom/schema/schema-download.json"
    with open(schemapath) as f:
        schema = json.load(f)
    return schema


@pytest.mark.parametrize(
    "dlresult",
    [
        DownloadResult(
            Path("/tmp/foo.tar"), DownloadStatus.OK, SourcePackage("foo", "1.0"), "foo.tar"
        ),
        DownloadResult(None, DownloadStatus.NOT_FOUND, SourcePackage("foo", "1.0"), "bar.tar"),
        DownloadResult(
            None, DownloadStatus.CHECKSUM_MISMATCH, BinaryPackage("bar", "1.0"), "bar.tar"
        ),
    ],
)
def test_download_result_format(dlschema, dlresult):
    data = json.loads(dlresult.json())
    if data["status"] == DownloadStatus.OK:
        assert data["status"] == "ok"

    jsonschema.validate(data, schema=dlschema)


def test_download_result_invalid(dlschema):
    data = {
        "status": "unknown",
        "package": {"name": "foo", "version": "1.0"},
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, schema=dlschema)


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
