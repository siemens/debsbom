# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from pathlib import Path

import pytest
from debsbom.download import PackageDownloader, PackageResolver
from debsbom.download.download import PersistentResolverCache
from debsbom.dpkg.package import BinaryPackage
from debsbom.generate.spdx import spdx_bom
from debsbom.generate.cdx import cyclonedx_bom
from debsbom.snapshot.client import RemoteFile, SnapshotDataLake

import spdx_tools.spdx.writer.json.json_writer as spdx_json_writer
import cyclonedx.output as cdx_output
import cyclonedx.schema as cdx_schema

from unittest import mock


@pytest.fixture()
def spdx_bomfile(tmpdir):
    """
    Return the path to a minimal spdx sbom file
    """
    pkgs = BinaryPackage.parse_status_file("tests/data/dpkg-status-minimal")
    bom = spdx_bom(list(pkgs), "debian")
    outfile = Path(tmpdir) / "bom.spdx.json"
    spdx_json_writer.write_document_to_file(bom, outfile, False)
    return outfile


@pytest.fixture()
def cdx_bomfile(tmpdir):
    """
    Return the path to a cdx minimal sbom file
    """
    pkgs = BinaryPackage.parse_status_file("tests/data/dpkg-status-minimal")
    bom = cyclonedx_bom(list(pkgs), "debian")
    outfile = Path(tmpdir) / "bom.cdx.json"
    cdx_output.make_outputter(
        bom, cdx_schema.OutputFormat.JSON, cdx_schema.SchemaVersion.V1_6
    ).output_to_file(outfile)
    return outfile


@pytest.mark.online
def test_download(tmpdir):
    dl = PackageDownloader(Path(tmpdir))
    test_file = RemoteFile(
        hash="1f3a43c181b81e3578d609dc0931ff147623eb38",
        filename="pytest_8.4.2-1.dsc",
        size=2757,
        archive_name="debian",
        path="/pool/main/p/pytest",
        first_seen=1757270199,
        downloadurl="https://snapshot.debian.org/file/1f3a43c181b81e3578d609dc0931ff147623eb38/pytest_8.4.2-1.dsc",
        architecture=None,
    )
    dl.register([test_file])
    assert dl.stat() == (1, 2757, 0, 0)
    mock_cb = mock.Mock()
    downloaded = list(dl.download(mock_cb))
    mock_cb.assert_called_once_with(0, 1, test_file.filename)

    assert len(downloaded) == 1
    assert downloaded[0].is_file()
    assert downloaded[0].is_relative_to(Path(tmpdir))
    stat_orig = downloaded[0].stat()

    # now download again (which should not actually download)
    dl.register([test_file])
    downloaded = list(dl.download(None))
    assert int(downloaded[0].stat().st_mtime_ns) == int(stat_orig.st_mtime_ns)

    # tamper the checksum of the downloaded file. Must result in re-download
    with open(downloaded[0], "w+") as f:
        f.write("append")
    dl.register([test_file])
    downloaded = list(dl.download(None))
    assert int(downloaded[0].stat().st_mtime_ns) != int(stat_orig.st_mtime_ns)


def test_package_resolver_parse_spdx(spdx_bomfile):
    rs = PackageResolver.create(spdx_bomfile)
    assert any(filter(lambda p: p.name == "binutils", rs.sources()))
    assert any(filter(lambda p: p.architecture == "amd64", rs.binaries()))


def test_package_resolver_parse_cdx(cdx_bomfile):
    rs = PackageResolver.create(cdx_bomfile)
    assert any(filter(lambda p: p.architecture == "amd64", rs.binaries()))


@pytest.mark.online
def test_package_resolver_resolve_spdx(spdx_bomfile, tmpdir):
    cachedir = Path(tmpdir) / ".cache"
    sdl = SnapshotDataLake()
    rs = PackageResolver.create(spdx_bomfile)
    rs_cache = PersistentResolverCache(cachedir)

    files = list(rs.resolve(sdl, next(rs.sources()), rs_cache))
    assert "binutils" in files[0].filename

    # resolve with cache
    files = list(rs.resolve(sdl, next(rs.sources()), rs_cache))
    assert "binutils" in files[0].filename
