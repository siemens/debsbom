# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import io
from pathlib import Path

import pytest
from debsbom.download import (
    PackageDownloader,
    PersistentResolverCache,
    UpstreamResolver,
)
from debsbom.resolver import PackageResolver, PackageStreamResolver
from debsbom.dpkg.package import BinaryPackage, ChecksumAlgo, SourcePackage
from debsbom.generate.spdx import spdx_bom
from debsbom.generate.cdx import cyclonedx_bom
from debsbom.repack.packer import BomTransformer, Packer
from debsbom.snapshot.client import RemoteFile
import debsbom.snapshot.client as sdlclient

import spdx_tools.spdx.writer.json.json_writer as spdx_json_writer
import cyclonedx.output as cdx_output
import cyclonedx.schema as cdx_schema

from unittest import mock


@pytest.fixture()
def spdx_bomfile(tmpdir):
    """
    Return the path to a minimal spdx sbom file
    """
    pkgs = BinaryPackage.parse_status_file(Path("tests/data/dpkg-status-minimal"))
    bom = spdx_bom(set(pkgs), "debian")
    outfile = Path(tmpdir) / "bom.spdx.json"
    spdx_json_writer.write_document_to_file(bom, outfile, False)
    return outfile


@pytest.fixture()
def cdx_bomfile(tmpdir):
    """
    Return the path to a cdx minimal sbom file
    """
    pkgs = BinaryPackage.parse_status_file(Path("tests/data/dpkg-status-minimal"))
    bom = cyclonedx_bom(set(pkgs), "debian")
    outfile = Path(tmpdir) / "bom.cdx.json"
    cdx_output.make_outputter(
        bom, cdx_schema.OutputFormat.JSON, cdx_schema.SchemaVersion.V1_6
    ).output_to_file(outfile)
    return outfile


@pytest.mark.online
def test_download(tmpdir, http_session):
    dl = PackageDownloader(Path(tmpdir), session=http_session)
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
    pkgs = list(rs)
    assert any(filter(lambda p: isinstance(p, SourcePackage) and p.name == "binutils", pkgs))
    assert any(filter(lambda p: isinstance(p, BinaryPackage) and p.architecture == "amd64", pkgs))


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
    assert any(filter(lambda p: isinstance(p, SourcePackage) and p.name == "guestfs-tools", pkgs))
    assert any(filter(lambda p: isinstance(p, BinaryPackage) and p.name == "binutils", pkgs))


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
    assert len(local_files) == 1

    # test invalid checksum
    local_files[0].unlink()
    # tamper checksum (sha256sum of '42')
    bpkg.checksums[ChecksumAlgo.SHA256SUM] = (
        "084c799cd551dd1d8d5c5f9a5d593b2e931f5e36122ee5c793c1d08a19839cc0"
    )
    dl.register(files, bpkg)
    stats = dl.stat()
    assert stats.files == 1
    local_files = list(dl.download())
    # no file was successfully downloaded
    assert len(local_files) == 0


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
        for p in filter(lambda p: isinstance(p, SourcePackage), pkgs):
            dl.register(urs.resolve(p))
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
