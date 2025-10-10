# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from pathlib import Path
import pytest
import requests
from debsbom.download import PackageDownloader
from debsbom.repack import SourceArchiveMerger
import debsbom.dpkg.package as dpkg
import debsbom.snapshot.client as sdlclient
from debsbom.util import Compression


def test_compressor_from_tool():
    assert Compression.from_tool(None) == Compression.NONE
    for c in Compression.formats():
        assert Compression.from_tool(c.tool) == c
    with pytest.raises(RuntimeError):
        Compression.from_tool("false")


def test_compressor_from_ext():
    assert Compression.from_ext("") == Compression.NONE
    assert Compression.from_ext(None) == Compression.NONE
    for c in Compression.formats():
        assert Compression.from_ext(c.fileext) == c
    with pytest.raises(ValueError):
        Compression.from_ext("foobar")


@pytest.fixture(scope="session")
def dldir(tmp_path_factory):
    return tmp_path_factory.mktemp("downloads")


@pytest.fixture(scope="session")
def some_packages(dldir):
    rs = requests.session()
    sdl = sdlclient.SnapshotDataLake(session=rs)
    dl = PackageDownloader(dldir, rs)

    packages = [
        # .orig.tar and .debian.tar
        dpkg.SourcePackage("sed", "4.9-2"),
        # .orig.tar and .debian.tar with epoch
        dpkg.SourcePackage("shadow", "1:4.17.4-2"),
        # debian dir in sources
        dpkg.SourcePackage("dgit", "13.13"),
        # debian dir via compressed .diff
        dpkg.SourcePackage("pcre2", "10.45-1"),
    ]
    srcfiles = []
    for p in packages:
        srcfiles.extend(list(sdlclient.SourcePackage(sdl, p.name, str(p.version)).srcfiles()))
    dl.register(srcfiles)
    list(dl.download())
    return packages


@pytest.mark.parametrize("compress", [None, "bzip2", "gzip", "xz", "zstd"])
@pytest.mark.online
def test_merger(tmpdir, some_packages, dldir, compress):
    outdir = Path(tmpdir / "merged")
    sam = SourceArchiveMerger(dldir / "sources", outdir, compress=Compression.from_tool(compress))

    for p in some_packages:
        assert p.name in sam.merge(p, apply_patches=True).name
