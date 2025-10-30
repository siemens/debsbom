# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from datetime import datetime
from email.utils import parsedate_to_datetime
import io
from pathlib import Path
import tarfile
import pytest
import requests
import zstandard
import lz4.frame
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
def some_packages(dldir, http_session):
    sdl = sdlclient.SnapshotDataLake(session=http_session)
    dl = PackageDownloader(dldir, http_session)

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


EXPECTED_CHANGELOG_TIMESTAMPS = {
    ("sed", "4.9-2"): "Mon, 01 Jan 2024 18:37:14 -0500",
    ("shadow", "1:4.17.4-2"): "Sat, 19 Apr 2025 12:20:28 +0200",
    ("dgit", "13.13"): "Sun, 24 Aug 2025 11:43:28 +0100",
    ("pcre2", "10.45-1"): "Wed, 05 Feb 2025 09:25:16 +0000",
}


@pytest.mark.parametrize("compress", [None, "bzip2", "gzip", "xz", "zstd", "lz4"])
@pytest.mark.parametrize("mtime", [None, "Wed, 01 Oct 2025 12:34:56 +0100"])
@pytest.mark.online
def test_merger(tmpdir, some_packages, dldir, compress, mtime):
    outdir = Path(tmpdir / "merged")
    sam = SourceArchiveMerger(dldir / "sources", outdir, compress=Compression.from_tool(compress))

    for p in some_packages:
        if mtime:
            expected_timestamp_str = mtime
        else:
            expected_timestamp_str = EXPECTED_CHANGELOG_TIMESTAMPS[(p.name, p.version)]
        dt_object = parsedate_to_datetime(expected_timestamp_str)
        expected_timestamp = int(dt_object.timestamp())
        result = sam.merge(
            p,
            apply_patches=True,
            mtime=dt_object if mtime else None,
        )
        assert p.name in result.name

        extract_path = Path(tmpdir) / f"extracted_{p.name}"
        extract_path.mkdir(exist_ok=True, parents=False)

        tar_open_args = {"name": result}
        if compress == "zstd" or compress == "lz4":
            with open(result, mode="rb") as compressed_file:
                if compress == "zstd":
                    dctx = zstandard.ZstdDecompressor()
                    decompressed_data_buffer = io.BytesIO()
                    dctx.copy_stream(compressed_file, decompressed_data_buffer)
                else:
                    decompressed_data_buffer = io.BytesIO(
                        lz4.frame.decompress(compressed_file.read())
                    )
            decompressed_data_buffer.seek(0)
            tar_open_args = {"fileobj": decompressed_data_buffer}

        with tarfile.open(**tar_open_args, mode="r") as tar:
            tar.extraction_filter = getattr(tarfile, "data_filter", (lambda member, path: member))
            tar.extractall(path=extract_path)

        found = False
        for item_path in extract_path.rglob("*"):
            found = True
            mtime_unix = item_path.stat().st_mtime
            assert mtime_unix == expected_timestamp, (
                f"Expected mtime {expected_timestamp_str} (Unix: {expected_timestamp}) "
                f"but got {datetime.fromtimestamp(mtime_unix)} for file {item_path}"
            )
        assert found, "No files found in the extracted archive to check timestamps"
