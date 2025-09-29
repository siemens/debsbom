# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from collections import namedtuple
from collections.abc import Iterable
from pathlib import Path
import subprocess


class Compression:

    Format = namedtuple("compression", "tool compress extract fileext")
    # fmt: off
    NONE  = Format("cat",   [],     [],                 "")
    BZIP2 = Format("bzip2", ["-q"], ["-q", "-d", "-c"], ".bz2")
    GZIP  = Format("gzip",  ["-q"], ["-q", "-d", "-c"], ".gz")
    XZ    = Format("xz",    ["-q"], ["-q", "-d", "-c"], ".xz")
    ZSTD  = Format("zstd",  ["-q"], ["-q", "-d", "-c"], ".zst")
    LZ4  = Format("lz4",    ["-q"], ["-q", "-d", "-c"], ".lz4")
    # fmt: on

    @staticmethod
    def from_tool(tool: str | None) -> Format:
        if not tool:
            return Compression.NONE
        comp = [c for c in Compression.formats() if c.tool == tool]
        if comp:
            return comp[0]
        raise RuntimeError(f"No handler for compression with {tool}")

    @staticmethod
    def from_ext(ext: str | None) -> Format:
        if not ext:
            return Compression.NONE
        comp = [c for c in Compression.formats() if c.fileext == ext]
        if comp:
            return comp[0]
        raise ValueError(f"no handler for extension {ext}")

    @staticmethod
    def formats():
        return [
            Compression.BZIP2,
            Compression.GZIP,
            Compression.XZ,
            Compression.ZSTD,
            Compression.LZ4,
        ]


def read_maybe_compressed_file(path: Path) -> Iterable[str]:
    """Opens a file or its compressed variants."""
    suffix = path.suffix
    if suffix in Compression.formats():
        comp = Compression.from_ext()
        compressor = subprocess.Popen(
            [comp.tool] + comp.extract + [path],
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            for line in compressor.stdout:
                yield line
        finally:
            compressor.stdout.close()
            compressor.wait()
            if compressor.returncode != 0:
                raise RuntimeError(f"decompression of {path} failed: {compressor.stderr}")
            return
    else:
        for comp in [Compression.NONE] + Compression.formats():
            cpath = str(path) + comp.fileext
            if Path(cpath).exists():
                compressor = subprocess.Popen(
                    [comp.tool] + comp.extract + [cpath],
                    stdout=subprocess.PIPE,
                    text=True,
                )
                try:
                    for line in compressor.stdout:
                        yield line
                finally:
                    compressor.stdout.close()
                    compressor.wait()
                    if compressor.returncode != 0:
                        raise RuntimeError(f"decompression of {cpath} failed: {compressor.stderr}")
                    return

        raise FileNotFoundError(f"failed to find file {path} or any compressed variant")
