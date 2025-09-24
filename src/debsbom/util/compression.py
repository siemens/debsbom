# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from collections import namedtuple


class Compression:

    Format = namedtuple("compression", "tool compress extract fileext")
    # fmt: off
    NONE  = Format("cat",   [],     [],                 "")
    BZIP2 = Format("bzip2", ["-q"], ["-q", "-d", "-c"], ".bz2")
    GZIP  = Format("gzip",  ["-q"], ["-q", "-d", "-c"], ".gz")
    XZ    = Format("xz",    ["-q"], ["-q", "-d", "-c"], ".xz")
    ZSTD  = Format("zstd",  ["-q"], ["-q", "-d", "-c"], ".zst")
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
        raise RuntimeError(f"No handler for extension {ext}")

    @staticmethod
    def formats():
        return [Compression.BZIP2, Compression.GZIP, Compression.XZ, Compression.ZSTD]

