# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from collections import namedtuple
import hashlib
import logging
from pathlib import Path
import re
import subprocess
import tempfile
from debian import deb822

from debsbom.dpkg import package


logger = logging.getLogger(__name__)


class CorruptedFileError(RuntimeError):
    pass


class DscFileNotFoundError(FileNotFoundError):
    pass


class Compression:
    """ """

    CmdAndExtType = namedtuple("compression", "tool compress extract fileext")
    # fmt: off
    NONE  = CmdAndExtType("cat",   [],     [],                 "")
    BZIP2 = CmdAndExtType("bzip2", ["-q"], ["-q", "-d", "-c"], ".bz2")
    GZIP  = CmdAndExtType("gzip",  ["-q"], ["-q", "-d", "-c"], ".gz")
    XZ    = CmdAndExtType("xz",    ["-q"], ["-q", "-d", "-c"], ".xz")
    ZSTD  = CmdAndExtType("zstd",  ["-q"], ["-q", "-d", "-c"], ".zst")
    # fmt: on

    @staticmethod
    def from_tool(tool: str) -> CmdAndExtType:
        if not tool:
            return Compression.NONE
        comp = [c for c in Compression.formats() if c.tool == tool]
        if comp:
            return comp[0]
        raise RuntimeError(f"No handler for compression with {tool}")

    @staticmethod
    def from_ext(ext: str) -> CmdAndExtType:
        if not ext:
            return Compression.NONE
        comp = [c for c in Compression.formats() if c.fileext == ext]
        if comp:
            return comp[0]
        raise RuntimeError(f"No handler for extension {ext}")

    @staticmethod
    def formats():
        return [Compression.BZIP2, Compression.GZIP, Compression.XZ, Compression.ZSTD]


class SourceArchiveMerger:
    """
    Creates a new archive containing the files from the source
    and the debian archive of a package.
    """

    def __init__(self, dldir: Path, outdir: Path = None, compress: Compression = Compression.NONE):
        self.dldir = dldir
        self.outdir = outdir or dldir
        self.compress = compress
        # archive files (either debian and source)
        self.archive_regex = re.compile(r"^.*\.tar\.(bz2|gz|xz|zst)$")
        # debian diff files (policy section 4.x)
        self.diff_regex = re.compile(r"^.*\.diff\.(bz2|gz|xz|zst)$")

    def _check_hash(self, dsc_entry):
        file = self.dldir / dsc_entry["name"]
        with open(file, "rb") as f:
            digest = hashlib.file_digest(f, "sha256")
            if digest.hexdigest() != dsc_entry["sha256"]:
                raise CorruptedFileError(file)

    def _patch(self, diff_file: Path):
        """
        Create the debian dir from a patch file (policy section 4.x).
        Note: This does not apply patches from the debian dir (debian/patches/*) itself
        """
        comp = Compression.from_ext(diff_file.suffix)
        extractor = subprocess.Popen([comp.tool] + comp.extract, stdout=subprocess.PIPE)
        patcher = subprocess.Popen(["patch"], stdin=extractor.stdout)
        _, stderr = patcher.communicate()
        ret = patcher.wait()
        if ret != 0:
            raise RuntimeError("Failed to apply patch: ", stderr.decode())

    def merge(self, p: package.SourcePackage) -> Path:
        merged = (
            self.dldir
            / f"{p.name}_{p.version.upstream_version}-{p.version.debian_revision}.merged.tar"
        )
        dsc = self.dldir / p.dscfile()
        if self.compress:
            merged = merged.with_suffix(f"{merged.suffix}{self.compress.fileext}")
        if merged.is_file():
            logger.debug(f"'{dsc}' already merged: '{merged}'")
            return merged

        if not dsc.is_file():
            raise DscFileNotFoundError(dsc)

        logger.debug(f"Merging sources from '{dsc}'...")
        # get all referenced tarballs from dsc file (usually .orig and .debian and check digests)
        with open(dsc, "r") as f:
            d = deb822.Dsc(f)
        files = d["Checksums-Sha256"]
        [self._check_hash(f) for f in files]

        archives = [self.dldir / f["name"] for f in files if self.archive_regex.match(f["name"])]
        diffs = [self.dldir / f["name"] for f in files if self.diff_regex.match(f["name"])]
        # extract all tars into tmpdir and create new tar with combined content
        with tempfile.TemporaryDirectory() as tmpdir:
            for archive in archives:
                subprocess.check_call(["tar", "xf", str(archive.absolute())], cwd=tmpdir)

            # apply diff if any
            if len(diffs) > 1:
                logger.warning(f"{p.name}@{p.version}: only a single debian .diff is supported.")
            if len(diffs):
                self._patch(diffs[0])

            # repack archive
            sources = [s.name for s in Path(tmpdir).iterdir() if s.is_dir() or s.is_file()]
            tmpfile = merged.with_suffix(f"{merged.suffix}.tmp")
            with open(tmpfile, "wb") as outfile:
                tar_writer = subprocess.Popen(
                    ["tar", "c"] + sorted(sources),
                    stdout=subprocess.PIPE,
                    cwd=tmpdir,
                )
                compressor = subprocess.Popen(
                    [self.compress.tool] + self.compress.compress,
                    stdin=tar_writer.stdout,
                    stdout=outfile,
                )
                _, stderr = compressor.communicate()
                ret = compressor.wait()
                if ret != 0:
                    raise RuntimeError("could not created merged tar: ", stderr.decode())
            tmpfile.rename(merged)
        return merged
