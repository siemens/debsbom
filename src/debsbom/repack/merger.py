# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import hashlib
import logging
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from debian import deb822

from ..dpkg import package
from ..util import Compression


logger = logging.getLogger(__name__)


class CorruptedFileError(RuntimeError):
    pass


class DscFileNotFoundError(FileNotFoundError):
    pass


class SourceArchiveMerger:
    """
    Creates a new archive containing the files from the source
    and the debian archive of a package.
    """

    def __init__(
        self,
        dldir: Path,
        outdir: Path | None = None,
        compress: Compression.Format = Compression.NONE,
    ):
        self.dldir = dldir
        self.outdir = outdir or dldir
        self.compress = compress
        self.dpkg_source = shutil.which("dpkg-source")
        if not self.dpkg_source:
            raise RuntimeError("'dpkg-source' from the 'dpkg-dev' package is missing.")

    @staticmethod
    def _file_sha256sum(file):
        with open(file, "rb") as f:
            digest = hashlib.file_digest(f, "sha256")
            return digest.hexdigest()

    @classmethod
    def _check_sha256sum(cls, file, expected: str):
        hexdigest = cls._file_sha256sum(file)
        if hexdigest != expected:
            raise CorruptedFileError(file)

    def _check_hash(self, base: Path, dsc_entry):
        file = base / dsc_entry["name"]
        self._check_sha256sum(file, dsc_entry["sha256"])

    @classmethod
    def locate_artifact(cls, p: package.Package, basedir: Path) -> Path | None:
        """
        Locate a related .deb or .dsc file in the downloads dir.
        """
        for d in basedir.iterdir():
            cand = d / p.filename
            if not cand.is_file():
                continue
            if package.ChecksumAlgo.SHA256SUM not in p.checksums:
                logger.warning(f"No SHA256 digest for {p}. Assume it is from archive '{d.name}'")
                return cand
            logger.debug(f"compute checksum of '{cand}'")
            if cls._file_sha256sum(cand) == p.checksums[package.ChecksumAlgo.SHA256SUM]:
                return cand
        return None

    def merge(self, p: package.SourcePackage, apply_patches: bool = False) -> Path:
        """
        The provided package will also be updated with information from the .dsc file.
        """
        suffix = ".merged.patched.tar" if apply_patches else ".merged.tar"
        dsc = self.locate_artifact(p, self.dldir)
        if not dsc:
            raise DscFileNotFoundError(p.dscfile())
        merged = dsc.with_suffix(suffix)
        if self.compress:
            merged = merged.with_suffix(f"{merged.suffix}{self.compress.fileext}")

        if package.ChecksumAlgo.SHA256SUM in p.checksums:
            logger.debug(f"Checking sha256sum of '{dsc}'...")
            self._check_sha256sum(dsc, p.checksums[package.ChecksumAlgo.SHA256SUM])

        logger.debug(f"Merging sources from '{dsc}'...")
        # get all referenced tarballs from dsc file (usually .orig and .debian and check digests)
        with open(dsc, "r") as f:
            d = deb822.Dsc(f)
        files = d["Checksums-Sha256"]
        [self._check_hash(dsc.parent, f) for f in files]

        # merge package with info from dsc file
        p.merge_with(package.SourcePackage.from_deb822(d))

        # metadata is now merged, archive can be skipped as we already have it
        if merged.is_file():
            logger.debug(f"'{dsc}' already merged: '{merged}'")
            return merged

        # extract all tars into tmpdir and create new tar with combined content
        with tempfile.TemporaryDirectory() as tmpdir:
            verbose = logger.getEffectiveLevel() <= logging.DEBUG
            dpkg_src_opts = ["--no-check"]
            # only set option if this is not a native package
            if not apply_patches and p.version.debian_revision:
                dpkg_src_opts.append("--skip-patches")
            subprocess.check_call(
                [self.dpkg_source] + dpkg_src_opts + ["-x", str(dsc.absolute())],
                cwd=tmpdir,
                stdout=sys.stderr if verbose else subprocess.DEVNULL,
            )

            # repack archive
            sources = [s.name for s in Path(tmpdir).iterdir() if s.is_dir() or s.is_file()]
            tmpfile = merged.with_suffix(f"{merged.suffix}.tmp")
            # options to build tar reproducible
            repro_tar_opts = [
                "--force-local",
                "--format=gnu",
                "--sort=name",
                "--owner=0",
                "--group=0",
                "--numeric-owner",
            ]
            with open(tmpfile, "wb") as outfile:
                tar_writer = subprocess.Popen(
                    ["tar", "c"] + repro_tar_opts + sorted(sources),
                    stdout=subprocess.PIPE,
                    cwd=tmpdir,
                )
                compressor = subprocess.Popen(
                    [self.compress.tool] + self.compress.compress,
                    stdin=tar_writer.stdout,
                    stdout=outfile,
                )
                _, stderr = compressor.communicate()
                tar_ret = tar_writer.wait()
                tar_writer.stdout.close()
                comp_ret = compressor.wait()
                if any([r != 0 for r in [tar_ret, comp_ret]]):
                    raise RuntimeError("could not created merged tar: ", stderr.decode())
            tmpfile.rename(merged)
        return merged
