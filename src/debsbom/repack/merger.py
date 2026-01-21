# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from datetime import datetime
from email.utils import parsedate_to_datetime
import hashlib
import logging
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from debian import deb822
from debian.changelog import Changelog

from ..util.checksum import verify_dsc_files, check_hash_from_path
from ..dpkg import package
from ..util import Compression

logger = logging.getLogger(__name__)


class CorruptedFileError(RuntimeError):
    pass


class DscFileNotFoundError(FileNotFoundError):
    pass


class ChangelogTimestampError(Exception):
    """Raised when mtime cannot be extracted from the changelog for reproducible builds."""

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
        self.outdir.mkdir(exist_ok=True, parents=False)
        self.compress = compress
        self.dpkg_source = shutil.which("dpkg-source")
        if not self.dpkg_source:
            raise RuntimeError("'dpkg-source' from the 'dpkg-dev' package is missing.")

    @classmethod
    def locate_artifact(cls, p: package.Package, basedir: Path) -> Path | None:
        """
        Locate a related .deb or .dsc file in the downloads dir.
        """
        for d in basedir.iterdir():
            cand = d / p.filename
            if not cand.is_file():
                continue
            if not p.checksums or len(p.checksums) == 0:
                logger.warning(f"No hash digest for {p}. Assume it is from archive '{d.name}'")
                return cand
            logger.debug(f"compute checksum of '{cand}'")
            if check_hash_from_path(cand, p.checksums):
                return cand
        return None

    @staticmethod
    def extract_timestamp(path: Path) -> datetime | None:
        changelog_path = None
        for d in path.iterdir():
            if not d.is_dir():
                continue
            cand = d / "debian" / "changelog"
            if cand.is_file():
                changelog_path = cand
                break
        if not changelog_path:
            raise ChangelogTimestampError(f"No changelog file found for package")
        # Open and parse the changelog
        try:
            with open(changelog_path) as changelog_file:
                changelog = Changelog(changelog_file, max_blocks=1)
        except Exception as e:
            raise ChangelogTimestampError(f"Error processing changelog for package")
        if not changelog or not changelog.date:
            raise ChangelogTimestampError(
                f"Could not extract a valid date from changelog for package'"
            )
        try:
            return parsedate_to_datetime(changelog.date)
        except ValueError as e:
            raise ChangelogTimestampError(
                f"Could not parse changelog date '{changelog.date}' for package"
            )

    def merge(
        self, p: package.SourcePackage, apply_patches: bool = False, mtime: datetime | None = None
    ) -> Path:
        """
        The provided package will also be updated with information from the .dsc file.
        """
        suffix = ".merged.patched.tar" if apply_patches else ".merged.tar"
        dsc = self.locate_artifact(p, self.dldir)
        if not dsc:
            raise DscFileNotFoundError(p.dscfile())
        dir = self.outdir / dsc.parent.name
        dir.mkdir(exist_ok=True)
        merged = dir / dsc.with_suffix(suffix).name
        if self.compress:
            merged = merged.with_suffix(f"{merged.suffix}{self.compress.fileext}")

        if len(p.checksums) > 0:
            logger.debug(f"Checking checksums of '{dsc}'...")
            if not p.checksums and not check_hash_from_path(dsc, p.checksums):
                raise CorruptedFileError(dsc)

        logger.debug(f"Merging sources from '{dsc}'...")
        # get all referenced tarballs from dsc file (usually .orig and .debian and check digests)
        with open(dsc, "r") as f:
            d = deb822.Dsc(f)
        if not verify_dsc_files(d, dsc.parent):
            raise CorruptedFileError(dsc)

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
            sources = [
                s.name for s in Path(tmpdir).iterdir() if s.is_dir() and (s / "debian").is_dir()
            ]
            tmpfile = merged.with_suffix(f"{merged.suffix}.tmp")

            if not mtime:
                # get timestamp from changelog for reproducible builds
                try:
                    mtime = SourceArchiveMerger.extract_timestamp(Path(tmpdir))
                except ChangelogTimestampError as e:
                    raise ValueError(
                        f"Please use the '--mtime' option to specify a timestamp. {e} {p}",
                    ) from e

            # options to build tar reproducible
            repro_tar_opts = [
                "--force-local",
                "--format=gnu",
                "--sort=name",
                "--mode=a=rX,u+w",
                "--owner=0",
                "--group=0",
                "--numeric-owner",
                f"--mtime={mtime}" if mtime else None,
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
