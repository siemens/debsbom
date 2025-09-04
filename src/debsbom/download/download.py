# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from abc import abstractmethod
from functools import reduce
import hashlib
import os
import re
from typing import Generator, Tuple, Type
from pathlib import Path
from urllib.request import urlretrieve
from ..dpkg import package
from ..snapshot import client as sdlclient


class PackageResolver:
    def __init__(self):
        self.purl_regex = re.compile(r"pkg:deb\/debian\/(.*)@(.*)[?]arch=(.*)$")

    @abstractmethod
    def debian_pkgs(self) -> Generator:
        """
        Return Debian package instances
        """
        pass

    def sources(self) -> Generator[package.SourcePackage, None, None]:
        return filter(lambda p: isinstance(p, package.SourcePackage), self.debian_pkgs())

    def binaries(self) -> Generator[package.BinaryPackage, None, None]:
        return filter(lambda p: isinstance(p, package.BinaryPackage), self.debian_pkgs())

    def package_from_purl(self, purl: str) -> Tuple[str, str, str]:
        parts = self.purl_regex.fullmatch(purl)
        if not parts:
            raise RuntimeError("Not a debian purl", purl)
        if parts[3] == "source":
            return package.SourcePackage(parts[1], parts[2])
        else:
            return package.BinaryPackage(
                parts[1], None, None, parts[3], None, parts[2], None, None, None
            )

    @staticmethod
    def resolve(
        sdl: sdlclient.SnapshotDataLake, p: package.SourcePackage | package.BinaryPackage
    ) -> Generator["sdlclient.RemoteFile", None, None]:
        """
        Resolve a local package to references on the upstream snapshot mirror
        """
        if isinstance(p, package.SourcePackage):
            return sdlclient.SourcePackage(sdl, p.name, p.version).srcfiles()
        elif isinstance(p, package.BinaryPackage):
            return sdlclient.BinaryPackage(sdl, p.name, p.version, None, None).files(
                arch=p.architecture
            )

    @staticmethod
    def create(filename: Path) -> Type["PackageResolver"]:
        if filename.name.endswith("spdx.json"):
            from .spdx import SpdxPackageResolver

            return SpdxPackageResolver(filename)
        elif filename.name.endswith("cdx.json"):
            from .cdx import CdxPackageResolver

            return CdxPackageResolver(filename)
        else:
            raise RuntimeError("Cannot determine file format")


class PackageDownloader:
    def __init__(self, outdir: Path | str = "downloads"):
        self.dldir = Path(outdir)
        self.dldir.mkdir(exist_ok=True)
        self.to_download: list["sdlclient.RemoteFile"] = []

    def register(self, files: list["sdlclient.RemoteFile"]):
        self.to_download.extend(list(files))

    def stat(self):
        """
        Returns a tuple (files to download, total size)
        """
        nbytes = reduce(lambda acc, x: acc + x.size, self.to_download, 0)
        return (len(self.to_download), nbytes)

    def download(self, progress_cb):
        for idx, f in enumerate(self.to_download):
            if progress_cb:
                progress_cb(idx, len(self.to_download), f.filename)
            target = Path(self.dldir / f.filename)
            if target.is_file():
                with open(target, "rb") as fd:
                    digest = hashlib.file_digest(fd, "sha1")
                if digest.hexdigest() == f.hash:
                    continue
                else:
                    print(f"Checksum mismatch on {f.filename}. Download again.", file=sys.stderr)
            fdst = target.with_suffix(target.suffix + ".tmp")
            urlretrieve(f.downloadurl, fdst)
            fdst.rename(target)
