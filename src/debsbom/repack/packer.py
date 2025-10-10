# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from abc import abstractmethod
from collections.abc import Iterable
import hashlib
import logging
from pathlib import Path
import shutil
import os
import sys

from ..sbom import BomSpecific, SBOMType
from ..dpkg.package import Package, SourcePackage
from ..dpkg.package import ChecksumAlgo as CSA
from .merger import DscFileNotFoundError, SourceArchiveMerger
from ..util import Compression

logger = logging.getLogger(__name__)


class Packer:
    """Abstract class for Packer implementations to re-layout the downloaded artifacts"""

    @abstractmethod
    def repack(self, pkg: Package, symlink=True) -> Package | None:
        raise NotImplementedError()

    @staticmethod
    def rewrite_sbom(transformer: "BomTransformer", packages: Iterable[Package]):
        return transformer.transform(packages)

    @staticmethod
    def from_format(
        fmt: str,
        dldir: Path | str = "downloads",
        outdir: Path | str = "packed",
        compress: Compression.Format = Compression.NONE,
        apply_patches: bool = False,
    ):
        if fmt == "standard-bom":
            return StandardBomPacker(dldir, outdir, compress, apply_patches=apply_patches)
        return NotImplementedError(f"No packer available for format '{fmt}'")


class StandardBomPacker(Packer):
    """Creates a Standard-BOM Package"""

    def __init__(
        self,
        dldir: Path | str = "downloads",
        outdir: Path | str = "standard-bom-package",
        compress: Compression.Format = Compression.NONE,
        apply_patches: bool = False,
    ):
        self.outdir = Path(outdir)
        self.dldir = Path(dldir)
        self.srcdir = self.outdir / "sources"
        self.bindir = self.outdir / "binaries"
        self.sam = SourceArchiveMerger(dldir / "sources", compress=compress)
        self.apply_patches = apply_patches

        for d in [self.outdir, self.srcdir, self.bindir]:
            d.mkdir(exist_ok=True)

    @staticmethod
    def _warn_missing_package(pkg: Package):
        logger.warning(f"Package {pkg.name}@{pkg.version} not found")

    def _path_to_local_uri(self, p: Path) -> str:
        prel = p.relative_to(self.outdir)
        return f"file:///{str(prel)}"

    def _create_target(self, pkg: Package) -> Path:
        if isinstance(pkg, SourcePackage):
            path = self.srcdir / pkg.checksums[CSA.SHA1SUM]
        else:
            path = self.bindir / pkg.checksums[CSA.SHA1SUM]
        path.mkdir(exist_ok=True)
        return path / pkg.filename

    def repack(self, pkg: Package, symlink=True) -> Package | None:
        chkalgs = [CSA.SHA1SUM, CSA.SHA256SUM]

        if isinstance(pkg, SourcePackage):
            try:
                pkgpath = self.sam.merge(pkg, apply_patches=self.apply_patches)
                pkg.locator = pkgpath.name
            except DscFileNotFoundError:
                self._warn_missing_package(pkg)
                return None
        else:
            pkgpath = Path(self.dldir / "binaries" / pkg.filename)
            if not pkgpath.is_file():
                self._warn_missing_package(pkg)
                return None

        for alg in chkalgs:
            with open(pkgpath, "rb") as fd:
                pkg.checksums[alg] = hashlib.file_digest(fd, CSA.to_hashlib(alg)).hexdigest()

        # update the locator to the merged / linked file
        target = self._create_target(pkg)
        pkg.locator = self._path_to_local_uri(target)

        if target.is_file():
            if (not symlink and target.is_symlink()) or (symlink and not target.is_symlink()):
                target.unlink()
            else:
                return pkg

        if symlink:
            if sys.version_info < (3, 12):
                rel_pkg_path = os.path.relpath(pkgpath, start=target.parent)
            else:
                rel_pkg_path = pkgpath.relative_to(target.parent, walk_up=True)
            target.symlink_to(rel_pkg_path)
        else:
            shutil.copy(pkgpath, target)
        return pkg


class BomTransformer(BomSpecific):
    @abstractmethod
    def transform(self, packages: Iterable[Package]):
        raise NotImplementedError()

    @property
    def document(self):
        return self._document

    @staticmethod
    def create(standard: str, sbom_type: SBOMType, bom):
        if standard == "standard-bom":
            if sbom_type == SBOMType.CycloneDX:
                from .cdx import StandardBomTransformerCDX

                return StandardBomTransformerCDX(bom)
            if sbom_type == SBOMType.SPDX:
                from .spdx import StandardBomTransformerSPDX

                return StandardBomTransformerSPDX(bom)
        raise NotImplementedError()
