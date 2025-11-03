# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from typing import IO
from ..dpkg.package import Package
from ..util.checksum_cdx import checksum_from_cdx, ChecksumNotSupportedError
from ..sbom import CDXType
from .resolver import PackageResolver

import logging
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component


logger = logging.getLogger(__name__)


class CdxPackageResolver(PackageResolver, CDXType):
    def __init__(self, document: Bom):
        super().__init__()
        self._document = document
        self._pkgs = map(
            lambda p: self.create_package(p),
            filter(self.is_debian_pkg, self._document.components),
        )

    @property
    def document(self):
        """get the parsed SBOM document"""
        return self._document

    def __next__(self) -> Package:
        return next(self._pkgs)

    @classmethod
    def is_debian_pkg(cls, p: Component):
        if str(p.purl).startswith("pkg:deb/debian/"):
            return True
        return False

    @classmethod
    def create_package(cls, c: Component) -> Package:
        pkg = Package.from_purl(str(c.purl))
        for cks in c.hashes:
            try:
                pkg.checksums[checksum_from_cdx(cks.alg)] = cks.content
            except ChecksumNotSupportedError:
                logger.debug(f"ignoring unknown checksum on {pkg}")
        return pkg
