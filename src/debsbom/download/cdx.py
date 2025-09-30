# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from ..dpkg.package import ChecksumAlgo, Package
from ..sbom import CDXType
from .resolver import PackageResolver

import json
import logging
from pathlib import Path
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component
from cyclonedx.model import HashAlgorithm as cdx_hashalgo


logger = logging.getLogger(__name__)


CHKSUM_TO_INTERNAL = {
    cdx_hashalgo.MD5: ChecksumAlgo.MD5SUM,
    cdx_hashalgo.SHA_1: ChecksumAlgo.SHA1SUM,
    cdx_hashalgo.SHA_256: ChecksumAlgo.SHA256SUM,
}


class CdxPackageResolver(PackageResolver, CDXType):
    def __init__(self, document: Bom):
        super().__init__()
        self._document = document

    @property
    def document(self):
        """get the parsed SBOM document"""
        return self._document

    @staticmethod
    def is_debian_pkg(p: Component):
        if str(p.purl).startswith("pkg:deb/debian/"):
            return True
        return False

    @classmethod
    def create_package(cls, c: Component) -> Package:
        pkg = Package.from_purl(str(c.purl))
        for cks in c.hashes:
            if cks.alg not in CHKSUM_TO_INTERNAL.keys():
                logger.debug(f"ignoring unknown checksum on {pkg.name}@{pkg.version}")
                continue
            pkg.checksums[CHKSUM_TO_INTERNAL[cks.alg]] = cks.content
        return pkg

    def debian_pkgs(self):
        return map(
            lambda p: self.create_package(p),
            filter(self.is_debian_pkg, self._document.components),
        )

    @classmethod
    def from_file(cls, filename: Path) -> "CdxPackageResolver":
        with open(filename, "r") as f:
            return cls(Bom.from_json(json.load(f)))
