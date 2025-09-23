# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from ..dpkg.package import ChecksumAlgo, Package
from .download import PackageResolver

import logging
from collections.abc import Iterable
from pathlib import Path
from spdx_tools.spdx.parser.parse_anything import parse_file
import spdx_tools.spdx.model.package as spdx_package
import spdx_tools.spdx.model.document as spdx_document
from spdx_tools.spdx.model.checksum import ChecksumAlgorithm


logger = logging.getLogger(__name__)


CHKSUM_TO_INTERNAL = {
    ChecksumAlgorithm.MD5: ChecksumAlgo.MD5SUM,
    ChecksumAlgorithm.SHA1: ChecksumAlgo.SHA1SUM,
    ChecksumAlgorithm.SHA256: ChecksumAlgo.SHA256SUM,
}


class SpdxPackageResolver(PackageResolver):
    def __init__(self, document: spdx_document.Document):
        super().__init__()
        self._document = document

    @classmethod
    def package_manager_ref(cls, p: spdx_package.Package) -> spdx_package.ExternalPackageRef | None:
        cat_pkg_manager = spdx_package.ExternalPackageRefCategory.PACKAGE_MANAGER
        return next(
            filter(lambda ref: ref.category == cat_pkg_manager, p.external_references), None
        )

    @classmethod
    def is_debian_pkg(cls, p: spdx_package.Package) -> bool:
        ref = cls.package_manager_ref(p)
        if ref and ref.reference_type == "purl" and ref.locator.startswith("pkg:deb"):
            return True
        return False

    @classmethod
    def create_package(cls, p: spdx_package.Package) -> Package:
        pkg = cls.package_from_purl(cls.package_manager_ref(p).locator)
        for cks in p.checksums:
            if cks.algorithm not in CHKSUM_TO_INTERNAL.keys():
                logger.debug(f"ignoring unknown checksum on {pkg.name}@{pkg.version}")
                continue
            pkg.checksums[CHKSUM_TO_INTERNAL[cks.algorithm]] = cks.value
        return pkg

    def debian_pkgs(self) -> Iterable[Package]:
        return map(
            lambda p: self.create_package(p),
            filter(self.is_debian_pkg, self._document.packages),
        )

    @classmethod
    def from_file(cls, filename: Path) -> "SpdxPackageResolver":
        return cls(parse_file(str(filename)))
