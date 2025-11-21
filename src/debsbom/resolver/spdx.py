# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from ..dpkg.package import Package
from ..util.checksum_spdx import checksum_dict_from_spdx
from ..sbom import SPDXType
from .resolver import PackageResolver

import logging
import spdx_tools.spdx.model.package as spdx_package
import spdx_tools.spdx.model.document as spdx_document


logger = logging.getLogger(__name__)


class SpdxPackageResolver(PackageResolver, SPDXType):
    def __init__(self, document: spdx_document.Document):
        super().__init__()
        self._document = document
        self._pkgs = map(
            lambda p: self.create_package(p),
            filter(self.is_debian_pkg, self._document.packages),
        )

    @property
    def document(self):
        """get the parsed SBOM document"""
        return self._document

    def __next__(self) -> Package:
        return next(self._pkgs)

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
        pkg = Package.from_purl(cls.package_manager_ref(p).locator)
        pkg.checksums = checksum_dict_from_spdx(p.checksums)
        return pkg
