# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Iterable
import logging
import spdx_tools.spdx.model.document as spdx_document
import spdx_tools.spdx.model.package as spdx_package
from spdx_tools.spdx.model.checksum import Checksum, ChecksumAlgorithm
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion

from ..generate.spdx import spdx_package_repr
from ..resolver.spdx import SpdxPackageResolver
from ..sbom import SPDX_REFERENCE_TYPE_DISTRIBUTION, SPDXType, SPDX_REFERENCE_TYPE_PURL
from .packer import BomTransformer
from ..dpkg.package import ChecksumAlgo, Package, SourcePackage


logger = logging.getLogger(__name__)


CHKSUM_TO_SPDX = {
    ChecksumAlgo.MD5SUM: ChecksumAlgorithm.MD5,
    ChecksumAlgo.SHA1SUM: ChecksumAlgorithm.SHA1,
    ChecksumAlgo.SHA256SUM: ChecksumAlgorithm.SHA256,
}


class StandardBomTransformerSPDX(BomTransformer, SPDXType):
    def __init__(self, bom: spdx_document.Document):
        self._document = bom
        self.pkgs_by_purl = dict(
            map(
                lambda p: (self.purl_from_spdx(p), p),
                filter(SpdxPackageResolver.is_debian_pkg, self._document.packages),
            )
        )

    @staticmethod
    def purl_from_spdx(p: spdx_package.Package) -> str:
        purl_ref = next(
            filter(
                lambda r: r.reference_type == SPDX_REFERENCE_TYPE_PURL,
                p.external_references,
            ),
            None,
        )
        return purl_ref.locator

    @staticmethod
    def _enhance(spdx_pkg: spdx_package.Package, p: Package):
        """fold in data we don't have in the SPDX representation (yet)"""
        _spdx_pkg = spdx_package_repr(p)
        if spdx_pkg.supplier == SpdxNoAssertion():
            spdx_pkg.supplier = _spdx_pkg.supplier
        if not spdx_pkg.homepage:
            spdx_pkg.homepage = _spdx_pkg.homepage
        if not spdx_pkg.summary:
            spdx_pkg.summary = _spdx_pkg.summary

    def transform(self, packages: Iterable[Package]) -> spdx_document.Document:
        for p in packages:
            # as we iterate the same set of packages, we must have it
            spdx_pkg = self.pkgs_by_purl[str(p.purl())]
            if isinstance(p, SourcePackage):
                self._enhance(spdx_pkg, p)

            spdx_pkg.external_references.append(
                spdx_package.ExternalPackageRef(
                    category=spdx_package.ExternalPackageRefCategory.PACKAGE_MANAGER,
                    reference_type=SPDX_REFERENCE_TYPE_DISTRIBUTION,
                    locator=p.locator,
                )
            )
            spdx_pkg.checksums = [
                Checksum(CHKSUM_TO_SPDX[alg], dig) for alg, dig in p.checksums.items()
            ]
        return self.document
