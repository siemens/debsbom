# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from packageurl import PackageURL

from ..dpkg.package import Dependency, Package, SourcePackage, BinaryPackage
from ..util.checksum_spdx import checksum_dict_from_spdx
from ..sbom import SPDXType
from .resolver import PackageResolver

import spdx_tools.spdx.model.package as spdx_package
import spdx_tools.spdx.model.document as spdx_document
from spdx_tools.spdx.model.relationship import RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion


class SpdxPackageResolver(PackageResolver, SPDXType):
    def __init__(self, document: spdx_document.Document):
        super().__init__()
        self._document = document
        self._pkgs_by_id: dict[str, Package] = dict(
            map(
                lambda p: (p.spdx_id, self.create_package(p)),
                filter(self.is_debian_pkg, self._document.packages),
            )
        )
        self._resolve_relations()
        self._pkgs = iter(self._pkgs_by_id.values())

    @property
    def document(self):
        """get the parsed SBOM document"""
        return self._document

    def __next__(self) -> Package:
        return next(self._pkgs)

    def _resolve_relations(self) -> None:
        """
        Restore the dependencies from the SBOM relations.

        This is partially debsbom specific, as it relies on the assumption
        that source packages relate to binary packages by using ``GENERATES``.
        """
        for rel in self._document.relationships:
            if rel.relationship_type == RelationshipType.GENERATES:
                src_pkg: SourcePackage = self._pkgs_by_id.get(rel.spdx_element_id)
                bin_pkg: BinaryPackage = self._pkgs_by_id.get(rel.related_spdx_element_id)
                if not src_pkg or not bin_pkg:
                    continue
                bin_pkg.source = Dependency(src_pkg.name, version=("=", src_pkg.version))
                src_pkg.binaries.append(bin_pkg.name)
            elif rel.relationship_type == RelationshipType.GENERATED_FROM:
                src_pkg: SourcePackage = self._pkgs_by_id.get(rel.related_spdx_element_id)
                bin_pkg: BinaryPackage = self._pkgs_by_id.get(rel.spdx_element_id)
                if not src_pkg or not bin_pkg:
                    continue
                bin_pkg.built_using.append(Dependency(src_pkg.name, version=("=", src_pkg.version)))
            elif rel.relationship_type == RelationshipType.DEPENDS_ON:
                pkg_self: BinaryPackage = self._pkgs_by_id.get(rel.spdx_element_id)
                pkg_other: BinaryPackage = self._pkgs_by_id.get(rel.related_spdx_element_id)
                if not pkg_self or not pkg_other:
                    continue
                pkg_self.depends.append(
                    Dependency(pkg_other.name, version=("=", pkg_other.version))
                )

    @classmethod
    def package_manager_ref(cls, p: spdx_package.Package) -> spdx_package.ExternalPackageRef | None:
        cat_pkg_manager = spdx_package.ExternalPackageRefCategory.PACKAGE_MANAGER
        return next(
            filter(lambda ref: ref.category == cat_pkg_manager, p.external_references), None
        )

    @classmethod
    def is_debian_pkg(cls, p: spdx_package.Package) -> bool:
        ref = cls.package_manager_ref(p)
        if ref and ref.reference_type == "purl":
            return cls.is_debian_purl(PackageURL.from_string(ref.locator))
        return False

    @classmethod
    def create_package(cls, p: spdx_package.Package) -> Package:
        pkg = Package.from_purl(cls.package_manager_ref(p).locator)
        pkg.maintainer = cls.get_maintainer(p)
        pkg.checksums = checksum_dict_from_spdx(p.checksums)
        return pkg

    @classmethod
    def get_maintainer(cls, p: spdx_package.Package) -> str | None:
        if not p.supplier or p.supplier == SpdxNoAssertion():
            return None
        supplier = p.supplier.name
        if p.supplier.email:
            supplier += f" <{p.supplier.email}>"
        return supplier
