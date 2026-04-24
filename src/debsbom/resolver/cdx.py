# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import logging

from ..dpkg.package import Dependency, Package
from ..util.checksum_cdx import checksum_dict_from_cdx
from ..sbom import CDXType
from .resolver import PackageResolver

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, BomRef

logger = logging.getLogger(__name__)


class CdxPackageResolver(PackageResolver, CDXType):
    def __init__(self, document: Bom):
        super().__init__()
        self._document = document
        self._pkgs_by_id: dict[BomRef, Package] = dict(
            map(
                lambda p: ((p.bom_ref, self.create_package(p))),
                filter(self.is_debian_pkg, self._document.components),
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

        This is debsbom specific, as there is no standard way to express
        binary <-> source relations in CycloneDX. According to our design
        decisions, we map binaries to sources by ``dependsOn``.
        """
        for dep in self._document.dependencies:
            pkg_self = self._pkgs_by_id.get(dep.ref)
            if not pkg_self or pkg_self.is_source():
                continue
            for sub in dep.dependencies:
                pkg_other = self._pkgs_by_id.get(sub.ref)
                if not pkg_other:
                    continue
                # self is binary, other is source
                if pkg_other.is_source():
                    if pkg_self.source:
                        # as we cannot distinguish between binary->src package and built-using,
                        # we just apply a simple heuristic:
                        # if there is a source package with the same name, use it
                        # else use the first one add the remaining packages into built-using
                        if pkg_self.name == pkg_other.name:
                            # replace the source as we found a better one
                            pkg_self.built_using.append(pkg_self.source)
                            pkg_self.source = Dependency(
                                pkg_other.name, version=("=", pkg_other.version)
                            )
                        else:
                            # not a source candidate -> add to built-using
                            pkg_self.built_using.append(
                                Dependency(pkg_other.name, version=("=", pkg_other.version))
                            )
                    else:
                        pkg_self.source = Dependency(
                            pkg_other.name, version=("=", pkg_other.version)
                        )
                    pkg_other.binaries.append(pkg_self.name)
                else:
                    pkg_self.depends.append(
                        Dependency(pkg_other.name, version=("=", pkg_other.version))
                    )

    def root_component_name(self) -> str | None:
        """Return the name of the root component."""
        try:
            return self._document.metadata.component.name
        except AttributeError:
            return None

    @classmethod
    def is_debian_pkg(cls, p: Component):
        if p.purl:
            return cls.is_debian_purl(p.purl)
        return False

    @classmethod
    def create_package(cls, c: Component) -> Package:
        pkg = Package.from_purl(str(c.purl))
        pkg.maintainer = cls.get_maintainer(c)
        pkg.checksums = checksum_dict_from_cdx(c.hashes)
        return pkg

    @classmethod
    def get_maintainer(cls, c: Component) -> str | None:
        if not c.supplier:
            return None
        try:
            return f"{c.supplier.name} <{c.supplier.contacts[0].email}>"
        except (KeyError, IndexError):
            pass

        try:
            return f"{c.supplier.name}"
        except KeyError:
            return None
