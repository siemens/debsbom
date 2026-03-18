# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Iterable
import cyclonedx.model.bom as cdx_bom
import cyclonedx.model.component as cdx_component
import cyclonedx.model as cdx_model
import cyclonedx.model.definition as cdx_definition
from cyclonedx.model import HashType as cdx_hashtype

from ..generate.cdx import cdx_package_repr, make_standard_bom_standard
from ..sbom import CDXType
from .packer import BomTransformer
from ..dpkg.package import Package
from ..util.checksum_cdx import checksum_to_cdx


class StandardBomTransformerCDX(BomTransformer, CDXType):
    def __init__(self, bom: cdx_bom.Bom):
        self._document = bom

    @staticmethod
    def _enhance(cdx_comp: cdx_component.Component, p: Package):
        """fold in data we don't have in the CDX representation (yet)"""
        _cdx_comp = cdx_package_repr(p, {})
        if not cdx_comp.supplier:
            cdx_comp.supplier = _cdx_comp.supplier
        if not cdx_comp.description:
            cdx_comp.description = _cdx_comp.description

        if not any(
            [
                r.type == cdx_model.ExternalReferenceType.WEBSITE
                for r in cdx_comp.external_references
            ]
        ):
            _website = next(
                filter(
                    lambda r: r.type == cdx_model.ExternalReferenceType.WEBSITE,
                    _cdx_comp.external_references,
                ),
                None,
            )
            if _website:
                cdx_comp.external_references.add(_website)

    def transform(self, packages: Iterable[Package]) -> cdx_bom.Bom:
        # add the standard bom definition if it is missing
        if not self._document.definitions or "standard-bom" not in map(
            lambda s: s.bom_ref.value, self._document.definitions.standards
        ):
            standard = make_standard_bom_standard()
            if self._document.definitions:
                if self._document.definitions.standards:
                    self._document.definitions.standards.add(standard)
                else:
                    self._document.definitions.standards = [standard]
            else:
                self.document.definitions = cdx_definition.Definitions(standards=[standard])
        for p in packages:
            # as we iterate the same set of packages, we must have it
            cdx_comp: cdx_component.Component = self._document.get_component_by_purl(p.purl())
            if not cdx_comp:
                continue
            if p.is_source():
                self._enhance(cdx_comp, p)

            cdx_comp.external_references.add(
                cdx_model.ExternalReference(
                    url=cdx_model.XsUri(p.locator),
                    type=cdx_model.ExternalReferenceType.DISTRIBUTION,
                    comment="source archive (local copy)",
                    hashes=[
                        cdx_hashtype(alg=checksum_to_cdx(alg), content=dig)
                        for alg, dig in p.checksums.items()
                    ],
                ),
            )
        return self._document
