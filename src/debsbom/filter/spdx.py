# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.relationship import (
    Relationship,
    RelationshipType,
)

from .filter import SbomFilter
from ..sbom import SPDX_REF_DOCUMENT


class SpdxSbomFilter(SbomFilter):

    @classmethod
    def binary_pkgs(cls, document: Document):
        document.packages = [
            pkg
            for pkg in document.packages
            if (
                not pkg.external_references
                or any(
                    "arch=source" not in ref.locator
                    for ref in pkg.external_references
                    if ref.reference_type == "purl"
                )
            )
        ]

        binary_ids = {pkg.spdx_id: pkg for pkg in document.packages}
        document.relationships = [
            rel
            for rel in document.relationships
            if (rel.spdx_element_id in binary_ids and rel.related_spdx_element_id in binary_ids)
            or rel.spdx_element_id == SPDX_REF_DOCUMENT
        ]

    @classmethod
    def source_pkgs(cls, document: Document):
        document.packages = [
            pkg
            for pkg in document.packages
            if (
                not pkg.external_references
                or any(
                    "arch=source" in ref.locator
                    for ref in pkg.external_references
                    if ref.reference_type == "purl"
                )
            )
        ]

        src_pkg_ids = [pkg.spdx_id for pkg in document.packages]
        root_ref = None
        for rel in document.relationships:
            if rel.spdx_element_id == SPDX_REF_DOCUMENT:
                root_ref = rel.related_spdx_element_id
                break

        new_relationships = []

        if root_ref:
            new_relationships.append(
                Relationship(
                    spdx_element_id=SPDX_REF_DOCUMENT,
                    related_spdx_element_id=root_ref,
                    relationship_type=RelationshipType.DESCRIBES,
                )
            )

            for pkg_id in src_pkg_ids:
                if pkg_id == root_ref:
                    continue
                new_relationships.append(
                    Relationship(
                        spdx_element_id=pkg_id,
                        related_spdx_element_id=root_ref,
                        relationship_type=RelationshipType.DEPENDS_ON,
                    )
                )
        document.relationships = new_relationships
