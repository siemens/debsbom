# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import itertools
import logging
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType

from ..generate.spdx import make_creation_info, make_distro_package
from .compare import SbomCompare
from ..sbom import (
    SPDX_REF_DOCUMENT,
    SPDX_REFERENCE_TYPE_PURL,
)


logger = logging.getLogger(__name__)


class SpdxSbomCompare(SbomCompare):
    def _purl_from_package(self, package: Package) -> str | None:
        """Return the PURL of the package if it exists."""
        for external_ref in package.external_references:
            if external_ref.reference_type == SPDX_REFERENCE_TYPE_PURL:
                return external_ref.locator
        return None

    def _hash_relationship(cls, rel: Relationship) -> int:
        return hash(
            (
                rel.spdx_element_id,
                str(rel.relationship_type),
                rel.related_spdx_element_id,
            )
        )

    def compare(self, base_sbom, target_sbom) -> Document:
        packages = {}
        non_purl_packages = []
        relationships = {}
        id_map = {}

        root_id = None
        for relationship in target_sbom.relationships:
            if relationship.spdx_element_id == SPDX_REF_DOCUMENT:
                root_id = relationship.related_spdx_element_id
                break
        if root_id is None:
            raise ValueError(
                f"failed to find root package in SBOM '{target_sbom.creation_info.name}'"
            )

        # Get the components list of base/reference SBOM
        base_packages = {
            self._purl_from_package(package): package
            for package in base_sbom.packages
            if self._purl_from_package(package) is not None
        }

        for package in target_sbom.packages:
            purl = self._purl_from_package(package)

            if purl is None:
                if package.spdx_id != root_id:
                    logger.warning(f"missing PURL for package '{package.name}'")
                non_purl_packages.append(package)
                continue

            if purl not in base_packages:
                logger.debug(f"Adding SPDX package '{purl}'")
                packages[purl] = package
                id_map[package.spdx_id] = packages[purl].spdx_id

        for rel in target_sbom.relationships:
            if (
                rel.spdx_element_id == SPDX_REF_DOCUMENT
                and rel.relationship_type == RelationshipType.DESCRIBES
            ):
                # skip adding the root DESCRIBES relationship
                continue

            if rel.spdx_element_id not in id_map:
                continue

            rel.spdx_element_id = id_map[rel.spdx_element_id]

            if rel.related_spdx_element_id in id_map:
                rel.related_spdx_element_id = id_map[rel.related_spdx_element_id]

            rel_hash = self._hash_relationship(rel)
            if rel_hash not in relationships:
                relationships[rel_hash] = rel

        distro_pkg = make_distro_package(
            distro_name=self.distro_name,
            distro_version=self.distro_version,
            distro_supplier=self.distro_supplier,
        )
        distro_ref = distro_pkg.spdx_id
        packages[distro_ref] = distro_pkg

        # set up relationships between the distro package and the merged documents
        relationships = list(
            itertools.chain(
                relationships.values(),
                [
                    Relationship(
                        spdx_element_id=root_id,
                        relationship_type=RelationshipType.PACKAGE_OF,
                        related_spdx_element_id=distro_ref,
                    )
                ],
            )
        )

        distro_relationship = Relationship(
            spdx_element_id=SPDX_REF_DOCUMENT,
            relationship_type=RelationshipType.DESCRIBES,
            related_spdx_element_id=distro_ref,
        )
        logger.debug(f"Created document relationship: {distro_relationship}")

        packages = itertools.chain(packages.values(), non_purl_packages)

        creation_info = make_creation_info(self.distro_name, self.namespace, self.timestamp)
        document = Document(
            creation_info=creation_info,
            packages=list(packages),
            relationships=relationships,
        )
        return document
