# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Iterable
import itertools
import logging
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType

from ..generate.spdx import make_creation_info, make_distro_package
from .merge import SbomMerger
from ..sbom import (
    SPDX_REF_DOCUMENT,
    SPDX_REFERENCE_TYPE_PURL,
)


logger = logging.getLogger(__name__)


class SpdxSbomMerger(SbomMerger):

    def _purl_from_package(self, package: Package) -> str | None:
        """Return the PURL of the package if it exists."""
        for external_ref in package.external_references:
            if external_ref.reference_type == SPDX_REFERENCE_TYPE_PURL:
                return external_ref.locator
        return None

    def _merge_package(self, package: Package, other: Package):
        if package.supplier == SpdxNoAssertion():
            package.supplier = other.supplier
        if package.checksums is None or package.checksums == []:
            package.checksums = other.checksums
        if package.homepage is None:
            package.homepage = other.homepage

    def merge_sboms(self, sboms: Iterable[Document]) -> Document:
        logger.info("Merging SBOMs")
        root_ids = []
        packages = {}
        non_purl_packages = []
        relationships = {}
        id_map = {}

        # TODO: progress
        for doc in sboms:
            logger.info(f"Processing document '{doc.creation_info.name}'")
            # first we need to find the root of the document
            root_id = None
            for relationship in doc.relationships:
                if relationship.spdx_element_id == SPDX_REF_DOCUMENT:
                    root_id = relationship.related_spdx_element_id
                    break
            if root_id is None:
                raise ValueError(f"failed to find root package in SBOM '{doc.creation_info.name}'")
            root_ids.append(root_id)

            for package in doc.packages:
                purl = self._purl_from_package(package)
                if purl is None:
                    if package.spdx_id not in root_ids:
                        # skip the warning if we have a root package
                        logger.warning(f"missing PURL for package '{package.name}'")
                    non_purl_packages.append(package)
                    continue
                if purl in packages:
                    logger.debug(f"Merging SPDX package '{purl}'")
                    self._merge_package(packages[purl], package)
                    # remember which IDs map to each other, so we can fix them up later
                    id_map[package.spdx_id] = packages[purl].spdx_id
                else:
                    logger.debug(f"Adding SPDX package '{purl}'")
                    packages[purl] = package

            for rel in doc.relationships:
                if (
                    rel.spdx_element_id == SPDX_REF_DOCUMENT
                    and rel.relationship_type == RelationshipType.DESCRIBES
                ):
                    # skip adding the root DESCRIBES relationship
                    continue
                element_id = rel.spdx_element_id
                if element_id in id_map:
                    rel.spdx_element_id = id_map[rel.spdx_element_id]
                rel_element_id = rel.related_spdx_element_id
                if rel_element_id in id_map:
                    rel.related_spdx_element_id = id_map[rel.related_spdx_element_id]

                # we can not use a set since the relationships
                # do not implement hash(..), so create the hash by hand
                def _hash_relationship(rel: Relationship) -> int:
                    return hash(
                        (
                            rel.spdx_element_id,
                            str(rel.relationship_type),
                            rel.related_spdx_element_id,
                        )
                    )

                rel_hash = _hash_relationship(rel)
                if rel_hash not in relationships:
                    relationships[rel_hash] = rel

        distro_pkg = make_distro_package(
            distro_name=self.distro_name,
            distro_version=self.distro_version,
            distro_supplier=self.distro_supplier,
        )
        distro_ref = distro_pkg.spdx_id
        packages[distro_ref] = distro_pkg

        relationships = relationships.values()

        # set up relationships between the distro package and the merged documents
        relationships = itertools.chain(
            relationships,
            map(
                lambda root_id: Relationship(
                    spdx_element_id=root_id,
                    relationship_type=RelationshipType.PACKAGE_OF,
                    related_spdx_element_id=distro_ref,
                ),
                root_ids,
            ),
        )

        distro_relationship = Relationship(
            spdx_element_id=SPDX_REF_DOCUMENT,
            relationship_type=RelationshipType.DESCRIBES,
            related_spdx_element_id=distro_ref,
        )
        logger.debug(f"Created document relationship: {distro_relationship}")

        relationships = list(relationships)
        relationships.append(distro_relationship)

        packages = itertools.chain(packages.values(), non_purl_packages)

        creation_info = make_creation_info(self.distro_name, self.namespace, self.timestamp)
        document = Document(
            creation_info=creation_info,
            packages=list(packages),
            relationships=relationships,
        )
        return document
