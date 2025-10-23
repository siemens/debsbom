# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Callable
import itertools
import logging
from spdx_tools.spdx.model.checksum import Checksum, ChecksumAlgorithm
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType

from ..generate.spdx import make_creation_info, make_distro_package
from .merge import ChecksumMismatchError, SbomMerger
from ..sbom import (
    SPDX_REF_DOCUMENT,
    SPDX_REFERENCE_TYPE_PURL,
)


logger = logging.getLogger(__name__)


class SpdxSbomMerger(SbomMerger):

    @classmethod
    def _purl_from_package(cls, package: Package) -> str | None:
        """Return the PURL of the package if it exists."""
        for external_ref in package.external_references:
            if external_ref.reference_type == SPDX_REFERENCE_TYPE_PURL:
                return external_ref.locator
        return None

    @classmethod
    def _hash_relationship(cls, rel: Relationship) -> int:
        return hash(
            (
                rel.spdx_element_id,
                str(rel.relationship_type),
                rel.related_spdx_element_id,
            )
        )

    def _merge_package(self, package: Package, other: Package):
        # merge all fields that we use, missing fields must be the
        # same since they are part of the PURL

        if package.checksums is None:
            package.checksums = []
        for other_chksum in other.checksums or []:
            for checksum in package.checksums:
                if checksum.algorithm == other_chksum.algorithm:
                    if checksum.value == other_chksum.value:
                        # we already have the checksum, continue
                        break
                    else:
                        purl = self._purl_from_package(package)
                        raise ChecksumMismatchError(
                            package.name,
                            purl,
                            str(checksum.algorithm),
                            checksum.value,
                            other_chksum.value,
                        )
                package.checksums.append(other_chksum)

        if package.download_location == SpdxNoAssertion():
            package.download_location = other.download_location
        if package.supplier == SpdxNoAssertion():
            package.supplier = other.supplier

        if package.homepage is None:
            package.homepage = other.homepage
        if not package.files_analyzed:
            package.files_analyzed = other.files_analyzed
        if package.license_concluded == SpdxNoAssertion():
            package.license_concluded = other.license_concluded
        if package.license_declared == SpdxNoAssertion():
            package.license_declared = other.license_declared
        if package.copyright_text == SpdxNoAssertion():
            package.copyright_text = other.copyright_text

    def merge(
        self, sboms: list[Document], progress_cb: Callable[[int, int, str], None] | None = None
    ) -> Document:
        root_ids = []
        packages = {}
        non_purl_packages = []
        relationships = {}
        id_map = {}

        num_steps = 0
        cur_step = 0
        if progress_cb:
            for doc in sboms:
                num_steps += len(doc.packages) + len(doc.relationships)

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
                if progress_cb:
                    progress_cb(cur_step, num_steps, package.name)
                    cur_step += 1
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
                if progress_cb:
                    progress_cb(cur_step, num_steps, f"Relationship: {rel.spdx_element_id}")
                    cur_step += 1
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
                map(
                    lambda root_id: Relationship(
                        spdx_element_id=root_id,
                        relationship_type=RelationshipType.PACKAGE_OF,
                        related_spdx_element_id=distro_ref,
                    ),
                    root_ids,
                ),
            )
        )

        distro_relationship = Relationship(
            spdx_element_id=SPDX_REF_DOCUMENT,
            relationship_type=RelationshipType.DESCRIBES,
            related_spdx_element_id=distro_ref,
        )
        logger.debug(f"Created document relationship: {distro_relationship}")

        relationships.append(distro_relationship)

        packages = itertools.chain(packages.values(), non_purl_packages)

        creation_info = make_creation_info(self.distro_name, self.namespace, self.timestamp)
        document = Document(
            creation_info=creation_info,
            packages=list(packages),
            relationships=relationships,
        )
        return document
