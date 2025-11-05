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
from .compare import SbomCompare
from ..sbom import (
    SPDX_REF_DOCUMENT,
    SPDX_REFERENCE_TYPE_PURL,
)


logger = logging.getLogger(__name__)


class SpdxSbomCompare(SbomCompare):
    def _load_spdx_sbom(self, sbom):
        ""
        packages = {}
        logger.info(f"Processing BOM '{sbom.creation_info.name}'")

        for package in sbom.packages:
            for external_ref in package.external_references:
                if external_ref.reference_type == SPDX_REFERENCE_TYPE_PURL:
                    purl = external_ref.locator
                    packages[purl] = package

        return packages

    def _get_spdx_pkg_sha256(self, package):
        for checksum in package.checksums:
            if checksum.algorithm == ChecksumAlgorithm.SHA256:
                return checksum.value
        return None

    def compare(self, base_sbom, target_sbom) -> Document:
        base_sbom_pkgs = self._load_spdx_sbom(base_sbom)
        target_sbom_pkgs = self._load_spdx_sbom(target_sbom)

        extras = []

        for purl, package in target_sbom_pkgs.items():
            base_pkg = base_sbom_pkgs.get(purl)

            if base_pkg is None:
                extras.append(package)
            else:
                base_pkg_sha256 = self._get_spdx_pkg_sha256(base_pkg)
                target_pkg_sha256 = self._get_spdx_pkg_sha256(package)
                if None not in (base_pkg_sha256, target_pkg_sha256) and base_pkg_sha256 != target_pkg_sha256:
                    extras.append(package)

        #for rel in doc.relationships:
        #    if progress_cb:
        #        progress_cb(cur_step, num_steps, f"Relationship: {rel.spdx_element_id}")
        #        cur_step += 1
        #    if (
        #        rel.spdx_element_id == SPDX_REF_DOCUMENT
        #        and rel.relationship_type == RelationshipType.DESCRIBES
        #    ):
                # skip adding the root DESCRIBES relationship
        #        continue
        #    element_id = rel.spdx_element_id
        #    if element_id in id_map:
        #        rel.spdx_element_id = id_map[rel.spdx_element_id]
        #    rel_element_id = rel.related_spdx_element_id
        #    if rel_element_id in id_map:
        #        rel.related_spdx_element_id = id_map[rel.related_spdx_element_id]

            # we can not use a set since the relationships
            # do not implement hash(..), so create the hash by hand
         #   rel_hash = self._hash_relationship(rel)
         #   if rel_hash not in relationships:
         #       relationships[rel_hash] = rel

        #distro_pkg = make_distro_package(
        #    distro_name=self.distro_name,
        #    distro_version=self.distro_version,
        #    distro_supplier=self.distro_supplier,
        #)
        #distro_ref = distro_pkg.spdx_id
        #packages[distro_ref] = distro_pkg

        # set up relationships between the distro package and the merged documents
        #relationships = list(
        #    itertools.chain(
        #        relationships.values(),
        #        map(
        #            lambda root_id: Relationship(
        #                spdx_element_id=root_id,
        #                relationship_type=RelationshipType.PACKAGE_OF,
        #                related_spdx_element_id=distro_ref,
        #            ),
        #            root_ids,
        #        ),
        #    )
        #)

        #distro_relationship = Relationship(
        #    spdx_element_id=SPDX_REF_DOCUMENT,
        #    relationship_type=RelationshipType.DESCRIBES,
        #    related_spdx_element_id=distro_ref,
        #)
        #logger.debug(f"Created document relationship: {distro_relationship}")

        #relationships.append(distro_relationship)

        #packages = itertools.chain(packages.values(), non_purl_packages)

        creation_info = make_creation_info(self.distro_name, self.namespace, self.timestamp)
        document = Document(
            creation_info=creation_info,
            packages=list(extras),
        )
        return document
