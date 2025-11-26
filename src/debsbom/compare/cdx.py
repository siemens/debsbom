# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Callable
from cyclonedx.model import HashAlgorithm
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component
from cyclonedx.model.dependency import Dependency
import itertools
import logging
from sortedcontainers import SortedSet
from uuid import uuid4

from .compare import SbomCompare
from ..generate.cdx import make_distro_component, make_metadata


logger = logging.getLogger(__name__)


class CdxSbomCompare(SbomCompare):
    def _load_cdx_sbom(self, sbom):
        ""
        components = {}
        logger.info(f"Processing BOM '{sbom.metadata.component.name}'")

        for component in sbom.components:
            purl = component.purl
            components[purl] = component

        return components

    def _get_cdx_comp_sha256(self, component):
        for comp_hash in component.hashes:
            if comp_hash.alg == HashAlgorithm.SHA_256:
                return comp_hash.content

        return None


    def compare(self, base_sbom, target_sbom) -> Bom:
        base_sbom_comp = self._load_cdx_sbom(base_sbom)
        target_sbom_comp = self._load_cdx_sbom(target_sbom)

        extras = []

        for purl, component in target_sbom_comp.items():
            if purl is None:
                logger.warning(f"missing PURL for component '{component.name}'")
                continue
            base_comp_info = base_sbom_comp.get(purl)

            if base_comp_info is None:
                extras.append(component)
            else:
                base_comp_sha256 = self._get_cdx_comp_sha256(base_comp_info)
                target_comp_sha256 = self._get_cdx_comp_sha256(component)

                if None not in (base_comp_sha256, target_comp_sha256) and base_comp_sha256 != target_comp_sha256:
                    extras.append(component)

        distro_component = make_distro_component(
            self.distro_name, self.distro_version, self.distro_supplier
        )
        bom_metadata = make_metadata(distro_component, self.timestamp)

        #distro_deps = []
        #for root_bom_ref in root_bom_refs:
        #    distro_deps.append(Dependency(ref=root_bom_ref))

        #dependency = Dependency(
        #    ref=distro_component.bom_ref,
        #    dependencies=distro_deps,
        #)
        #logger.debug(f"Created distro dependency: {dependency}")
        #dependencies[dependency.ref] = dependency


        if self.cdx_serialnumber is None:
            serial_number = uuid4()
        else:
            serial_number = self.cdx_serialnumber

        bom = Bom(
            serial_number=serial_number,
            metadata=bom_metadata,
            components=list(extras),
        )

        return bom
