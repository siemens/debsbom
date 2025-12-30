# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from cyclonedx.model.bom import Bom
from cyclonedx.model.dependency import Dependency
import itertools
import logging
from uuid import uuid4

from .compare import SbomCompare
from ..generate.cdx import make_distro_component, make_metadata


logger = logging.getLogger(__name__)


class CdxSbomCompare(SbomCompare):
    def compare(self, base_sbom, target_sbom) -> Bom:
        components = {}
        non_purl_components = []
        dependencies = {}
        ref_map = {}

        non_purl_components.append(target_sbom.metadata.component)

        # Get the components list of base/reference SBOM
        base_components = {
            component.purl: component
            for component in base_sbom.components
            if component.purl is not None
        }

        for component in target_sbom.components:
            purl = component.purl
            if purl is None:
                logger.warning(f"missing PURL for component '{component.name}'")
                non_purl_components.append(component)
                continue
            else:
                logger.debug(f"Checking CDX component '{purl}' in reference SBOM")
                if purl not in base_components:
                    logger.debug(f"Adding CDX component '{purl}'")
                    components[purl] = component
                    ref_map[component.bom_ref] = components[purl].bom_ref

        for dep in target_sbom.dependencies:
            if dep.ref not in ref_map:
                continue

            # Add child dependencies only if they are present in the extra components list
            child_deps = [ch_dep for ch_dep in (dep.dependencies or []) if ch_dep.ref in ref_map]

            dependencies[dep.ref] = Dependency(ref=dep.ref, dependencies=child_deps)

        distro_component = make_distro_component(
            self.distro_name, self.distro_version, self.distro_supplier
        )
        bom_metadata = make_metadata(distro_component, self.timestamp)

        distro_deps = []
        target_bom_ref = target_sbom.metadata.component.bom_ref
        distro_deps.append(Dependency(ref=target_bom_ref))

        dependency = Dependency(
            ref=distro_component.bom_ref,
            dependencies=distro_deps,
        )
        logger.debug(f"Created distro dependency: {dependency}")
        dependencies[dependency.ref] = dependency

        if self.cdx_serialnumber is None:
            serial_number = uuid4()
        else:
            serial_number = self.cdx_serialnumber

        components = itertools.chain(components.values(), non_purl_components)

        bom = Bom(
            serial_number=serial_number,
            metadata=bom_metadata,
            components=list(components),
            dependencies=dependencies.values(),
        )

        return bom
