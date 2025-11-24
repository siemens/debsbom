# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Callable
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component
from cyclonedx.model.dependency import Dependency
import itertools
import logging
from sortedcontainers import SortedSet
from uuid import uuid4

from ..util.checksum import NoMatchingDigestError, verify_best_matching_digest
from ..util.checksum_cdx import checksum_dict_from_cdx

from .merge import SbomMerger
from ..generate.cdx import make_distro_component, make_metadata


logger = logging.getLogger(__name__)


class CdxSbomMerger(SbomMerger):
    def _merge_component(self, component: Component, other: Component):
        # merge all fields that we use in our SBOMs, all other fields
        # are either part of the PURL or the PURL itself, and these
        # must match before merging
        try:
            verify_best_matching_digest(
                checksum_dict_from_cdx(component.hashes),
                checksum_dict_from_cdx(other.hashes),
                name=component.name,
                purl=str(component.purl),
            )
        except NoMatchingDigestError:
            pass
        if component.hashes is None:
            component.hashes = SortedSet([])
        for other_hash in other.hashes or []:
            if other_hash not in component.hashes:
                component.hashes.add(other_hash)

        if component.supplier is None:
            component.supplier = other.supplier
        if component.external_references is None:
            component.external_references = other.homepage
        if component.group is None:
            component.group = other.group

    def _merge_dependency(self, dependency: Dependency, other: Dependency):
        for dep in other.dependencies:
            if dep not in dependency.dependencies:
                dependency.dependencies.add(dep)

    def merge(
        self, sboms: list[Bom], progress_cb: Callable[[int, int, str], None] | None = None
    ) -> Bom:
        components = {}
        non_purl_components = []

        dependencies = {}

        root_bom_refs = []
        ref_map = {}

        num_steps = 0
        cur_step = 0
        if progress_cb:
            for sbom in sboms:
                num_steps += len(sbom.components) + len(sbom.dependencies)

        for sbom in sboms:
            logger.info(f"Processing BOM '{sbom.metadata.component.name}'")
            root_bom_refs.append(sbom.metadata.component.bom_ref)

            non_purl_components.append(sbom.metadata.component)

            for component in sbom.components:
                if progress_cb:
                    progress_cb(cur_step, num_steps, component.name)
                    cur_step += 1
                purl = component.purl
                if purl is None:
                    logger.warning(f"missing PURL for component '{component.name}'")
                    non_purl_components.append(component)
                    continue
                if purl in components:
                    logger.debug(f"Merging CDX component '{purl}'")
                    self._merge_component(components[purl], component)
                    # remember which bom refs map so we can fix them up later
                    ref_map[component.bom_ref] = components[purl].bom_ref
                else:
                    logger.debug(f"Adding CDX component '{purl}'")
                    components[purl] = component

            for dep in sbom.dependencies:
                if progress_cb:
                    ref_str = str(dep.ref)
                    progress_cb(cur_step, num_steps, f"Dependency: {ref_str}")
                    cur_step += 1
                # fix up bom refs
                if dep.ref in ref_map:
                    dep.ref = ref_map[dep.ref]

                for ref in dep.dependencies:
                    if ref in ref_map:
                        ref = ref_map[ref]

                if dep.ref in dependencies:
                    self._merge_dependency(dependencies[dep.ref], dep)
                else:
                    dependencies[dep.ref] = dep

        distro_component = make_distro_component(
            self.distro_name, self.distro_version, self.distro_supplier
        )
        bom_metadata = make_metadata(distro_component, self.timestamp)

        distro_deps = []
        for root_bom_ref in root_bom_refs:
            distro_deps.append(Dependency(ref=root_bom_ref))

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
