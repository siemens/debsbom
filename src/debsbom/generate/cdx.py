# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import cyclonedx.model as cdx_model
import cyclonedx.model.bom as cdx_bom
import cyclonedx.model.bom_ref as cdx_bom_ref
import cyclonedx.model.component as cdx_component
import cyclonedx.model.contact as cdx_contact
import cyclonedx.model.dependency as cdx_dependency
from datetime import datetime
import logging
from sortedcontainers import SortedSet
from typing import Callable, Dict, List, Tuple
from uuid import UUID, uuid4

from ..dpkg.package import BinaryPackage, Package, SourcePackage
from ..sbom import SUPPLIER_PATTERN, CDX_REF_PREFIX, Reference, SBOMType


logger = logging.getLogger(__name__)


def cdx_package_repr(
    package: Package, refs: Dict[str, cdx_bom_ref.BomRef]
) -> cdx_component.Component | None:
    """Get the CDX representation of a Package."""
    if isinstance(package, BinaryPackage):
        ref = Reference(package.name).as_str(SBOMType.CycloneDX)
        refs[ref] = cdx_bom_ref.BomRef(ref)

        match = SUPPLIER_PATTERN.match(package.maintainer)
        supplier = cdx_contact.OrganizationalEntity(name=match["supplier_name"])
        supplier_email = match["supplier_email"]
        if supplier_email:
            supplier.contacts = [cdx_contact.OrganizationalContact(email=supplier_email)]
        entry = cdx_component.Component(
            name=package.name,
            type=cdx_component.ComponentType.LIBRARY,
            bom_ref=refs[ref],
            supplier=supplier,
            version=str(package.version),
            description=package.description,
            purl=package.purl(),
        )
        if package.homepage:
            entry.externalReferences = (
                cdx_model.ExternalReference(
                    url=cdx_model.XsUri(package.homepage),
                    type=cdx_model.ExternalReferenceType.WEBSITE,
                    comment="homepage",
                ),
            )
        logger.debug(f"Created binary component: {entry}")
        return entry
    elif isinstance(package, SourcePackage):
        # TODO: we are missing source packages here
        # Figure out how do properly represent them and the source<->binary relationship,
        # see https://github.com/CycloneDX/specification/issues/612#issuecomment-2958815330
        logger.debug(f"Skipped component for source package: '{package.name}'")
        return None


def cyclonedx_bom(
    packages: List[Package],
    distro_name: str,
    distro_supplier: str | None = None,
    distro_version: str | None = None,
    serial_number: UUID | None = None,
    timestamp: datetime | None = None,
    progress_cb: Callable[[int, int, str], None] | None = None,
) -> cdx_bom.Bom:
    """Return a valid CycloneDX SBOM."""
    data = SortedSet([])
    dependencies = SortedSet([])

    binary_packages = [p for p in packages if isinstance(p, BinaryPackage)]

    # progress tracking
    num_steps = len(packages) + len(binary_packages)
    cur_step = 0

    # bom refs need to be unique so store them there with the
    # string representation as key
    refs = {}

    logger.info("Creating components...")
    for package in packages:
        if progress_cb:
            progress_cb(cur_step, num_steps, package.name)
        cur_step += 1

        entry = cdx_package_repr(package, refs)
        if entry is None:
            continue
        data.add(entry)

    distro_bom_ref = CDX_REF_PREFIX + distro_name
    refs[distro_bom_ref] = cdx_bom_ref.BomRef(distro_bom_ref)

    distro_dependencies = []
    logger.info("Resolving dependencies...")
    # after we have found all packages we can start to resolve dependencies
    for package in binary_packages:
        if progress_cb:
            progress_cb(cur_step, num_steps, package.name)
        cur_step += 1

        reference = Reference(package.name)
        distro_dependencies.append(
            cdx_dependency.Dependency(refs[reference.as_str(SBOMType.CycloneDX)])
        )
        if package.depends:
            deps = SortedSet([])
            for dep in package.depends:
                try:
                    dref = Reference(dep.name)
                    dep_bom_ref = refs[dref.as_str(SBOMType.CycloneDX)]
                except KeyError:
                    # this means we have a virtual dependency, ignore it
                    logger.debug(f"Skipped optional dependency: '{dep.name}'")
                    continue
                deps.add(cdx_dependency.Dependency(ref=dep_bom_ref))
            dependency = cdx_dependency.Dependency(
                ref=refs[reference.as_str(SBOMType.CycloneDX)],
                dependencies=deps,
            )
            logger.debug(f"Created dependency: {dependency}")
            dependencies.add(dependency)
    dependency = cdx_dependency.Dependency(
        ref=refs[distro_bom_ref],
        dependencies=distro_dependencies,
    )
    logger.debug(f"Created distro dependency: {dependency}")
    dependencies.add(dependency)

    if distro_supplier:
        supplier = cdx_contact.OrganizationalEntity(name=distro_supplier)
    else:
        supplier = None

    distro_component = cdx_component.Component(
        type=cdx_component.ComponentType.OPERATING_SYSTEM,
        bom_ref=refs[distro_bom_ref],
        supplier=supplier,
        name=distro_name,
        version=distro_version,
    )

    if serial_number is None:
        serial_number = uuid4()

    if timestamp is None:
        timestamp = datetime.now()

    bom = cdx_bom.Bom(
        serial_number=serial_number,
        metadata=cdx_bom.BomMetaData(
            timestamp=timestamp,
            component=distro_component,
        ),
        components=data,
        dependencies=dependencies,
    )
    return bom
