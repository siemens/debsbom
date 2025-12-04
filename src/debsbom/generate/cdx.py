# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from importlib.metadata import version, metadata
import cyclonedx.model as cdx_model
import cyclonedx.model.bom as cdx_bom
import cyclonedx.model.bom_ref as cdx_bom_ref
import cyclonedx.model.component as cdx_component
import cyclonedx.model.tool as cdx_tool
import cyclonedx.model.contact as cdx_contact
import cyclonedx.model.dependency as cdx_dependency
import cyclonedx.model.definition as cdx_definition
from cyclonedx.model import HashAlgorithm as cdx_hashalgo
from cyclonedx.model import HashType as cdx_hashtype
from datetime import datetime
import logging
from sortedcontainers import SortedSet
from uuid import UUID, uuid4
from collections.abc import Callable

from ..util.checksum_cdx import checksum_to_cdx
from ..dpkg.package import Package, DpkgStatus, filter_binaries
from ..sbom import SUPPLIER_PATTERN, CDX_REF_PREFIX, Reference, SBOMType, BOM_Standard

logger = logging.getLogger(__name__)


def cdx_package_repr(
    package: Package, refs: dict[str, cdx_bom_ref.BomRef], vendor: str = "debian"
) -> cdx_component.Component | None:
    """
    Get the CDX representation of a Package.

    CycloneDX v1.6 does not have a proposed way of expressing the relation
    between a source package and a binary package in a machine readable way.
    Until this is fixed in the spec, we add the source packages similar to
    binary packages, where they can be distinguished by the PURL. We further add
    a dependency from the binary to the source package.
    Also see: https://github.com/CycloneDX/specification/issues/612#issuecomment-2958815330
    """
    ref = Reference.make_from_pkg(package).as_str(SBOMType.CycloneDX)
    refs[ref] = cdx_bom_ref.BomRef(package.purl().to_string())

    match = SUPPLIER_PATTERN.match(package.maintainer or "")
    if match:
        supplier = cdx_contact.OrganizationalEntity(name=match["supplier_name"].strip())
        supplier_email = match["supplier_email"]
        if supplier_email:
            supplier.contacts = [cdx_contact.OrganizationalContact(email=supplier_email)]
    else:
        supplier = None
        logger.warning(f"no supplier for {package}")
    entry = cdx_component.Component(
        name=package.name,
        type=cdx_component.ComponentType.LIBRARY,
        bom_ref=refs[ref],
        supplier=supplier,
        version=str(package.version),
        purl=package.purl(vendor),
        group="debian",
        hashes=[
            cdx_hashtype(alg=checksum_to_cdx(alg), content=dig)
            for alg, dig in package.checksums.items()
        ],
    )
    external_refs = []
    if package.homepage:
        external_refs.append(
            cdx_model.ExternalReference(
                url=cdx_model.XsUri(package.homepage),
                type=cdx_model.ExternalReferenceType.WEBSITE,
                comment="homepage",
            ),
        )
    if package.is_binary():
        entry.description = package.description
        entry.properties.add(cdx_model.Property(name="section", value=package.section))
        logger.debug(f"Created binary component: {entry}")
    elif package.is_source():
        if package.vcs:
            external_refs.append(
                cdx_model.ExternalReference(
                    url=cdx_model.XsUri(package.vcs.locator),
                    type=cdx_model.ExternalReferenceType.VCS,
                    comment=f"Version control system of type {package.vcs.type.value}",
                ),
            )
        logger.debug(f"Created source component: {entry}")
    else:
        raise RuntimeError(f"The package {package} is neither a source nor a binary package")
    entry.external_references = external_refs
    return entry


def make_distro_component(
    distro_name: str, distro_version: str | None, distro_supplier: str | None
) -> cdx_component.Component:
    distro_bom_ref = CDX_REF_PREFIX + distro_name

    if distro_supplier:
        supplier = cdx_contact.OrganizationalEntity(name=distro_supplier)
    else:
        supplier = None

    distro_component = cdx_component.Component(
        type=cdx_component.ComponentType.OPERATING_SYSTEM,
        bom_ref=distro_bom_ref,
        supplier=supplier,
        name=distro_name,
        version=distro_version,
    )
    return distro_component


def make_metadata(
    component: cdx_component.Component,
    timestamp: datetime | None = None,
    add_meta_data: dict[str, str] | None = None,
) -> cdx_bom.BomMetaData:
    if timestamp is None:
        timestamp = datetime.now()

    tool_urls = metadata("debsbom").get_all("Project-URL")
    tool_component = cdx_component.Component(
        bom_ref=cdx_bom_ref.BomRef(
            Reference("debsbom-{}".format(version("debsbom"))).as_str(SBOMType.CycloneDX)
        ),
        type=cdx_component.ComponentType.APPLICATION,
        name="debsbom",
        version=version("debsbom"),
    )
    if tool_urls:
        tool_component.external_references = (
            cdx_model.ExternalReference(
                url=cdx_model.XsUri(tool_urls[0].split(",")[1].strip()),
                type=cdx_model.ExternalReferenceType.WEBSITE,
            ),
        )

    bom_metadata = cdx_bom.BomMetaData(
        timestamp=timestamp,
        component=component,
        tools=cdx_tool.ToolRepository(components=[tool_component]),
    )

    # add meta-data as cyclonedx property
    if add_meta_data:
        bom_metadata.properties = [
            cdx_model.Property(name=key, value=value) for key, value in add_meta_data.items()
        ]

    return bom_metadata


def cyclonedx_bom(
    packages: set[Package],
    distro_name: str,
    distro_arch: str,
    distro_supplier: str | None = None,
    distro_version: str | None = None,
    base_distro_vendor: str | None = "debian",
    serial_number: UUID | None = None,
    timestamp: datetime | None = None,
    add_meta_data: dict[str, str] | None = None,
    standard: BOM_Standard = BOM_Standard.DEFAULT,
    progress_cb: Callable[[int, int, str], None] | None = None,
) -> cdx_bom.Bom:
    """Return a valid CycloneDX SBOM."""
    data = SortedSet([])
    dependencies = SortedSet([])

    binary_packages = list(filter_binaries(packages))

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

        entry = cdx_package_repr(package, refs, vendor=base_distro_vendor)
        if entry is None:
            continue
        data.add(entry)

    distro_dependencies = []
    logger.info("Resolving dependencies...")
    # after we have found all packages we can start to resolve dependencies
    for package in binary_packages:
        if progress_cb:
            progress_cb(cur_step, num_steps, package.name)
        cur_step += 1

        reference = Reference.make_from_pkg(package)
        if package.manually_installed:
            distro_dependencies.append(
                cdx_dependency.Dependency(refs[reference.as_str(SBOMType.CycloneDX)])
            )
        # copy the depends to not alter the package itself
        pkg_deps = list(package.unique_depends) or []
        # add dependency to source package
        if package.source:
            pkg_deps.append(package.source)
        pkg_deps.extend(package.built_using)

        deps = SortedSet([])
        for dep in pkg_deps:
            try:
                ref_id = Reference.lookup(
                    package, dep, SBOMType.CycloneDX, refs.keys(), distro_arch
                )
                dep_bom_ref = refs[ref_id]
            except KeyError:
                # this means we have a virtual dependency, ignore it
                logger.debug(f"Skipped optional dependency: '{dep.name}'")
                continue
            deps.add(cdx_dependency.Dependency(ref=dep_bom_ref))
        if pkg_deps:
            dependency = cdx_dependency.Dependency(
                ref=refs[reference.as_str(SBOMType.CycloneDX)],
                dependencies=deps,
            )
            logger.debug(f"Created dependency: {dependency}")
            dependencies.add(dependency)

    distro_component = make_distro_component(distro_name, distro_version, distro_supplier)
    refs[distro_component.bom_ref] = distro_component.bom_ref

    dependency = cdx_dependency.Dependency(
        ref=refs[distro_component.bom_ref],
        dependencies=distro_dependencies,
    )
    logger.debug(f"Created distro dependency: {dependency}")
    dependencies.add(dependency)

    bom_metadata = make_metadata(distro_component, timestamp, add_meta_data)

    if serial_number is None:
        serial_number = uuid4()

    bom = cdx_bom.Bom(
        serial_number=serial_number,
        metadata=bom_metadata,
        components=data,
        dependencies=dependencies,
    )

    if standard == BOM_Standard.STANDARD_BOM:
        bom.definitions = cdx_definition.Definitions(
            standards=[
                cdx_definition.Standard(
                    bom_ref=cdx_bom_ref.BomRef("standard-bom"),
                    name="Standard BOM",
                    version="3.0.0",
                    description="The Standard for Software Bills of Materials in Siemens",
                    owner="Siemens AG",
                    external_references=[
                        cdx_model.ExternalReference(
                            url=cdx_model.XsUri("https://sbom.siemens.io"),
                            type=cdx_model.ExternalReferenceType.WEBSITE,
                        )
                    ],
                )
            ],
        )

    return bom
