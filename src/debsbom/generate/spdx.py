# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Callable
from datetime import datetime
from importlib.metadata import version
import logging
import spdx_tools.spdx.model.actor as spdx_actor
import spdx_tools.spdx.model.document as spdx_document
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
import spdx_tools.spdx.model.package as spdx_package
import spdx_tools.spdx.model.relationship as spdx_relationship
from spdx_tools.spdx.model.checksum import Checksum, ChecksumAlgorithm
from urllib.parse import urlparse, urlunparse
from uuid import uuid4

from ..dpkg.package import BinaryPackage, Package, SourcePackage, ChecksumAlgo
from ..sbom import (
    Reference,
    SPDX_REF_PREFIX,
    SPDX_REF_DOCUMENT,
    SUPPLIER_PATTERN,
    SPDX_REFERENCE_TYPE_PURL,
    SPDX_SUPPLIER_ORG_CUE,
    SBOMType,
)

CHKSUM_TO_SPDX = {
    ChecksumAlgo.MD5SUM: ChecksumAlgorithm.MD5,
    ChecksumAlgo.SHA1SUM: ChecksumAlgorithm.SHA1,
    ChecksumAlgo.SHA256SUM: ChecksumAlgorithm.SHA256,
}

logger = logging.getLogger(__name__)


def spdx_package_repr(package: Package, vendor: str = "debian") -> spdx_package.Package:
    """Get the SPDX representation of a Package."""
    match = SUPPLIER_PATTERN.match(package.maintainer or "")
    if match:
        supplier_name = match["supplier_name"].strip()
        supplier_email = match["supplier_email"]
    if match and any([cue in supplier_name.lower() for cue in SPDX_SUPPLIER_ORG_CUE]):
        supplier = spdx_actor.Actor(
            actor_type=spdx_actor.ActorType.ORGANIZATION,
            name=supplier_name,
            email=supplier_email,
        )
    elif match:
        supplier = spdx_actor.Actor(
            actor_type=spdx_actor.ActorType.PERSON,
            name=supplier_name,
            email=supplier_email,
        )
    else:
        supplier = SpdxNoAssertion()
        logger.warning(f"no supplier for {package.name}@{package.version}")
    if isinstance(package, BinaryPackage):
        spdx_pkg = spdx_package.Package(
            spdx_id=Reference.make_from_pkg(package).as_str(SBOMType.SPDX),
            name=package.name,
            download_location=SpdxNoAssertion(),
            version=str(package.version),
            supplier=supplier,
            files_analyzed=False,
            # TODO: it should be possible to conclude license/copyright
            # information, we could look e.g. in /usr/share/doc/*/copyright
            license_concluded=SpdxNoAssertion(),
            license_declared=SpdxNoAssertion(),
            copyright_text=SpdxNoAssertion(),
            summary=package.description,
            external_references=[
                spdx_package.ExternalPackageRef(
                    category=spdx_package.ExternalPackageRefCategory.PACKAGE_MANAGER,
                    reference_type=SPDX_REFERENCE_TYPE_PURL,
                    locator=package.purl(vendor).to_string(),
                )
            ],
            primary_package_purpose=spdx_package.PackagePurpose.LIBRARY,
            checksums=[
                Checksum(CHKSUM_TO_SPDX[alg], dig) for alg, dig in package.checksums.items()
            ],
        )
        if package.homepage:
            url = urlparse(package.homepage)
            url = url._replace(netloc=url.netloc.lower())
            spdx_pkg.homepage = urlunparse(url)
        logger.debug(f"Created binary package: {spdx_pkg}")
        return spdx_pkg
    elif isinstance(package, SourcePackage):
        spdx_pkg = spdx_package.Package(
            spdx_id=Reference.make_from_pkg(package).as_str(SBOMType.SPDX),
            name=package.name,
            version=str(package.version),
            supplier=supplier,
            files_analyzed=False,
            license_concluded=SpdxNoAssertion(),
            license_declared=SpdxNoAssertion(),
            download_location=SpdxNoAssertion(),
            copyright_text=SpdxNoAssertion(),
            summary="Debian source code package '{}'".format(package.name),
            external_references=[
                spdx_package.ExternalPackageRef(
                    category=spdx_package.ExternalPackageRefCategory.PACKAGE_MANAGER,
                    reference_type=SPDX_REFERENCE_TYPE_PURL,
                    locator=package.purl(vendor).to_string(),
                )
            ],
            primary_package_purpose=spdx_package.PackagePurpose.SOURCE,
        )
        logger.debug(f"Created source package: {spdx_pkg}")
        return spdx_pkg


def spdx_bom(
    packages: set[Package],
    distro_name: str,
    distro_supplier: str | None = None,
    distro_version: str | None = None,
    base_distro_vendor: str | None = "debian",
    namespace: tuple | None = None,  # 6 item tuple representing an URL
    timestamp: datetime | None = None,
    progress_cb: Callable[[int, int, str], None] | None = None,
) -> spdx_document.Document:
    "Return a valid SPDX SBOM."

    if distro_supplier is None:
        supplier = None
    else:
        supplier = spdx_actor.Actor(
            actor_type=spdx_actor.ActorType.ORGANIZATION,
            name=distro_supplier,
        )

    data = []
    # create an entry for the distribution
    distro_ref = SPDX_REF_PREFIX + distro_name
    distro_package = spdx_package.Package(
        spdx_id=distro_ref,
        name=distro_name,
        download_location=SpdxNoAssertion(),
        version=distro_version,
        primary_package_purpose=spdx_package.PackagePurpose.OPERATING_SYSTEM,
        supplier=supplier,
        files_analyzed=False,
        license_concluded=SpdxNoAssertion(),
        license_declared=SpdxNoAssertion(),
        copyright_text=SpdxNoAssertion(),
    )

    data.append(distro_package)

    binary_packages = [p for p in packages if isinstance(p, BinaryPackage)]

    # progress tracking
    num_steps = len(packages) + len(binary_packages)
    cur_step = 0

    logger.info("Creating packages...")
    for package in packages:
        if progress_cb:
            progress_cb(cur_step, num_steps, package.name)
        cur_step += 1

        entry = spdx_package_repr(package, vendor=base_distro_vendor)
        data.append(entry)

    relationships = []
    logger.info("Resolving dependencies...")
    # after we have found all packages we can start to resolve dependencies
    refs = set(map(lambda p: Reference.make_from_pkg(p).as_str(SBOMType.SPDX), binary_packages))
    for package in binary_packages:
        if progress_cb:
            progress_cb(cur_step, num_steps, package.name)
        cur_step += 1

        reference = Reference.make_from_pkg(package)
        if package.manually_installed:
            relationships.append(
                spdx_relationship.Relationship(
                    spdx_element_id=reference.as_str(SBOMType.SPDX),
                    relationship_type=spdx_relationship.RelationshipType.PACKAGE_OF,
                    related_spdx_element_id=distro_ref,
                )
            )
        if package.depends:
            for dep in package.unique_depends:
                ref_id = Reference.lookup(package, dep, SBOMType.SPDX, refs)
                if ref_id:
                    relationship = spdx_relationship.Relationship(
                        spdx_element_id=reference.as_str(SBOMType.SPDX),
                        relationship_type=spdx_relationship.RelationshipType.DEPENDS_ON,
                        related_spdx_element_id=ref_id,
                    )
                    logger.debug(f"Created dependency relationship: {relationship}")
                    relationships.append(relationship)
                else:
                    # this might happen if we have optional dependencies
                    logger.debug(f"Skipped optional dependency: '{dep.name}'")

        if package.built_using:
            for dep in package.built_using:
                bu_dep = Reference.make_from_dep(dep)
                relationship = spdx_relationship.Relationship(
                    spdx_element_id=reference.as_str(SBOMType.SPDX),
                    relationship_type=spdx_relationship.RelationshipType.GENERATED_FROM,
                    related_spdx_element_id=bu_dep.as_str(SBOMType.SPDX),
                    comment="built-using",
                )
                logger.debug(f"Created built-using relationship: {relationship}")
                relationships.append(relationship)

        if package.source:
            sref = Reference.make_from_dep(package.source)
            relationship = spdx_relationship.Relationship(
                spdx_element_id=sref.as_str(SBOMType.SPDX),
                relationship_type=spdx_relationship.RelationshipType.GENERATES,
                related_spdx_element_id=reference.as_str(SBOMType.SPDX),
            )
            logger.debug(f"Created source relationship: {relationship}")
            relationships.append(relationship)

    distro_relationship = spdx_relationship.Relationship(
        spdx_element_id=SPDX_REF_DOCUMENT,
        relationship_type=spdx_relationship.RelationshipType.DESCRIBES,
        related_spdx_element_id=distro_ref,
    )
    logger.debug(f"Created document relationship: {distro_relationship}")
    relationships.append(distro_relationship)

    if namespace is None:
        namespace = urlparse(
            "https://spdx.org/spdxdocs/debsbom-{}-{}".format(
                version("debsbom"),
                uuid4(),
            )
        )

    if timestamp is None:
        timestamp = datetime.now()

    creation_info = spdx_document.CreationInfo(
        spdx_version="SPDX-2.3",
        spdx_id=SPDX_REF_DOCUMENT,
        name=distro_name,
        document_namespace=urlunparse(namespace),
        creators=[
            spdx_actor.Actor(
                actor_type=spdx_actor.ActorType.TOOL,
                name="debsbom-{}".format(version("debsbom")),
            )
        ],
        created=timestamp,
    )
    document = spdx_document.Document(
        creation_info=creation_info,
        packages=data,
        relationships=relationships,
    )
    return document
