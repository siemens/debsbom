# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import re
from collections.abc import Callable, Iterable
from datetime import datetime
from hashlib import sha1, sha256
from importlib.metadata import version
from license_expression import AND, ExpressionError
import logging
from pathlib import Path
import spdx_tools.spdx.model.actor as spdx_actor
import spdx_tools.spdx.model.document as spdx_document
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
import spdx_tools.spdx.model.package as spdx_package
import spdx_tools.spdx.model.relationship as spdx_relationship
import spdx_tools.spdx.spdx_element_utils as spdx_element_utils
import spdx_tools.spdx3.bump_from_spdx2.creation_info as spdx3_bump_creation_info
import spdx_tools.spdx3.bump_from_spdx2.package as spdx3_bump_package
import spdx_tools.spdx3.bump_from_spdx2.relationship as spdx3_bump_relationship
import spdx_tools.spdx3.bump_from_spdx2.actor as spdx3_bump_actor
import spdx_tools.spdx3.model.artifact as spdx3_artifact
import spdx_tools.spdx3.model.creation_info as spdx3_creation_info
import spdx_tools.spdx3.model.element as spdx3_element
import spdx_tools.spdx3.model.external_identifier as spdx3_external_identifier
import spdx_tools.spdx3.model.external_reference as spdx3_external_reference
import spdx_tools.spdx3.model.namespace_map as spdx3_namespace_map
import spdx_tools.spdx3.model.organization as spdx3_organization
import spdx_tools.spdx3.model.relationship as spdx3_relationship
import spdx_tools.spdx3.model.security.vuln_assessment_relationship as spdx3_vlun_assessment_relationship
import spdx_tools.spdx3.model.software.file as spdx3_file
import spdx_tools.spdx3.model.software.sbom as spdx3_software_sbom
import spdx_tools.spdx3.model.software.software_purpose as spdx3_software_purpose
import spdx_tools.spdx3.model.software_agent as spdx_software_agent
import spdx_tools.spdx3.model.spdx_collection as spdx3_collection
import spdx_tools.spdx3.model.spdx_document as spdx3_spdx_document
import spdx_tools.spdx3.payload as spdx3_payload
from spdx_tools.spdx.model.checksum import Checksum
from urllib.parse import urlparse, urlunparse, urlsplit
from uuid import uuid4

from ..apt.copyright import UnknownLicenseError
from ..dpkg.package import (
    BinaryPackage,
    DebianPriority,
    Dependency,
    Package,
    VirtualPackage,
    filter_binaries,
)
from ..util.checksum import calculate_checksums
from ..util.checksum_spdx import checksum_to_spdx
from ..util.gitoid import gitoid_hashes
from ..util.omnibor import artifact_id_from_digest
from ..util.swh import swh_id_from_digest
from ..sbom import (
    Reference,
    SPDX_REF_PREFIX,
    SPDX_REF_DOCUMENT,
    SPDX_REFERENCE_TYPE_GITOID,
    SPDX_REFERENCE_TYPE_SWH,
    SUPPLIER_PATTERN,
    SPDX_REFERENCE_TYPE_PURL,
    SPDX_REFERENCE_TYPE_VCS,
    SPDX_SUPPLIER_ORG_CUE,
    SBOMType,
    SPDX_ID_RE,
)

logger = logging.getLogger(__name__)


def make_distro_package(
    distro_name: str,
    distro_version: str | None = None,
    distro_supplier: str | None = None,
    distro_summary: str | None = None,
    artifact: Path | None = None,
) -> spdx_package.Package:
    if distro_supplier is None:
        supplier = spdx_actor.Actor(
            actor_type=spdx_actor.ActorType.TOOL, name=f'debsbom-{version("debsbom")}'
        )
    else:
        m = SUPPLIER_PATTERN.search(distro_supplier)
        if m and m.lastindex == 2:
            url_parts = urlsplit(m["supplier_email"], scheme="mailto")
            supplier = spdx_actor.Actor(
                actor_type=(
                    spdx_actor.ActorType.PERSON
                    if url_parts.scheme == "mailto"
                    else spdx_actor.ActorType.ORGANIZATION
                ),
                name=m["supplier_name"].strip(),
                email=m["supplier_email"].strip(),
            )
        else:
            supplier = spdx_actor.Actor(
                actor_type=spdx_actor.ActorType.ORGANIZATION,
                name=distro_supplier,
            )

    # create an entry for the distribution
    distro_ref = SPDX_REF_PREFIX + distro_name
    distro_package = spdx_package.Package(
        spdx_id=distro_ref,
        name=distro_name,
        summary=distro_summary,
        download_location=SpdxNoAssertion(),
        version=distro_version,
        primary_package_purpose=spdx_package.PackagePurpose.OPERATING_SYSTEM,
        supplier=supplier,
        files_analyzed=False,
        license_concluded=SpdxNoAssertion(),
        license_declared=SpdxNoAssertion(),
        copyright_text=SpdxNoAssertion(),
    )

    external_references = None
    if artifact:
        distro_package.file_name = artifact.name

        sha1_digest, sha256_digest = gitoid_hashes(artifact, hashers=[sha1(), sha256()])

        external_references = [
            spdx_package.ExternalPackageRef(
                category=spdx_package.ExternalPackageRefCategory.PERSISTENT_ID,
                reference_type=SPDX_REFERENCE_TYPE_GITOID,
                locator=artifact_id_from_digest(sha256_digest),
            ),
            spdx_package.ExternalPackageRef(
                category=spdx_package.ExternalPackageRefCategory.PERSISTENT_ID,
                reference_type=SPDX_REFERENCE_TYPE_SWH,
                locator=swh_id_from_digest(sha1_digest),
            ),
        ]

        distro_package.external_references = external_references

        distro_package.checksums = [
            Checksum(checksum_to_spdx(alg), dig)
            for alg, dig in calculate_checksums(artifact).items()
        ]

    return distro_package


def _gen_namespace(
    namespace: tuple | None = None,  # 6 item tuple representing an URL
) -> tuple:
    if namespace is None:
        namespace = urlparse(
            "https://spdx.org/spdxdocs/debsbom-{}-{}".format(
                version("debsbom"),
                uuid4(),
            )
        )
    return namespace


debsbom_name = "debsbom-{}".format(version("debsbom"))


def make_creation_info(
    distro_name: str,
    namespace: tuple | None = None,  # 6 item tuple representing an URL
    timestamp: datetime | None = None,
    add_meta_data: dict[str, str] | None = None,
) -> spdx_document.CreationInfo:
    namespace = _gen_namespace(namespace)

    if timestamp is None:
        timestamp = datetime.now().astimezone()

    creation_info = spdx_document.CreationInfo(
        spdx_version="SPDX-2.3",
        spdx_id=SPDX_REF_DOCUMENT,
        name=distro_name,
        document_namespace=urlunparse(namespace),
        creators=[
            spdx_actor.Actor(
                actor_type=spdx_actor.ActorType.TOOL,
                name=debsbom_name,
            )
        ],
        created=timestamp,
    )
    if add_meta_data:
        creation_info.creator_comment = ", ".join(
            f"{key}={value}" for key, value in add_meta_data.items()
        )
    return creation_info


def spdx_package_repr(package: Package, vendor: str = "debian") -> spdx_package.Package:
    """Get the SPDX representation of a Package."""
    match = SUPPLIER_PATTERN.match(package.maintainer or "")
    if match:
        supplier_name = match["supplier_name"].strip()
        supplier_email = match["supplier_email"]
    if match and any(cue in supplier_name.lower() for cue in SPDX_SUPPLIER_ORG_CUE):
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
        logger.warning(f"no supplier for {package}")
    if package.is_binary():
        # https://github.com/spdx/using/blob/main/docs/diffs-from-previous-editions.md
        # says that "If there is a single ExternalReference of type purl without
        # the optional ExternalRef comment property, place that in the packageUrl property."
        # when translating from 2.3 to 3.0
        external_refs = [
            spdx_package.ExternalPackageRef(
                category=spdx_package.ExternalPackageRefCategory.PACKAGE_MANAGER,
                reference_type=SPDX_REFERENCE_TYPE_PURL,
                locator=package.purl(vendor).to_string(),
            )
        ]
        if package.omnibor_id:
            external_refs.append(
                spdx_package.ExternalPackageRef(
                    category=spdx_package.ExternalPackageRefCategory.PERSISTENT_ID,
                    reference_type=SPDX_REFERENCE_TYPE_GITOID,
                    locator=package.omnibor_id,
                )
            )
        if package.swh_id:
            external_refs.append(
                spdx_package.ExternalPackageRef(
                    category=spdx_package.ExternalPackageRefCategory.PERSISTENT_ID,
                    reference_type=SPDX_REFERENCE_TYPE_SWH,
                    locator=package.swh_id,
                )
            )
        spdx_pkg = spdx_package.Package(
            spdx_id=Reference.make_from_pkg(package).as_str(SBOMType.SPDX),
            name=package.name,
            download_location=SpdxNoAssertion(),
            version=str(package.version),
            supplier=supplier,
            files_analyzed=False,
            license_concluded=SpdxNoAssertion(),
            license_declared=SpdxNoAssertion(),
            copyright_text=SpdxNoAssertion(),
            summary=package.description.split("\n")[0] if package.description else None,
            external_references=external_refs,
            primary_package_purpose=spdx_package.PackagePurpose.LIBRARY,
            checksums=[
                Checksum(checksum_to_spdx(alg), dig) for alg, dig in package.checksums.items()
            ],
        )
        if package.description and "\n" in package.description:
            _desc = package.description.split("\n")
            spdx_pkg.description = "\n".join(_desc[1:])
        if package.homepage:
            url = urlparse(package.homepage)
            url = url._replace(netloc=url.netloc.lower())
            spdx_pkg.homepage = urlunparse(url)
        logger.debug(f"Created binary package: {spdx_pkg}")
    elif package.is_source():
        external_refs = [
            spdx_package.ExternalPackageRef(
                category=spdx_package.ExternalPackageRefCategory.PACKAGE_MANAGER,
                reference_type=SPDX_REFERENCE_TYPE_PURL,
                locator=package.purl(vendor).to_string(),
            )
        ]
        if package.vcs:
            external_refs.append(
                spdx_package.ExternalPackageRef(
                    category=spdx_package.ExternalPackageRefCategory.OTHER,
                    reference_type=SPDX_REFERENCE_TYPE_VCS,
                    locator=package.vcs.locator,
                    comment=f"Version control system of type {package.vcs.type.value}",
                ),
            )

        licenses_decl = SpdxNoAssertion()
        if package.copyright:
            try:
                licenses = list(package.copyright.spdx_license_expressions())
                combined = licenses[0]
                if len(licenses) > 1:
                    combined = AND(*licenses)
                licenses_decl = combined.simplify()
            except (ExpressionError, UnknownLicenseError) as e:
                logger.debug(f"no SPDX license expression for {package}: {e}")

        spdx_pkg = spdx_package.Package(
            spdx_id=Reference.make_from_pkg(package).as_str(SBOMType.SPDX),
            name=package.name,
            version=str(package.version),
            supplier=supplier,
            files_analyzed=False,
            license_concluded=SpdxNoAssertion(),
            license_declared=licenses_decl,
            download_location=SpdxNoAssertion(),
            copyright_text=SpdxNoAssertion(),
            summary="Debian source code package '{}'".format(package.name),
            external_references=external_refs,
            checksums=[
                Checksum(checksum_to_spdx(alg), dig) for alg, dig in package.checksums.items()
            ],
            primary_package_purpose=spdx_package.PackagePurpose.SOURCE,
        )
        logger.debug(f"Created source package: {spdx_pkg}")
    else:
        raise RuntimeError(f"The package {package} is neither a source nor a binary package")
    return spdx_pkg


def make_relationships_for_deps(
    dependencies: Iterable[Dependency],
    package: Package,
    reference: Reference,
    refs: dict[str, Package],
    distro_arch: str,
    virtual_packages: dict[str, list[tuple[VirtualPackage, BinaryPackage]]],
    comment: str | None = None,
) -> Iterable[spdx_relationship.Relationship]:
    for dep in dependencies:
        ref_id = Reference.lookup(package, dep, SBOMType.SPDX, refs, distro_arch)
        if not ref_id:
            # no concrete package available, look for a virtual package
            virtual_candidates = virtual_packages.get(dep.name)
            if virtual_candidates is None:
                continue

            pkg = VirtualPackage.best_match(virtual_candidates, dep)
            if pkg:
                ref_id = Reference.make_from_pkg(pkg).as_str(SBOMType.SPDX)
                logger.debug(f"Dependency on virtual package resolved: {dep.name} -> {pkg.name}")
        if ref_id:
            relationship = spdx_relationship.Relationship(
                spdx_element_id=reference.as_str(SBOMType.SPDX),
                relationship_type=spdx_relationship.RelationshipType.DEPENDS_ON,
                related_spdx_element_id=ref_id,
            )
            if comment:
                relationship.comment = comment
            logger.debug(f"Created dependency relationship: {relationship}")
            yield relationship
        else:
            # this might happen if we have optional dependencies
            logger.debug(f"Skipped optional dependency: '{dep.name}'")


def spdx_bom(
    packages: set[Package],
    distro_name: str,
    distro_arch: str,
    distro_supplier: str | None = None,
    distro_version: str | None = None,
    distro_summary: str | None = None,
    artifact: Path | None = None,
    base_distro_vendor: str | None = "debian",
    namespace: tuple | None = None,  # 6 item tuple representing an URL
    timestamp: datetime | None = None,
    add_meta_data: dict[str, str] | None = None,
    virtual_packages: dict[str, list[tuple[VirtualPackage, BinaryPackage]]] | None = None,
    recommends_deps: bool = True,
    suggests_deps: bool = False,
    use_spdx3: bool = False,
    progress_cb: Callable[[int, int, str], None] | None = None,
) -> spdx_document.Document | spdx3_payload.Payload:
    "Return a valid SPDX SBOM."

    namespace = _gen_namespace(namespace)
    namespace_str = urlunparse(namespace)
    if use_spdx3:
        namespace_map = spdx3_namespace_map.NamespaceMap("dsb:", namespace_str + "#")

        def spdx3_id_from_spdx2(spdx_id: str) -> str:
            return namespace_str + "#" + spdx_id

        def spdx3_id(suffix: str) -> str:
            return spdx3_id_from_spdx2(SPDX_REF_PREFIX + suffix)

    payload = spdx3_payload.Payload()
    external_document_refs = []
    imports = []
    if use_spdx3:
        relationship_id_counter = 0

        def next_relationsip_id():
            nonlocal relationship_id_counter
            relationship_id_counter += 1
            return relationship_id_counter

        def gen_relationship_id():
            rid = next_relationsip_id()
            # note that spdx_tools uses the prefix "Relationship-"
            return spdx3_id("RELATIONSHIP-" + str(rid))

    if virtual_packages is None:
        virtual_packages = {}

    data = []

    distro_package = make_distro_package(
        distro_name=distro_name,
        distro_version=distro_version,
        distro_supplier=distro_supplier,
        distro_summary=distro_summary,
        artifact=artifact,
    )
    if use_spdx3:
        spdx3_bump_package.bump_package(
            distro_package,
            payload,
            namespace_str,
            external_document_refs,
            imports,
        )
    else:
        data.append(distro_package)

    binary_packages = list(filter_binaries(packages))

    # progress tracking
    num_steps = len(packages) + len(binary_packages)
    cur_step = 0

    logger.info("Creating packages...")
    for package in packages:
        if progress_cb:
            progress_cb(cur_step, num_steps, package.name)
        cur_step += 1

        entry = spdx_package_repr(
            package,
            vendor=base_distro_vendor,
        )
        if use_spdx3:
            spdx3_bump_package.bump_package(
                entry, payload, namespace_str, external_document_refs, imports
            )
            package_reference = spdx_element_utils.get_full_element_spdx_id(
                entry, namespace_str, external_document_refs
            )
            package3 = payload.get_element(package_reference)
            package3.external_identifier.append(
                spdx3_external_identifier.ExternalIdentifier(
                    external_identifier_type=spdx3_external_identifier.ExternalIdentifierType.PURL,
                    identifier=str(package.purl()),
                ),
            )
            if package.swh_id is not None:
                package3.external_identifier.append(
                    spdx3_external_identifier.ExternalIdentifier(
                        external_identifier_type=spdx3_external_identifier.ExternalIdentifierType.SWHID,
                        identifier=str(package.swh_id),
                    ),
                )
            if package.omnibor_id is not None:
                package3.external_identifier.append(
                    spdx3_external_identifier.ExternalIdentifier(
                        external_identifier_type=spdx3_external_identifier.ExternalIdentifierType.GITOID,
                        identifier=str(package.omnibor_id),
                    ),
                )

        else:
            data.append(entry)

    relationships = []
    logger.info("Resolving dependencies...")
    # after we have found all packages we can start to resolve dependencies
    refs = {Reference.make_from_pkg(p).as_str(SBOMType.SPDX): p for p in binary_packages}

    for package in binary_packages:
        if progress_cb:
            progress_cb(cur_step, num_steps, package.name)
        cur_step += 1

        reference = Reference.make_from_pkg(package)
        reference_id = reference.as_str(SBOMType.SPDX)
        if (
            package.manually_installed
            or package.essential
            or package.priority == DebianPriority.REQUIRED
        ):
            relationships.append(
                spdx_relationship.Relationship(
                    spdx_element_id=reference_id,
                    relationship_type=spdx_relationship.RelationshipType.PACKAGE_OF,
                    related_spdx_element_id=distro_package.spdx_id,
                )
            )

        if package.depends:
            relationships.extend(
                make_relationships_for_deps(
                    dependencies=package.unique_depends,
                    package=package,
                    reference=reference,
                    refs=refs,
                    distro_arch=distro_arch,
                    virtual_packages=virtual_packages,
                )
            )

        if recommends_deps and package.recommends:
            relationships.extend(
                make_relationships_for_deps(
                    dependencies=package.unique_recommends,
                    package=package,
                    reference=reference,
                    refs=refs,
                    distro_arch=distro_arch,
                    virtual_packages=virtual_packages,
                    comment="recommends",
                )
            )

        if suggests_deps and package.suggests:
            relationships.extend(
                make_relationships_for_deps(
                    dependencies=package.unique_suggests,
                    package=package,
                    reference=reference,
                    refs=refs,
                    distro_arch=distro_arch,
                    virtual_packages=virtual_packages,
                    comment="suggests",
                )
            )

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

        for dep in package.static_built_using:
            bu_dep = Reference.make_from_dep(dep)
            relationship = spdx_relationship.Relationship(
                spdx_element_id=reference.as_str(SBOMType.SPDX),
                relationship_type=spdx_relationship.RelationshipType.GENERATED_FROM,
                related_spdx_element_id=bu_dep.as_str(SBOMType.SPDX),
                comment="static-built-using",
            )
            logger.debug(f"Created static-built-using relationship: {relationship}")
            relationships.append(relationship)

        if package.source:
            sref = Reference.make_from_dep(package.source)
            sref_id = sref.as_str(SBOMType.SPDX)
            relationship = spdx_relationship.Relationship(
                spdx_element_id=sref_id,
                relationship_type=spdx_relationship.RelationshipType.GENERATES,
                related_spdx_element_id=reference.as_str(SBOMType.SPDX),
            )
            logger.debug(f"Created source relationship: {relationship}")
            relationships.append(relationship)

    distro_relationship = spdx_relationship.Relationship(
        spdx_element_id=SPDX_REF_DOCUMENT,
        relationship_type=spdx_relationship.RelationshipType.DESCRIBES,
        related_spdx_element_id=distro_package.spdx_id,
    )
    logger.debug(f"Created document relationship: {distro_relationship}")
    relationships.append(distro_relationship)

    creation_info = make_creation_info(distro_name, namespace, timestamp, add_meta_data)
    creation_info.creators.append(distro_package.supplier)

    if use_spdx3:
        document3 = spdx3_bump_creation_info.bump_creation_info(creation_info, payload)
        # creation_info does not bump actors correctly: SPDX namespace needs fixing
        creation3_info = document3.creation_info
        supplier3_id = spdx3_bump_actor.bump_actor(
            distro_package.supplier,
            payload=payload,
            document_namespace=namespace_str,
            creation_info=None,
        )
        creation3_info.created_by.clear()
        creation3_info.created_by.append(supplier3_id)

        tool3_id = spdx3_bump_actor.bump_actor(
            distro_package.supplier,
            payload=payload,
            document_namespace=namespace_str,
            creation_info=None,
        )

        spdx3_bump_relationship.bump_relationships(relationships, payload, namespace_str)

        sbom3 = spdx3_software_sbom.Sbom(
            spdx_id=spdx3_id("BOM"),
            element=list(payload.get_full_map().keys()),
            root_element=[spdx3_id_from_spdx2(distro_package.spdx_id)],
            sbom_type=[
                spdx3_software_sbom.SBOMType.DEPLOYED,
                spdx3_software_sbom.SBOMType.ANALYZED,
            ],
        )
        payload.add_element(sbom3)

        # https://github.com/spdx/using/blob/main/docs/getting-started.md
        # says: "Technically speaking, the [element] property should link
        # to all the elements that are in the document using this property.
        # However because this would be error prone, it is implied that all
        # Element objects present in the @graph (that is, all the objects
        # we are writing) are implicitly added to the element property."
        document3 = spdx3_spdx_document.SpdxDocument(
            spdx_id=spdx3_id("SPDX_DOCUMENT"),
            name=(distro_name or "unknown")
            + "+"
            + (distro_version or "unknown")
            + "+"
            + (distro_arch or "unknown"),
            element=list(payload.get_full_map().keys()) if False else list(),
            root_element=[sbom3.spdx_id],
            creation_info=creation3_info,
            summary=distro_summary,
            namespaces=[namespace_map],
        )
        payload.add_element(document3)

        if False:
            # The code below minimizes spdx_ids (i.e. RDF identifiers)
            # via the namespace map.
            # However, this is the wrong place to do that:
            # the namespace map must be evaluated in the serialization routine,
            # so that it can be put into, e.g., the JSON-LDs @context; if this is not done,
            # the transformation below will not work.
            new_payload = spdx3_payload.Payload()
            namespaces = document3.namespaces
            namespaces.sort(key=lambda l: len(l.namespace), reverse=True)

            def abbreviate_key(key: str) -> str:
                for n in namespaces:
                    if key.startswith(n.namespace):
                        return n.prefix + k.lstrip(n.namespace)
                return key

            def abbreviate_keys(l: list[str]) -> list[str]:
                new_list = []
                for k in l:
                    new_list.append(abbreviate_key(k))
                return new_list

            for k, e in payload.get_full_map().items():
                e.spdx_id = abbreviate_key(k)
                # the following is not guaranteed to be exhaustive
                if isinstance(e, spdx3_element.Element):
                    if e.creation_info is None:
                        # SPDX 3 specifies that creation_info must exist
                        # (minCount = maxCount = 1)
                        # but this adds a whole lot of redundant information.
                        # Unfortunately, spdx_tools models this as a UML
                        # "composition", not as an "aggregation", i.e.,
                        # creation_info does not exist as a separate node
                        # that can be linked to (saving space), but is copied into each
                        # element.
                        # https://github.com/spdx/using/blob/main/docs/getting-started.md
                        # shows how a blank node can be used to identify the CreationInfo node.
                        if True:
                            e.creation_info = creation3_info
                    else:
                        e.creation_info.created_by = abbreviate_keys(e.creation_info.created_by)
                        e.creation_info.created_using = abbreviate_keys(
                            e.creation_info.created_using
                        )
                if isinstance(e, spdx3_artifact.Artifact):
                    e.originated_by = abbreviate_keys(e.originated_by)
                    e.supplied_by = abbreviate_keys(e.supplied_by)
                    e.supplied_by = abbreviate_keys(e.supplied_by)
                if isinstance(e, spdx3_creation_info.CreationInfo):
                    e.created_by = abbreviate_keys(e.created_by)
                    e.created_using = abbreviate_keys(e.created_using)
                if isinstance(e, spdx3_collection.ElementCollection):
                    e.element = abbreviate_keys(e.element)
                    e.root_element = abbreviate_keys(e.root_element)

                if isinstance(e, spdx3_relationship.Relationship):
                    e.from_element = abbreviate_key(e.from_element)
                    e.to = abbreviate_keys(e.to)
                    if isinstance(e, spdx3_vlun_assessment_relationship.VulnAssessmentRelationship):
                        e.assessed_element = abbreviate_key(e.assessed_element)
                        e.assessed_element = abbreviate_key(e.assessed_element)

                new_payload.add_element(e)

            return new_payload
        else:
            return payload

    else:
        document = spdx_document.Document(
            creation_info=creation_info,
            packages=data,
            relationships=relationships,
        )
        return document
