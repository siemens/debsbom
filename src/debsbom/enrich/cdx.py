# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Iterable
from cyclonedx.model import HashAlgorithm, ExternalReference, ExternalReferenceType, HashType
from cyclonedx.model.component import Component, Swhid, OmniborId
from hashlib import sha1, sha256
import logging
from pathlib import Path
from sortedcontainers import SortedSet

from .enrich import Enricher
from ..resolver.cdx import CdxPackageResolver
from ..util.checksum import (
    ChecksumMismatchError,
    NoMatchingDigestError,
    calculate_checksums,
    verify_best_matching_digest,
)
from ..util.checksum_cdx import checksum_dict_from_cdx, checksum_to_cdx
from ..util.gitoid import gitoid_hashes
from ..util.omnibor import artifact_id_from_digest
from ..util.swh import swh_id_from_digest

logger = logging.getLogger(__name__)


class CdxEnricher(Enricher):
    def incomplete_components(self) -> Iterable[Component]:
        def _needs_enrichment(component: Component) -> bool:
            if self.with_checksums:
                wanted_algos = [
                    HashAlgorithm.MD5,
                    HashAlgorithm.SHA_1,
                    HashAlgorithm.SHA_256,
                    HashAlgorithm.SHA_512,
                ]
                available_algos = set(map(lambda h: h.alg, component.hashes))
                if not all(algo in available_algos for algo in wanted_algos):
                    return True

            if self.with_omniborid and not component.omnibor_ids:
                return True

            if self.with_swhid and not component.swhids:
                return True

            if self.with_download_loc and ExternalReferenceType.DISTRIBUTION not in map(
                lambda r: r.type, component.external_references
            ):
                return True

            return False

        return filter(_needs_enrichment, self.document.components)

    def enrich_component(self, component: Component, artifacts: list[tuple[Path, str | None]]):
        package_file = None
        package_remote = None
        if CdxPackageResolver.create_package(component).is_binary():
            for artifact, remote in artifacts:
                if artifact.suffix == ".deb":
                    package_file = artifact
                    package_remote = remote
                    break
        else:
            for artifact, remote in artifacts:
                if artifact.suffix == ".dsc":
                    package_file = artifact
                    package_remote = remote
                    break

        if package_file is not None:
            id_hashers = []
            if self.with_swhid:
                id_hashers.append(
                    (
                        sha1(),
                        "swhids",
                        lambda digest: SortedSet([Swhid(swh_id_from_digest(digest))]),
                    )
                )
            if self.with_omniborid:
                id_hashers.append(
                    (
                        sha256(),
                        "omnibor_ids",
                        lambda digest: SortedSet([OmniborId(artifact_id_from_digest(digest))]),
                    )
                )
            if id_hashers:
                digests = gitoid_hashes(package_file, hashers=[h for h, _, _ in id_hashers])
                for (_, field_name, to_id_field), digest in zip(id_hashers, digests):
                    setattr(component, field_name, to_id_field(digest))

            if self.with_checksums:
                mismatch = False
                checksums = calculate_checksums(package_file)
                try:
                    verify_best_matching_digest(checksums, checksum_dict_from_cdx(component.hashes))
                except NoMatchingDigestError:
                    pass
                except ChecksumMismatchError as e:
                    logger.warning(e)
                    mismatch = True
                if not mismatch:
                    component.hashes = [
                        HashType(alg=checksum_to_cdx(alg), content=dig)
                        for alg, dig in checksums.items()
                    ]

            if self.with_download_loc and package_remote:
                ref = ExternalReference(type=ExternalReferenceType.DISTRIBUTION, url=package_remote)
                component.external_references.add(ref)
