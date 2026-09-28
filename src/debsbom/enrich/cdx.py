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

    def enrich_component(self, component: Component, artifacts: list[(Path, str | None)]):
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
            sha1_digest = None
            sha256_digest = None
            if self.with_omniborid and self.with_swhid:
                sha1_digest, sha256_digest = gitoid_hashes(package_file, hashers=[sha1(), sha256()])
            elif self.with_omniborid:
                sha256_digest = gitoid_hashes(package_file, hashers=[sha256()])[0]
            elif self.with_swhid:
                sha1_digest = gitoid_hashes(package_file, hashers=[sha1()])[0]

            if sha1_digest:
                swhid = swh_id_from_digest(sha1_digest)
                if component.swhids:
                    component.swhids.add(Swhid(swhid))
                else:
                    component.swhids = SortedSet([Swhid(swhid)])

            if sha256_digest:
                omnibor_id = artifact_id_from_digest(sha256_digest)
                if component.omnibor_ids:
                    component.omnibor_ids.add(OmniborId(omnibor_id))
                else:
                    component.omnibor_ids = SortedSet([OmniborId(omnibor_id)])

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
