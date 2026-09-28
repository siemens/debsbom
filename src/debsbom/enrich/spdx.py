# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Iterable
from hashlib import sha1, sha256
import logging
from pathlib import Path
from spdx_tools.spdx.model.checksum import Checksum, ChecksumAlgorithm
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
import spdx_tools.spdx.model.package as spdx_package

from .enrich import Enricher
from ..resolver.spdx import SpdxPackageResolver
from ..sbom import SPDX_REFERENCE_TYPE_GITOID, SPDX_REFERENCE_TYPE_SWH
from ..util.checksum import (
    ChecksumMismatchError,
    NoMatchingDigestError,
    calculate_checksums,
    verify_best_matching_digest,
)
from ..util.checksum_spdx import checksum_dict_from_spdx, checksum_to_spdx
from ..util.gitoid import gitoid_hashes
from ..util.omnibor import artifact_id_from_digest
from ..util.swh import swh_id_from_digest

logger = logging.getLogger(__name__)


class SpdxEnricher(Enricher):
    def incomplete_components(self) -> Iterable[spdx_package.Package]:
        def _needs_enrichment(package: spdx_package.Package) -> bool:
            if self.with_checksums:
                wanted_algos = [
                    ChecksumAlgorithm.MD5,
                    ChecksumAlgorithm.SHA1,
                    ChecksumAlgorithm.SHA256,
                    ChecksumAlgorithm.SHA512,
                ]
                available_algos = set(map(lambda cs: cs.algorithm, package.checksums))
                if not all(algo in available_algos for algo in wanted_algos):
                    return True

            if self.with_omniborid or self.with_swhid:
                wanted_refs = []
                if self.with_omniborid:
                    wanted_refs.append("gitoid")
                if self.with_swhid:
                    wanted_refs.append("swh")
                available_refs = set(map(lambda r: r.reference_type, package.external_references))
                if not all(wanted_ref in available_refs for wanted_ref in wanted_refs):
                    return True

            if self.with_download_loc and (
                not package.download_location or package.download_location == SpdxNoAssertion()
            ):
                return True

            return False

        return filter(_needs_enrichment, self.document.packages)

    @staticmethod
    def _append_ext_ref(package: spdx_package.Package, ref_type: str, ref_locator: str):
        ref = spdx_package.ExternalPackageRef(
            category=spdx_package.ExternalPackageRefCategory.PERSISTENT_ID,
            reference_type=ref_type,
            locator=ref_locator,
        )
        if package.external_references:
            package.external_references.append(ref)
        else:
            package.external_references = [ref]

    def enrich_component(self, package: spdx_package.Package, artifacts: list[(Path, str | None)]):
        package_file = None
        package_remote = None
        if SpdxPackageResolver.create_package(package).is_binary():
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
                ref_type = SPDX_REFERENCE_TYPE_SWH
                loc = swh_id_from_digest(sha1_digest)
                self._append_ext_ref(package, ref_type, loc)
            if sha256_digest:
                ref_type = SPDX_REFERENCE_TYPE_GITOID
                loc = artifact_id_from_digest(sha256_digest)
                self._append_ext_ref(package, ref_type, loc)

            if self.with_checksums:
                mismatch = False
                checksums = calculate_checksums(package_file)
                try:
                    verify_best_matching_digest(
                        checksums, checksum_dict_from_spdx(package.checksums)
                    )
                except NoMatchingDigestError:
                    pass
                except ChecksumMismatchError as e:
                    logger.warning(e)
                    mismatch = True
                if not mismatch:
                    package.checksums = [
                        Checksum(checksum_to_spdx(alg), dig) for alg, dig in checksums.items()
                    ]

            if self.with_download_loc and package_remote:
                package.download_location = package_remote
