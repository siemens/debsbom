# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from .checksum import ChecksumAlgo, ChecksumNotSupportedError
from spdx_tools.spdx.model.checksum import ChecksumAlgorithm

_CHKSUM_TO_SPDX = {
    ChecksumAlgo.MD5SUM: ChecksumAlgorithm.MD5,
    ChecksumAlgo.SHA1SUM: ChecksumAlgorithm.SHA1,
    ChecksumAlgo.SHA256SUM: ChecksumAlgorithm.SHA256,
}


def checksum_to_spdx(alg: ChecksumAlgo) -> ChecksumAlgorithm:
    cdx_hashalg = _CHKSUM_TO_SPDX.get(alg)
    if cdx_hashalg:
        return cdx_hashalg
    raise ChecksumNotSupportedError(str(alg))


def checksum_from_spdx(alg: ChecksumAlgorithm) -> ChecksumAlgo:
    for cs_algo, cdx_algo in _CHKSUM_TO_SPDX.items():
        if cdx_algo == alg:
            return cs_algo

    raise ChecksumNotSupportedError(str(alg))
