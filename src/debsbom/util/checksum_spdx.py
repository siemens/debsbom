# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from .checksum import ChecksumAlgo, ChecksumNotSupportedError, checksum_dict_from_iterable
from spdx_tools.spdx.model.checksum import Checksum, ChecksumAlgorithm

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


def checksum_dict_from_spdx(checksums: list[Checksum]) -> dict[ChecksumAlgo, str]:
    """
    Processes a list of SPDX Checksum objects into a dictionary.
    """
    return checksum_dict_from_iterable(
        items=checksums,
        get_algo_str=lambda c: c.algorithm,
        get_value_str=lambda c: c.value,
        checksum_parser=checksum_from_spdx,
    )
