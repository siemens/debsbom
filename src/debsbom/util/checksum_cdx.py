# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from sortedcontainers import SortedSet
from .checksum import ChecksumAlgo, ChecksumNotSupportedError, checksum_dict_from_iterable
from cyclonedx.model import HashAlgorithm as cdx_hashalgo, HashType as cdx_hashtype

_CHKSUM_TO_CDX = {
    ChecksumAlgo.MD5SUM: cdx_hashalgo.MD5,
    ChecksumAlgo.SHA1SUM: cdx_hashalgo.SHA_1,
    ChecksumAlgo.SHA256SUM: cdx_hashalgo.SHA_256,
}


def checksum_to_cdx(alg: ChecksumAlgo) -> cdx_hashalgo:
    cdx_hashalg = _CHKSUM_TO_CDX.get(alg)
    if cdx_hashalg:
        return cdx_hashalg
    raise ChecksumNotSupportedError(str(alg))


def checksum_from_cdx(alg: cdx_hashalgo) -> ChecksumAlgo:
    for cs_algo, cdx_algo in _CHKSUM_TO_CDX.items():
        if cdx_algo == alg:
            return cs_algo

    raise ChecksumNotSupportedError(str(alg))


def checksum_dict_from_cdx(checksums: SortedSet[cdx_hashtype]) -> dict[ChecksumAlgo, str]:
    """
    Processes a list of CDX Hash objects into a dictionary.
    """
    return checksum_dict_from_iterable(
        items=checksums,
        get_algo_str=lambda c: c.alg,
        get_value_str=lambda c: c.content,
        checksum_parser=checksum_from_cdx,
    )
