# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Mapping
from enum import IntEnum


class ChecksumNotSupportedError(ValueError):
    def __init__(self, algo: str):
        super().__init__(f"Hash algorithm '{algo}' is not supported")


class NoMatchingDigestError(ValueError):
    pass


class ChecksumAlgo(IntEnum):
    """
    Checksum algorithms, ordered by priority (higher means better).
    """

    MD5SUM = 1
    SHA1SUM = 2
    SHA256SUM = 3

    @classmethod
    def from_hashlib(cls, algo: str):
        if algo == "md5":
            return cls.MD5SUM
        if algo == "sha1":
            return cls.SHA1SUM
        if algo == "sha256":
            return cls.SHA256SUM
        raise ChecksumNotSupportedError(algo)

    def to_hashlib(self) -> str:
        if self == ChecksumAlgo.MD5SUM:
            return "md5"
        if self == ChecksumAlgo.SHA1SUM:
            return "sha1"
        if self == ChecksumAlgo.SHA256SUM:
            return "sha256"
        raise NotImplementedError()

    def __str__(self) -> str:
        return self.to_hashlib()


def best_digest(digests: Mapping[ChecksumAlgo, str]) -> tuple[ChecksumAlgo, str]:
    """
    Return the best checksum from ``digests``.
    """

    if not digests:
        raise ValueError("No digests provided")

    best_algo = max(digests.keys())
    return best_algo, digests[best_algo]


def best_matching_digest(
    digests_a: Mapping[ChecksumAlgo, str], digests_b: Mapping[ChecksumAlgo, str]
) -> tuple[ChecksumAlgo, str, str]:
    """
    Find the best checksum that is present in both.
    """
    if not digests_a or not digests_b:
        raise NoMatchingDigestError("Both digest mappings must contain at least one entry")

    common_algos = set(digests_a) & set(digests_b)
    if not common_algos:
        raise NoMatchingDigestError("No matching digest algorithms between the two mappings")

    best_algo = max(common_algos)
    return best_algo, digests_a[best_algo], digests_b[best_algo]
