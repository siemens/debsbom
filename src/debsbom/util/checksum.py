# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from enum import IntEnum


class ChecksumNotSupportedError(ValueError):
    def __init__(self, algo: str):
        super().__init__(f"Hash algorithm '{algo}' is not supported")


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

    @classmethod
    def to_hashlib(cls, algo):
        if algo == cls.MD5SUM:
            return "md5"
        if algo == cls.SHA1SUM:
            return "sha1"
        if algo == cls.SHA256SUM:
            return "sha256"
        raise NotImplementedError()
