# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from enum import IntEnum


class ChecksumAlgo(IntEnum):
    """
    Checksum algorithms, ordered by priority (higher means better).
    """

    MD5SUM = 1
    SHA1SUM = 2
    SHA256SUM = 3

    @classmethod
    def to_hashlib(cls, algo):
        if algo == cls.MD5SUM:
            return "md5"
        if algo == cls.SHA1SUM:
            return "sha1"
        if algo == cls.SHA256SUM:
            return "sha256"
        raise NotImplementedError()
