# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Mapping, Callable, Iterable
from typing import Any, ContextManager
from enum import IntEnum
import hashlib
from hmac import compare_digest
import hashlib
import io
from pathlib import Path


class ChecksumNotSupportedError(ValueError):
    def __init__(self, algo: str):
        super().__init__(f"Hash algorithm '{algo}' is not supported")


class NoMatchingDigestError(ValueError):
    pass


class ChecksumMismatchError(RuntimeError):
    def __init__(self, name: str, purl: str | None, alg: str, checksum1: str, checksum2: str):
        if purl:
            super().__init__(
                f"Checksum mismatch for '{name}' ({purl}): {alg}: {checksum1} != {checksum2}"
            )
        else:
            super().__init__(f"Checksum mismatch for '{name}': {alg}: {checksum1} != {checksum2}")


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


def _best_matching_digest(
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


def verify_best_matching_digest(
    digests_a: Mapping[ChecksumAlgo, str],
    digests_b: Mapping[ChecksumAlgo, str],
    name: str | None = None,
    purl: str | None = None,
) -> bool:
    """
    Verifies if the best matching digest between two sets matches.

    Returns True if a common algorithm is found and its digests match.
    Returns False if no common digest algorithms are found.
    Raises NoMatchingDigestError if no common digest algorithms are found.
    If `name` is set and a mismatch occurs, a `ChecksumMismatchError`
    is raised, with the corresponding 'name' and 'purl'.
    """
    alg, digest_a, digest_b = _best_matching_digest(digests_a, digests_b)
    result = compare_digest(digest_a, digest_b)
    if name and not result:
        raise ChecksumMismatchError(name, purl, str(alg), digest_a, digest_b)
    return result


def check_hash_from_path(file: Path, checksums: Mapping[ChecksumAlgo, str]) -> bool:
    """
    Check if the hash of a file matches the best digest provided.
    """
    try:
        best, digest = best_digest(checksums)
    except ValueError:
        return False
    with open(file, "rb") as fd:
        return compare_digest(digest, hashlib.file_digest(fd, str(best)).hexdigest())


def _get_byte_stream(source: Path | bytes) -> ContextManager[io.BytesIO | io.BufferedReader]:
    """
    Provides a seekable, readable byte stream from either a Path or raw bytes.
    """
    if isinstance(source, Path):
        return open(source, "rb")
    elif isinstance(source, bytes):
        return io.BytesIO(source)
    else:
        raise TypeError(f"Unsupported source type for checksum calculation: {type(source)}.")


def calculate_checksums(
    source: Path | bytes,
    algorithms: Iterable[ChecksumAlgo] | None = None,
    chunk_size: int = 65536,  # A common default chunk size (64KB)
) -> dict[ChecksumAlgo, str]:
    """
    Calculate supported checksums for either raw file content or a file path.
    """
    if algorithms is None:
        algorithms_to_calculate = list(ChecksumAlgo)
    else:
        algorithms_to_calculate = list(algorithms)

    if not algorithms_to_calculate:
        return {}

    hash_objects = {}
    for algo in algorithms_to_calculate:
        try:
            hash_objects[algo] = hashlib.new(str(algo))
        except ValueError:
            raise ValueError(f"Unsupported checksum algorithm: '{algo.value}'")

    with _get_byte_stream(source) as stream:
        while True:
            chunk = stream.read(chunk_size)
            if not chunk:
                break
            for h_obj in hash_objects.values():
                h_obj.update(chunk)

    return {algo: h_obj.hexdigest() for algo, h_obj in hash_objects.items()}


def checksum_dict_from_iterable(
    items: Iterable[Any],
    get_algo_str: Callable[[Any], str],
    get_value_str: Callable[[Any], str],
    checksum_parser: Callable[[str], ChecksumAlgo],
) -> dict[ChecksumAlgo, str]:
    """
    Generic function to process a list or set of checksum-like items and return a dictionary
    mapping ChecksumAlgo to their string values.
    """
    result: list[tuple[ChecksumAlgo, str]] = []
    for item in items:
        try:
            algo_str = get_algo_str(item)
            value_str = get_value_str(item)
            algo = checksum_parser(algo_str)
            result.append((algo, value_str))
        except ChecksumNotSupportedError:
            pass
    return dict(result)
