# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from pathlib import Path

from .gitoid import gitoid_hash


def swh_id(artifact: Path) -> str:
    """
    Calculate the content swhid for the given artifact.
    """
    digest = gitoid_hash(artifact)
    return swh_id_from_digest(digest)


def swh_id_from_digest(sha256_digest: str) -> str:
    """
    Create the content swhid from a given sha256 digest.
    """
    return f"swh:1:cnt:{sha256_digest}"
