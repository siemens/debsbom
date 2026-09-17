# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from hashlib import sha1
from pathlib import Path

from .gitoid import gitoid_hashes


def swh_id(artifact: Path) -> str:
    """
    Calculate the content swhid for the given artifact.
    """
    digests = gitoid_hashes(artifact, hashers=[sha1()])
    return swh_id_from_digest(digests[0])


def swh_id_from_digest(sha1_digest: str) -> str:
    """
    Create the content swhid from a given sha1 digest.
    """
    return f"swh:1:cnt:{sha1_digest}"
