# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from hashlib import sha256
from pathlib import Path

from .gitoid import gitoid_hashes


def artifact_id(artifact: Path) -> str:
    """
    Calculate the omnibor artifact ID for the given artifact.
    """
    digests = gitoid_hashes(artifact, hashers=[sha256()])
    return artifact_id_from_digest(digests[0])


def artifact_id_from_digest(sha256_digest: str) -> str:
    """
    Create the omnibor artifact ID for a sha256 digest.
    """
    return f"gitoid:blob:sha256:{sha256_digest}"
