# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from pathlib import Path

from .gitoid import gitoid_hash


def artifact_id(artifact: Path) -> str:
    """
    Calculate the omnibor artifact ID for the given artifact.
    """
    digest = gitoid_hash(artifact)
    return artifact_id_from_digest(digest)


def artifact_id_from_digest(sha256_digest: str) -> str:
    """
    Create the omnibor artifact ID for a sha256 digest.
    """
    return f"gitoid:blob:sha256:{sha256_digest}"
