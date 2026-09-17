# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from pathlib import Path

from .gitoid import gitoid_hash


def swh_id(artifact: Path) -> str:
    """
    Calculate the content swhid for the given artifact.

    The artifact should be in uncompressed form as otherwise we depend
    on the compression algorithms reproducability guarantees.
    """
    digest = gitoid_hash(artifact)
    return swh_id_from_digest(digest)


def swh_id_from_digest(digest: str) -> str:
    """
    Calculate the content swhid from a given digest.
    """
    return f"swh:1:cnt:{digest}"
