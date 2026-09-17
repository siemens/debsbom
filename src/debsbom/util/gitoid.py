# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from hashlib import sha256
import os
from pathlib import Path


def gitoid_hash(artifact: Path, hasher=None) -> str:
    """
    Calculate the gitoid hash for the given artifact blob.
    """
    if not hasher:
        hasher = sha256()
    with open(artifact, "rb") as f:
        size = os.fstat(f.fileno()).st_size

        hasher.update(f"blob {size}\0".encode("ascii"))
        while True:
            data = f.read()
            if not data:
                break
            hasher.update(data)

    return hasher.hexdigest()
