# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from hashlib import sha256
import os
from pathlib import Path


def gitoid_hashes(artifact: Path, hashers=None) -> list[str]:
    """
    Calculate the gitoid hashes for the given artifact blob.
    """
    if not hashers:
        hashers = [sha256()]
    with open(artifact, "rb") as f:
        size = os.fstat(f.fileno()).st_size

        prefix = f"blob {size}\0".encode("ascii")
        for hasher in hashers:
            hasher.update(prefix)
        while True:
            data = f.read()
            if not data:
                break
            for hasher in hashers:
                hasher.update(data)

    return [hasher.hexdigest() for hasher in hashers]
