# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from pathlib import Path
from urllib.parse import quote

from ..dpkg.package import BinaryPackage


class ArchiveCache:

    def __init__(self, archives_dir: str | Path):
        """Create an apt cache archive for the given directory."""
        self.archives_dir = archives_dir

    def package_file(self, package: BinaryPackage) -> Path | None:
        # apt stores the files in a slightly non-standard way: it is urlencoded, but does not correctly encode "+" as it should for paths
        filename = (
            quote(f"{package.name}_{package.version}_{package.architecture}.deb")
            .lower()
            .replace("%2b", "+")
        )
        full_path = self.archives_dir / filename
        if full_path.exists():
            return full_path
        else:
            return None
