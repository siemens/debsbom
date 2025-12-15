# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Iterable
from debian.copyright import Copyright as DebCopyright, License
from pathlib import Path


class Copyright(DebCopyright):
    """Copyright information for a source package."""

    def __init__(self, path: Path):
        with open(path) as f:
            self.inner = DebCopyright(f)

    def licenses(self) -> Iterable[License]:
        """Return all licenses found in the copyright file."""
        lic = self.inner.header.license
        if lic:
            yield lic

        for paragraph in self.inner.all_files_paragraphs():
            yield paragraph.license


class CopyrightDirectory:
    """Directory of Debian copyright information."""

    def __init__(self, path: Path):
        self.copyright_root = path

    @classmethod
    def for_rootdir(cls, root: Path) -> "CopyrightDirectory":
        return CopyrightDirectory(root / "usr/share/doc")

    def copyright(self, bin_pkg) -> Copyright:
        """Get the copyright information for a binary package."""
        copyright_path = self.copyright_root / bin_pkg.name / "copyright"
        return Copyright(copyright_path)
