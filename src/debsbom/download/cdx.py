# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import json
from .download import PackageResolver
from pathlib import Path
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component


class CdxPackageResolver(PackageResolver):
    def __init__(self, document: Bom):
        super().__init__()
        self.document = document

    @staticmethod
    def _is_debian_pkg(p: Component):
        if str(p.purl).startswith("pkg:deb/debian/"):
            return True
        return False

    def debian_pkgs(self):
        return map(
            lambda p: self.package_from_purl(str(p.purl)),
            filter(self._is_debian_pkg, self.document.components),
        )

    @classmethod
    def from_file(cls, filename: Path):
        with open(filename, "r") as f:
            return cls(Bom.from_json(json.load(f)))
