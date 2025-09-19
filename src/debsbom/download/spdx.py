# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from .download import PackageResolver
from pathlib import Path
from spdx_tools.spdx.parser.parse_anything import parse_file
import spdx_tools.spdx.model.package as spdx_package
import spdx_tools.spdx.model.document as spdx_document


class SpdxPackageResolver(PackageResolver):
    def __init__(self, document: spdx_document.Document):
        super().__init__()
        self._document = document

    @staticmethod
    def is_debian_pkg(p):
        if not p.external_references:
            return False
        # TODO: scan all references
        if (
            p.external_references[0].category
            != spdx_package.ExternalPackageRefCategory.PACKAGE_MANAGER
        ):
            return False
        return True

    def debian_pkgs(self):
        return map(
            lambda p: self.package_from_purl(p.external_references[0].locator),
            filter(self.is_debian_pkg, self._document.packages),
        )

    @classmethod
    def from_file(cls, filename: Path) -> "SpdxPackageResolver":
        return cls(parse_file(str(filename)))
