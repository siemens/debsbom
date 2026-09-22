# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from abc import abstractmethod
from collections.abc import Iterable

from ..dpkg.package import Package
from ..sbom import BomSpecific, SBOMType


class BomTransformer(BomSpecific):
    @abstractmethod
    def transform(self, packages: Iterable[Package]):
        raise NotImplementedError()

    @property
    def document(self):
        return self._document
