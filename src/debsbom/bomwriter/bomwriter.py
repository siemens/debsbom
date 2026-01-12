# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from abc import abstractmethod
from io import TextIOWrapper
from pathlib import Path

from ..sbom import SBOMType


class BomWriter:
    @staticmethod
    def create(bomtype: SBOMType) -> "BomWriter":
        """
        Factory to create a BomWriter for the given SBOM type
        """
        bomtype.validate_dependency_availability()
        if bomtype == SBOMType.CycloneDX:
            from .cdxbomwriter import CdxBomWriter

            return CdxBomWriter()
        elif bomtype == SBOMType.SPDX:
            from .spdxbomwriter import SpdxBomWriter

            return SpdxBomWriter()
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def write_to_file(bom, filename: Path, validate: bool):
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def write_to_stream(bom, f: TextIOWrapper, validate: bool):
        raise NotImplementedError()
