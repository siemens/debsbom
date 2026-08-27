# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from abc import abstractmethod
from io import TextIOWrapper
from pathlib import Path

from ..sbom import SBOMType


class SerializerOpts:
    """
    Options for the SBOM serializer
    """

    @staticmethod
    def create(bomtype: SBOMType, schema_version: str | None = None) -> "SerializerOpts":
        bomtype.validate_dependency_availability()
        if bomtype == SBOMType.CycloneDX:
            from .cdxbomwriter import CdxSerializerOpts

            return CdxSerializerOpts(cdx_schema_version=schema_version or "1.6")
        elif bomtype == SBOMType.SPDX:
            # no options yet
            return SerializerOpts()
        raise NotImplementedError()


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
    def write_to_file(bom, filename: Path, validate: bool, opts: SerializerOpts | None = None):
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def write_to_stream(bom, f: TextIOWrapper, validate: bool, opts: SerializerOpts | None = None):
        raise NotImplementedError()
