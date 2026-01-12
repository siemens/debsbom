# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from abc import abstractmethod
from io import IOBase
from pathlib import Path

from ..sbom import SBOMType
from ..util.sbom_processor import SbomProcessor


class BomReader(SbomProcessor):
    """Base class for SBOM importers"""

    @classmethod
    def create(cls, filename: Path, bomtype: SBOMType | None = None):
        if bomtype is SBOMType.SPDX or filename.name.endswith("spdx.json"):
            SBOMType.SPDX.validate_dependency_availability()
            from .spdxbomreader import SpdxBomFileReader

            reader_cls = SpdxBomFileReader
        elif bomtype is SBOMType.CycloneDX or filename.name.endswith("cdx.json"):
            SBOMType.CycloneDX.validate_dependency_availability()
            from .cdxbomreader import CdxBomFileReader

            reader_cls = CdxBomFileReader
        else:
            raise RuntimeError("SBOM type cannot be detected based on filename")

        return reader_cls(filename)

    @classmethod
    def from_stream(cls, stream: IOBase, bomtype: SBOMType):
        if bomtype is SBOMType.SPDX:
            SBOMType.SPDX.validate_dependency_availability()
            from .spdxbomreader import SpdxBomFileReader

            reader_cls = SpdxBomFileReader
        elif bomtype is SBOMType.CycloneDX:
            SBOMType.CycloneDX.validate_dependency_availability()
            from .cdxbomreader import CdxBomFileReader

            reader_cls = CdxBomFileReader
        else:
            raise NotImplementedError("Unsupported SBOM type")

        return reader_cls(stream)

    @classmethod
    def from_json(cls, json_obj, bomtype: SBOMType):
        if bomtype is SBOMType.SPDX:
            SBOMType.SPDX.validate_dependency_availability()
            from .spdxbomreader import SpdxBomJsonReader

            reader_cls = SpdxBomJsonReader
        elif bomtype is SBOMType.CycloneDX:
            SBOMType.CycloneDX.validate_dependency_availability()
            from .cdxbomreader import CdxBomJsonReader

            reader_cls = CdxBomJsonReader
        else:
            raise NotImplementedError("Unsupported SBOM type")

        return reader_cls(json_obj)

    @abstractmethod
    def read(self):
        return NotImplementedError()
