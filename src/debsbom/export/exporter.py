# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from abc import abstractmethod
from enum import Enum
from pathlib import Path
from io import IOBase

from ..bomreader.bomreader import BomReader
from ..util.sbom_processor import SbomProcessor
from ..sbom import SBOMType


class GraphOutputFormat(Enum):
    """Enum of supported graph formats"""

    GRAPHML = (0,)

    @classmethod
    def from_str(cls, name: str) -> "GraphOutputFormat":
        if name.lower() == "graphml":
            return cls.GRAPHML
        raise RuntimeError(f"Unsupported output format: '{name}'")


class GraphExporter(SbomProcessor):
    """
    Base class of graph exporters
    """

    @staticmethod
    def create(filename: Path, format: GraphOutputFormat) -> "GraphExporter":
        """
        Factory to create a GraphExporter for the given SBOM type (based on the filename extension).
        """
        reader = BomReader.create(filename)
        if format == GraphOutputFormat.GRAPHML:
            if reader.sbom_type() == SBOMType.SPDX:
                from .spdx import SpdxGraphMLExporter

                exporter_cls = SpdxGraphMLExporter
            elif reader.sbom_type() == SBOMType.CycloneDX:
                from .cdx import CdxGraphMLExporter

                exporter_cls = CdxGraphMLExporter
            else:
                raise NotImplementedError("unreachable")
        else:
            raise NotImplementedError("unreachable")

        return exporter_cls(reader.read())

    @staticmethod
    def from_stream(
        stream: IOBase, bomtype: SBOMType, format: GraphOutputFormat
    ) -> "GraphExporter":
        """
        Factory to create a GraphExporter for the given SBOM type that takes the SBOM as stream.
        """
        bomtype.validate_dependency_availability()
        if bomtype == SBOMType.SPDX:
            from ..bomreader.spdxbomreader import SpdxBomReader
            from .spdx import SpdxGraphMLExporter

            bom = SpdxBomReader.read_stream(stream)
            if format == GraphOutputFormat.GRAPHML:
                return SpdxGraphMLExporter(bom)
        else:
            from ..bomreader.cdxbomreader import CdxBomReader
            from .cdx import CdxGraphMLExporter

            bom = CdxBomReader.read_stream(stream)
            if format == GraphOutputFormat.GRAPHML:
                return CdxGraphMLExporter(bom)

    @abstractmethod
    def export(self, output: IOBase):
        """Export the graph. Abstract method."""
        raise NotImplementedError()
