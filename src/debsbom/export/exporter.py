# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from abc import abstractmethod
from enum import Enum
from pathlib import Path
from typing import IO

from ..sbom import SBOMType


class GraphOutputFormat(Enum):
    """Enum of supported graph formats"""

    GRAPHML = (0,)

    @classmethod
    def from_str(cls, name: str) -> "GraphOutputFormat":
        if name.lower() == "graphml":
            return cls.GRAPHML
        raise RuntimeError(f"Unsupported output format: '{name}'")


class GraphExporter:
    """
    Base class of graph exporters
    """

    @staticmethod
    def create(filename: Path, format: GraphOutputFormat) -> "GraphExporter":
        """
        Factory to create a GraphExporter for the given SBOM type (based on the filename extension).
        """
        if filename.name.endswith("spdx.json"):
            from ..bomreader import SpdxBomReader
            from .spdx import SpdxGraphMLExporter

            bom = SpdxBomReader.read_file(filename)
            if format == GraphOutputFormat.GRAPHML:
                return SpdxGraphMLExporter(bom)
        elif filename.name.endswith("cdx.json"):
            from ..bomreader import CdxBomReader
            from .cdx import CdxGraphMLExporter

            bom = CdxBomReader.read_file(filename)
            if format == GraphOutputFormat.GRAPHML:
                return CdxGraphMLExporter(bom)
        else:
            raise RuntimeError("Cannot determine file format")

    @staticmethod
    def from_stream(stream: IO, bomtype: SBOMType, format: GraphOutputFormat) -> "GraphExporter":
        """
        Factory to create a GraphExporter for the given SBOM type that takes the SBOM as stream.
        """
        if bomtype == SBOMType.SPDX:
            from ..bomreader import SpdxBomReader
            from .spdx import SpdxGraphMLExporter

            bom = SpdxBomReader.read_stream(stream)
            if format == GraphOutputFormat.GRAPHML:
                return SpdxGraphMLExporter(bom)
        else:
            from ..bomreader import CdxBomReader
            from .cdx import CdxGraphMLExporter

            bom = CdxBomReader.read_stream(stream)
            if format == GraphOutputFormat.GRAPHML:
                return CdxGraphMLExporter(bom)

    @abstractmethod
    def export(self, output: IO):
        """Export the graph. Abstract method."""
        raise NotImplementedError()
