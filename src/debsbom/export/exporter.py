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
    def _create_from_reader(reader: BomReader, format: GraphOutputFormat) -> "GraphExporter":
        if format != GraphOutputFormat.GRAPHML:
            raise NotImplementedError("only GraphML is supported")

        if reader.sbom_type() == SBOMType.SPDX:
            from .spdx import SpdxGraphMLExporter

            return SpdxGraphMLExporter(reader.read())
        else:
            from .cdx import CdxGraphMLExporter

            return CdxGraphMLExporter(reader.read())

    @classmethod
    def create(
        cls,
        filename: Path,
        bomtype: SBOMType | None = None,
        format: GraphOutputFormat = GraphOutputFormat.GRAPHML,
    ) -> "GraphExporter":
        """
        Factory to create a GraphExporter for the given SBOM type (based on the filename extension).
        """
        reader = BomReader.create(filename, bomtype)
        return cls._create_from_reader(reader, format)

    @classmethod
    def from_stream(
        cls, stream: IOBase, bomtype: SBOMType, format: GraphOutputFormat
    ) -> "GraphExporter":
        """
        Factory to create a GraphExporter for the given SBOM type that takes the SBOM as stream.
        """
        reader = BomReader.from_stream(stream, bomtype)
        return cls._create_from_reader(reader, format)

    @abstractmethod
    def export(self, output: IOBase):
        """Export the graph. Abstract method."""
        raise NotImplementedError()
