# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from abc import abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from io import IOBase

from packageurl import PackageURL

from ..bomreader.bomreader import BomReader
from ..util.sbom_processor import SbomProcessor
from ..sbom import SBOMType


@dataclass
class PackageRepr:
    """
    Simple package representation that covers meta, source and binary packages.
    """

    name: str
    ref: str
    version: str | None = None
    maintainer: str | None = None
    purl: str | None = None

    def __str__(self):
        NOA = "NoAssertion"
        return f"{self.name}\t{self.version or NOA}\t{self.purl or NOA}\t{self.maintainer or NOA}"


class GraphWalker(SbomProcessor):
    """
    Base class of graph walkers
    """

    @staticmethod
    def _create_from_reader(reader: BomReader) -> "GraphWalker":
        if reader.sbom_type() == SBOMType.SPDX:
            from .spdx import SpdxGraphWalker

            return SpdxGraphWalker(reader.read())
        else:
            from .cdx import CdxGraphWalker

            return CdxGraphWalker(reader.read())

    @classmethod
    def create(
        cls,
        filename: Path,
        bomtype: SBOMType | None = None,
    ) -> "GraphWalker":
        """
        Factory to create a GraphWalker for the given SBOM type (based on the filename extension).
        """
        reader = BomReader.create(filename, bomtype)
        return cls._create_from_reader(reader)

    @classmethod
    def from_stream(cls, stream: IOBase, bomtype: SBOMType) -> "GraphWalker":
        """
        Factory to create a GraphWalker for the given SBOM type that takes the SBOM as stream.
        """
        reader = BomReader.from_stream(stream, bomtype)
        return cls._create_from_reader(reader)

    @classmethod
    def from_json(cls, json_obj: IOBase, bomtype: SBOMType) -> "GraphWalker":
        """
        Factory to create a GraphWalker for the given SBOM type that takes a json object.
        """
        reader = BomReader.from_json(json_obj, bomtype)
        return cls._create_from_reader(reader)

    @abstractmethod
    def shortest(self, source: PackageURL) -> list[PackageRepr]:
        """Return shortest path from source to root. Abstract method."""
        raise NotImplementedError()

    @abstractmethod
    def all_shortest(self, source: PackageURL) -> Iterable[list[PackageRepr]]:
        """Return all shortest path from source to root. Abstract method."""
        raise NotImplementedError()

    @abstractmethod
    def all_simple(self, source: PackageURL) -> Iterable[list[PackageRepr]]:
        """Return all non-cyclic path from source to root. Abstract method."""
        raise NotImplementedError()
