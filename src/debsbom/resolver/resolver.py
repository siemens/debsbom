# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from abc import abstractmethod
from pathlib import Path
from io import IOBase

from ..bomreader.bomreader import BomReader
from ..util.sbom_processor import SbomProcessor
from ..dpkg import package
from ..sbom import SBOMType


class PackageResolver(SbomProcessor):
    """
    Creates internal package representations of an arbitrary
    package input. The packages are iteratively resolved.
    Iterable class.
    """

    def __iter__(self):
        return self

    @abstractmethod
    def __next__(self) -> package.Package:
        """Return next package"""
        raise NotImplementedError()

    @staticmethod
    def _create_from_reader(reader: BomReader) -> "PackageResolver":
        if reader.sbom_type() is SBOMType.SPDX:
            from .spdx import SpdxPackageResolver

            return SpdxPackageResolver(reader.read())
        else:
            from .cdx import CdxPackageResolver

            return CdxPackageResolver(reader.read())

    @classmethod
    def create(cls, filename: Path, bomtype: SBOMType | None = None) -> "PackageResolver":
        """
        Factory to create a PackageResolver for the given SBOM type (based on the filename extension).
        """
        reader = BomReader.create(filename, bomtype)
        return cls._create_from_reader(reader)

    @classmethod
    def from_stream(cls, stream: IOBase, bomtype=SBOMType) -> "PackageResolver":
        """
        Factory to create a PackageResolver for the given SBOM type that parses a stream.
        """
        reader = BomReader.from_stream(stream, bomtype)
        return cls._create_from_reader(reader)


class PackageStreamResolver(PackageResolver):
    """
    Handles universal package ingress. Emits (partial) package
    instances, depending on input. Iterable class.
    """

    def __init__(self, pkgstream: IOBase):
        """
        The input can be either be newline separated pkg-list entries
        (name version architecture) or newline separated PURLs.
        """
        self.packages = package.Package.parse_pkglist_stream(pkgstream)

    def __next__(self) -> package.Package:
        try:
            return next(self.packages)
        except ValueError as e:
            raise ValueError(f"invalid package-list format: {e}")
