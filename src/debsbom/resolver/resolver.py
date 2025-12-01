# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from abc import abstractmethod
from pathlib import Path
from io import IOBase

from ..dpkg import package
from ..sbom import SBOMType


class PackageResolver:
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
    def create(filename: Path) -> "PackageResolver":
        """
        Factory to create a PackageResolver for the given SBOM type (based on the filename extension).
        """
        if filename.name.endswith("spdx.json"):
            from .spdx import SpdxPackageResolver
            from ..bomreader import SpdxBomReader

            return SpdxPackageResolver(SpdxBomReader.read_file(filename))
        elif filename.name.endswith("cdx.json"):
            from .cdx import CdxPackageResolver
            from ..bomreader import CdxBomReader

            return CdxPackageResolver(CdxBomReader.read_file(filename))
        else:
            raise RuntimeError("Cannot determine file format")

    @staticmethod
    def from_stream(stream: IOBase, bomtype=SBOMType) -> "PackageResolver":
        """
        Factory to create a PackageResolver for the given SBOM type that parses a stream.
        """
        if bomtype == SBOMType.SPDX:
            from .spdx import SpdxPackageResolver
            from ..bomreader import SpdxBomReader

            return SpdxPackageResolver(SpdxBomReader.read_stream(stream))
        else:
            from .cdx import CdxPackageResolver
            from ..bomreader import CdxBomReader

            return CdxPackageResolver(CdxBomReader.read_stream(stream))


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
