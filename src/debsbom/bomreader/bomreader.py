# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from abc import abstractmethod
from pathlib import Path
from io import TextIOBase


class BomReader:
    """Base class for SBOM importers"""

    @classmethod
    @abstractmethod
    def read_file(cls, filename: Path):
        """Parse and return a BOM instance from the file"""
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def read_stream(cls, stream: TextIOBase):
        """Parse and return a BOM instance from the stream"""
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def from_json(cls, json_obj):
        """Parse and return a BOM instance from a Json object"""
        raise NotImplementedError
