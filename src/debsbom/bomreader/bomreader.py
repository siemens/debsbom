# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from abc import abstractmethod
from pathlib import Path
from typing import IO


class BomReader:
    """Base class for SBOM importers"""

    @classmethod
    @abstractmethod
    def read_file(cls, filename: Path):
        """Parse and return a BOM instance from the file"""
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def read_stream(cls, stream: IO[str]):
        """Parse and return a BOM instance from the stream"""
        raise NotImplementedError()
