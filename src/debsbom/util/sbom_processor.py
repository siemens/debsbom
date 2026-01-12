# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from abc import abstractmethod
from io import IOBase
from pathlib import Path

from ..sbom import SBOMType


class SbomProcessor:
    """
    Interface class for all SBOM processors.
    """

    @classmethod
    @abstractmethod
    def create(cls, filename: Path, bomtype: SBOMType | None = None, **kwargs):
        """
        Factory to create a processor for the given SBOM type (based on filename extension).
        """
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def from_stream(cls, stream: IOBase, bomtype: SBOMType, **kwargs):
        """
        Factory to create a processor for the given stream.
        """
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def from_json(cls, json_obj, bomtype: SBOMType, **kwargs):
        """
        Factory to create a processor for the given sbom json object.
        """
        raise NotImplementedError()
