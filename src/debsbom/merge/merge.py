# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from abc import abstractmethod
from collections.abc import Callable
from datetime import datetime
from uuid import UUID

from ..sbom import SBOMType


class SbomMerger:
    """Base class for merging SBOMs."""

    def __init__(
        self,
        distro_name: str,
        distro_supplier: str | None = None,
        distro_version: str | None = None,
        base_distro_vendor: str | None = "debian",
        spdx_namespace: tuple | None = None,  # 6 item tuple representing an URL
        cdx_serialnumber: UUID | None = None,
        timestamp: datetime | None = None,
    ):
        self.distro_name = distro_name
        self.distro_supplier = distro_supplier
        self.distro_version = distro_version
        self.base_distro_vendor = base_distro_vendor
        self.namespace = spdx_namespace
        self.cdx_serialnumber = cdx_serialnumber
        if timestamp is None:
            self.timestamp = datetime.now()
        else:
            self.timestamp = timestamp

    @staticmethod
    def create(sbom_type: SBOMType, **kwargs) -> "SbomMerger":
        sbom_type.validate_dependency_availability()
        if sbom_type is SBOMType.SPDX:
            from .spdx import SpdxSbomMerger

            return SpdxSbomMerger(**kwargs)
        elif sbom_type is SBOMType.CycloneDX:
            from .cdx import CdxSbomMerger

            return CdxSbomMerger(**kwargs)
        else:
            raise NotImplementedError()

    @classmethod
    @abstractmethod
    def merge(cls, sboms, progress_cb: Callable[[int, int, str], None] | None = None):
        """Merge the SBOMs."""
        raise NotImplementedError()
