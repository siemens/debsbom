# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from abc import abstractmethod
from datetime import datetime
from uuid import UUID

from ..sbom import SBOMType


class SbomComparator:
    """Base class for comparing SBOMs."""

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
    def create(sbom_type: SBOMType, **kwargs) -> "SbomComparator":
        sbom_type.validate_dependency_availability()
        if sbom_type is SBOMType.SPDX:
            from .spdx import SpdxSbomComparator

            return SpdxSbomComparator(**kwargs)
        elif sbom_type is SBOMType.CycloneDX:
            from .cdx import CdxSbomComparator

            return CdxSbomComparator(**kwargs)
        else:
            raise NotImplementedError()

    @classmethod
    @abstractmethod
    def compare(cls, base_sbom, target_sbom):
        """Compare the SBOMs."""
        raise NotImplementedError()
