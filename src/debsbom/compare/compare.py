# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from abc import abstractmethod
from collections.abc import Callable
from datetime import datetime
from uuid import UUID


class SbomCompare:
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

    @classmethod
    @abstractmethod
    def compare(cls, base_sbom, target_sbom):
        """Compare the SBOMs."""
        raise NotImplementedError()

    @classmethod
    def run_compare(cls, fmt: str, args, base_json_obj, target_json_obj, base_path, target_path):
        if fmt == "spdx":
            from ..bomreader.spdxbomreader import SpdxBomReader
            from .spdx import SpdxSbomCompare

            reader = SpdxBomReader
            comparator_cls = SpdxSbomCompare

        elif fmt == "cdx":
            from ..bomreader.cdxbomreader import CdxBomReader
            from .cdx import CdxSbomCompare

            reader = CdxBomReader
            comparator_cls = CdxSbomCompare

        else:
            raise ValueError(f"Unsupported SBOM format: {fmt}")

        if base_json_obj is not None:
            base_sbom = reader.from_json(base_json_obj)
        else:
            base_sbom = reader.read_file(base_path)

        if target_json_obj is not None:
            target_sbom = reader.from_json(target_json_obj)
        else:
            target_sbom = reader.read_file(target_path)

        comparator = comparator_cls(
            distro_name=args.distro_name,
            distro_supplier=args.distro_supplier,
            distro_version=args.distro_version,
            base_distro_vendor=args.base_distro_vendor,
            spdx_namespace=args.spdx_namespace,
            cdx_serialnumber=args.cdx_serialnumber,
            timestamp=args.timestamp,
        )

        bom = comparator.compare(base_sbom, target_sbom)

        return bom
