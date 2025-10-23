# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from abc import abstractmethod
from collections.abc import Callable
from datetime import datetime
from uuid import UUID


class ChecksumMismatchError(RuntimeError):
    def __init__(self, name: str, purl: str | None, alg: str, checksum1: str, checksum2: str):
        if purl:
            super().__init__(
                f"Checksum mismatch for '{name}' ({purl}): {alg}: {checksum1} != {checksum2}"
            )
        else:
            super().__init__(f"Checksum mismatch for '{name}': {alg}: {checksum1} != {checksum2}")


class SbomMerger:
    """Base class for merging SBOMs."""

    def __init__(
        self,
        distro_name: str,
        distro_supplier: str | None = None,
        distro_version: str | None = None,
        base_distro_vendor: str | None = "debian",
        spdx_namespace: tuple | None = None,  # 6 item tuple representing an URL
        cdx_serialnumber: UUID = None,
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
    def merge(cls, sboms, progress_cb: Callable[[int, int, str], None] | None = None):
        """Merge the SBOMs."""
        raise NotImplementedError()
