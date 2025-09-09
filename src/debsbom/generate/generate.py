# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from datetime import datetime
from typing import Callable, Set, Tuple
import cyclonedx.output as cdx_output
import cyclonedx.schema as cdx_schema
from pathlib import Path
import spdx_tools.spdx.writer.json.json_writer as spdx_json_writer
from uuid import UUID

from ..dpkg.package import Package
from ..sbom import SBOMType
from .cdx import cyclonedx_bom
from .spdx import spdx_bom


class Debsbom:
    def __init__(
        self,
        distro_name: str,
        sbom_types: Set[SBOMType] = SBOMType.SPDX,
        root: str = "/",
        distro_supplier: str = None,
        distro_version: str = None,
        spdx_namespace: Tuple | None = None,  # 6 item tuple representing an URL
        cdx_serialnumber: UUID = None,
        timestamp: datetime = None,
    ):
        self.sbom_types = sbom_types
        self.root = root
        self.distro_name = distro_name
        self.distro_version = distro_version
        self.distro_supplier = distro_supplier

        self.spdx_namespace = spdx_namespace
        if spdx_namespace is not None and self.spdx_namespace.fragment:
            raise ValueError(
                "url fragments are not allowed in SPDX namespaces: '#{}'".format(
                    self.spdx_namespace.fragment
                )
            )

        self.cdx_serialnumber = cdx_serialnumber
        self.timestamp = timestamp

        self.packages = None

    def generate(
        self,
        out: str,
        progress_cb: Callable[[int, int, str], None] | None = None,
        validate: bool = False,
    ):
        """
        Generate SBOMs. The progress callback is of format: (i,n,package)
        """
        self.packages = list(Package.parse_status_file(Path(self.root) / "var/lib/dpkg/status"))

        if SBOMType.CycloneDX in self.sbom_types:
            cdx_out = out
            if not cdx_out.endswith(".cdx.json"):
                cdx_out += ".cdx.json"
            bom = cyclonedx_bom(
                self.packages,
                self.distro_name,
                distro_supplier=self.distro_supplier,
                distro_version=self.distro_version,
                serial_number=self.cdx_serialnumber,
                timestamp=self.timestamp,
                progress_cb=progress_cb,
            )
            cdx_output.make_outputter(
                bom, cdx_schema.OutputFormat.JSON, cdx_schema.SchemaVersion.V1_6
            ).output_to_file(cdx_out, allow_overwrite=True, indent=4)
        if SBOMType.SPDX in self.sbom_types:
            spdx_out = out
            if not spdx_out.endswith(".spdx.json"):
                spdx_out += ".spdx.json"
            bom = spdx_bom(
                self.packages,
                self.distro_name,
                distro_supplier=self.distro_supplier,
                distro_version=self.distro_version,
                namespace=self.spdx_namespace,
                timestamp=self.timestamp,
                progress_cb=progress_cb,
            )
            spdx_json_writer.write_document_to_file(bom, spdx_out, validate)
