# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from collections import defaultdict
from collections.abc import Callable
from datetime import datetime
import itertools
import cyclonedx.output as cdx_output
import cyclonedx.schema as cdx_schema
import logging
from pathlib import Path
import spdx_tools.spdx.writer.json.json_writer as spdx_json_writer
from uuid import UUID

from ..apt.cache import Repository
from ..dpkg.package import Package, SourcePackage
from ..sbom import SBOMType, BOM_Standard
from .cdx import cyclonedx_bom
from .spdx import spdx_bom


logger = logging.getLogger(__name__)


class Debsbom:
    def __init__(
        self,
        distro_name: str,
        sbom_types: set[SBOMType] | list[SBOMType] = [SBOMType.SPDX],
        root: str = "/",
        distro_supplier: str = None,
        distro_version: str = None,
        base_distro_vendor: str = "debian",
        spdx_namespace: tuple | None = None,  # 6 item tuple representing an URL
        cdx_serialnumber: UUID = None,
        timestamp: datetime = None,
        cdx_standard: BOM_Standard = BOM_Standard.DEFAULT,
    ):
        self.sbom_types = set(sbom_types)
        self.root = root
        self.distro_name = distro_name
        self.distro_version = distro_version
        self.distro_supplier = distro_supplier
        self.base_distro_vendor = base_distro_vendor
        self.cdx_standard = cdx_standard

        self.spdx_namespace = spdx_namespace
        if spdx_namespace is not None and self.spdx_namespace.fragment:
            raise ValueError(
                "url fragments are not allowed in SPDX namespaces: '#{}'".format(
                    self.spdx_namespace.fragment
                )
            )

        self.cdx_serialnumber = cdx_serialnumber
        self.timestamp = timestamp

        logger.info(f"Configuration: {self.__dict__}")

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
        root = Path(self.root)
        self.packages = set(Package.parse_status_file(root / "var/lib/dpkg/status"))
        # names of packages in apt cache we also have referenced
        sp_names_apt = set([p.name for p in self.packages if isinstance(p, SourcePackage)])

        logging.info("load source packages from apt cache")
        apt_lists = root / "var/lib/apt/lists"
        if apt_lists.is_dir():
            repos = Repository.from_apt_cache(apt_lists)
        else:
            logger.info("Missing apt lists cache, some source packages might be incomplete")
            repos = iter([])

        sources_it = itertools.chain.from_iterable(
            map(lambda r: r.sources(lambda p: p in sp_names_apt), repos)
        )

        # O(n) algorithm to extend our packages with information from the apt cache
        sources_by_name: defaultdict[str, SourcePackage] = defaultdict(set)
        for p in sources_it:
            sources_by_name[p.name].add(p)

        logging.info("enhance referenced packages with apt cache information")
        # find any source packages with incomplete information
        for package in [
            p for p in self.packages if isinstance(p, SourcePackage) and not p.maintainer
        ]:
            # this set is small, as each package has a limited number of known versions
            for source in sources_by_name.get(package.name, set()):
                if source.version == package.version:
                    logger.debug(
                        f"Extended source package information for '{package.name}@{package.version}'"
                    )
                    package.maintainer = source.maintainer
                    break

        if SBOMType.CycloneDX in self.sbom_types:
            cdx_out = out
            if not cdx_out.endswith(".cdx.json"):
                cdx_out += ".cdx.json"
            logger.info(f"Generating CycloneDX SBOM in '{cdx_out}'...")
            bom = cyclonedx_bom(
                self.packages,
                self.distro_name,
                distro_supplier=self.distro_supplier,
                distro_version=self.distro_version,
                serial_number=self.cdx_serialnumber,
                base_distro_vendor=self.base_distro_vendor,
                timestamp=self.timestamp,
                standard=self.cdx_standard,
                progress_cb=progress_cb,
            )
            cdx_output.make_outputter(
                bom, cdx_schema.OutputFormat.JSON, cdx_schema.SchemaVersion.V1_6
            ).output_to_file(cdx_out, allow_overwrite=True, indent=4)
        if SBOMType.SPDX in self.sbom_types:
            spdx_out = out
            if not spdx_out.endswith(".spdx.json"):
                spdx_out += ".spdx.json"
            logger.info(f"Generating SPDX SBOM in '{spdx_out}'...")
            bom = spdx_bom(
                self.packages,
                self.distro_name,
                distro_supplier=self.distro_supplier,
                distro_version=self.distro_version,
                namespace=self.spdx_namespace,
                base_distro_vendor=self.base_distro_vendor,
                timestamp=self.timestamp,
                progress_cb=progress_cb,
            )
            spdx_json_writer.write_document_to_file(bom, spdx_out, validate)
