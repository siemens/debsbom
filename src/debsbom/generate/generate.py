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

from ..apt.cache import Repository, ExtendedStates
from ..dpkg.package import BinaryPackage, Package, SourcePackage
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

    def _import_packages(self):
        root = Path(self.root)
        packages = dict(
            map(lambda p: (hash(p), p), Package.parse_status_file(root / "var/lib/dpkg/status"))
        )

        # names of packages in apt cache we also have referenced
        sp_names_apt = set([p.name for p in packages.values() if isinstance(p, SourcePackage)])
        bin_names_apt = set(
            [(p.name, p.architecture) for p in packages.values() if isinstance(p, BinaryPackage)]
        )

        logging.info("load source packages from apt cache")
        apt_lists = root / "var/lib/apt/lists"
        if apt_lists.is_dir():
            repos = Repository.from_apt_cache(apt_lists)
        else:
            logger.info("Missing apt lists cache, some source packages might be incomplete")
            repos = iter([])

        # load extended status information
        apt_ext_s_file = root / "var/lib/apt/extended_states"
        if apt_ext_s_file.is_file():
            apt_extended_states = ExtendedStates.from_file(
                apt_ext_s_file, lambda p, a: (p, a) in bin_names_apt
            )
        else:
            logging.info(
                "Missing apt extended_states file, all packages will be marked as manually installed"
            )
            apt_extended_states = ExtendedStates(set())

        # Create uniform list of all packages both we and the apt cache knows
        # This list shall contain a superset of our packages (minus non-upstream ones)
        # but filtering should be as good as possible as the apt cache contains potentially
        # tenth of thousands packages.
        packages_it = itertools.chain.from_iterable(
            map(
                lambda r: itertools.chain(
                    r.sources(lambda p: p in sp_names_apt),
                    r.binpackages(lambda p, a: (p, a) in bin_names_apt, apt_extended_states),
                ),
                repos,
            )
        )

        # O(n) algorithm to extend our packages with information from the apt cache
        # Idea: Iterate apt cache (expensive!) and annotate local package if matching
        logging.info("enhance referenced packages with apt cache information")
        for p in packages_it:
            ours = packages.get(hash(p))
            if not ours:
                continue
            if not ours.maintainer and p.maintainer:
                ours.maintainer = p.maintainer
                logger.debug(f"Extended package information for '{p.name}@{p.version}'")
            if isinstance(ours, BinaryPackage):
                if not ours.checksums and p.checksums:
                    ours.checksums = p.checksums
                ours.manually_installed = p.manually_installed

        self.packages = set(packages.values())

    def generate(
        self,
        out: str,
        progress_cb: Callable[[int, int, str], None] | None = None,
        validate: bool = False,
    ):
        """
        Generate SBOMs. The progress callback is of format: (i,n,package)
        """
        self._import_packages()

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
