# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Callable, Iterable
from datetime import datetime
from io import TextIOWrapper
import itertools
import sys
import cyclonedx.output as cdx_output
import cyclonedx.schema as cdx_schema
import logging
from pathlib import Path
import spdx_tools.spdx.writer.json.json_writer as spdx_json_writer
from uuid import UUID

from ..apt.cache import Repository, ExtendedStates
from ..dpkg.package import BinaryPackage, Package, PkgListType, SourcePackage
from ..sbom import SBOMType, BOM_Standard
from .cdx import cyclonedx_bom
from .spdx import spdx_bom


logger = logging.getLogger(__name__)


class Debsbom:
    def __init__(
        self,
        distro_name: str,
        sbom_types: set[SBOMType] | list[SBOMType] = [SBOMType.SPDX],
        root: str | Path = "/",
        distro_supplier: str = None,
        distro_version: str = None,
        base_distro_vendor: str = "debian",
        spdx_namespace: tuple | None = None,  # 6 item tuple representing an URL
        cdx_serialnumber: UUID = None,
        timestamp: datetime = None,
        cdx_standard: BOM_Standard = BOM_Standard.DEFAULT,
    ):
        self.sbom_types = set(sbom_types)
        self.root = Path(root)
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
        self.packages: set[Package] = set()

    def _import_packages(self, stream=None):
        if stream:
            packages_it = Package.parse_pkglist_stream(stream)
        else:
            packages_it = Package.parse_status_file(self.root / "var/lib/dpkg/status")
        pkgdict = dict(map(lambda p: (hash(p), p), packages_it))
        self.packages = self._merge_apt_data(
            pkgdict, inject_sources=packages_it.kind != PkgListType.STATUS_FILE
        )

    def _create_apt_repos_it(self) -> Iterable[Repository]:
        apt_lists = self.root / "var/lib/apt/lists"
        if apt_lists.is_dir():
            return Repository.from_apt_cache(apt_lists)
        else:
            logger.info("Missing apt lists cache, some source packages might be incomplete")
            return iter([])

    def _merge_pkginfo(self, our_pkgs: dict[int, Package], cache_pkgs: Iterable[Package]):
        # O(n) algorithm to extend our packages with information from the apt cache
        # Idea: Iterate apt cache (expensive!) and annotate local package if matching
        for p in cache_pkgs:
            ours = our_pkgs.get(hash(p))
            if not ours:
                continue
            ours.merge_with(p)

    def _merge_apt_binary_data(
        self,
        packages: dict[int, Package],
        repos: list[Repository],
        filter_fn: Callable[[str, str, str], bool],
    ):
        # Create uniform list of all packages both we and the apt cache knows
        # This list shall contain a superset of our packages (minus non-upstream ones)
        # but filtering should be as good as possible as the apt cache contains potentially
        # tens of thousands packages. If we don't have apt-cache data, this iterator is empty.
        packages_it = itertools.chain.from_iterable(
            map(
                lambda r: itertools.chain(
                    r.binpackages(filter_fn),
                ),
                repos,
            )
        )

        logger.info("Enhance binary packages with apt cache information")
        self._merge_pkginfo(packages, packages_it)

    def _merge_apt_source_data(
        self,
        packages: dict[int, Package],
        repos: list[Repository],
        filter_fn: Callable[[str, str], bool],
    ):
        # see _merge_apt_binary_data why we create the iterator this way
        packages_it = itertools.chain.from_iterable(
            map(
                lambda r: itertools.chain(
                    r.sources(filter_fn),
                ),
                repos,
            )
        )

        logger.info("Enhance source packages with apt cache information")
        self._merge_pkginfo(packages, packages_it)

    def _merge_extended_states(
        self,
        packages: dict[int, Package],
        filter_fn: Callable[[ExtendedStates.PackageFilter], bool],
    ):
        apt_ext_s_file = self.root / "var/lib/apt/extended_states"
        if apt_ext_s_file.is_file():
            ext_states = ExtendedStates.from_file(
                apt_ext_s_file,
                filter_fn,
            )
        else:
            logger.info(
                "Missing apt extended_states file, all packages will be marked as manually installed"
            )
            return

        for p in filter(lambda pkg: isinstance(pkg, BinaryPackage), packages.values()):
            p.manually_installed = ext_states.is_manual(p.name, p.architecture)

    def _merge_apt_data(
        self, packages: dict[int, Package], inject_sources: bool = False
    ) -> set[Package]:
        bin_names_apt = set(
            map(
                lambda p: (p.name, p.architecture, p.version),
                filter(lambda p: isinstance(p, BinaryPackage), packages.values()),
            )
        )

        def binary_filter(bpf: Repository.BinaryPackageFilter) -> bool:
            return bpf in bin_names_apt

        logger.info("load source packages from apt cache")
        repos = list(self._create_apt_repos_it())

        # by incorporating the binary data from the apt-cache first we might
        # discover previously unknown source packages
        self._merge_apt_binary_data(packages, repos, binary_filter)

        # add any newly discovered source packages, if needed
        if inject_sources:
            to_add = []
            for source_pkg in Package.referenced_src_packages(
                filter(lambda p: isinstance(p, BinaryPackage), packages.values())
            ):
                shash = hash(source_pkg)
                if shash not in packages:
                    to_add.append(source_pkg)
            # we add it in a separate loop so we do not invalidate the packages iterator
            for source_pkg in to_add:
                packages[hash(source_pkg)] = source_pkg

        # now that we are sure have discovered all source packages, we can add any
        # additional apt-cache package data to them
        sp_names_apt = set(
            map(
                lambda p: (p.name, p.version),
                filter(lambda p: isinstance(p, SourcePackage), packages.values()),
            )
        )

        def source_filter(spf: Repository.SourcePackageFilter) -> bool:
            return spf in sp_names_apt

        self._merge_apt_source_data(packages, repos, source_filter)

        bin_names_apt = set(map(lambda bn: (bn[0], bn[1]), bin_names_apt))

        def extended_states_filter(pf: ExtendedStates.PackageFilter) -> bool:
            return pf in bin_names_apt

        # Even without apt-cache data, we still may have extended states. Add them.
        self._merge_extended_states(
            packages,
            extended_states_filter,
        )
        return set(packages.values())

    def generate(
        self,
        out: str,
        progress_cb: Callable[[int, int, str], None] | None = None,
        validate: bool = False,
        pkgs_stream: TextIOWrapper | None = None,
    ):
        """
        Generate SBOMs. The progress callback is of format: (i,n,package)
        """
        self._import_packages(stream=pkgs_stream)

        write_to_stdout = out == "-"
        if SBOMType.CycloneDX in self.sbom_types:
            cdx_out = out
            if cdx_out != "-" and not cdx_out.endswith(".cdx.json"):
                cdx_out += ".cdx.json"
            if write_to_stdout:
                logger.info("Generating CycloneDX SBOM...")
            else:
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
            if write_to_stdout:
                self.write_to_stream(bom, SBOMType.CycloneDX, sys.stdout, validate)
            else:
                self.write_to_file(bom, SBOMType.CycloneDX, Path(cdx_out), validate)
        if SBOMType.SPDX in self.sbom_types:
            spdx_out = out
            if spdx_out != "-" and not spdx_out.endswith(".spdx.json"):
                spdx_out += ".spdx.json"
            if write_to_stdout:
                logger.info("Generating SPDX SBOM...")
            else:
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
            if write_to_stdout:
                self.write_to_stream(bom, SBOMType.SPDX, sys.stdout, validate)
            else:
                self.write_to_file(bom, SBOMType.SPDX, Path(spdx_out), validate)

    @staticmethod
    def write_to_file(bom, bomtype: SBOMType, outfile: Path, validate: bool):
        if bomtype == SBOMType.CycloneDX:
            cdx_output.make_outputter(
                bom, cdx_schema.OutputFormat.JSON, cdx_schema.SchemaVersion.V1_6
            ).output_to_file(str(outfile), allow_overwrite=True, indent=4)
        elif bomtype == SBOMType.SPDX:
            spdx_json_writer.write_document_to_file(bom, str(outfile), validate)

    @staticmethod
    def write_to_stream(bom, bomtype: SBOMType, f: TextIOWrapper, validate: bool):
        if bomtype == SBOMType.CycloneDX:
            f.write(
                cdx_output.make_outputter(
                    bom, cdx_schema.OutputFormat.JSON, cdx_schema.SchemaVersion.V1_6
                ).output_as_string(indent=4)
            )
        elif bomtype == SBOMType.SPDX:
            spdx_json_writer.write_document_to_stream(bom, f, validate)
        f.write("\n")
