# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Callable, Iterable
from datetime import datetime
from debian.copyright import MachineReadableFormatError, NotMachineReadableError
from debian.debian_support import Version
from io import TextIOWrapper
import itertools
import sys
import logging
from pathlib import Path
from uuid import UUID

from ..apt.cache import Repository, ExtendedStates
from ..apt.copyright import CopyrightDirectory
from ..dpkg.package import (
    BinaryPackage,
    Dependency,
    Package,
    PkgListType,
    VirtualPackage,
    filter_binaries,
    filter_sources,
)
from ..bomwriter import BomWriter
from ..sbom import SBOMType, BOM_Standard


logger = logging.getLogger(__name__)

# disable noisy URL format warnings
deb_logger = logging.getLogger("debian.copyright")
deb_logger.setLevel(logging.ERROR)


class DistroArchUnknownError(RuntimeError):
    """The distro arch is not set and could not be determined"""

    def __init__(self):
        super().__init__("Unable to auto detect distro architecture")


class Debsbom:
    def __init__(
        self,
        distro_name: str,
        sbom_types: set[SBOMType] | list[SBOMType] = [SBOMType.SPDX],
        root: str | Path = "/",
        distro_supplier: str | None = None,
        distro_version: str | None = None,
        distro_arch: str | None = None,
        base_distro_vendor: str = "debian",
        spdx_namespace: tuple | None = None,  # 6 item tuple representing an URL
        cdx_serialnumber: UUID | None = None,
        timestamp: datetime | None = None,
        add_meta_data: dict[str, str] | None = None,
        cdx_standard: BOM_Standard = BOM_Standard.DEFAULT,
        with_licenses: bool = False,
    ):
        self.sbom_types = set(sbom_types)
        self.root = Path(root)
        self.distro_name = distro_name
        self.distro_version = distro_version
        self.distro_supplier = distro_supplier
        self.distro_arch = distro_arch
        self.base_distro_vendor = base_distro_vendor
        self.cdx_standard = cdx_standard
        self.with_licenses = with_licenses

        self.spdx_namespace = spdx_namespace
        if spdx_namespace is not None and self.spdx_namespace.fragment:
            raise ValueError(
                "url fragments are not allowed in SPDX namespaces: '#{}'".format(
                    self.spdx_namespace.fragment
                )
            )

        self.cdx_serialnumber = cdx_serialnumber
        self.timestamp = timestamp
        self.add_meta_data: dict[str, str] = self._parse_meta_data(add_meta_data)

        logger.info(f"Configuration: {self.__dict__}")
        self.packages: set[Package] = set()

    @staticmethod
    def _parse_meta_data(meta_args: list[str] | None) -> dict[str, str]:
        metadata: dict[str, str] = {}

        if not meta_args:
            return metadata

        for item in meta_args:
            if "=" not in item:
                raise ValueError(f"invalid --add-meta-data '{item}', expected key=value")

            key, value = item.split("=", 1)

            if not key:
                raise ValueError(f"invalid --add-meta-data '{item}', key must be non-empty")
            if not value:
                raise ValueError(f"invalid --add-meta-data '{item}', value must be non-empty")

            metadata[key] = value

        return metadata

    def _import_packages(self, stream=None):
        if stream:
            packages_it = Package.parse_pkglist_stream(stream)
            # if we use packages from a stream we skip extended states since
            # the apt cache is not directly related to the package list
            merge_ext_states = False
        else:
            packages_it = Package.parse_status_file(self.root / "var/lib/dpkg/status")
            merge_ext_states = True
        if not self.distro_arch:
            if self.root:
                self.distro_arch = self._parse_distro_arch(self.root / "var/lib/dpkg/arch-native")
            if not self.distro_arch:
                raise DistroArchUnknownError()
        logger.debug(f"distro arch is '{self.distro_arch}'")

        pkgdict = dict(map(lambda p: (hash(p), p), packages_it))
        self.packages = self._merge_apt_data(
            pkgdict,
            inject_sources=packages_it.kind != PkgListType.STATUS_FILE,
            merge_ext_states=merge_ext_states,
            with_licenses=self.with_licenses,
        )

    @classmethod
    def _parse_distro_arch(cls, arch_native_file: Path) -> str | None:
        if not arch_native_file.is_file():
            return None
        return arch_native_file.read_text().strip()

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

        for p in filter_binaries(packages.values()):
            p.manually_installed = ext_states.is_manual(p.name, p.architecture)

    def _merge_apt_data(
        self,
        packages: dict[int, Package],
        inject_sources: bool = False,
        merge_ext_states: bool = True,
        with_licenses: bool = False,
    ) -> set[Package]:
        bin_names_apt = set(
            map(
                lambda p: (p.name, p.architecture, p.version),
                filter_binaries(packages.values()),
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
            for source_pkg in Package.referenced_src_packages(filter_binaries(packages.values())):
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
                filter_sources(packages.values()),
            )
        )

        # wait for the copyright merging until we have all source packages
        if with_licenses:
            self._add_copyright(packages)

        def source_filter(spf: Repository.SourcePackageFilter) -> bool:
            return spf in sp_names_apt

        self._merge_apt_source_data(packages, repos, source_filter)

        bin_names_apt = set(map(lambda bn: (bn[0], bn[1]), bin_names_apt))

        def extended_states_filter(pf: ExtendedStates.PackageFilter) -> bool:
            return pf in bin_names_apt

        # Even without apt-cache data, we still may have extended states. Add them.
        if merge_ext_states:
            self._merge_extended_states(
                packages,
                extended_states_filter,
            )
        return set(packages.values())

    def _add_copyright(self, packages: dict[int, Package]):
        logger.info("Adding copyright information...")
        cr_dir = CopyrightDirectory.for_rootdir(self.root)
        to_add = {}
        for bin_pkg in filter_binaries(packages.values()):
            src_pkg = bin_pkg.source_package()
            if not src_pkg:
                continue
            try:
                cr = cr_dir.copyright(bin_pkg)
            except FileNotFoundError:
                logger.debug(f"no copyright information for {bin_pkg}")
                continue
            except NotMachineReadableError:
                logger.debug(f"non-machine-readable copyright file for {bin_pkg}")
                continue
            except (MachineReadableFormatError, ValueError):
                logger.debug(f"bad format for machine-readable copyright file for {bin_pkg}")
                continue
            src_pkg = packages.get(hash(src_pkg))
            if src_pkg:
                src_pkg.copyright = cr

        for k, v in to_add.items():
            packages[k].copyright = v

    def _virtual_packages(self) -> dict[str, list[tuple[VirtualPackage, BinaryPackage]]]:
        binary_packages = filter(lambda p: p.is_binary(), self.packages)

        virtual_packages = {}
        for bpkg in binary_packages:
            for provides in bpkg.provides or []:
                vpkg_name = provides.name
                p = virtual_packages.get(vpkg_name)
                if p:
                    p.append((provides, bpkg))
                else:
                    virtual_packages[vpkg_name] = [(provides, bpkg)]

        return virtual_packages

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

        virtual_packages = self._virtual_packages()

        write_to_stdout = out == "-"
        if SBOMType.CycloneDX in self.sbom_types:
            from .cdx import cyclonedx_bom

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
                distro_arch=self.distro_arch,
                distro_supplier=self.distro_supplier,
                distro_version=self.distro_version,
                serial_number=self.cdx_serialnumber,
                base_distro_vendor=self.base_distro_vendor,
                timestamp=self.timestamp,
                add_meta_data=self.add_meta_data,
                standard=self.cdx_standard,
                virtual_packages=virtual_packages,
                progress_cb=progress_cb,
            )
            bomwriter = BomWriter.create(SBOMType.CycloneDX)
            if write_to_stdout:
                bomwriter.write_to_stream(bom, sys.stdout, validate)
            else:
                bomwriter.write_to_file(bom, Path(cdx_out), validate)
        if SBOMType.SPDX in self.sbom_types:
            from .spdx import spdx_bom

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
                distro_arch=self.distro_arch,
                distro_supplier=self.distro_supplier,
                distro_version=self.distro_version,
                namespace=self.spdx_namespace,
                base_distro_vendor=self.base_distro_vendor,
                timestamp=self.timestamp,
                add_meta_data=self.add_meta_data,
                virtual_packages=virtual_packages,
                progress_cb=progress_cb,
            )
            bomwriter = BomWriter.create(SBOMType.SPDX)
            if write_to_stdout:
                bomwriter.write_to_stream(bom, sys.stdout, validate)
            else:
                bomwriter.write_to_file(bom, Path(spdx_out), validate)
