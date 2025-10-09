# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from collections import namedtuple
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from debian.deb822 import Deb822, Sources, Packages
from debian.debian_support import Version
import logging
from pathlib import Path

from ..util.compression import find_compressed_file_variants, stream_compressed_file
from ..dpkg.package import BinaryPackage, SourcePackage
from .. import HAS_PYTHON_APT


logger = logging.getLogger(__name__)


@dataclass
class ExtendedStates:
    """
    The apt extended states encode information if a package is manually
    installed or installed via a dependency only.
    """

    PackageFilter = namedtuple("BinaryPackage", "name arch")

    auto_installed: set[tuple[str, str]]

    def is_manual(self, name: str, arch: str) -> bool:
        """True if package is explicitly installed"""
        return (name, arch) not in self.auto_installed

    @classmethod
    def from_file(
        cls, file: str | Path, filter_fn: Callable[[PackageFilter], bool] | None = None
    ) -> "ExtendedStates":
        """Factory to create instance from the apt extended states file"""
        auto_installed = set()
        with open(Path(file)) as f:
            for s in Deb822.iter_paragraphs(f, use_apt_pkg=HAS_PYTHON_APT):
                name = s.get("Package")
                arch = s.get("Architecture")
                if s.get("Auto-Installed") != "1":
                    continue
                if (filter_fn is None) or (filter_fn(cls.PackageFilter(name, arch))):
                    auto_installed.add((name, arch))

        return cls(auto_installed=auto_installed)


@dataclass
class Repository:
    """Represents a debian repository as cached by apt."""

    in_release_file: Path
    origin: str | None
    codename: str | None
    architectures: list[str]
    components: list[str] | None = None
    version: Version | None = None
    description: str | None = None

    BinaryPackageFilter = namedtuple("BinaryPackage", "name arch version")
    SourcePackageFilter = namedtuple("SourcePackage", "name version")

    @classmethod
    def from_apt_cache(cls, lists_dir: str | Path) -> Iterable["Repository"]:
        """Create repositories from apt lists directory."""
        for entry in Path(lists_dir).iterdir():
            if entry.name.endswith("_InRelease"):
                with open(entry) as f:
                    repo = Deb822(f)
                origin = repo.get("Origin")
                codename = repo.get("Codename")
                version = repo.get("Version")
                architectures = repo.get("Architectures", "").split()
                components = repo.get("Components")
                description = repo.get("Description")
                logger.info(f"Found apt lists cache repository: {entry}")
                if not len(architectures):
                    logger.error(f"Repository does not specify 'Architectures', ignoring: {entry}")
                    continue
                yield Repository(
                    in_release_file=entry,
                    origin=origin,
                    codename=codename,
                    version=Version(version) if version else None,
                    architectures=architectures,
                    components=components.split() if components else None,
                    description=description,
                )

    @classmethod
    def _make_srcpkgs(
        cls,
        sources: Iterable[Sources],
        filter_fn: Callable[[SourcePackageFilter], bool] | None = None,
    ) -> Iterable[SourcePackage]:
        _sources = (
            filter(
                lambda p: filter_fn(cls.SourcePackageFilter(p["Package"], p["Version"])), sources
            )
            if filter_fn
            else sources
        )
        for source in _sources:
            yield SourcePackage.from_dep822(source)

    @classmethod
    def _make_binpkgs(
        cls,
        packages: Iterable[Packages],
        filter_fn: Callable[[BinaryPackageFilter], bool] | None = None,
    ) -> Iterable[BinaryPackage]:
        _pkgs = (
            filter(
                lambda p: filter_fn(
                    cls.BinaryPackageFilter(p["Package"], p["Architecture"], p["Version"])
                ),
                packages,
            )
            if filter_fn
            else packages
        )
        for pkg in _pkgs:
            yield BinaryPackage.from_dep822(pkg)

    @classmethod
    def _parse_sources(
        cls, sources_file: str, srcpkg_filter: Callable[[SourcePackageFilter], bool] | None = None
    ) -> Iterable["SourcePackage"]:
        sources_path = Path(sources_file)
        try:
            if sources_path.exists():
                with open(sources_path) as f:
                    logger.debug(f"Parsing apt cache source packages: {sources_file}")
                    sources_raw = Packages.iter_paragraphs(f, use_apt_pkg=HAS_PYTHON_APT)
                    for s in Repository._make_srcpkgs(sources_raw, srcpkg_filter):
                        yield s
            else:
                compressed_variant = find_compressed_file_variants(sources_path)[0]
                content = stream_compressed_file(compressed_variant)
                logger.debug(f"Parsing apt cache source packages: {sources_file}")
                # TODO: in python-debian >= 1.0.0 it is possible to directly
                # pass the filename of a compressed file when using apt_pkg
                sources_raw = Packages.iter_paragraphs(content, use_apt_pkg=False)
                for s in Repository._make_srcpkgs(sources_raw, srcpkg_filter):
                    yield s
        except (FileNotFoundError, IndexError, RuntimeError):
            logger.debug(f"Missing apt cache sources: {sources_file}")

    @classmethod
    def _parse_packages(
        cls, packages_file: str, binpkg_filter: Callable[[BinaryPackageFilter], bool] | None = None
    ) -> Iterable[BinaryPackage]:
        packages_path = Path(packages_file)
        try:
            if packages_path.exists():
                with open(packages_path) as f:
                    packages_raw = Packages.iter_paragraphs(f, use_apt_pkg=HAS_PYTHON_APT)
                    logger.debug(f"Parsing apt cache binary packages: {packages_file}")
                    for s in Repository._make_binpkgs(packages_raw, binpkg_filter):
                        yield s
            else:
                compressed_variant = find_compressed_file_variants(packages_path)[0]
                content = stream_compressed_file(compressed_variant)
                # TODO: in python-debian >= 1.0.0 it is possible to directly
                # pass the filename of a compressed file when using apt_pkg
                packages_raw = Packages.iter_paragraphs(content, use_apt_pkg=False)
                logger.debug(f"Parsing apt cache binary packages: {packages_file}")
                for s in Repository._make_binpkgs(packages_raw, binpkg_filter):
                    yield s
        except (FileNotFoundError, IndexError, RuntimeError):
            logger.debug(f"Missing apt cache packages: {packages_file}")

    def sources(
        self, filter_fn: Callable[[SourcePackageFilter], bool] | None = None
    ) -> Iterable[SourcePackage]:
        """Get all source packages from this repository."""
        repo_base = str(self.in_release_file).removesuffix("_InRelease")
        if self.components:
            for component in self.components:
                sources_file = "_".join([repo_base, component, "source", "Sources"])
                for s in self._parse_sources(sources_file, filter_fn):
                    yield s
        else:
            sources_file = "_".join([repo_base, "source", "Sources"])
            return self._parse_sources(sources_file, filter_fn)

    def binpackages(
        self,
        filter_fn: Callable[[BinaryPackageFilter], bool] | None = None,
        ext_states: ExtendedStates = ExtendedStates(set()),
    ) -> Iterable[BinaryPackage]:
        """Get all binary packages from this repository"""
        repo_base = str(self.in_release_file).removesuffix("_InRelease")
        if self.components:
            for component in self.components:
                for arch in self.architectures:
                    packages_file = "_".join([repo_base, component, f"binary-{arch}", "Packages"])
                    for p in self._parse_packages(packages_file, filter_fn):
                        p.manually_installed = ext_states.is_manual(p.name, p.architecture)
                        yield p
        else:
            for arch in self.architectures:
                packages_file = "_".join([repo_base, f"binary-{arch}", "Packages"])
                for p in self._parse_packages(packages_file, filter_fn):
                    p.manually_installed = ext_states.is_manual(p.name, p.architecture)
                    yield p
