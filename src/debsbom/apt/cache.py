# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Iterable
from dataclasses import dataclass
from debian.deb822 import Deb822, Sources
from debian.debian_support import Version
import logging
import os
from pathlib import Path

from ..dpkg.package import SourcePackage


logger = logging.getLogger(__name__)


@dataclass
class Repository:
    """Represents a debian repository as cached by apt."""

    in_release_file: Path
    origin: str
    codename: str
    architectures: list[str]
    components: list[str] | None = None
    version: Version | None = None
    description: str | None = None

    @classmethod
    def from_apt_cache(cls, lists_dir: str | Path) -> Iterable["Repository"]:
        """Create repositories from apt lists directory."""
        for entry in Path(lists_dir).iterdir():
            if entry.name.endswith("_InRelease"):
                with open(entry) as f:
                    repo = Deb822(f)
                origin = repo["Origin"]
                codename = repo.get("Codename")
                version = repo.get("Version")
                architectures = repo["Architectures"].split()
                components = repo.get("Components")
                description = repo.get("Description")
                logger.info(f"Found apt lists cache repository: {entry}")
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
    def _make_srcpkgs(cls, sources: Iterable[Sources]) -> Iterable[SourcePackage]:

        for source in sources:
            name = source["Package"]
            version = Version(source.get("Version"))
            maintainer = source.get("Maintainer")
            if source.get("Binaries") is not None:
                binaries = [b.strip() for b in source["Binaries"].split(",")]
            else:
                binaries = None
            homepage = source.get("Homepage")
            vcs_browser = source.get("Vcs-Browser")
            vcs_git = source.get("Vcs-Git")
            yield SourcePackage(
                name=name,
                version=version,
                maintainer=maintainer,
                binaries=binaries,
                homepage=homepage,
                vcs_browser=vcs_browser,
                vcs_git=vcs_git,
            )

    @classmethod
    def _parse_sources(cls, sources_file: str) -> Iterable["SourcePackage"]:
        try:
            with open(sources_file) as f:
                logger.debug(f"Parsing apt cache sources: {sources_file}")
                sources_raw = Sources.iter_paragraphs(f, use_apt_pkg=False)
                for s in Repository._make_srcpkgs(sources_raw):
                    yield s
        except FileNotFoundError:
            logger.debug(f"Missing apt cache sources: {sources_file}")

    def sources(self) -> Iterable[SourcePackage]:
        """Get all source packages from this repository."""
        repo_base = str(self.in_release_file).removesuffix("_InRelease")
        if self.components:
            for component in self.components:
                sources_file = "_".join([repo_base, component, "source", "Sources"])
                for s in self._parse_sources(sources_file):
                    yield s
        else:
            sources_file = "_".join([repo_base, "source", "Sources"])
            return self._parse_sources(sources_file)
