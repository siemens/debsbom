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
        entries = list(os.scandir(lists_dir))
        for entry in entries:
            if entry.name.endswith("_InRelease"):
                with open(entry) as f:
                    repo = Deb822(f)
                    origin = repo["Origin"]
                    codename = repo.get("Codename")
                    version = repo.get("Version")
                    architectures = repo["Architectures"].split()
                    components = repo.get("Components")
                    description = repo.get("Description")
                    logger.info(f"Found apt lists cache repository: {entry.path}")
                    yield Repository(
                        in_release_file=Path(entry.path),
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

    def sources(self) -> list[SourcePackage]:
        """Get all source packages from this repository."""
        sources = []
        repo_base = str(self.in_release_file).removesuffix("_InRelease")
        if self.components:
            for component in self.components:
                sources_file = "_".join([repo_base, component, "source", "Sources"])
                try:
                    with open(sources_file) as f:
                        logger.debug(f"Parsing apt cache sources: {sources_file}")
                        sources_raw = list(Sources.iter_paragraphs(f, use_apt_pkg=False))
                        sources.extend(Repository._make_srcpkgs(sources_raw))
                except FileNotFoundError:
                    logger.debug(f"Missing apt cache sources: {sources_file}")
                    continue
        else:
            sources_file = "_".join([repo_base, "source", "Sources"])
            try:
                with open(sources_file) as f:
                    sources_raw = list(Sources.iter_paragraphs(f, use_apt_pkg=False))
                    sources.extend(Repository._make_srcpkgs(sources_raw))
            except FileNotFoundError:
                logger.debug(f"Missing apt cache sources: {sources_file}")
                pass

        return sources
