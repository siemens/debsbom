# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from abc import ABC, abstractmethod
from dataclasses import dataclass
from collections.abc import Iterable
from enum import Enum, IntEnum
import io
import itertools
from pathlib import Path
from typing import IO
from debian.deb822 import Packages, PkgRelation
from debian.debian_support import Version
import logging
import re
from packageurl import PackageURL

from .. import HAS_PYTHON_APT

logger = logging.getLogger(__name__)

# Debian policy 5.6.13, item 1
DESC_REGEX_P1 = re.compile(r"^\s(\w.*)$")


class ChecksumAlgo(IntEnum):
    MD5SUM = 1
    SHA1SUM = 2
    SHA256SUM = 3

    @classmethod
    def to_hashlib(cls, algo):
        if algo == cls.MD5SUM:
            return "md5"
        if algo == cls.SHA1SUM:
            return "sha1"
        if algo == cls.SHA256SUM:
            return "sha256"
        raise NotImplementedError()


class DpkgStatus(Enum):
    NOT_INSTALLED = "n"
    CONFIG_FILES = "c"
    HALF_INSTALLED = "H"
    UNPACKED = "U"
    HALF_CONFIGURED = "F"
    TRIGGERS_AWAITING = "W"
    TRIGGERS_PENDING = "t"
    INSTALLED = "i"
    DEBSBOM_UNKNOWN = "0"

    @classmethod
    def from_dpkg(cls, status: str) -> "DpkgStatus":
        if len(status) > 1:
            status = status.lower()
        if status in ["n", "not-installed"]:
            return cls.NOT_INSTALLED
        if status in ["c", "config-files"]:
            return cls.CONFIG_FILES
        if status in ["H", "half-installed"]:
            return cls.HALF_INSTALLED
        if status in ["U", "unpacked"]:
            return cls.UNPACKED
        if status in ["F", "half-configured"]:
            return cls.HALF_CONFIGURED
        if status in ["W", "triggers-awaiting"]:
            return cls.TRIGGERS_AWAITING
        if status in ["t", "triggers-pending"]:
            return cls.TRIGGERS_PENDING
        if status in ["i", "installed"]:
            return cls.INSTALLED
        raise ValueError(f"Unknown dpkg status '{status}'")


class PkgListType(Enum):
    """Type of package list data (e.g. PURL or dpkg status file)"""

    STATUS_FILE = (0,)
    PKG_LIST = (1,)
    PURL_LIST = (2,)
    ISAR_MANIFEST = (3,)


class PkgListStream:
    """
    Wrapper around a packages iterator that takes care of closing the attached
    stream (either on StopIteration or via context manager). It further allows
    to return the source type of data from which the packages are created.
    """

    def __init__(self, stream: IO, kind: PkgListType, pkgs: Iterable["Package"]):
        self._stream = stream
        self.kind = kind
        self._pkgs = pkgs

    def __iter__(self) -> "PkgListStream":
        return self

    def __next__(self) -> "Package":
        """return the next package, close the stream if no further elements."""
        try:
            return next(self._pkgs)
        except StopIteration:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self):
        """explicitly close the stream"""
        self._stream.close()


def filter_sources(pkgs: Iterable["Package"]) -> Iterable["SourcePackage"]:
    """Free function to only return source packages"""
    return filter(lambda p: p.is_source(), pkgs)


def filter_binaries(pkgs: Iterable["Package"]) -> Iterable["BinaryPackage"]:
    """Free function to only return binary packages"""
    return filter(lambda p: p.is_binary(), pkgs)


@dataclass
class Dependency:
    """Representation of a dependency for a package."""

    name: str
    archqual: str | None = None
    version: tuple[str, Version] | None = None
    arch: str | None = None
    restrictions: str | None = None

    @classmethod
    def from_pkg_relations(cls, relations: list[list[dict]], is_source=False) -> list["Dependency"]:
        dependencies = []
        for relation in relations:
            for dep in relation:
                if dep.get("version"):
                    # make a proper Version out of it
                    dep["version"] = (dep["version"][0], Version(dep["version"][1]))
                if is_source:
                    dep["arch"] = "source"
                dependencies.append(Dependency(**dep))
        return dependencies

    @classmethod
    def parse_depends_line(cls, line: str) -> list["Dependency"]:
        return Dependency.from_pkg_relations(PkgRelation.parse_relations(line))


@dataclass(init=False)
class Package(ABC):
    """Base class for binary and source packages."""

    name: str
    version: Version
    maintainer: str | None = None
    homepage: str | None = None
    checksums: dict[ChecksumAlgo, str]

    def __init__(self, name: str, version: str | Version):
        self.name = name
        self.version = Version(version)

    @classmethod
    def parse_status_file(cls, status_file: Path) -> PkgListStream:
        """
        Parse a dpkg status file and returns packages with their relations.
        """
        logger.info(f"Parsing status file '{status_file}'...")
        deb822_stream = open(status_file, "r")
        pkgs_it = cls.inject_src_packages(cls._parse_dpkg_status(deb822_stream))
        return PkgListStream(deb822_stream, PkgListType.STATUS_FILE, pkgs_it)

    @classmethod
    def _parse_dpkg_status(
        cls, stream: IO, force_no_apt: bool = False
    ) -> Iterable["BinaryPackage"]:
        """
        Parse a dpkg status file and returns binary packages with their relations.
        The relations might contain links to packages that are not known yet (e.g.
        all source packages). These need to be resolved in a second pass.

        The force_no_apt flag can be used to explicitly disable the use of python-apt.
        Due to bugs in some python-apt versions, this might be required if a non-file
        input stream is used.
        """
        use_apt = HAS_PYTHON_APT and not force_no_apt
        for package in Packages.iter_paragraphs(stream, use_apt_pkg=use_apt):
            bpkg = BinaryPackage.from_deb822(package)
            logger.debug(f"Found binary package: '{bpkg.name}'")
            yield bpkg

    @classmethod
    def parse_pkglist_stream(cls, stream: IO) -> PkgListStream:
        """
        Parses a stream of space separated tuples describing packages
        (name, version, arch), PURLs, isar manifest data
        (<src name>|<src version>|<bin name>:<bin arch>|<bin version>) or a
        dpkg-status file. If not passing a dpkg-status file, each line describes
        one package. Example:
        gcc 15.0-1 amd64
        g++ 15.0-1 amd64
        """
        DPKG_STATUS_MAGIC = "Package: ".encode()
        PURL_MAGIC = "pkg:deb/".encode()

        if isinstance(stream, io.BufferedReader):
            bstream = stream
        elif isinstance(stream, io.TextIOBase):
            bstream = io.BufferedReader(stream.buffer)
        else:
            bstream = io.BufferedReader(stream)

        if bstream.peek(len(DPKG_STATUS_MAGIC)).startswith(DPKG_STATUS_MAGIC):
            pkgs_it = cls.inject_src_packages(cls._parse_dpkg_status(bstream, force_no_apt=True))
            return PkgListStream(bstream, PkgListType.STATUS_FILE, pkgs_it)
        elif bstream.peek(len(PURL_MAGIC)).startswith(PURL_MAGIC):
            return PkgListStream(
                stream, PkgListType.PURL_LIST, map(lambda l: Package.from_purl(l.decode()), bstream)
            )
        elif sum(c == b"|"[0] for c in bstream.peek(128).split(b"\n")[0]) == 3:
            return PkgListStream(
                bstream, PkgListType.ISAR_MANIFEST, cls._parse_manifest_line_stream(bstream)
            )
        return PkgListStream(bstream, PkgListType.PKG_LIST, cls._parse_pkglist_line_stream(bstream))

    @classmethod
    def _parse_pkglist_line_stream(cls, stream: IO[bytes]) -> Iterable["Package"]:
        for line in stream:
            name, version, arch = line.decode().strip().split()
            if arch == "source":
                yield SourcePackage(
                    name=name,
                    version=version,
                )
            else:
                yield BinaryPackage(
                    name=name,
                    architecture=arch,
                    version=version,
                )

    @classmethod
    def _parse_manifest_line_stream(cls, stream: IO[bytes]) -> Iterable["Package"]:
        """
        Parse isar manifest file entries. The format is:
        <src name>|<src version>|<bin name>:<bin arch>|<bin version>
        Example:
        json-c|0.16-2|libjson-c5:amd64|0.16-2
        """
        for line in stream:
            src, srcv, bin, binv = line.decode().strip().split("|")
            yield SourcePackage(name=src, version=srcv)
            bin_parts = bin.split(":")
            if len(bin_parts) != 2:
                logger.error(f"Binary package '{bin}' misses the architecture specifier")
            yield BinaryPackage(
                name=bin_parts[0],
                architecture=bin_parts[1] if len(bin_parts) == 2 else "unknown",
                version=binv,
            )

    @classmethod
    def from_purl(cls, purl: str) -> "Package":
        """
        Create a package from a PURL. Note, that the package only encodes
        information that can be derived from the PURL.
        """
        purl = PackageURL.from_string(purl)
        if not purl.type == "deb":
            raise RuntimeError("Not a debian purl", purl)
        if purl.qualifiers.get("arch") == "source":
            return SourcePackage(purl.name, purl.version)
        else:
            return BinaryPackage(
                name=purl.name,
                architecture=purl.qualifiers.get("arch"),
                version=purl.version,
            )

    @classmethod
    def inject_src_packages(cls, binpkgs: Iterable["BinaryPackage"]) -> Iterable["Package"]:
        """Create and inject referenced source packages"""
        return cls._unique_everseen(
            itertools.chain.from_iterable(map(lambda p: cls._resolve_sources(p, True), binpkgs))
        )

    @classmethod
    def referenced_src_packages(
        cls, binpkgs: Iterable["BinaryPackage"]
    ) -> Iterable["SourcePackage"]:
        """Create and return referenced source packages"""
        return cls._unique_everseen(
            itertools.chain.from_iterable(map(lambda p: cls._resolve_sources(p, False), binpkgs))
        )

    @classmethod
    def _unique_everseen(cls, iterable: Iterable[object], key=None):
        """
        Yield unique elements, preserving order. Remember all elements ever seen.
        """
        seen = set()
        if key is None:
            for element in itertools.filterfalse(seen.__contains__, iterable):
                seen.add(element)
                yield element
        else:
            for element in iterable:
                k = key(element)
                if k not in seen:
                    seen.add(k)
                yield element

    def merge_with(self, other: "Package"):
        """
        Copy the corresponding values of the other package for each unset field.
        """
        if not self.maintainer:
            self.maintainer = other.maintainer
        if not self.homepage:
            self.homepage = other.homepage
        self.checksums |= other.checksums

    @classmethod
    def _resolve_sources(cls, pkg: "BinaryPackage", add_pkg=False) -> Iterable["Package"]:
        """
        Returns an iterator to resolve the source package of a binary package.
        If add_pkg=True is set, the passed binary package is returned as well.
        """
        if pkg.source:
            logger.debug(f"Found source package: '{pkg.source.name}'")
            yield SourcePackage(pkg.source.name, pkg.source.version[1], pkg.maintainer)
        for bu in pkg.built_using:
            # When creating the source package from a built-depends, we don't know the maintainer.
            # If we now create a source package first via a built-using relation and later
            # re-create the same source package from a binary package, it still misses the
            # maintainer information, despite we would have it from the binary package.
            # Some tests on a rather large debian sid showed, that this situation is unlikely.
            logger.debug(f"Found built-using source package: '{bu.name}@{bu.version[1]}'")
            yield SourcePackage(bu.name, bu.version[1])
        if add_pkg:
            yield pkg

    def is_binary(self) -> bool:
        """Helper to check if the package is a binary package"""
        if isinstance(self, BinaryPackage):
            return True
        return False

    def is_source(self) -> bool:
        """Helper to check if the package is a source package"""
        if isinstance(self, SourcePackage):
            return True
        return False

    @abstractmethod
    def purl(self) -> PackageURL:
        raise NotImplementedError

    @property
    @abstractmethod
    def locator(self) -> str:
        raise NotImplementedError()

    @property
    def filename(self) -> str:
        """Return the filename part from the locator of a package."""
        return self.locator.split("/")[-1]


@dataclass(init=False)
class SourcePackage(Package):
    """
    Representation of a Debian Source package.
    The checksums refer to the .dsc file.
    """

    binaries: list[str] | None = None
    vcs_browser: str | None = None
    vcs_git: str | None = None
    _locator: str | None = None

    def __init__(
        self,
        name: str,
        version: str | Version,
        maintainer: str | None = None,
        binaries: list[str] = [],
        homepage: str | None = None,
        vcs_browser: str | None = None,
        vcs_git: str | None = None,
        checksums: dict[ChecksumAlgo, str] | None = None,
    ):
        self.name = name
        self.version = Version(version)
        self.maintainer = maintainer
        self.binaries = binaries
        self.homepage = homepage
        self.vcs_browser = vcs_browser
        self.vcs_git = vcs_git
        self.checksums = checksums or {}

    def __hash__(self):
        return hash(self.purl())

    def __eq__(self, other):
        # For compatibility reasons
        if other.is_source():
            return self.purl() == other.purl()
        return NotImplemented

    def purl(self, vendor="debian") -> PackageURL:
        """Return the PURL of the package."""
        return PackageURL.from_string(
            "pkg:deb/{}/{}@{}?arch=source".format(vendor, self.name, self.version)
        )

    @property
    def locator(self) -> str:
        """Path to file if set or name of .dsc file"""
        return self._locator or self.dscfile()

    @locator.setter
    def locator(self, loc) -> None:
        self._locator = loc

    def dscfile(self) -> str:
        """Return the name of the .dsc file"""
        # TODO: find where this filename format is specified
        if self.version.debian_revision:
            version_wo_epoch = f"{self.version.upstream_version}-{self.version.debian_revision}"
        else:
            version_wo_epoch = self.version.upstream_version
        return f"{self.name}_{version_wo_epoch}.dsc"

    def merge_with(self, other: "SourcePackage"):
        """Copy properties from other which are unset on our side. Merge lists."""
        super().merge_with(other)
        if not self.vcs_browser:
            self.vcs_browser = other.vcs_browser
        if not self.vcs_git:
            self.vcs_git = other.vcs_git
        # add binaries from other
        binaries = list(self.binaries)
        binaries.extend(x for x in other.binaries if x not in binaries)
        self.binaries = binaries

    @staticmethod
    def from_deb822(package) -> "SourcePackage":
        """
        Create a package from a deb822 representation. If the deb822 input
        is a .dsc file, the name is read from the source property.
        """
        name = package.get("Source") or package["Package"]
        version = Version(package.get("Version"))
        maintainer = package.get("Maintainer")
        binary_entry = package.get("Binary")
        if binary_entry is not None:
            binaries = [b.strip() for b in binary_entry.split(",")]
        else:
            binaries = []
        homepage = package.get("Homepage")
        vcs_browser = package.get("Vcs-Browser")
        vcs_git = package.get("Vcs-Git")

        # Checksums according to Debian policy 5.6.24
        pkg_chksums = {}
        for alg, deb822_name in [
            (ChecksumAlgo.SHA1SUM, "Sha1"),
            (ChecksumAlgo.SHA256SUM, "Sha256"),
        ]:
            chksums = package.get(f"Checksums-{deb822_name}") or []
            for c in filter(lambda c_: c_["name"].endswith(".dsc"), chksums):
                pkg_chksums[alg] = c[deb822_name]

        return SourcePackage(
            name=name,
            version=version,
            maintainer=maintainer,
            binaries=binaries,
            homepage=homepage,
            vcs_browser=vcs_browser,
            vcs_git=vcs_git,
            checksums=pkg_chksums,
        )


@dataclass(init=False)
class BinaryPackage(Package):
    """Incomplete representation of a Debian binary package."""

    section: str | None
    architecture: str | None
    source: Dependency | None
    depends: list[Dependency]
    built_using: list[Dependency]
    description: str | None
    manually_installed: bool
    status: DpkgStatus
    _locator: str | None = None

    def __init__(
        self,
        name: str,
        version: str | Version,
        section: str | None = None,
        maintainer: str | None = None,
        architecture: str | None = None,
        source: Dependency | None = None,
        depends: list[Dependency] = [],
        built_using: list[Dependency] = [],
        description: str | None = None,
        homepage: str | None = None,
        checksums: dict[ChecksumAlgo, str] | None = None,
        manually_installed: bool = True,
        status: DpkgStatus = DpkgStatus.DEBSBOM_UNKNOWN,
    ):
        self.name = name
        self.section = section
        self.maintainer = maintainer
        self.architecture = architecture
        self.source = source
        self.version = Version(version)
        self.depends = depends
        self.built_using = built_using
        self.description = description
        self.homepage = homepage
        self.checksums = checksums or {}
        self.manually_installed = manually_installed
        self.status = status

    def __hash__(self):
        return hash(self.purl())

    def __eq__(self, other):
        if other.is_binary():
            return self.purl() == other.purl()
        return NotImplemented

    def purl(self, vendor="debian") -> PackageURL:
        """Return the PURL of the package."""
        purl = "pkg:deb/{}/{}@{}".format(vendor, self.name, self.version)
        if self.architecture:
            purl = purl + "?arch={}".format(self.architecture)
        return PackageURL.from_string(purl)

    @property
    def unique_depends(self):
        """
        Returns the unique dependencies without version.
        The raw dependencies can include version specifiers, but as only a single
        version can be installed at a time, we ignore them.
        """
        seen = set()
        unique = []
        for dep in self.depends:
            key = (dep.name, dep.arch)
            if key not in seen:
                seen.add(key)
                unique.append(dep)
        return unique

    def merge_with(self, other: "BinaryPackage"):
        """Copy properties from other which are unset on our side. Merge lists and dicts. Or booleans."""
        super().merge_with(other)
        if not self.section:
            self.section = other.section
        if not self.architecture:
            self.architecture = other.architecture
        if not self.source:
            self.source = other.source
        if not self.description:
            self.description = other.description
        self.manually_installed |= other.manually_installed
        # we cannot merge the status, but if the other package is
        # marked as installed, consider all as installed.
        if self.status == DpkgStatus.DEBSBOM_UNKNOWN:
            self.status = other.status
        elif other.status != DpkgStatus.DEBSBOM_UNKNOWN and self.status != other.status:
            # this indicates an internal error
            logger.warning(f"package statuses are inconsistent: {self.status} != {other.status}")

        depends = list(self.depends)
        depends.extend(x for x in other.depends if x not in depends)
        self.depends = depends

        built_using = list(self.built_using)
        built_using.extend(x for x in other.built_using if x not in built_using)
        self.built_using = built_using

    @property
    def locator(self) -> str:
        """Return the name (and path if available) of the .deb file"""
        if self._locator:
            return self._locator
        # TODO: find where this filename format is specified
        if self.version.debian_revision:
            version_wo_epoch = f"{self.version.upstream_version}-{self.version.debian_revision}"
        else:
            version_wo_epoch = self.version.upstream_version
        return f"{self.name}_{version_wo_epoch}_{self.architecture}.deb"

    @locator.setter
    def locator(self, loc) -> None:
        self._locator = loc

    @staticmethod
    def _cleanup_description(desc: str | None) -> str | None:
        """
        Parse description according to Debian policy 5.6.13
        """
        if desc is None:
            return None
        buffer = str()
        in_paragraph = False
        for line in desc.split("\n"):
            matches = DESC_REGEX_P1.match(line)
            if matches:
                buffer += (" " if in_paragraph else "") + matches[1]
                in_paragraph = True
                continue

            if len(line) == 0:
                pass
            elif line == " .":
                buffer += "\n"
            elif line[0] != " ":
                # First line
                buffer += line + "\n"
            else:
                buffer += "\n" + line[1:]
            in_paragraph = False
        return buffer.strip()

    @classmethod
    def from_deb822(cls, package) -> "BinaryPackage":
        """
        Create a ``BinaryPackage`` from a deb822 representation.
        """
        if package.source:
            srcdep = Dependency(package.source, None, ("=", package.source_version), arch="source")
        else:
            srcdep = None

        pdepends = package.relations["depends"] or []
        dependencies = Dependency.from_pkg_relations(pdepends)

        # static dependencies
        s_built_using = package.relations["built-using"] or []
        sdepends = Dependency.from_pkg_relations(s_built_using, is_source=True)

        pkg_chksums = {}
        for alg, deb822_name in [
            (ChecksumAlgo.MD5SUM, "MD5sum"),
            (ChecksumAlgo.SHA1SUM, "SHA1"),
            (ChecksumAlgo.SHA256SUM, "SHA256"),
        ]:
            chksum = package.get(deb822_name)
            if chksum:
                pkg_chksums[alg] = chksum

        status_raw = package.get("Status")
        if status_raw:
            _, _, pkg_status = status_raw.split(" ")
            status = DpkgStatus.from_dpkg(pkg_status)
        else:
            status = DpkgStatus.DEBSBOM_UNKNOWN

        return BinaryPackage(
            name=package.get("Package"),
            section=package.get("Section"),
            maintainer=package.get("Maintainer"),
            architecture=package.get("Architecture"),
            source=srcdep,
            version=package.get("Version"),
            depends=dependencies,
            built_using=sdepends,
            description=cls._cleanup_description(package.get("Description")),
            homepage=package.get("Homepage"),
            checksums=pkg_chksums,
            status=status,
        )
