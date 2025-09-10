# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from debian.deb822 import PkgRelation
from debian.debian_support import Version

from debsbom.dpkg.package import Dependency, BinaryPackage, SourcePackage
from debsbom.sbom import Reference


def test_parse_dependency():
    dependency_line = (
        "binutils-common (= 2.40-2), libbinutils (= 2.40-2), binutils-x86-64-linux-gnu (= 2.40-2)"
    )
    deps = Dependency.parse_depends_line(dependency_line)
    assert deps == [
        Dependency(name="binutils-common", version=("=", Version("2.40-2"))),
        Dependency(name="libbinutils", version=("=", Version("2.40-2"))),
        Dependency(name="binutils-x86-64-linux-gnu", version=("=", Version("2.40-2"))),
    ]


def test_parse_minimal_status_file():
    packages = list(BinaryPackage.parse_status_file("tests/data/dpkg-status-minimal"))
    bpkg = [p for p in packages if isinstance(p, BinaryPackage)][0]

    assert bpkg.name == "binutils"
    assert bpkg.section == "devel"
    assert bpkg.maintainer == "Matthias Klose <doko@debian.org>"
    assert bpkg.source == Dependency(bpkg.name, None, ("=", bpkg.version))
    assert bpkg.version == "2.40-2"
    assert bpkg.depends == [
        Dependency("binutils-common", None, ("=", bpkg.version)),
        Dependency("libbinutils", None, ("=", bpkg.version)),
        Dependency("binutils-x86-64-linux-gnu", None, ("=", bpkg.version)),
    ]
    assert (
        bpkg.description
        == """GNU assembler, linker and binary utilities
 The programs in this package are used to assemble, link and manipulate
 binary and object files.  They may be used in conjunction with a compiler
 and various libraries to build programs."""
    )
    assert bpkg.homepage == "https://www.gnu.org/software/binutils/"

    spkg = packages[1]
    assert spkg.name == "binutils"
    assert spkg.version == bpkg.version
    assert spkg.maintainer == bpkg.maintainer


def test_parse_source_status_file():
    packages = list(BinaryPackage.parse_status_file("tests/data/dpkg-status-source"))
    bpkg = [p for p in packages if isinstance(p, BinaryPackage)][0]

    assert bpkg.name == "apt-utils"
    assert bpkg.section == "admin"
    assert bpkg.maintainer == "APT Development Team <deity@lists.debian.org>"
    assert bpkg.source == Dependency("apt", None, ("=", bpkg.version))
    assert bpkg.version == "2.6.1"
    assert bpkg.depends == [
        Dependency("apt", None, ("=", bpkg.version)),
        Dependency("libapt-pkg6.0", None, (">=", bpkg.version)),
        Dependency("libc6", None, (">=", Version("2.34"))),
        Dependency("libdb5.3", None, None),
        Dependency("libgcc-s1", None, (">=", Version("3.0"))),
        Dependency("libstdc++6", None, (">=", Version("11"))),
    ]
    assert (
        bpkg.description
        == """package management related utility programs
 This package contains some less used commandline utilities related
 to package management with APT.
 .
  * apt-extracttemplates is used by debconf to prompt for configuration
    questions before installation.
  * apt-ftparchive is used to create Packages and other index files
    needed to publish an archive of Debian packages
  * apt-sortpkgs is a Packages/Sources file normalizer."""
    )
    assert bpkg.homepage is None

    spkg = [p for p in packages if isinstance(p, SourcePackage)][0]
    assert spkg.name == "apt"
    assert spkg.version == bpkg.version
    assert spkg.maintainer == bpkg.maintainer

    # check source package with version != binary version
    spkg = [p for p in packages if isinstance(p, SourcePackage)][1]
    assert spkg.name == "guestfs-tools"
    assert spkg.version == "1.52.3-1"
