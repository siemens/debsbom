from debian.deb822 import PkgRelation
from debian.debian_support import Version

from debsbom.dpkg.package import Dependency, BinaryPackage, SourcePackage


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
    package = next(BinaryPackage.parse_status_file("tests/data/dpkg-status-minimal"))

    assert package.name == "binutils"
    assert package.section == "devel"
    assert package.maintainer == "Matthias Klose <doko@debian.org>"
    assert package.source == SourcePackage(package.name, package.version)
    assert package.version == "2.40-2"
    assert package.depends == [
        Dependency(name="binutils-common", version=("=", Version("2.40-2"))),
        Dependency(name="libbinutils", version=("=", Version("2.40-2"))),
        Dependency(name="binutils-x86-64-linux-gnu", version=("=", Version("2.40-2"))),
    ]
    assert (
        package.description
        == """GNU assembler, linker and binary utilities
 The programs in this package are used to assemble, link and manipulate
 binary and object files.  They may be used in conjunction with a compiler
 and various libraries to build programs."""
    )
    assert package.homepage == "https://www.gnu.org/software/binutils/"


def test_parse_source_status_file():
    package = next(BinaryPackage.parse_status_file("tests/data/dpkg-status-source"))

    assert package.name == "apt-utils"
    assert package.section == "admin"
    assert package.maintainer == "APT Development Team <deity@lists.debian.org>"
    assert package.source == SourcePackage("apt", package.version)
    assert package.version == "2.6.1"
    assert package.depends == [
        Dependency(name="apt", version=("=", Version("2.6.1"))),
        Dependency(name="libapt-pkg6.0", version=(">=", Version("2.6.1"))),
        Dependency(name="libc6", version=(">=", Version("2.34"))),
        Dependency(name="libdb5.3", version=None),
        Dependency(name="libgcc-s1", version=(">=", Version("3.0"))),
        Dependency(name="libstdc++6", version=(">=", Version("11"))),
    ]
    assert (
        package.description
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
    assert package.homepage is None
