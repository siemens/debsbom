# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import pytest

from debsbom.snapshot.client import (
    BinaryPackage,
    NotFoundOnSnapshotError,
    Package,
    SnapshotDataLakeError,
    SourcePackage,
)


@pytest.mark.online
def test_list_packages(sdl):
    pkgs = sdl.packages()
    assert any(filter(lambda p: p.name == "sed", pkgs))


@pytest.mark.online
def test_fileinfo(sdl):
    pkg_hash = "1f3a43c181b81e3578d609dc0931ff147623eb38"
    assert any(filter(lambda x: x.filename == "pytest_8.4.2-1.dsc", sdl.fileinfo(pkg_hash)))

    with pytest.raises(SnapshotDataLakeError):
        hash_invalid = "foobar"
        next(sdl.fileinfo(hash_invalid))


@pytest.mark.online
def test_binary_package(sdl):
    # no relation to src package
    pkg_hash = "c9e30e325d77dca96d85d094037ae2f7eac919ff"
    pkg_nosrc = BinaryPackage(sdl, "python3-pytest", "8.4.2-1", None, None)
    files = list(pkg_nosrc.files())
    assert files[0].hash == pkg_hash

    # with relation to src package
    pkg = BinaryPackage(sdl, pkg_nosrc.binname, pkg_nosrc.binversion, "pytest", "8.4.2-1")
    files = list(pkg.files())
    assert files[0].hash == pkg_hash

    pkg = BinaryPackage(sdl, "sed", "4.9-2", "sed", "4.9-2")
    assert all(map(lambda f: f.architecture == "riscv64", pkg.files(arch="riscv64")))

    with pytest.raises(NotFoundOnSnapshotError):
        next(BinaryPackage(sdl, "python3", "8.4.2-1", None, None).files())


@pytest.mark.online
def test_source_package(sdl):
    pkg = SourcePackage(sdl, "pytest", "8.4.2-1")
    dsc_hash = "1f3a43c181b81e3578d609dc0931ff147623eb38"
    src_files = list(pkg.srcfiles())
    assert any(filter(lambda s: s.hash == dsc_hash, src_files))

    binpkgs = list(pkg.binpackages())
    assert any(filter(lambda b: b.binname == "python3-pytest", binpkgs))

    with pytest.raises(NotFoundOnSnapshotError):
        # the name corresponds to a binary package
        next(SourcePackage(sdl, "python3-pytest", "8.4.2-1").srcfiles())

    with pytest.raises(SnapshotDataLakeError):
        next(SourcePackage(sdl, "python3-pytest", "8.4.2-1").binpackages())


@pytest.mark.online
def test_generic_package(sdl):
    """
    list all versions of a source package
    """
    pkg = Package(sdl, "pytest")
    assert any(filter(lambda p: p.version == "8.4.2-1", pkg.versions()))

    with pytest.raises(NotFoundOnSnapshotError):
        next(Package(sdl, "python3-pytest").versions())
