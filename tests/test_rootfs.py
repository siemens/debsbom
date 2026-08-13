# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from io import BytesIO
from pathlib import Path
import shutil
import subprocess
import tarfile

import pytest

from debsbom.generate.generate import Debsbom
from debsbom.generate.rootfs import rootfs_directory
from debsbom.util.compression import Compression


def _add_rootfs(archive: tarfile.TarFile) -> None:
    archive.add("tests/root/tree", arcname=".")
    ignored = tarfile.TarInfo("etc/not-needed")
    ignored.size = len(b"ignored")
    archive.addfile(ignored, BytesIO(b"ignored"))


def _assert_scannable(root: Path) -> None:
    debsbom = Debsbom(distro_name="pytest-distro", root=root)
    debsbom.scan()

    assert debsbom.distro_arch == "amd64"
    assert "libc6" in {package.name for package in debsbom.packages}
    assert not (root / "etc/not-needed").exists()


def test_tar_rootfs_file(tmp_path):
    archive_path = tmp_path / "rootfs.tar"
    with tarfile.open(archive_path, mode="w") as archive:
        _add_rootfs(archive)

    with rootfs_directory(archive_path) as root:
        _assert_scannable(root)
        materialized_root = root

    assert not materialized_root.exists()


def test_directory_rootfs_is_used_directly():
    expected_root = Path("tests/root/tree")

    with rootfs_directory(expected_root) as root:
        assert root == expected_root
        _assert_scannable(root)


def test_tar_rootfs_stdin():
    stream = BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        _add_rootfs(archive)
    stream.seek(0)

    with rootfs_directory("-", stream) as root:
        _assert_scannable(root)


@pytest.mark.parametrize("compression", Compression.formats(), ids=lambda comp: comp.tool)
def test_compressed_tar_rootfs_file(tmp_path, compression):
    tool = shutil.which(compression.tool)
    if tool is None:
        pytest.skip(f"{compression.tool} is not installed")

    uncompressed_path = tmp_path / "rootfs.tar"
    with tarfile.open(uncompressed_path, mode="w") as archive:
        _add_rootfs(archive)
    archive_path = tmp_path / f"rootfs.tar{compression.fileext}"
    with uncompressed_path.open("rb") as uncompressed, archive_path.open("wb") as output:
        subprocess.run(
            [tool] + compression.compress,
            stdin=uncompressed,
            stdout=output,
            check=True,
        )

    with rootfs_directory(archive_path) as root:
        _assert_scannable(root)


def test_copyright_files_are_materialized_only_when_requested(tmp_path):
    archive_path = tmp_path / "rootfs.tar"
    with tarfile.open(archive_path, mode="w") as archive:
        archive.add("tests/root/copyright", arcname=".")
        ignored = tarfile.TarInfo("usr/share/doc/copyright-tests/changelog.gz")
        ignored.size = len(b"ignored")
        archive.addfile(ignored, BytesIO(b"ignored"))

    copyright_path = Path("usr/share/doc/copyright-tests/copyright")
    with rootfs_directory(archive_path) as root:
        assert not (root / copyright_path).exists()
    with rootfs_directory(archive_path, include_copyright=True) as root:
        assert (root / copyright_path).is_file()
        assert not (root / "usr/share/doc/copyright-tests/changelog.gz").exists()


def test_copyright_directory_symlink_stays_inside_materialized_root(tmp_path):
    archive_path = tmp_path / "rootfs.tar"
    with tarfile.open(archive_path, mode="w") as archive:
        archive.add("tests/root/copyright", arcname=".")
        member = tarfile.TarInfo("usr/share/doc/alias-package")
        member.type = tarfile.SYMTYPE
        member.linkname = "copyright-tests"
        archive.addfile(member)

    with rootfs_directory(archive_path, include_copyright=True) as root:
        link = root / "usr/share/doc/alias-package"
        assert link.is_symlink()
        assert link.resolve().is_relative_to(root.resolve())
        assert (link / "copyright").is_file()


def test_tar_rootfs_rejects_metadata_symlink_escape():
    stream = BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        member = tarfile.TarInfo("var/lib/dpkg/status")
        member.type = tarfile.SYMTYPE
        member.linkname = "../../../../etc/passwd"
        archive.addfile(member)
    stream.seek(0)

    with pytest.raises(ValueError, match="escapes the rootfs"):
        with rootfs_directory("-", stream):
            pass


def test_tar_rootfs_rejects_parent_traversal():
    stream = BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        member = tarfile.TarInfo("../escape")
        member.size = len(b"escape")
        archive.addfile(member, BytesIO(b"escape"))
    stream.seek(0)

    with pytest.raises(ValueError, match="escapes the rootfs"):
        with rootfs_directory("-", stream):
            pass
