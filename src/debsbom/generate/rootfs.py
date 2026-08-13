# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Iterator
from contextlib import contextmanager
import io
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
from tempfile import TemporaryDirectory

from ..util.compression import Compression, CompressionToolMissing

_ROOT_FILES = {
    "var/lib/dpkg/status",
    "var/lib/dpkg/arch-native",
    "var/lib/apt/extended_states",
}
_APT_LISTS = "var/lib/apt/lists"
_COPYRIGHT_ROOT = PurePosixPath("usr/share/doc")


def _normalized_member_path(name: str) -> PurePosixPath:
    if "\\" in name:
        raise ValueError(f"tar archive member uses an invalid path separator: {name}")
    while name.startswith("./"):
        name = name[2:]
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"tar archive member escapes the rootfs: {name}")
    return path


def _is_rootfs_metadata(path: PurePosixPath, include_copyright: bool) -> bool:
    archive_path = path.as_posix()
    if archive_path in _ROOT_FILES:
        return True
    if archive_path == _APT_LISTS or archive_path.startswith(f"{_APT_LISTS}/"):
        return True
    if not include_copyright:
        return False

    relative_to_doc = path.parts[len(_COPYRIGHT_ROOT.parts) :]
    return path.parts[: len(_COPYRIGHT_ROOT.parts)] == _COPYRIGHT_ROOT.parts and (
        len(relative_to_doc) == 1
        or (len(relative_to_doc) == 2 and relative_to_doc[-1] == "copyright")
    )


def _normalized_link_target(member_path: PurePosixPath, linkname: str) -> PurePosixPath:
    if "\\" in linkname:
        raise ValueError(f"tar archive link uses an invalid path separator: {linkname}")

    link_path = PurePosixPath(linkname)
    if link_path.is_absolute():
        combined = PurePosixPath(*link_path.parts[1:])
    else:
        combined = member_path.parent / link_path

    normalized_parts: list[str] = []
    for part in combined.parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not normalized_parts:
                raise ValueError(f"tar archive link escapes the rootfs: {linkname}")
            normalized_parts.pop()
            continue
        normalized_parts.append(part)
    return PurePosixPath(*normalized_parts)


def _materialize_rootfs_metadata(
    archive: tarfile.TarFile, destination: Path, include_copyright: bool
) -> None:
    for member in archive:
        member_path = _normalized_member_path(member.name)
        if not _is_rootfs_metadata(member_path, include_copyright):
            continue

        output_path = destination.joinpath(*member_path.parts)
        if member.isdir():
            output_path.mkdir(parents=True, exist_ok=True)
            continue
        if member.issym():
            target_path = _normalized_link_target(member_path, member.linkname)
            if not _is_rootfs_metadata(target_path, include_copyright):
                raise ValueError(
                    f"tar archive link points outside the scanned rootfs metadata: {member.name}"
                )
            output_path.parent.mkdir(parents=True, exist_ok=True)
            relative_target = os.path.relpath(
                destination.joinpath(*target_path.parts), output_path.parent
            )
            output_path.symlink_to(relative_target)
            continue
        if not member.isfile():
            raise ValueError(f"unsupported tar archive member type: {member.name}")

        source = archive.extractfile(member)
        if source is None:
            raise RuntimeError(f"Unable to read tar archive member: {member.name}")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with source, output_path.open("wb") as output:
            shutil.copyfileobj(source, output)


@contextmanager
def _decompressed_tar_stream(path: Path) -> Iterator[io.BufferedIOBase]:
    try:
        compression = Compression.from_ext(path.suffix)
    except ValueError:
        compression = Compression.NONE

    if compression == Compression.NONE:
        with path.open("rb") as stream:
            yield stream
        return

    tool = shutil.which(compression.tool)
    if tool is None:
        raise CompressionToolMissing(compression.tool)
    process = subprocess.Popen(
        [tool] + compression.extract + [path],
        stdout=subprocess.PIPE,
    )
    assert process.stdout is not None
    try:
        yield process.stdout
    finally:
        process.stdout.close()
        return_code = process.wait()
    if return_code != 0:
        raise RuntimeError(f"decompression of {path} failed")


@contextmanager
def rootfs_directory(
    root: str | Path,
    input_stream: io.IOBase | None = None,
    include_copyright: bool = False,
) -> Iterator[Path]:
    """Yield a scan-ready directory for a directory, tar file, or tar stream rootfs."""
    if str(root) != "-":
        root_path = Path(root)
        if root_path.is_dir():
            yield root_path
            return
        if not root_path.is_file():
            raise FileNotFoundError(f"rootfs path does not exist: {root_path}")

    with TemporaryDirectory(prefix="debsbom-rootfs-") as temp_dir:
        materialized_root = Path(temp_dir)
        if str(root) == "-":
            if input_stream is None:
                raise ValueError("rootfs stdin input requires a binary stream")
            with tarfile.open(fileobj=input_stream, mode="r|*") as archive:
                _materialize_rootfs_metadata(archive, materialized_root, include_copyright)
        else:
            with _decompressed_tar_stream(Path(root)) as stream:
                with tarfile.open(fileobj=stream, mode="r|") as archive:
                    _materialize_rootfs_metadata(archive, materialized_root, include_copyright)
        yield materialized_root
