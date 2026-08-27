# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Callable, Iterator
from contextlib import contextmanager
import io
import logging
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
from tempfile import TemporaryDirectory

from ..util.compression import Compression, CompressionToolMissing

logger = logging.getLogger(__name__)

_ROOT_FILES = frozenset(
    {
        PurePosixPath("var/lib/dpkg/status"),
        PurePosixPath("var/lib/dpkg/arch-native"),
        PurePosixPath("var/lib/apt/extended_states"),
    }
)
_APT_LISTS = PurePosixPath("var/lib/apt/lists")
_COPYRIGHT_ROOT = PurePosixPath("usr/share/doc")


def _is_rootfs_metadata(name: str, include_copyright: bool) -> bool:
    path = PurePosixPath(name.lstrip("/"))
    if path in _ROOT_FILES:
        return True
    if path == _APT_LISTS or _APT_LISTS in path.parents:
        return True
    if not include_copyright or _COPYRIGHT_ROOT not in path.parents:
        return False

    relative_to_doc = path.relative_to(_COPYRIGHT_ROOT)
    return len(relative_to_doc.parts) == 1 or (
        len(relative_to_doc.parts) == 2 and relative_to_doc.name == "copyright"
    )


def _metadata_filter(
    include_copyright: bool,
) -> Callable[[tarfile.TarInfo, str | Path], tarfile.TarInfo | None]:
    """Build an extraction filter selecting rootfs metadata, hardened by :data:`tarfile.data_filter`.

    Path traversal, links leaving the destination and special files are rejected by the
    tarfile data filter, which raises a :class:`tarfile.FilterError` for the offending member.
    """

    def select(member: tarfile.TarInfo, destination: str | Path) -> tarfile.TarInfo | None:
        if not _is_rootfs_metadata(member.name, include_copyright):
            return None
        if member.islnk() and not _is_rootfs_metadata(member.linkname, include_copyright):
            # the target is skipped, so the link cannot be materialized from the stream
            logger.warning(
                f"skipping {member.name}: hard link target '{member.linkname}' "
                "is outside the scanned rootfs metadata"
            )
            return None
        return tarfile.data_filter(member, destination)

    return select


def _materialize_rootfs_metadata(
    archive: tarfile.TarFile, destination: Path, include_copyright: bool
) -> None:
    # A rootfs may legitimately carry only part of this metadata: stock Debian containers
    # ship no apt lists, and var/lib/dpkg/arch-native only exists from trixie on. Missing
    # data is handled downstream, so tarfile's default errorlevel is kept and only the
    # filter rejections below stay fatal.
    archive.extractall(path=destination, filter=_metadata_filter(include_copyright))


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
