# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Iterable
import hashlib
from requests import RequestException
from debian import deb822
from ..snapshot.client import (
    NotFoundOnSnapshotError,
    RemoteFile,
    SnapshotDataLake,
    SnapshotDataLakeError,
)


class RemoteDscFile:
    """
    Wrapper around a RemoteFile to only iterate the files referenced in the dsc file.
    """

    sdl: SnapshotDataLake
    dscfile: RemoteFile
    allfiles: list[RemoteFile]

    def __init__(self, sdl: SnapshotDataLake, dscfile: RemoteFile, allfiles: list[RemoteFile]):
        self.sdl = sdl
        self.dscfile = dscfile
        self.allfiles = list(filter(lambda rf: rf.archive_name == dscfile.archive_name, allfiles))
        self._fetch()

    def _fetch(self):
        try:
            r = self.sdl.rs.get(self.dscfile.downloadurl)
            if r.status_code == 404:
                raise NotFoundOnSnapshotError()
        except RequestException as e:
            raise SnapshotDataLakeError(e)
        self.sha256 = hashlib.sha256(r.content).hexdigest()
        self._dsc = deb822.Dsc(r.content)

    @property
    def filename(self):
        return self.dscfile.filename

    @property
    def archive_name(self):
        return self.dscfile.archive_name

    @property
    def path(self):
        return self.dscfile.path

    def srcfiles(self) -> Iterable["RemoteFile"]:
        for rf in self.allfiles:
            for entry in self._dsc.get("checksums-sha1", []):
                if rf.hash == entry["sha1"] and rf.filename == entry["name"]:
                    yield rf
