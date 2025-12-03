# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Iterable
from requests import RequestException
from debian import deb822
from ..util.checksum import (
    NoMatchingDigestError,
    calculate_checksums,
    checksums_from_dsc,
    verify_best_matching_digest,
)
from ..snapshot.client import (
    RemoteFile,
    SnapshotDataLake,
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
        r = self.sdl.get(url=self.dscfile.downloadurl)
        self.checksums = calculate_checksums(r.content)
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
        """
        Yields RemoteFile objects from self.allfiles that match
        checksums defined in self._dsc.
        """
        dsc_checksums = checksums_from_dsc(self._dsc)
        for rf in self.allfiles:
            try:
                if verify_best_matching_digest(rf.checksums, dsc_checksums.get(rf.filename)):
                    yield rf
            except NoMatchingDigestError:
                continue
