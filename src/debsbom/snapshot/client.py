#!/usr/bin/env python3

# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from dataclasses import dataclass
from typing import Generator, Type
import requests
from requests.exceptions import RequestException


class SnapshotDataLakeError(Exception):
    """
    All client exceptions inherit from this
    """

    pass


class NotFoundOnSnapshotError(SnapshotDataLakeError, FileNotFoundError):
    pass


class Package:
    """
    Source package name (without specific version)
    """

    def __init__(self, sdl, name: str):
        self.sdl = sdl
        self.name = name

    def versions(self):
        try:
            r = self.sdl.rs.get(self.sdl.url + f"/mr/package/{self.name}/")
            data = r.json()
        except RequestException as e:
            raise SnapshotDataLakeError(e)
        for v in data["result"]:
            yield SourcePackage(self.sdl, self.name, v["version"])


class SourcePackage:
    """
    Source package in a specific version
    """

    def __init__(self, sdl, name: str, version: str):
        self.sdl = sdl
        self.name = name
        self.version = version

    def srcfiles(self) -> Generator["RemoteFile", None, None]:
        """
        All files associated with the source package
        """
        try:
            r = self.sdl.rs.get(
                self.sdl.url + f"/mr/package/{self.name}/{self.version}" "/srcfiles?fileinfo=1"
            )
            if r.status_code == 404:
                raise NotFoundOnSnapshotError()
            data = r.json()
        except RequestException as e:
            raise SnapshotDataLakeError(e)

        fileinfo = data.get("fileinfo")
        for s in data.get("result", []):
            hash = s["hash"]
            # TODO: this might be ambiguous if the same file is uploaded
            # under different names. On a debian mirror this case is not expected
            rf = RemoteFile.fromfileinfo(self.sdl, hash, fileinfo[hash][0])
            rf.architecture = "source"
            yield rf

    def binpackages(self) -> Generator["BinaryPackage", None, None]:
        """
        All binary packages created from this source package
        """
        try:
            r = self.sdl.rs.get(
                self.sdl.url + f"/mr/package/{self.name}/{self.version}" "/binpackages"
            )
            data = r.json()
        except RequestException as e:
            raise SnapshotDataLakeError(e)
        for b in data.get("result", []):
            yield BinaryPackage(self.sdl, b["name"], b["version"], self.name, self.version)


class BinaryPackage:
    """
    Binary package in a specific version
    """

    def __init__(self, sdl, binname, binversion, srcname, srcversion):
        self.sdl = sdl
        self.binname = binname
        self.binversion = binversion
        self.srcname = srcname
        self.srcversion = srcversion

    def files(self, arch: str = None) -> Generator["RemoteFile", None, None]:
        """
        All files associated with this binary package (e.g. per-architecture)

        If no architecture is specified, all packages are returned.
        Otherwise, only the packages with the matching architecture are returned.
        If we have information about the source package as well, we precisely resolve the binary package
        including the original path on the debian mirror. If not, we just resolve the file.
        The difference is only in the metadata, the file itself is the same in both cases.
        """
        if self.srcname and self.srcversion:
            # resolve via source package
            api = (
                self.sdl.url + f"/mr/package/{self.srcname}/{self.srcversion}"
                f"/binfiles/{self.binname}/{self.binversion}"
                "?fileinfo=1"
            )
        else:
            # resolve via binary only
            api = self.sdl.url + f"/mr/binary/{self.binname}/{self.binversion}/binfiles?fileinfo=1"
        try:
            r = self.sdl.rs.get(api)
            if r.status_code == 404:
                raise NotFoundOnSnapshotError()
            data = r.json()
        except RequestException as e:
            raise SnapshotDataLakeError(e)
        fileinfo = data.get("fileinfo")
        for f in data.get("result"):
            hash = f["hash"]
            rf = RemoteFile.fromfileinfo(self.sdl, hash, fileinfo[hash][0])
            rf.architecture = f["architecture"]
            if arch and arch != rf.architecture:
                continue
            yield rf


@dataclass
class RemoteFile:
    """
    File on the snapshot farm
    """

    hash: str
    filename: str
    size: int
    archive_name: str
    path: str
    first_seen: int
    downloadurl: str
    architecture: str = None

    @staticmethod
    def fromfileinfo(sdl, hash, fileinfo):
        return RemoteFile(
            hash,
            fileinfo["name"],
            fileinfo["size"],
            fileinfo["archive_name"],
            fileinfo["path"],
            fileinfo["first_seen"],
            sdl.url + f"/file/{hash}/{fileinfo['name']}",
        )


class SnapshotDataLake:
    """
    Snapshot instance to query against
    """

    def __init__(
        self, url="https://snapshot.debian.org", session: requests.Session = requests.Session()
    ):
        self.url = url
        # reuse the same connection for all requests
        self.rs = session

    def packages(self) -> Generator[Package, None, None]:
        try:
            r = self.rs.get(self.url + "/mr/package/")
            data = r.json()
        except RequestException as e:
            raise SnapshotDataLakeError(e)
        for p in data.get("result", []):
            yield Package(self, p["package"])

    def fileinfo(self, hash):
        try:
            r = self.rs.get(self.url + f"/mr/file/{hash}/info")
            data = r.json()
        except RequestException as e:
            raise SnapshotDataLakeError(e)
        for f in data.get("result", []):
            yield RemoteFile.fromfileinfo(self, hash, f)
