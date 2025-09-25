#!/usr/bin/env python3

# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

"""
This module contains wrappers of the snapshot.debian.org machine-usable interface
documented in https://salsa.debian.org/snapshot-team/snapshot/raw/master/API.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import requests
from datetime import datetime
from requests.exceptions import RequestException


class SnapshotDataLakeError(Exception):
    """
    All client exceptions inherit from this
    """

    pass


class NotFoundOnSnapshotError(SnapshotDataLakeError, FileNotFoundError):
    """
    The requested file is not found on the snapshot mirror
    """

    pass


class Package:
    """
    Source package name (without specific version)
    """

    def __init__(self, sdl: "SnapshotDataLake", name: str):
        self.sdl = sdl
        self.name = name

    def versions(self) -> Iterable["SourcePackage"]:
        """
        Iterate all versions of a ``SourcePackage``.
        """
        try:
            r = self.sdl.rs.get(self.sdl.url + f"/mr/package/{self.name}/")
            if r.status_code == 404:
                raise NotFoundOnSnapshotError()
            data = r.json()
        except RequestException as e:
            raise SnapshotDataLakeError(e)
        for v in data["result"]:
            yield SourcePackage(self.sdl, self.name, v["version"])


class SourcePackage:
    """
    Source package in a specific version
    """

    def __init__(self, sdl: "SnapshotDataLake", name: str, version: str):
        self.sdl = sdl
        self.name = name
        self.version = version

    def srcfiles(self) -> Iterable["RemoteFile"]:
        """
        All files associated with the source package. Returns multiple RemoteFile
        instances for a single hash in case the file is known under multiple names.
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
            for res in fileinfo[hash]:
                rf = RemoteFile.fromfileinfo(self.sdl, hash, res)
                rf.architecture = "source"
                yield rf

    def binpackages(self) -> Iterable["BinaryPackage"]:
        """
        All binary packages created from this source package
        """
        try:
            r = self.sdl.rs.get(
                self.sdl.url + f"/mr/package/{self.name}/{self.version}" "/binpackages"
            )
            if r.status_code == 404:
                raise NotFoundOnSnapshotError()
            data = r.json()
        except RequestException as e:
            raise SnapshotDataLakeError(e)
        for b in data.get("result", []):
            yield BinaryPackage(self.sdl, b["name"], b["version"], self.name, self.version)


class BinaryPackage:
    """
    Binary package in a specific version
    """

    def __init__(
        self,
        sdl: "SnapshotDataLake",
        binname: str,
        binversion: str,
        srcname: str | None,
        srcversion: str | None,
    ):
        self.sdl = sdl
        self.binname = binname
        self.binversion = binversion
        self.srcname = srcname
        self.srcversion = srcversion

    def files(self, arch: str | None = None) -> Iterable["RemoteFile"]:
        """
        All files associated with this binary package (e.g. per-architecture)

        If no architecture is specified, all packages are returned.
        Otherwise, only the packages with the matching architecture are returned.
        If we have information about the source package as well, we precisely resolve the binary package
        including the original path on the debian mirror. If not, we just resolve the file.
        The difference is only in the metadata, the file itself is the same in both cases.

        Returns multiple RemoteFile instances for a single hash in case the file is known under
        multiple names.
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
            for res in fileinfo[hash]:
                rf = RemoteFile.fromfileinfo(self.sdl, hash, res)
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
    architecture: str | None = None

    @staticmethod
    def fromfileinfo(sdl, hash: str, fileinfo: Mapping) -> "RemoteFile":
        """
        Factory to create a ``RemoteFile`` from a fileinfo object.
        """
        return RemoteFile(
            hash,
            fileinfo["name"],
            fileinfo["size"],
            fileinfo["archive_name"],
            fileinfo["path"],
            int(datetime.fromisoformat(fileinfo["first_seen"]).timestamp()),
            sdl.url + f"/file/{hash}/{fileinfo['name']}",
        )


class SnapshotDataLake:
    """
    Snapshot instance to query against. If you use this API from a tool,
    please use a dedicated requests session and set a custom user-agent header.
    """

    def __init__(
        self, url="https://snapshot.debian.org", session: requests.Session = requests.Session()
    ):
        self.url = url
        # reuse the same connection for all requests
        self.rs = session

    def packages(self) -> Iterable[Package]:
        """
        Iterate all known packages on the mirror. The request is costly.
        If you need to access a package by name, create the ``Package`` directly.
        """
        try:
            r = self.rs.get(self.url + "/mr/package/")
            data = r.json()
        except RequestException as e:
            raise SnapshotDataLakeError(e)
        for p in data.get("result", []):
            yield Package(self, p["package"])

    def fileinfo(self, hash: str) -> Iterable[RemoteFile]:
        """
        Retrieve information about a file by hash.
        """
        try:
            r = self.rs.get(self.url + f"/mr/file/{hash}/info")
            data = r.json()
        except RequestException as e:
            raise SnapshotDataLakeError(e)
        for f in data.get("result", []):
            yield RemoteFile.fromfileinfo(self, hash, f)
