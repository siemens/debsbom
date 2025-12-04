# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

"""
This module contains wrappers of the snapshot.debian.org machine-usable interface
documented in https://salsa.debian.org/snapshot-team/snapshot/raw/master/API.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from debian import deb822
import logging
import requests
from requests.exceptions import RequestException

from ..dpkg import package
from ..util.checksum import (
    ChecksumAlgo,
    NoMatchingDigestError,
    calculate_checksums,
    checksums_from_dsc,
    verify_best_matching_digest,
)
from ..download.resolver import RemoteFile, PackageResolverCache, Resolver, ResolveError


logger = logging.getLogger(__name__)


UPSTREAM_ARCHIVE_ORDER = ["debian", "debian-security", "debian-debug", "debian-ports"]


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


class SnapshotResolveError(ResolveError):
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
        data = self.sdl.get(path=f"/mr/package/{self.name}/").json()
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

    def srcfiles(
        self, archive: str | None = None, sha1: str | None = None
    ) -> Iterable["SnapshotRemoteFile"]:
        """
        All files associated with the source package. Returns multiple SnaphshotRemoteFile
        instances for a single hash in case the file is known under multiple names.
        If the package is not known to the snapshot mirror, raises NotFoundOnSnapshotError.
        If the filtering does not match any, return empty iterator.
        """
        data = self.sdl.get(
            path=f"/mr/package/{self.name}/{self.version}/srcfiles?fileinfo=1"
        ).json()
        fileinfo = data.get("fileinfo")
        for s in data.get("result", []):
            hash = s["hash"]
            for res in fileinfo[hash]:
                rf = SnapshotRemoteFile.fromfileinfo(self.sdl, hash, res)
                if archive and rf.archive_name != archive:
                    continue
                if sha1 and rf.hash != sha1:
                    continue
                rf.architecture = "source"
                yield rf

    def binpackages(self) -> Iterable["BinaryPackage"]:
        """
        All binary packages created from this source package
        """
        data = self.sdl.get(path=f"/mr/package/{self.name}/{self.version}/binpackages").json()
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

    def files(self, arch: str | None = None) -> Iterable["SnapshotRemoteFile"]:
        """
        All files associated with this binary package (e.g. per-architecture)

        If no architecture is specified, all packages are returned.
        Otherwise, only the packages with the matching architecture are returned.
        If we have information about the source package as well, we precisely resolve the binary package
        including the original path on the debian mirror. If not, we just resolve the file.
        The difference is only in the metadata, the file itself is the same in both cases.

        Returns multiple SnapshotRemoteFile instances for a single hash in case the file is known under
        multiple names.
        """
        if self.srcname and self.srcversion:
            # resolve via source package
            api = (
                f"/mr/package/{self.srcname}/{self.srcversion}"
                f"/binfiles/{self.binname}/{self.binversion}"
                "?fileinfo=1"
            )
        else:
            # resolve via binary only
            api = f"/mr/binary/{self.binname}/{self.binversion}/binfiles?fileinfo=1"
        data = self.sdl.get(path=api).json()
        fileinfo = data.get("fileinfo")
        for f in data.get("result"):
            hash = f["hash"]
            for res in fileinfo[hash]:
                rf = SnapshotRemoteFile.fromfileinfo(self.sdl, hash, res)
                rf.architecture = f["architecture"]
                if arch and arch != rf.architecture:
                    continue
                yield rf


@dataclass(kw_only=True)
class SnapshotRemoteFile(RemoteFile):
    """
    File on the snapshot farm.
    """

    size: int
    path: str
    first_seen: int
    architecture: str | None = None

    @staticmethod
    def fromfileinfo(sdl, hash: str, fileinfo: Mapping) -> "SnapshotRemoteFile":
        """
        Factory to create a ``SnapshotRemoteFile`` from a fileinfo object.
        """
        return SnapshotRemoteFile(
            checksums={ChecksumAlgo.SHA1SUM: hash},
            filename=fileinfo["name"],
            size=fileinfo["size"],
            archive_name=fileinfo["archive_name"],
            path=fileinfo["path"],
            first_seen=int(datetime.fromisoformat(fileinfo["first_seen"]).timestamp()),
            downloadurl=sdl.url + f"/file/{hash}/{fileinfo['name']}",
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

    def get(self, path: str = None, url: str = None) -> requests.Response:
        """
        Perform a GET request on the snapshot server. Either a full URL or a path relative to the
        base URL must be provided.
        """
        if (url is None) == (path is None):
            raise ValueError("either path or url must be provided")
        try:
            response: requests.Response = self.rs.get(self.url + path if path else url)
            if response.status_code == 404:
                raise NotFoundOnSnapshotError()
            response.raise_for_status()
            return response
        except RequestException as e:
            raise SnapshotDataLakeError(e)

    def packages(self) -> Iterable[Package]:
        """
        Iterate all known packages on the mirror. The request is costly.
        If you need to access a package by name, create the ``Package`` directly.
        """
        data = self.get(path="/mr/package/").json()
        for p in data.get("result", []):
            yield Package(self, p["package"])

    def fileinfo(self, hash: str) -> Iterable[SnapshotRemoteFile]:
        """
        Retrieve information about a file by hash.
        """
        data = self.get(path=f"/mr/file/{hash}/info").json()
        for f in data.get("result", []):
            yield SnapshotRemoteFile.fromfileinfo(self, hash, f)


class SnapshotRemoteDscFile:
    """
    Wrapper around a RemoteFile to only iterate the files referenced in the dsc file.
    """

    sdl: SnapshotDataLake
    dscfile: SnapshotRemoteFile
    allfiles: list[SnapshotRemoteFile]

    def __init__(
        self, sdl: SnapshotDataLake, dscfile: SnapshotRemoteFile, allfiles: list[SnapshotRemoteFile]
    ):
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

    def srcfiles(self) -> Iterable["SnapshotRemoteFile"]:
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


class UpstreamResolver(Resolver):
    """
    Helper to lookup packages on an upstream snapshot server. The lookup works as following:

    Binary package: ask the snapshot client for files of a binary package with name, version
    and architecture

    Source package (with checksum): ask the snapshot client for all files related to the source
    package identified by name and version. Then, sort the list by to sorting order and
    filter all .dsc files in the returned list. For each dsc file, fetch it and compute the
    checksum. If the checksum is not matching, ignore it. If it is matching, yield it and yield
    all referenced source files of the .dsc file.

    Source package (without checksum): ask the snapshot client for all files related to the
    source package identified by name and version. Then, sort the list by to sorting order and
    deduplicate based on (archive_name, filename). Note, that each deduplication contains the
    most recent file.

    Sorting order: First by archive_name (priority), then by first_seen (descending).

    Checksum computation: The checksums of the returned files are not checked at this stage
    (except for the .dsc files for source packages with checksum information). This operation is
    left to the caller (usually the downloader), as it creates potentially a lot of traffic
    between the snapshot mirror and the downloader. The resolving operations itself are cached
    in the cache, but the download artifacts have to be cached by the caller.
    """

    def __init__(self, sdl: SnapshotDataLake, cache: PackageResolverCache = PackageResolverCache()):
        super().__init__(cache)
        self.sdl = sdl

    @classmethod
    def _sort_by_archive(
        cls,
        files: Iterable["SnapshotRemoteFile"] | Iterable["SnapshotRemoteDscFile"],
    ) -> list["SnapshotRemoteFile"] | list["SnapshotRemoteDscFile"]:
        """
        Sort the input list by priority of the upstream archives. By that, we can iterate
        the items in the most likely order to have checksum matches more likely early.
        """
        priority = {name: i for i, name in enumerate(UPSTREAM_ARCHIVE_ORDER)}
        default_prio = len(UPSTREAM_ARCHIVE_ORDER)
        return sorted(
            files,
            key=lambda f: (
                # Primary: archive priority
                priority.get(f.archive_name, default_prio),
                # Secondary: most recent “first_seen” first (descending)
                -f.first_seen,
            ),
        )

    @classmethod
    def _distinct_by_archive_filename(
        cls, files: Iterable[SnapshotRemoteFile]
    ) -> Iterable[SnapshotRemoteFile]:
        """
        Return a list of RemoteFiles that is made unique on archive and filename key.
        If multiple elements share the same keys, the first seen is returned.
        """
        seen: set[tuple[str, str]] = set()
        for file in files:
            key = (file.archive_name, file.filename)
            if key not in seen:
                seen.add(key)
                yield file

    @classmethod
    def _resolve_dsc_files(
        cls, pkg: SourcePackage, archive: str | None = None
    ) -> Iterable["SnapshotRemoteDscFile"]:
        """
        Locate all .dsc files associated with the source package and lazily create
        RemoteDscFile instances to lookup associated artifacts.
        """
        files = cls._sort_by_archive(pkg.srcfiles(archive=archive))
        for f in files:
            if f.filename.endswith(".dsc"):
                yield SnapshotRemoteDscFile(sdl=pkg.sdl, dscfile=f, allfiles=files)

    def _filter_rel_sources(
        self, srcpkg: package.SourcePackage, sdlpkg: SourcePackage
    ) -> Iterable[SnapshotRemoteFile]:
        """
        A debian source package can be found in multiple snapshot archives with varying
        content and checksum. In case we have a checksum, download all .dsc files until
        we find the one with a matching checksum. Then use the .dsc file to locate all other
        referenced artifacts.
        """
        if not srcpkg.checksums or len(srcpkg.checksums) == 0:
            # a source package should be uniquely identifiable by just its name + version,
            # so we do not want to emit a warning here;
            # see https://lists.debian.org/debian-devel/2025/10/msg00236.html
            logger.info(f"no digest for {srcpkg}. Lookup will be imprecise")
            yield from self._distinct_by_archive_filename(self._sort_by_archive(sdlpkg.srcfiles()))
            return

        dscfiles = self._resolve_dsc_files(sdlpkg, archive=None)
        for d in dscfiles:
            try:
                if verify_best_matching_digest(d.checksums, srcpkg.checksums):
                    yield d.dscfile
                    yield from d.srcfiles()
                    return
            except NoMatchingDigestError:
                continue

    def resolve(self, p: package.Package) -> list["RemoteFile"]:
        """
        Resolve a local package to references on the upstream snapshot mirror
        """
        # Determine which type of package and fetch files
        try:
            if p.is_source():
                files = self._filter_rel_sources(p, SourcePackage(self.sdl, p.name, str(p.version)))
            else:
                files = BinaryPackage(self.sdl, p.name, str(p.version), None, None).files(
                    arch=p.architecture
                )
            files_list = list(files)
        except SnapshotDataLakeError as e:
            raise SnapshotResolveError(e)
        return files_list
