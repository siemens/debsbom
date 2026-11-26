# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from collections import Counter

import pytest
import requests
from debian import deb822

from debsbom.apt.remote import (
    RemoteRepository,
    RepositoryAccessError,
    RepositoryConfigurationError,
    RepositoryMetadataError,
)
from debsbom.download.download import DownloadStatus, PackageDownloader
from debsbom.download.mirror import (
    MirrorIntegrityError,
    MirrorNotFoundError,
    MirrorResolveError,
    MirrorResolver,
    archive_label,
)
from debsbom.download.resolver import NotFoundError, PackageResolverCache
from debsbom.dpkg.package import BinaryPackage, SourcePackage
from debsbom.util.checksum import ChecksumAlgo, calculate_checksums
from test_apt_remote import (
    LISTS,
    PACKAGES,
    ROOT,
    LocalRepository,
    binary,
    file_list,
    http,
    http_repository,
    offline_session,
    paragraph,
    source,
)

MD5, SHA256, SHA512 = ChecksumAlgo.MD5SUM, ChecksumAlgo.SHA256SUM, ChecksumAlgo.SHA512SUM
FILES = {"foo_1.0.orig.tar.xz": b"upstream\n", "foo_1.0-1.debian.tar.xz": b"debian\n"}
SOURCES = "dists/trixie/main/source/Sources"


def digest(data: bytes, algo: ChecksumAlgo = SHA256) -> dict[ChecksumAlgo, str]:
    return calculate_checksums(data, [algo])


def dsc_file(
    name="foo",
    version="1.0-1",
    files=FILES,
    lists=("Files", "Checksums-Sha256"),
    signature=None,
    **fields,
) -> bytes:
    """A .dsc file listing ``files``, optionally with an OpenPGP signature (not a valid one)."""
    values = {"Format": "3.0 (quilt)", "Source": name, "Version": version}
    values |= {field: file_list(files, LISTS[field]) for field in lists}
    text = paragraph(values | fields)
    if signature:
        text = (
            f"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n{text}\n"
            f"-----BEGIN PGP SIGNATURE-----\n\n{signature}\n-----END PGP SIGNATURE-----\n"
        )
    return text.encode()


class Mirror(LocalRepository):
    """A local repository with the files of its packages."""

    def publish_binary(self, name="foo", version="1.0", arch="amd64", data=None, **fields) -> str:
        """Write the file of a binary package and return its paragraph of a Packages index."""
        data = f"{name} {version} {arch}\n".encode() if data is None else data
        record = binary(name, version, arch, data, **fields)
        self.write(deb822.Deb822(record)["Filename"], data)
        return record

    def publish_source(self, name="foo", version="1.0-1", files=FILES, dsc=None, **fields) -> str:
        """Write the files of a source package and return its paragraph of a Sources index."""
        dsc = dsc_file(name, version, files) if dsc is None else dsc
        files = {SourcePackage(name, version).dscfile(): dsc} | files
        record = source(name, version, files, **fields)
        directory = deb822.Deb822(record)["Directory"]
        for filename, data in files.items():
            self.write(f"{directory}/{filename}", data)
        return record

    def resolver(self, **kwargs) -> MirrorResolver:
        return MirrorResolver(self.repository(**kwargs))


@pytest.fixture
def mirror(tmp_path):
    repo = Mirror(tmp_path / "mirror")
    yield repo
    repo.session.close()


@pytest.mark.parametrize(
    "url, label",
    [
        ("https://deb.debian.org/debian", "mirror_deb.debian.org_debian"),
        (
            "http://mirror.example:8080/debian-security",
            "mirror_mirror.example_8080_debian-security",
        ),
        ("file:///srv/apt/repo", "mirror_srv_apt_repo"),
        ("https://mirror.example", "mirror_mirror.example"),
        ("file://", "mirror"),
    ],
)
def test_archive_label(url, label):
    assert archive_label(url) == label


def test_archive_label_of_long_url():
    base = "https://mirror.example/" + "a" * 100
    labels = {archive_label(f"{base}/{suite}") for suite in ("one", "two")}
    assert len(labels) == 2
    for label in labels:
        assert len(label) == len("mirror_") + 64
        assert label.startswith("mirror_mirror.example_aaa")


def test_resolver_is_offline(offline_session):
    resolver = MirrorResolver(RemoteRepository(offline_session, ROOT, ["trixie"], ["main"]))
    assert resolver.archive_name == "mirror_mirror.example_debian"
    # the results are not cached
    assert type(resolver.cache) is PackageResolverCache


def test_resolve_binary(mirror):
    data = b"foo deb\n"
    mirror.packages(binary("foo", "0.9"), mirror.publish_binary(data=data), binary("bar"))
    resolver = mirror.resolver()
    pkg = BinaryPackage("foo", "1.0", architecture="amd64", checksums=digest(data))
    (f,) = resolver.resolve(pkg)
    assert f.filename == "foo_1.0_amd64.deb"
    assert f.downloadurl == f"{mirror.url}/pool/main/f/foo/foo_1.0_amd64.deb"
    assert f.archive_name == resolver.archive_name
    assert f.size == len(data)
    assert f.checksums == calculate_checksums(data, [MD5, SHA256])
    assert mirror.requested == Counter({f"{mirror.url}/{PACKAGES}.xz": 1})


@pytest.mark.parametrize(
    "name, version, arch",
    [
        ("bar", "1.0", "amd64"),
        ("foo", "1.1", "amd64"),
        ("foo", "1:1.0", "amd64"),
        ("foo", "1.0", "arm64"),
    ],
)
def test_binary_not_found(mirror, name, version, arch):
    mirror.packages(mirror.publish_binary())
    resolver = mirror.resolver()
    with pytest.raises(MirrorNotFoundError) as e:
        resolver.resolve(BinaryPackage(name, version, architecture=arch))
    assert isinstance(e.value, NotFoundError)
    assert str(e.value) == f"not found in '{resolver.repository.url}'"


def test_binary_without_architecture(mirror):
    mirror.packages(mirror.publish_binary())
    with pytest.raises(MirrorNotFoundError, match="without architecture"):
        mirror.resolver().resolve(BinaryPackage("foo", "1.0"))
    assert not mirror.requested


def test_binary_checksums(mirror):
    """Without a checksum in common, the downloaded file is verified independently."""
    data = b"foo deb\n"
    mirror.packages(mirror.publish_binary(data=data))
    resolver = mirror.resolver()
    sha256 = digest(data)[SHA256]
    for checksums in ({}, digest(data), {SHA256: sha256.upper()}, digest(b"other\n", SHA512)):
        pkg = BinaryPackage("foo", "1.0", architecture="amd64", checksums=checksums)
        (f,) = resolver.resolve(pkg)
        assert f.checksums[SHA256] == sha256


def test_binary_candidates(mirror):
    """Candidates are skipped if the strongest checksum in common differs."""
    old, new = b"old\n", b"new\n"
    mirror.packages(mirror.publish_binary(data=old))
    mirror.packages(
        mirror.publish_binary(data=new, Filename="pool/updates/foo_1.0_amd64.deb"),
        suite="trixie-updates",
    )
    resolver = mirror.resolver(suites=("trixie", "trixie-updates"))
    pkg = BinaryPackage("foo", "1.0", architecture="amd64", checksums=digest(new))
    (f,) = resolver.resolve(pkg)
    assert f.downloadurl == f"{mirror.url}/pool/updates/foo_1.0_amd64.deb"

    # a matching weaker checksum does not matter
    pkg.checksums = digest(old, MD5) | digest(b"other\n")
    with pytest.raises(MirrorNotFoundError, match=r"\(skipped 2 with different checksums\)"):
        resolver.resolve(pkg)


def test_resolve_source(mirror):
    mirror.sources(source("foo", "0.9-1"), mirror.publish_source(), source("bar", "1.0-1"))
    dsc = (mirror.root / "pool/main/f/foo/foo_1.0-1.dsc").read_bytes()
    resolver = mirror.resolver()
    files = resolver.resolve(SourcePackage("foo", "1.0-1", checksums=digest(dsc)))
    assert [f.filename for f in files] == ["foo_1.0-1.dsc", *FILES]
    for f in files:
        data = (mirror.root / "pool/main/f/foo" / f.filename).read_bytes()
        assert f.downloadurl == f"{mirror.url}/pool/main/f/foo/{f.filename}"
        assert f.archive_name == resolver.archive_name
        assert f.size == len(data)
        assert f.checksums == calculate_checksums(data, [MD5, SHA256])
    # only the .dsc file is retrieved
    assert mirror.requested == Counter(
        {f"{mirror.url}/{SOURCES}.xz": 1, f"{mirror.url}/pool/main/f/foo/foo_1.0-1.dsc": 1}
    )


@pytest.mark.parametrize("algo", [SHA256, SHA512])
def test_source_identity(mirror, algo):
    """
    The checksums of a source package identify the complete .dsc file, including its
    signature. Without a checksum in common with the index, the .dsc files are compared.
    """
    dscs = [dsc_file(signature=signature) for signature in ("first", "second")]
    mirror.sources(mirror.publish_source(dsc=dscs[0]))
    mirror.sources(
        mirror.publish_source(dsc=dscs[1], Directory="pool/updates/f/foo"), suite="trixie-updates"
    )
    resolver = mirror.resolver(suites=("trixie", "trixie-updates"))
    files = resolver.resolve(SourcePackage("foo", "1.0-1", checksums=digest(dscs[1], algo)))
    assert {f.downloadurl.rsplit("/", 1)[0] for f in files} == {f"{mirror.url}/pool/updates/f/foo"}
    first = f"{mirror.url}/pool/main/f/foo/foo_1.0-1.dsc"
    assert mirror.requested[first] == (1 if algo == SHA512 else 0)

    with pytest.raises(MirrorNotFoundError, match="skipped 2"):
        resolver.resolve(SourcePackage("foo", "1.0-1", checksums=digest(dsc_file(), algo)))


def test_source_without_checksums(mirror):
    mirror.sources(mirror.publish_source())
    mirror.sources(mirror.publish_source(Directory="pool/updates/f/foo"), suite="trixie-updates")
    resolver = mirror.resolver(suites=("trixie", "trixie-updates"))
    files = resolver.resolve(SourcePackage("foo", "1.0-1"))
    assert {f.downloadurl.rsplit("/", 1)[0] for f in files} == {f"{mirror.url}/pool/main/f/foo"}


@pytest.mark.parametrize(
    "files",
    [
        {"foo_1.0-1.tar.xz": b"native\n"},
        FILES,
        {
            "foo_1.0.orig.tar.xz": b"upstream\n",
            "foo_1.0.orig-docs.tar.xz": b"docs\n",
            "foo_1.0-1.debian.tar.xz": b"debian\n",
        },
        {
            "foo_1.0.orig.tar.xz": b"upstream\n",
            "foo_1.0.orig.tar.xz.asc": b"upstream signature\n",
            "foo_1.0-1.debian.tar.xz": b"debian\n",
        },
        {"foo_1.0.orig.tar.gz": b"upstream\n", "foo_1.0-1.diff.gz": b"diff\n"},
    ],
    ids=["native", "quilt", "multiple-upstream", "upstream-signature", "diff"],
)
@pytest.mark.parametrize(
    "lists",
    [("Files", "Checksums-Sha256"), ("Checksums-Sha256",), ("Files",), tuple(LISTS)],
    ids=["md5-sha256", "sha256", "md5", "all"],
)
def test_source_bundles(mirror, files, lists):
    """All files of a source package are used, whatever checksums are listed."""
    dsc = dsc_file(files=files, lists=lists)
    mirror.sources(mirror.publish_source(files=files, dsc=dsc, lists=lists))
    result = mirror.resolver().resolve(SourcePackage("foo", "1.0-1", checksums=digest(dsc)))
    assert [f.filename for f in result] == ["foo_1.0-1.dsc", *files]
    assert [f.checksums for f in result[1:]] == [
        calculate_checksums(data, [LISTS[field] for field in lists]) for data in files.values()
    ]


@pytest.mark.parametrize(
    "dsc, error, match",
    [
        (dsc_file("bar"), MirrorIntegrityError, "describes bar 1.0-1, but .* for foo 1.0-1"),
        (dsc_file(version="1.0-2"), MirrorIntegrityError, "describes foo 1.0-2"),
        (dsc_file(files={"foo_1.0.orig.tar.xz": b"upstream\n"}), MirrorIntegrityError, "files"),
        (dsc_file(files=FILES | {"foo_1.0.orig-x.tar.xz": b"x\n"}), MirrorIntegrityError, "files"),
        (
            dsc_file(files=FILES | {"foo_1.0.orig.tar.xz": b"another size\n"}),
            MirrorIntegrityError,
            "'foo_1.0.orig.tar.xz' with 13 bytes, but .* with 9 bytes",
        ),
        (
            dsc_file(files=FILES | {"foo_1.0.orig.tar.xz": b"UPSTREAM\n"}),
            MirrorIntegrityError,
            "for 'foo_1.0.orig.tar.xz': Checksum mismatch",
        ),
        (
            dsc_file(lists=("Checksums-Sha1",)),
            MirrorIntegrityError,
            "for 'foo_1.0.orig.tar.xz': No matching digest",
        ),
        (dsc_file() + b"Description: \xff\n", MirrorIntegrityError, "not valid UTF-8"),
        (
            dsc_file(Files=file_list(FILES, MD5) + file_list(FILES, MD5)),
            MirrorResolveError,
            "lists 'foo_1.0.orig.tar.xz' twice",
        ),
    ],
)
def test_inconsistent_dsc_file(mirror, dsc, error, match):
    """A .dsc file which contradicts the index is an error, regardless of the checksums."""
    mirror.sources(mirror.publish_source(dsc=dsc))
    resolver = mirror.resolver()
    for checksums in ({}, digest(dsc), digest(b"other\n", SHA512)):
        with pytest.raises(error, match=match) as e:
            resolver.resolve(SourcePackage("foo", "1.0-1", checksums=checksums))
        assert not isinstance(e.value, NotFoundError)


@pytest.mark.parametrize("field, algo", LISTS.items())
@pytest.mark.parametrize("signature", [None, "signature"])
def test_dsc_rejects_extra_file_columns(mirror, field, algo, signature):
    dsc = dsc_file(
        lists=(field,),
        signature=signature,
        **{field: file_list(FILES, algo) + " extra"},
    )
    mirror.sources(mirror.publish_source(dsc=dsc, lists=(field,)))

    with pytest.raises(MirrorResolveError, match="unsafe file name") as error:
        mirror.resolver().resolve(SourcePackage("foo", "1.0-1"))

    assert isinstance(error.value.__cause__, RepositoryMetadataError)


@pytest.mark.parametrize(
    "tamper, match",
    [
        (lambda data: data.replace(b"foo", b"bar"), "does not match .*: Checksum mismatch"),
        (lambda data: data[:-1], "has .* bytes, but .* lists"),
        (lambda data: data + b"\n", "is larger than the .* bytes listed"),
    ],
)
def test_tampered_dsc_file(mirror, tamper, match):
    mirror.sources(mirror.publish_source())
    path = mirror.root / "pool/main/f/foo/foo_1.0-1.dsc"
    dsc = path.read_bytes()
    path.write_bytes(tamper(dsc))
    with pytest.raises(MirrorIntegrityError, match=match):
        mirror.resolver().resolve(SourcePackage("foo", "1.0-1", checksums=digest(dsc)))


def test_dsc_file_errors(mirror, monkeypatch):
    mirror.sources(mirror.publish_source())
    resolver = mirror.resolver()
    pkg = SourcePackage("foo", "1.0-1")
    path = mirror.root / "pool/main/f/foo/foo_1.0-1.dsc"

    with monkeypatch.context() as m:
        m.setattr("debsbom.download.mirror.MAX_DSC_SIZE", 10)
        with pytest.raises(MirrorResolveError, match="exceeds the size limit of 10 bytes"):
            resolver.resolve(pkg)
        assert path.as_uri() not in mirror.requested

    path.unlink()
    with pytest.raises(MirrorResolveError, match="listed in the metadata, but not available") as e:
        resolver.resolve(pkg)
    assert not isinstance(e.value, NotFoundError)
    assert isinstance(e.value.__cause__, RepositoryAccessError)


@pytest.mark.parametrize(
    "response",
    [
        dict(status=401),
        dict(status=403),
        dict(status=429),
        dict(status=500),
        dict(status=503),
        dict(body=requests.ConnectionError("connection refused")),
        dict(body=requests.Timeout("read timed out")),
    ],
)
def test_access_errors_are_not_misses(http, response):
    http.add(PACKAGES + ".xz", **response)
    with pytest.raises(MirrorResolveError) as e:
        MirrorResolver(http_repository(http)).resolve(
            BinaryPackage("foo", "1.0", architecture="amd64")
        )
    assert not isinstance(e.value, NotFoundError)
    assert isinstance(e.value.__cause__, RepositoryAccessError)


def test_repository_errors_are_not_misses(mirror):
    mirror.write(PACKAGES + ".xz", b"not xz")
    resolver = mirror.resolver()
    with pytest.raises(MirrorResolveError) as e:
        resolver.resolve(BinaryPackage("foo", "1.0", architecture="amd64"))
    assert not isinstance(e.value, NotFoundError)
    assert isinstance(e.value.__cause__, RepositoryMetadataError)

    # the indexes of 'Architecture: all' packages are unknown without Release file
    with pytest.raises(MirrorResolveError, match="Architecture: all") as e:
        resolver.resolve(BinaryPackage("foo", "1.0", architecture="all"))
    assert not isinstance(e.value, NotFoundError)
    assert isinstance(e.value.__cause__, RepositoryConfigurationError)


def test_indexes_are_retrieved_once(mirror):
    mirror.packages(mirror.publish_binary("foo"), mirror.publish_binary("bar"))
    mirror.sources(mirror.publish_source())
    resolver = mirror.resolver()
    for _ in range(2):
        for name in ("foo", "bar"):
            resolver.resolve(BinaryPackage(name, "1.0", architecture="amd64"))
        with pytest.raises(MirrorNotFoundError):
            resolver.resolve(BinaryPackage("baz", "1.0", architecture="amd64"))
        with pytest.raises(MirrorNotFoundError):
            resolver.resolve(SourcePackage("baz", "1.0-1"))
    assert mirror.requested[f"{mirror.url}/{PACKAGES}.xz"] == 1
    assert mirror.requested[f"{mirror.url}/{SOURCES}.xz"] == 1


def test_download(mirror, tmp_path):
    deb = b"foo deb\n"
    mirror.packages(mirror.publish_binary(data=deb))
    mirror.sources(mirror.publish_source())
    dsc = (mirror.root / "pool/main/f/foo/foo_1.0-1.dsc").read_bytes()
    resolver = mirror.resolver()
    outdir = tmp_path.resolve() / "downloads"
    downloader = PackageDownloader(outdir, mirror.session)
    packages = [
        BinaryPackage("foo", "1.0", architecture="amd64", checksums=digest(deb)),
        SourcePackage("foo", "1.0-1", checksums=digest(dsc)),
    ]
    for pkg in packages:
        downloader.register(resolver.resolve(pkg), pkg)
    results = list(downloader.download())
    assert [r.status for r in results] == [DownloadStatus.OK] * 4
    label = resolver.archive_name
    assert [r.path.relative_to(outdir).as_posix() for r in results] == [
        f"binaries/{label}/foo_1.0_amd64.deb",
        f"sources/{label}/foo_1.0-1.dsc",
        *(f"sources/{label}/{name}" for name in FILES),
    ]
    assert [r.source for r in results] == [
        f"{mirror.url}/pool/main/f/foo/foo_1.0_amd64.deb",
        *(f"{mirror.url}/pool/main/f/foo/{name}" for name in ["foo_1.0-1.dsc", *FILES]),
    ]


@pytest.mark.parametrize("substituted", [False, True])
def test_download_verifies_source_files_against_dsc_file(mirror, tmp_path, substituted):
    """
    The other files of a source package are verified against the checksums of its .dsc
    file, which identifies them, even if the index only lists weaker ones.
    """
    listed = {name: data.upper() if substituted else data for name, data in FILES.items()}
    dsc = dsc_file(lists=("Files",), **{"Checksums-Sha512": file_list(listed, SHA512)})
    mirror.sources(mirror.publish_source(dsc=dsc, lists=("Files",)))
    pkg = SourcePackage("foo", "1.0-1", checksums=digest(dsc))
    downloader = PackageDownloader(tmp_path / "downloads", mirror.session)
    downloader.register(mirror.resolver().resolve(pkg), pkg)
    status = DownloadStatus.CHECKSUM_MISMATCH if substituted else DownloadStatus.OK
    assert [r.status for r in downloader.download()] == [DownloadStatus.OK, status, status]


def test_download_verifies_independently(mirror, tmp_path):
    """A binary package without a checksum in common is verified when downloaded."""
    mirror.packages(mirror.publish_binary(data=b"foo deb\n"))
    downloader = PackageDownloader(tmp_path / "downloads", mirror.session)
    pkg = BinaryPackage("foo", "1.0", architecture="amd64", checksums=digest(b"other\n", SHA512))
    downloader.register(mirror.resolver().resolve(pkg), pkg)
    (result,) = downloader.download()
    assert result.status == DownloadStatus.CHECKSUM_MISMATCH
    assert result.path is None
