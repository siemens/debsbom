# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from collections import Counter
import io
import json
from unittest import mock

import jsonschema
import pytest
import requests
from debian import deb822
from requests.adapters import BaseAdapter

from debsbom import schema
from debsbom.apt.remote import (
    RemoteRepository,
    RepositoryAccessError,
    RepositoryConfigurationError,
    RepositoryMetadataError,
)
from debsbom.cli import setup_parser
from debsbom.commands import download
from debsbom.commands.download import MIRROR_OPTIONS, DownloadCmd, DownloadInput
from debsbom.commands.enrich import EnrichCmd
from debsbom.download.download import DownloadStatus, PackageDownloader
from debsbom.download.mirror import (
    MirrorIntegrityError,
    MirrorNotFoundError,
    MirrorResolveError,
    MirrorResolver,
    archive_label,
)
from debsbom.download.resolver import (
    FallbackResolver,
    NotFoundError,
    PackageResolverCache,
    PersistentResolverCache,
    RemoteFile,
    Resolver,
)
from debsbom.dpkg.package import BinaryPackage, SourcePackage
import debsbom.snapshot.client as sdlclient
from debsbom.util.checksum import ChecksumAlgo, calculate_checksums
from test_apt_remote import (
    LISTS,
    PACKAGES,
    ROOT,
    HTTPResponses,
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


class Snapshot:
    """
    Stands in for the resolution on snapshot.debian.org, without network access: serves
    the packages of a local directory and records the lookups.
    """

    def __init__(self, root):
        self.root = root
        self.packages = {}
        self.lookups = []

    def publish(self, pkg, files: dict[str, bytes]) -> None:
        self.packages[str(pkg.purl())] = []
        for name, data in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            remote = RemoteFile(digest(data), name, "debian", path.as_uri(), len(data))
            self.packages[str(pkg.purl())].append(remote)

    def resolve(self, p) -> list[RemoteFile]:
        self.lookups.append(str(p.purl()))
        if str(p.purl()) not in self.packages:
            # like the real resolver, without a message
            raise sdlclient.SnapshotNotFoundError(sdlclient.NotFoundOnSnapshotError())
        return self.packages[str(p.purl())]


@pytest.fixture
def snapshot(tmp_path, monkeypatch):
    fake = Snapshot(tmp_path / "snapshot")
    monkeypatch.setattr(sdlclient.UpstreamResolver, "resolve", lambda _, p: fake.resolve(p))
    return fake


@pytest.fixture
def session(mirror, monkeypatch):
    """Let the commands use the session of the mirror, which fails on network access."""
    network = mock.Mock(spec=BaseAdapter, send=mock.Mock(side_effect=AssertionError("network")))
    for prefix in ("http://", "https://"):
        mirror.session.mount(prefix, network)
    monkeypatch.setattr(
        DownloadInput, "_create_default_session", staticmethod(lambda: mirror.session)
    )
    yield mirror.session
    network.send.assert_not_called()


def mirror_args(url: str, *args) -> list[str]:
    return [
        *("--resolver", "debian-mirror", "--mirror-url", url),
        *("--mirror-suite", "trixie", "--mirror-component", "main"),
        *args,
    ]


def run_download(tmp_path, monkeypatch, capsys, pkglist: str, *args) -> list[dict]:
    """Download the packages of a package list and return the results."""
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(pkglist.encode())))
    outdir = str(tmp_path / "downloads")
    DownloadCmd.run(setup_parser().parse_args(["--json", "download", "--outdir", outdir, *args]))
    results = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    for result in results:
        jsonschema.validate(result, schema=schema.download)
    return results


BINARY = "pkg:deb/debian/foo@1.0?arch=amd64"
SOURCE = "pkg:deb/debian/foo@1.0-1?arch=source"


@pytest.mark.parametrize("command", ["download", "enrich"])
def test_parser(command):
    parser = setup_parser()
    args = parser.parse_args([command, "sbom.cdx.json"])
    assert args.resolver == "debian-snapshot"
    assert [getattr(args, option) for option in MIRROR_OPTIONS] == [None] * 5

    args = parser.parse_args(
        [
            *(command, *mirror_args(ROOT, "--mirror-suite", "trixie-updates")),
            *("--mirror-component", "contrib", "--mirror-architecture", "all"),
            *("--snapshot-fallback", "sbom.cdx.json"),
        ]
    )
    assert args.resolver == "debian-mirror"
    assert args.mirror_url == ROOT
    assert args.mirror_suite == ["trixie", "trixie-updates"]
    assert args.mirror_component == ["main", "contrib"]
    assert args.mirror_architecture == ["all"]
    assert args.snapshot_fallback is True
    args = parser.parse_args([command, "--no-snapshot-fallback", "sbom.cdx.json"])
    assert args.snapshot_fallback is False


@pytest.mark.parametrize("command", [DownloadCmd, EnrichCmd])
@pytest.mark.parametrize(
    "args, match",
    [
        (["--resolver", "debian-mirror"], "requires --mirror-url"),
        (["--resolver", "debian-mirror", "--mirror-url", ROOT], "requires --mirror-suite"),
        (mirror_args("ftp://mirror.example/debian"), "must use http, https or file"),
        (mirror_args(ROOT)[:-2], "at least one component"),
        (mirror_args(ROOT, "--mirror-suite", "./"), "cannot be combined"),
        (["--mirror-url", ROOT], "^--mirror-url can only be used with the built-in"),
        (["--mirror-suite", "trixie", "--mirror-component", "main"], "^--mirror-suite, --mir"),
        (["--mirror-architecture", "amd64"], "^--mirror-architecture can only"),
        (["--snapshot-fallback"], "^--snapshot-fallback can only"),
        (["--no-snapshot-fallback"], "^--no-snapshot-fallback can only"),
    ],
)
def test_invalid_configuration(mirror, session, tmp_path, command, args, match):
    """The configuration is checked before any input is read or request is made."""
    name = "download" if command is DownloadCmd else "enrich"
    outdir = str(tmp_path / "downloads")
    missing = str(tmp_path / "missing.cdx.json")
    with pytest.raises(ValueError, match=match):
        command.run(setup_parser().parse_args([name, "--outdir", outdir, *args, missing]))
    assert not mirror.requested


def test_download_command(mirror, session, snapshot, tmp_path, monkeypatch, capsys):
    mirror.packages(mirror.publish_binary())
    mirror.sources(mirror.publish_source())
    results = run_download(
        tmp_path,
        monkeypatch,
        capsys,
        "foo 1.0 amd64\nfoo 1.0-1 source\n",
        *mirror_args(mirror.url, "--snapshot-fallback"),
    )
    label = archive_label(mirror.url)
    assert [(r["status"], r["source"], r["path"]) for r in results] == [
        (
            DownloadStatus.OK,
            f"{mirror.url}/pool/main/f/foo/{name}",
            str(tmp_path.resolve() / "downloads" / kind / label / name),
        )
        for kind, name in [
            ("binaries", "foo_1.0_amd64.deb"),
            ("sources", "foo_1.0-1.dsc"),
            *(("sources", name) for name in FILES),
        ]
    ]
    assert not snapshot.lookups
    # the results of the mirror are not cached
    assert not (tmp_path / "downloads" / ".cache" / "debian-mirror").exists()


@pytest.mark.parametrize("fallback", [None, False, True])
@pytest.mark.parametrize("mirrored, on_snapshot", [(True, True), (False, True), (False, False)])
def test_snapshot_fallback(
    mirror, session, snapshot, tmp_path, monkeypatch, capsys, fallback, mirrored, on_snapshot
):
    """Only packages which are not in the mirror are resolved on snapshot.debian.org."""
    mirror.packages(mirror.publish_binary() if mirrored else binary("bar"))
    if on_snapshot:
        snapshot.publish(BinaryPackage("foo", "1.0", architecture="amd64"), {"foo.deb": b"foo\n"})
    flags = {None: [], False: ["--no-snapshot-fallback"], True: ["--snapshot-fallback"]}
    (result,) = run_download(
        tmp_path, monkeypatch, capsys, "foo 1.0 amd64\n", *mirror_args(mirror.url, *flags[fallback])
    )
    if mirrored:
        assert result["source"] == f"{mirror.url}/pool/main/f/foo/foo_1.0_amd64.deb"
    elif fallback and on_snapshot:
        assert result["source"] == (snapshot.root / "foo.deb").as_uri()
    else:
        assert result["status"] == DownloadStatus.NOT_FOUND
        assert "source" not in result
    assert snapshot.lookups == ([BINARY] if fallback and not mirrored else [])


@pytest.mark.parametrize(
    "pkglist",
    [
        pytest.param("foo 1.0 amd64\n", id="invalid-index"),
        pytest.param("foo 1.0 arm64\n", id="error-page"),
        pytest.param("foo 1.0-1 source\n", id="tampered-dsc"),
    ],
)
def test_mirror_errors_are_not_resolved_on_snapshot(
    mirror, session, snapshot, tmp_path, monkeypatch, capsys, pkglist
):
    mirror.write(PACKAGES + ".xz", b"not xz")
    mirror.packages("<html>Service unavailable</html>", arch="arm64", variant="")
    mirror.sources(mirror.publish_source())
    (mirror.root / "pool/main/f/foo/foo_1.0-1.dsc").write_bytes(b"tampered")
    snapshot.publish(BinaryPackage("foo", "1.0", architecture="amd64"), {"foo.deb": b"foo\n"})
    snapshot.publish(SourcePackage("foo", "1.0-1"), {"foo_1.0-1.dsc": b"dsc\n"})
    (result,) = run_download(
        tmp_path, monkeypatch, capsys, pkglist, *mirror_args(mirror.url, "--snapshot-fallback")
    )
    assert result["status"] == DownloadStatus.NOT_FOUND
    assert not snapshot.lookups


@pytest.mark.parametrize("status", [403, 500])
def test_access_errors_are_not_resolved_on_snapshot(
    session, snapshot, tmp_path, monkeypatch, capsys, status
):
    responses = HTTPResponses()
    responses.add(PACKAGES + ".xz", status=status)
    session.mount(f"{ROOT}/", responses)
    snapshot.publish(BinaryPackage("foo", "1.0", architecture="amd64"), {"foo.deb": b"foo\n"})
    (result,) = run_download(
        tmp_path, monkeypatch, capsys, "foo 1.0 amd64\n", *mirror_args(ROOT, "--snapshot-fallback")
    )
    assert result["status"] == DownloadStatus.NOT_FOUND
    assert not snapshot.lookups


def test_checksum_mismatch_is_resolved_on_snapshot(mirror, snapshot):
    """A package whose checksum differs from the one in the mirror is not found there."""
    mirror.packages(mirror.publish_binary())
    pkg = BinaryPackage("foo", "1.0", architecture="amd64", checksums=digest(b"foo\n"))
    snapshot.publish(pkg, {"foo.deb": b"foo\n"})
    sdl = sdlclient.SnapshotDataLake(session=mirror.session)
    resolver = FallbackResolver(mirror.resolver(), sdlclient.UpstreamResolver(sdl))
    (f,) = resolver._resolve_pkg(pkg)
    assert f.downloadurl == (snapshot.root / "foo.deb").as_uri()


def test_download_errors_are_not_resolved_on_snapshot(
    mirror, session, snapshot, tmp_path, monkeypatch, capsys
):
    """Only the resolution falls back, not the download of the files."""
    mirror.sources(mirror.publish_source())
    (mirror.root / "pool/main/f/foo/foo_1.0.orig.tar.xz").unlink()
    snapshot.publish(SourcePackage("foo", "1.0-1"), {"foo_1.0-1.dsc": b"dsc\n"})
    with pytest.raises(requests.HTTPError, match="404"):
        run_download(
            tmp_path,
            monkeypatch,
            capsys,
            "foo 1.0-1 source\n",
            *mirror_args(mirror.url, "--snapshot-fallback"),
        )
    assert not snapshot.lookups


@pytest.mark.parametrize(
    "args, pkglist",
    [
        (["--sources"], "foo 1.0 amd64\n"),
        (["--binaries"], "foo 1.0-1 source\n"),
        (["--skip-pkgs", "foo 1.0 amd64"], "foo 1.0 amd64\n"),
    ],
)
def test_skipped_packages_are_not_resolved(
    mirror, session, snapshot, tmp_path, monkeypatch, capsys, args, pkglist
):
    fallback = mirror_args(mirror.url, "--snapshot-fallback")
    assert not run_download(tmp_path, monkeypatch, capsys, pkglist, *fallback, *args)
    assert not mirror.requested
    assert not snapshot.lookups


def test_snapshot_cache(mirror, session, snapshot, tmp_path, monkeypatch, capsys):
    """
    The results of snapshot.debian.org are cached like the ones of the debian-snapshot
    resolver, but do not hide packages of the mirror.
    """
    snapshot.publish(BinaryPackage("foo", "1.0", architecture="amd64"), {"foo.deb": b"foo\n"})
    on_snapshot = (snapshot.root / "foo.deb").as_uri()
    for args in [mirror_args(mirror.url, "--snapshot-fallback")] * 2 + [[]]:
        (result,) = run_download(tmp_path, monkeypatch, capsys, "foo 1.0 amd64\n", *args)
        assert result["source"] == on_snapshot
    assert snapshot.lookups == [BINARY]

    mirror.packages(mirror.publish_binary())
    (result,) = run_download(
        tmp_path,
        monkeypatch,
        capsys,
        "foo 1.0 amd64\n",
        *mirror_args(mirror.url, "--snapshot-fallback"),
    )
    assert result["source"] == f"{mirror.url}/pool/main/f/foo/foo_1.0_amd64.deb"


def test_fallback_with_replaced_snapshot_resolver(
    mirror, session, snapshot, tmp_path, monkeypatch, capsys
):
    """The fallback is the built-in resolver, without the cache of a plugin replacing it."""
    pkg = BinaryPackage("foo", "1.0", architecture="amd64")
    snapshot.publish(pkg, {"foo.deb": b"foo\n"})
    plugin = mock.Mock(side_effect=AssertionError("plugin used"))
    monkeypatch.setitem(download.RESOLVERS, "debian-snapshot", plugin)
    cachedir = tmp_path / "downloads" / ".cache" / "debian-snapshot"
    cachedir.parent.mkdir(parents=True)
    plugin_file = RemoteFile({}, "foo.deb", "plugin", "https://plugin.example/foo.deb")
    PersistentResolverCache(cachedir).insert(pkg, [plugin_file])
    entries = {p: p.read_bytes() for p in cachedir.iterdir()}

    (result,) = run_download(
        tmp_path,
        monkeypatch,
        capsys,
        "foo 1.0 amd64\n",
        *mirror_args(mirror.url, "--snapshot-fallback"),
    )
    assert result["source"] == (snapshot.root / "foo.deb").as_uri()
    assert snapshot.lookups == [BINARY]
    plugin.assert_not_called()
    assert {p: p.read_bytes() for p in cachedir.iterdir()} == entries


def test_replaced_mirror_resolver(mirror, session, tmp_path, monkeypatch, capsys):
    """A plugin replacing the debian-mirror resolver is used like other plugins."""

    class Plugin(Resolver):
        def resolve(self, p):
            raise NotFoundError("not found by the plugin")

    plugin = Plugin()
    factory = mock.Mock(return_value=plugin)
    monkeypatch.setitem(download.RESOLVERS, "debian-mirror", factory)
    pkglist = "foo 1.0 amd64\n"
    (result,) = run_download(tmp_path, monkeypatch, capsys, pkglist, "--resolver", "debian-mirror")
    assert result["status"] == DownloadStatus.NOT_FOUND
    factory.assert_called_once_with(session)
    assert plugin.cache.cachedir == tmp_path / "downloads" / ".cache" / "debian-mirror"

    factory.reset_mock()
    with pytest.raises(ValueError, match="^--mirror-url, --mirror-suite, --mirror-component can"):
        run_download(tmp_path, monkeypatch, capsys, pkglist, *mirror_args(mirror.url))
    factory.assert_not_called()


def test_results_are_delivered_lazily(mirror, tmp_path):
    mirror.packages(mirror.publish_binary("foo"), mirror.publish_binary("bar"))
    downloader = PackageDownloader(tmp_path / "downloads", mirror.session)
    pkgs = [BinaryPackage(name, "1.0", architecture="amd64") for name in ("foo", "bar")]
    results = DownloadInput._download_packages(downloader, mirror.resolver(), pkgs, False, True)
    first = next(results)
    assert first.package.name == "foo"
    assert not (first.path.parent / "bar_1.0_amd64.deb").exists()
    assert [r.package.name for r in results] == ["bar"]
