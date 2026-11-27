# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

import json
import pytest
from collections import defaultdict
from debsbom.bomwriter.bomwriter import BomWriter
from debsbom.cli import setup_parser
from debsbom.commands.enrich import EnrichCmd
from debsbom.download.download import PackageDownloader
from debsbom.download.resolver import PersistentResolverCache
from debsbom.dpkg.package import BinaryPackage, SourcePackage
from debsbom.enrich import Enricher
from debsbom.resolver.resolver import PackageResolver
from debsbom.sbom import SBOMType
from debsbom.snapshot.client import SnapshotDataLake, UpstreamResolver
from debsbom.util.checksum import calculate_checksums
from debsbom.util.omnibor import artifact_id
from debsbom.util.swh import swh_id
from pathlib import Path
from test_apt_remote import PACKAGES, source
from test_mirror import BINARY, SOURCE, mirror, mirror_args, session, snapshot


@pytest.fixture
def enrich_sbom():
    def _enrich(tmpdir, http_session, sbom_type: SBOMType, base_filename: str):
        if sbom_type == SBOMType.SPDX:
            _spdx_tools = pytest.importorskip("spdx_tools")
            sbom_file = Path(f"tests/data/{base_filename}.spdx.json")
        elif sbom_type == SBOMType.CycloneDX:
            _cyclonedx = pytest.importorskip("cyclonedx")
            sbom_file = Path(f"tests/data/{base_filename}.cdx.json")
        else:
            raise RuntimeError("unknown SBOM type")

        pkg_resolver = PackageResolver.create(sbom_file)
        enricher = Enricher.create_from_reader(
            pkg_resolver,
            with_checksums=True,
            with_omniborid=True,
            with_swhid=True,
            with_download_loc=True,
        )

        incomplete = list(enricher.incomplete_components())
        pkgs = dict(
            map(
                lambda p: (pkg_resolver.create_package(p), p),
                filter(pkg_resolver.is_debian_pkg, incomplete),
            )
        )
        assert len(pkgs) == 1

        downloader = PackageDownloader(Path(tmpdir) / "downloads", session=http_session)

        sdl = SnapshotDataLake()
        dl_results = EnrichCmd._download_packages(
            downloader,
            UpstreamResolver(sdl, PersistentResolverCache(Path(tmpdir) / "downloads" / "cache")),
            list(pkgs.keys()),
            False,
            False,
        )

        pkg_paths = defaultdict(list)
        for res in dl_results:
            pkg_paths[res.package].append((res.path, res.source))

        for pkg, paths in pkg_paths.items():
            enricher.enrich_component(pkgs[pkg], paths)

        return enricher.document

    return _enrich


@pytest.mark.parametrize("sbom_type", list(SBOMType))
@pytest.mark.online
def test_enrich_binary(tmpdir, http_session, sbom_type, enrich_sbom):
    document = enrich_sbom(tmpdir, http_session, sbom_type, "enrich")
    if sbom_type == SBOMType.SPDX:
        assert any([p.name == "debsbom" for p in document.packages])
        for package in document.packages:
            if package.name == "debsbom":
                assert len(package.checksums) == 4
                assert any(
                    [
                        ref.reference_type == "gitoid"
                        and ref.locator
                        == "gitoid:blob:sha256:75576edffe8dddbacd14dc19be3db7b153830146ac46e1863e23c517a8b3fc54"
                        for ref in package.external_references
                    ]
                )
                assert any(
                    [
                        ref.reference_type == "swh"
                        and ref.locator == "swh:1:cnt:b6cce72c3dd4e742096d2a48b880c6243c4adda2"
                        for ref in package.external_references
                    ]
                )
                assert (
                    package.download_location
                    == "https://snapshot.debian.org/file/8f18211ccd48cb2a170e6ccd41612d4bb081d37d/debsbom_0.10.1-1~bpo13+1_all.deb"
                )
    elif sbom_type == SBOMType.CycloneDX:
        from cyclonedx.model import ExternalReference, ExternalReferenceType
        from cyclonedx.model.component import OmniborId, Swhid
        from sortedcontainers import SortedSet

        assert len(document.components) == 1
        component = document.components[0]
        assert len(component.hashes) == 4
        assert component.omnibor_ids == SortedSet(
            [
                OmniborId(
                    "gitoid:blob:sha256:75576edffe8dddbacd14dc19be3db7b153830146ac46e1863e23c517a8b3fc54"
                )
            ]
        )
        assert component.swhids == SortedSet(
            [Swhid("swh:1:cnt:b6cce72c3dd4e742096d2a48b880c6243c4adda2")]
        )
        assert any(
            [
                ref.type == ExternalReferenceType.DISTRIBUTION
                and ref.url
                == "https://snapshot.debian.org/file/8f18211ccd48cb2a170e6ccd41612d4bb081d37d/debsbom_0.10.1-1~bpo13+1_all.deb"
                for ref in component.external_references
            ]
        )


@pytest.mark.parametrize("sbom_type", list(SBOMType))
@pytest.mark.online
def test_enrich_source(tmpdir, http_session, sbom_type, enrich_sbom):
    document = enrich_sbom(tmpdir, http_session, sbom_type, "enrich-src")
    if sbom_type == SBOMType.SPDX:
        assert any([p.name == "debsbom" for p in document.packages])
        for package in document.packages:
            if package.name == "debsbom":
                assert len(package.checksums) == 4
                assert any(
                    [
                        ref.reference_type == "gitoid"
                        and ref.locator
                        == "gitoid:blob:sha256:713eb660998d709f05295550acfce588d8d5c3a2035880619ac9414e789ba8f5"
                        for ref in package.external_references
                    ]
                )
                assert any(
                    [
                        ref.reference_type == "swh"
                        and ref.locator == "swh:1:cnt:48a5dfc43c7f55815ec43f882f94bc66e2c1b012"
                        for ref in package.external_references
                    ]
                )
                assert (
                    package.download_location
                    == "https://snapshot.debian.org/file/ce4824c356e157da770f9b20ba57676052ce92ce/debsbom_0.10.1-1~bpo13+1.dsc"
                )
    elif sbom_type == SBOMType.CycloneDX:
        from cyclonedx.model import ExternalReference, ExternalReferenceType
        from cyclonedx.model.component import OmniborId, Swhid
        from sortedcontainers import SortedSet

        assert len(document.components) == 1
        component = document.components[0]
        assert len(component.hashes) == 4
        assert component.omnibor_ids == SortedSet(
            [
                OmniborId(
                    "gitoid:blob:sha256:713eb660998d709f05295550acfce588d8d5c3a2035880619ac9414e789ba8f5"
                )
            ]
        )
        assert component.swhids == SortedSet(
            [Swhid("swh:1:cnt:48a5dfc43c7f55815ec43f882f94bc66e2c1b012")]
        )
        assert any(
            [
                ref.type == ExternalReferenceType.DISTRIBUTION
                and ref.url
                == "https://snapshot.debian.org/file/ce4824c356e157da770f9b20ba57676052ce92ce/debsbom_0.10.1-1~bpo13+1.dsc"
                for ref in component.external_references
            ]
        )


def write_sbom(path: Path, sbom_type: SBOMType, packages) -> Path:
    if sbom_type == SBOMType.SPDX:
        pytest.importorskip("spdx_tools")
        from debsbom.generate.spdx import spdx_bom as make_bom
    else:
        pytest.importorskip("cyclonedx")
        from debsbom.generate.cdx import cyclonedx_bom as make_bom
    BomWriter.create(sbom_type).write_to_file(
        make_bom(set(packages), "debian", "amd64"), path, validate=False
    )
    return path


def enriched_packages(path: Path, sbom_type: SBOMType) -> dict[str, dict]:
    """The checksums, download locations and persistent IDs of the packages by PURL."""
    document = json.loads(path.read_text())
    packages = {}
    if sbom_type == SBOMType.CycloneDX:
        for c in document["components"]:
            packages[c["purl"]] = {
                "checksums": sorted(h["content"] for h in c.get("hashes", [])),
                "locations": [
                    r["url"] for r in c.get("externalReferences", []) if r["type"] == "distribution"
                ],
                "ids": sorted(c.get("omniborId", []) + c.get("swhid", [])),
            }
        return packages
    for p in document["packages"]:
        refs = p.get("externalRefs", [])
        for purl in (r["referenceLocator"] for r in refs if r["referenceType"] == "purl"):
            location = p["downloadLocation"]
            packages[purl] = {
                "checksums": sorted(c["checksumValue"] for c in p.get("checksums", [])),
                "locations": [location] if location != "NOASSERTION" else [],
                "ids": sorted(
                    r["referenceLocator"] for r in refs if r["referenceType"] in ("gitoid", "swh")
                ),
            }
    return packages


def enriched_from(path: Path, url: str) -> dict:
    return {
        "checksums": sorted(calculate_checksums(path).values()),
        "locations": [url],
        "ids": sorted([artifact_id(path), swh_id(path)]),
    }


NOT_ENRICHED = {"checksums": [], "locations": [], "ids": []}


def run_enrich(tmp_path, sbom_type: SBOMType, *args) -> dict[str, dict]:
    """Enrich an SBOM with a binary and a source package and return the packages."""
    packages = [BinaryPackage("foo", "1.0", architecture="amd64"), SourcePackage("foo", "1.0-1")]
    bomin = write_sbom(tmp_path / f"input.{sbom_type}.json", sbom_type, packages)
    outdir = str(tmp_path / "downloads")
    bomout = str(tmp_path / "enriched")
    EnrichCmd.run(
        setup_parser().parse_args(["enrich", "--outdir", outdir, *args, str(bomin), bomout])
    )
    return enriched_packages(tmp_path / f"enriched.{sbom_type}.json", sbom_type)


@pytest.mark.parametrize("sbom_type", list(SBOMType))
def test_enrich_from_mirror(mirror, session, snapshot, tmp_path, sbom_type):
    mirror.packages(mirror.publish_binary())
    mirror.sources(mirror.publish_source())
    packages = run_enrich(tmp_path, sbom_type, *mirror_args(mirror.url, "--snapshot-fallback"))
    pool = "pool/main/f/foo"
    assert packages[BINARY] == enriched_from(
        mirror.root / pool / "foo_1.0_amd64.deb", f"{mirror.url}/{pool}/foo_1.0_amd64.deb"
    )
    assert packages[SOURCE] == enriched_from(
        mirror.root / pool / "foo_1.0-1.dsc", f"{mirror.url}/{pool}/foo_1.0-1.dsc"
    )
    assert not snapshot.lookups


@pytest.mark.parametrize("fallback", [None, False, True])
@pytest.mark.parametrize("sbom_type", list(SBOMType))
def test_enrich_with_snapshot_fallback(mirror, session, snapshot, tmp_path, sbom_type, fallback):
    """Only packages which are not in the mirror are resolved on snapshot.debian.org."""
    mirror.packages(mirror.publish_binary())
    mirror.sources(source("bar"))
    dsc = snapshot.root / "foo_1.0-1.dsc"
    snapshot.publish(SourcePackage("foo", "1.0-1"), {dsc.name: b"dsc\n"})
    flags = {None: [], False: ["--no-snapshot-fallback"], True: ["--snapshot-fallback"]}
    packages = run_enrich(tmp_path, sbom_type, *mirror_args(mirror.url, *flags[fallback]))
    pool = "pool/main/f/foo"
    assert packages[BINARY] == enriched_from(
        mirror.root / pool / "foo_1.0_amd64.deb", f"{mirror.url}/{pool}/foo_1.0_amd64.deb"
    )
    if fallback:
        assert packages[SOURCE] == enriched_from(dsc, dsc.as_uri())
        assert snapshot.lookups == [SOURCE]
    else:
        assert packages[SOURCE] == NOT_ENRICHED
        assert not snapshot.lookups


@pytest.mark.parametrize("sbom_type", list(SBOMType))
def test_enrich_mirror_errors_are_not_resolved_on_snapshot(
    mirror, session, snapshot, tmp_path, sbom_type
):
    mirror.write(PACKAGES + ".xz", b"not xz")
    mirror.sources(mirror.publish_source())
    (mirror.root / "pool/main/f/foo/foo_1.0-1.dsc").write_bytes(b"tampered")
    snapshot.publish(BinaryPackage("foo", "1.0", architecture="amd64"), {"foo.deb": b"foo\n"})
    snapshot.publish(SourcePackage("foo", "1.0-1"), {"foo_1.0-1.dsc": b"dsc\n"})
    packages = run_enrich(tmp_path, sbom_type, *mirror_args(mirror.url, "--snapshot-fallback"))
    assert packages[BINARY] == packages[SOURCE] == NOT_ENRICHED
    assert not snapshot.lookups


@pytest.mark.parametrize("sbom_type", list(SBOMType))
def test_enrich_without_work(mirror, session, snapshot, tmp_path, sbom_type):
    """Without anything to enrich, no package is resolved."""
    disabled = ["--no-checksums", "--no-download-location", "--no-omnibor-id", "--no-swh-id"]
    args = mirror_args(mirror.url, "--snapshot-fallback", *disabled)
    packages = run_enrich(tmp_path, sbom_type, *args)
    assert packages[BINARY] == packages[SOURCE] == NOT_ENRICHED
    assert not mirror.requested
    assert not snapshot.lookups
