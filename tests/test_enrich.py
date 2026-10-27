# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

import pytest
from collections import defaultdict
from debsbom.commands.enrich import EnrichCmd
from debsbom.download.download import PackageDownloader
from debsbom.download.resolver import PersistentResolverCache
from debsbom.enrich import Enricher
from debsbom.resolver.resolver import PackageResolver
from debsbom.sbom import SBOMType
from debsbom.snapshot.client import SnapshotDataLake, UpstreamResolver
from pathlib import Path


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
