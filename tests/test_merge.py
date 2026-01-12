# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from pathlib import Path
import pytest

from debsbom.util.checksum import ChecksumMismatchError


def test_spdx_merge():
    _spdx_tools = pytest.importorskip("spdx_tools")

    from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
    from debsbom.bomreader.spdxbomreader import SpdxBomFileReader
    from debsbom.merge.spdx import SpdxSbomMerger

    # The test files are created with
    # `echo "buildah 1.28.2+ds1-3+deb12u1+b1 amd64" | debsbom -v generate --distro-name <full|minimal> --from-pkglist`
    # once with apt-cache available and once without ('full' is with cache, 'minimal' without).
    # Then the bom reference ID is was edited in the minimal SBOMs for the buildah component/package
    # to test if the ID merging works
    distro_name = "spdx-merge-package-merge"
    merger = SpdxSbomMerger(distro_name=distro_name)
    docs = []
    for sbom in ["tests/data/merge-full.spdx.json", "tests/data/merge-minimal.spdx.json"]:
        docs.append(SpdxBomFileReader(Path(sbom)).read())
    bom = merger.merge(docs)

    assert (
        Relationship(
            spdx_element_id="SPDXRef-minimal",
            relationship_type=RelationshipType.PACKAGE_OF,
            related_spdx_element_id=f"SPDXRef-{distro_name}",
        )
        in bom.relationships
    )
    assert (
        Relationship(
            spdx_element_id="SPDXRef-full",
            relationship_type=RelationshipType.PACKAGE_OF,
            related_spdx_element_id=f"SPDXRef-{distro_name}",
        )
        in bom.relationships
    )
    assert (
        Relationship(
            spdx_element_id="SPDXRef-buildah-amd64",
            relationship_type=RelationshipType.PACKAGE_OF,
            related_spdx_element_id="SPDXRef-minimal",
        )
        in bom.relationships
    )
    assert (
        Relationship(
            spdx_element_id="SPDXRef-buildah-amd64",
            relationship_type=RelationshipType.PACKAGE_OF,
            related_spdx_element_id="SPDXRef-full",
        )
        in bom.relationships
    )
    assert (
        Relationship(
            spdx_element_id="SPDXRef-buildah-amd64-different",
            relationship_type=RelationshipType.PACKAGE_OF,
            related_spdx_element_id="SPDXRef-minimal",
        )
        not in bom.relationships
    )


def test_cdx_merge():
    _cyclonedx = pytest.importorskip("cyclonedx")

    from cyclonedx.model.dependency import Dependency
    from debsbom.bomreader.cdxbomreader import CdxBomFileReader
    from debsbom.merge.cdx import CdxSbomMerger

    # The test files are created with
    # `echo "buildah 1.28.2+ds1-3+deb12u1+b1 amd64" | debsbom -v generate --distro-name <full|minimal> --from-pkglist`
    # once with apt-cache available and once without ('full' is with cache, 'minimal' without).
    # Then the bom reference ID is was edited in the minimal SBOMs for the buildah component/package
    # to test if the ID merging works
    distro_name = "cdx-merge-package-merge"
    merger = CdxSbomMerger(distro_name=distro_name)
    docs = []
    for sbom in ["tests/data/merge-full.cdx.json", "tests/data/merge-minimal.cdx.json"]:
        docs.append(CdxBomFileReader(Path(sbom)).read())
    bom = merger.merge(docs)

    distro_bom_ref = bom.metadata.component.bom_ref

    for component in bom.components:
        if component.name == "full":
            bom_ref_full = component.bom_ref
        elif component.name == "minimal":
            bom_ref_minimal = component.bom_ref
        elif component.name == "buildah":
            bom_ref_buildah = component.bom_ref

    found_distro_ref = False
    found_full_ref = False
    found_minimal_ref = False
    for dependency in bom.dependencies:
        if dependency.ref == distro_bom_ref:
            assert Dependency(ref=bom_ref_full) in dependency.dependencies
            assert Dependency(ref=bom_ref_minimal) in dependency.dependencies
            found_distro_ref = True
        if dependency.ref == bom_ref_full:
            assert Dependency(ref=bom_ref_buildah) in dependency.dependencies
            found_full_ref = True
        if dependency.ref == bom_ref_minimal:
            assert Dependency(ref=bom_ref_buildah) in dependency.dependencies
            found_minimal_ref = True

    assert found_distro_ref
    assert found_full_ref
    assert found_minimal_ref


def test_cdx_hash_merge():
    _cyclonedx = pytest.importorskip("cyclonedx")

    from debsbom.bomreader.cdxbomreader import CdxBomFileReader
    from debsbom.merge.cdx import CdxSbomMerger

    distro_name = "cdx-merge-hash-merge"
    merger = CdxSbomMerger(distro_name=distro_name)
    docs = []
    for sbom in [
        "tests/data/checksum-merge-md5.cdx.json",
        "tests/data/checksum-merge-sha256.cdx.json",
    ]:
        docs.append(CdxBomFileReader(Path(sbom)).read())
    bom = merger.merge(docs)

    component = next(iter(bom.components))
    assert len(component.hashes) == 2


def test_spdx_checksum_merge():
    _spdx_tools = pytest.importorskip("spdx_tools")

    from debsbom.bomreader.spdxbomreader import SpdxBomFileReader
    from debsbom.merge.spdx import SpdxSbomMerger

    distro_name = "spx-merge-checksum-merge"
    merger = SpdxSbomMerger(distro_name=distro_name)
    docs = []
    for sbom in [
        "tests/data/checksum-merge-md5.spdx.json",
        "tests/data/checksum-merge-sha256.spdx.json",
    ]:
        docs.append(SpdxBomFileReader(Path(sbom)).read())
    bom = merger.merge(docs)

    package = next(iter(filter(lambda p: p.name == "example-pkg", bom.packages)))
    assert len(package.checksums) == 2


def test_cdx_bad_checksum():
    _cyclonedx = pytest.importorskip("cyclonedx")

    from debsbom.bomreader.cdxbomreader import CdxBomFileReader
    from debsbom.merge.cdx import CdxSbomMerger

    distro_name = "cdx-merge-hash-merge"
    merger = CdxSbomMerger(distro_name=distro_name)
    docs = []
    for sbom in [
        "tests/data/checksum-merge-md5.cdx.json",
        "tests/data/checksum-merge-bad.cdx.json",
    ]:
        docs.append(CdxBomFileReader(Path(sbom)).read())
    with pytest.raises(ChecksumMismatchError):
        _bom = merger.merge(docs)


def test_spdx_bad_checksum():
    _spdx_tools = pytest.importorskip("spdx_tools")

    from debsbom.bomreader.spdxbomreader import SpdxBomFileReader
    from debsbom.merge.spdx import SpdxSbomMerger

    distro_name = "cdx-merge-checksum-bad"
    merger = SpdxSbomMerger(distro_name=distro_name)
    docs = []
    for sbom in [
        "tests/data/checksum-merge-md5.spdx.json",
        "tests/data/checksum-merge-bad.spdx.json",
    ]:
        docs.append(SpdxBomFileReader(Path(sbom)).read())

    with pytest.raises(ChecksumMismatchError):
        _bom = merger.merge(docs)
