# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from io import TextIOWrapper
from pathlib import Path
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType

from debsbom.bomreader.spdxbomreader import SpdxBomReader
from debsbom.bomwriter import BomWriter
from debsbom.merge.spdx import SpdxSbomMerger


def test_spdx_merge(tmpdir):
    # use two SBOMs that have the same package
    # but with different SPDXIDs, and one of the
    # packages being incomplete
    distro_name = "spdx-merge-package-merge"
    merger = SpdxSbomMerger(distro_name=distro_name)
    docs = []
    for sbom in ["tests/data/merge-full.spdx.json", "tests/data/merge-minimal.spdx.json"]:
        docs.append(SpdxBomReader.read_file(Path(sbom)))
    bom = merger.merge_sboms(iter(docs))

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
