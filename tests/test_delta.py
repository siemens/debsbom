# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from debsbom.bomwriter.bomwriter import BomWriter
from debsbom.generate import SBOMType
import json
from pathlib import Path
import pytest

# The base SBOM was generated with:
#   cat <<EOF | debsbom generate --from-pkglist
#   htop 3.4.1-5 amd64
#   bash 5.2.37-2+b7 amd64
#   btop 1.3.2-0.1 amd64
#   dash 0.5.12-12 amd64
#   EOF
#
# The target SBOM was generated with:
#   cat <<EOF | debsbom generate --from-pkglist
#   bash 5.2.37-2+b7 amd64
#   btop 1.3.2-0.1 amd64
#   dash 0.5.12-12 amd64
#   dhcpcd-base 1:10.1.0-11+deb13u2 amd64
#   vim 2:9.1.1230-2 amd64
#   EOF
#
# Run the delta function on the base and target SBOMs.
# Include only packages present in the target but not in the base SBOM.
# Preserve their relationships and add DISTRIBUTION relationships.
# Verify that extra packages and relationships appear correctly.


def test_spdx_delta(tmpdir):
    _spdx_tools = pytest.importorskip("spdx_tools")

    from debsbom.bomreader.spdxbomreader import SpdxBomFileReader
    from debsbom.delta.spdx import SpdxDeltaGenerator

    distro_name = "spdx-delta-generator"
    delta_generator = SpdxDeltaGenerator(distro_name=distro_name)
    docs = []
    for sbom in ["tests/data/delta-base.spdx.json", "tests/data/delta-target.spdx.json"]:
        docs.append(SpdxBomFileReader(Path(sbom)).read())
    bom = delta_generator.delta(base_sbom=docs[0], target_sbom=docs[1])

    outdir = Path(tmpdir)
    bomfile = outdir / "extras.spdx.json"
    BomWriter.create(SBOMType.SPDX).write_to_file(bom, bomfile, validate=True)

    with open(bomfile) as file:
        spdx_json = json.loads(file.read())
        relationships = spdx_json["relationships"]
        assert {
            "spdxElementId": "SPDXRef-Debian",
            "relationshipType": "PACKAGE_OF",
            "relatedSpdxElement": f"SPDXRef-{distro_name}",
        } in relationships
        assert {
            "spdxElementId": "SPDXRef-dhcpcd-1.10.1.0-11.deb13u2-srcpkg",
            "relationshipType": "GENERATES",
            "relatedSpdxElement": "SPDXRef-dhcpcd-base-amd64",
        } in relationships
        assert {
            "spdxElementId": "SPDXRef-vim-2.9.1.1230-2-srcpkg",
            "relationshipType": "GENERATES",
            "relatedSpdxElement": "SPDXRef-vim-amd64",
        } in relationships
        assert {
            "spdxElementId": "SPDXRef-htop-3.4.1-5-srcpkg",
            "relationshipType": "GENERATES",
            "relatedSpdxElement": "SPDXRef-htop-amd64",
        } not in relationships


def test_cdx_delta(tmpdir):
    _cyclonedx = pytest.importorskip("cyclonedx")

    from debsbom.bomreader.cdxbomreader import CdxBomFileReader
    from debsbom.delta.cdx import CdxDeltaGenerator

    distro_name = "cdx-delta-generator"
    delta_generator = CdxDeltaGenerator(distro_name=distro_name)
    docs = []
    for sbom in ["tests/data/delta-base.cdx.json", "tests/data/delta-target.cdx.json"]:
        docs.append(CdxBomFileReader(Path(sbom)).read())
    bom = delta_generator.delta(base_sbom=docs[0], target_sbom=docs[1])

    outdir = Path(tmpdir)
    bomfile = outdir / "extras.cdx.json"
    BomWriter.create(SBOMType.CycloneDX).write_to_file(bom, bomfile, validate=True)

    with open(bomfile) as file:
        cdx_json = json.loads(file.read())
        deps = cdx_json["dependencies"]
        assert {
            "dependsOn": ["CDXRef-Debian"],
            "ref": f"CDXRef-{distro_name}",
        } in deps
        assert {
            "dependsOn": ["pkg:deb/debian/dhcpcd@1:10.1.0-11%2Bdeb13u2?arch=source"],
            "ref": "pkg:deb/debian/dhcpcd-base@1:10.1.0-11%2Bdeb13u2?arch=amd64",
        } in deps
        assert {
            "dependsOn": ["pkg:deb/debian/vim@2:9.1.1230-2?arch=source"],
            "ref": "pkg:deb/debian/vim@2:9.1.1230-2?arch=amd64",
        } in deps
        assert {
            "dependsOn": ["pkg:deb/debian/htop@3.4.1-5?arch=source"],
            "ref": "pkg:deb/debian/htop@3.4.1-5?arch=amd64",
        } not in deps
