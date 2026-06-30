# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from debsbom.bomwriter.bomwriter import BomWriter
from debsbom.graph.walker import PackageRepr
from debsbom.sbom import SBOMType
import json
from pathlib import Path
from packageurl import PackageURL
import pytest
from urllib.parse import unquote

# The filter SBOM was generated using:
# cat <<EOF | debsbom generate --from-pkglist
# > accountsservice 23.13.9-7 amd64
# > base-files 13.8+deb13u3 amd64
# > dash 0.5.12-12 amd64
# > libxtst6 2:1.2.3-1.1 amd64
# > x11vnc 0.9.16-9 amd64
# > EOF

# The package-filter SBOM was generated using this package list:
# pkg:deb/debian/debsbom@0.8.1-1~bpo13+1?arch=all
# pkg:deb/debian/debsbom@0.8.1-1~bpo13+1?arch=source
# pkg:deb/debian/python3-cyclonedx-lib@9.1.0-2?arch=all
# pkg:deb/debian/cyclonedx-python-lib@9.1.0-2?arch=source
# pkg:deb/debian/python3-py-serializable@2.0.0-2?arch=all
# pkg:deb/debian/py-serializable@2.0.0-2?arch=source
# pkg:deb/debian/python3-packageurl@0.16.0-2?arch=all
# pkg:deb/debian/python-packageurl@0.16.0-2?arch=source
# pkg:deb/debian/python3-license-expression@30.4.1-1?arch=all
# pkg:deb/debian/python-license-expression@30.4.1-1?arch=source
# pkg:deb/debian/python3-sortedcontainers@2.4.0-2?arch=all
# pkg:deb/debian/sortedcontainers@2.4.0-2?arch=source
# pkg:deb/debian/dash@0.5.12-12?arch=amd64
# pkg:deb/debian/dash@0.5.12-12?arch=source
# pkg:deb/debian/debianutils@5.23.2?arch=amd64
# pkg:deb/debian/debianutils@5.23.2?arch=source


def test_spdx_filter_sources(tmpdir):
    _spdx_tools = pytest.importorskip("spdx_tools")

    from debsbom.resolver import PackageResolver
    from debsbom.commands.input import SourceBinaryInput
    from debsbom.filter.spdx import SpdxSbomFilter

    resolver = PackageResolver.create(Path("tests/data/filter.spdx.json"))
    SpdxSbomFilter.source_pkgs(resolver.document)
    outdir = Path(tmpdir)
    bomfile = outdir / "filtered_sources.spdx.json"
    BomWriter.create(SBOMType.SPDX).write_to_file(resolver.document, bomfile, validate=True)

    with open(bomfile) as file:
        spdx_json = json.loads(file.read())

    packages = spdx_json["packages"]
    relationships = spdx_json["relationships"]
    assert any("srcpkg" in pkg["SPDXID"] for pkg in packages)
    assert all(pkg["SPDXID"] == "SPDXRef-Debian" or "srcpkg" for pkg in packages)
    assert any(rel["relationshipType"] == "DESCRIBES" for rel in relationships)
    assert any(rel["relationshipType"] == "DEPENDS_ON" for rel in relationships)


def test_spdx_filter_binaries(tmpdir):
    _spdx_tools = pytest.importorskip("spdx_tools")

    from debsbom.resolver import PackageResolver
    from debsbom.commands.input import SourceBinaryInput
    from debsbom.filter.spdx import SpdxSbomFilter

    resolver = PackageResolver.create(Path("tests/data/filter.spdx.json"))
    SpdxSbomFilter.binary_pkgs(resolver.document)
    outdir = Path(tmpdir)
    bomfile = outdir / "filtered_binaries.spdx.json"
    BomWriter.create(SBOMType.SPDX).write_to_file(resolver.document, bomfile, validate=True)

    with open(bomfile) as file:
        spdx_json = json.loads(file.read())

    packages = spdx_json["packages"]
    relationships = spdx_json.get("relationships", [])
    assert all(
        pkg["SPDXID"] == "SPDXRef-Debian" or "srcpkg" not in pkg["SPDXID"] for pkg in packages
    )
    assert any(
        rel["spdxElementId"] == "SPDXRef-DOCUMENT" and rel["relationshipType"] == "DESCRIBES"
        for rel in relationships
    )


def test_cdx_filter_sources(tmpdir):
    _cyclonedx = pytest.importorskip("cyclonedx")

    from debsbom.resolver import PackageResolver
    from debsbom.commands.input import SourceBinaryInput
    from debsbom.filter.cdx import CdxSbomFilter

    resolver = PackageResolver.create(Path("tests/data/filter.cdx.json"))
    CdxSbomFilter.source_pkgs(resolver.document)
    outdir = Path(tmpdir)
    bomfile = outdir / "filtered_sources.cdx.json"
    BomWriter.create(SBOMType.CycloneDX).write_to_file(resolver.document, bomfile, validate=False)

    with open(bomfile) as file:
        cdx_json = json.loads(file.read())

    components = cdx_json["components"]
    relationships = cdx_json["dependencies"]
    assert all("arch=source" in comp["bom-ref"] for comp in components)


def test_cdx_filter_binaries(tmpdir):
    _cyclonedx = pytest.importorskip("cyclonedx")

    from debsbom.resolver import PackageResolver
    from debsbom.commands.input import SourceBinaryInput
    from debsbom.filter.cdx import CdxSbomFilter

    resolver = PackageResolver.create(Path("tests/data/filter.cdx.json"))
    CdxSbomFilter.binary_pkgs(resolver.document)
    outdir = Path(tmpdir)
    bomfile = outdir / "filtered_binaries.cdx.json"
    BomWriter.create(SBOMType.CycloneDX).write_to_file(resolver.document, bomfile, validate=False)

    with open(bomfile) as file:
        cdx_json = json.loads(file.read())

    components = cdx_json["components"]
    relationships = cdx_json["dependencies"]
    assert all("arch=source" not in comp["bom-ref"] for comp in components)


EXPECTED_PURLS = [
    "pkg:deb/debian/debsbom@0.8.1-1~bpo13+1?arch=all",
    "pkg:deb/debian/debsbom@0.8.1-1~bpo13+1?arch=source",
    "pkg:deb/debian/python3-cyclonedx-lib@9.1.0-2?arch=all",
    "pkg:deb/debian/cyclonedx-python-lib@9.1.0-2?arch=source",
    "pkg:deb/debian/python3-py-serializable@2.0.0-2?arch=all",
    "pkg:deb/debian/py-serializable@2.0.0-2?arch=source",
    "pkg:deb/debian/python3-packageurl@0.16.0-2?arch=all",
    "pkg:deb/debian/python-packageurl@0.16.0-2?arch=source",
    "pkg:deb/debian/python3-license-expression@30.4.1-1?arch=all",
    "pkg:deb/debian/python-license-expression@30.4.1-1?arch=source",
    "pkg:deb/debian/python3-sortedcontainers@2.4.0-2?arch=all",
    "pkg:deb/debian/sortedcontainers@2.4.0-2?arch=source",
]


def test_spdx_filter_packages(tmpdir):
    _spdx_tools = pytest.importorskip("spdx_tools")

    from debsbom.resolver import PackageResolver
    from debsbom.graph.spdx import SpdxGraphWalker
    from debsbom.filter.spdx import SpdxSbomFilter
    from spdx_tools.spdx.model.relationship import Relationship, RelationshipType

    resolver = PackageResolver.create(Path("tests/data/package-filter.spdx.json"))
    walker = SpdxGraphWalker(resolver.document)
    pkgs = walker.descendants(
        PackageURL.from_string("pkg:deb/debian/debsbom@0.8.1-1~bpo13+1?arch=all")
    )
    SpdxSbomFilter.packages(
        resolver.document, PackageRepr(name="debsbom", ref="SPDXRef-debsbom-all"), list(pkgs)
    )
    outdir = Path(tmpdir)
    bomfile = outdir / "filtered_packages.spdx.json"
    BomWriter.create(SBOMType.SPDX).write_to_file(resolver.document, bomfile, validate=True)

    with open(bomfile) as file:
        spdx_json = json.loads(file.read())

    packages = spdx_json["packages"]
    relationships = spdx_json.get("relationships", [])
    for pkg in packages:
        if pkg["SPDXID"] == "SPDXRef-Debian":
            continue
        assert pkg["SPDXID"] != "SPDXRef-dash-amd64"
        assert pkg["SPDXID"] != "SPDXRef-debianutils-amd64"
        for external_reference in pkg["externalRefs"]:
            if external_reference["referenceType"] == "purl":
                assert unquote(external_reference["referenceLocator"]) in EXPECTED_PURLS

    assert {
        "spdxElementId": "SPDXRef-debsbom-all",
        "relationshipType": "PACKAGE_OF",
        "relatedSpdxElement": "SPDXRef-Debian",
    } in relationships
    assert {
        "spdxElementId": "SPDXRef-debsbom-all",
        "relationshipType": "DEPENDS_ON",
        "relatedSpdxElement": "SPDXRef-python3-cyclonedx-lib-all",
        "comment": "recommends",
    } in relationships
    assert {
        "spdxElementId": "SPDXRef-debsbom-all",
        "relationshipType": "DEPENDS_ON",
        "relatedSpdxElement": "SPDXRef-python3-packageurl-all",
    } in relationships
    assert {
        "spdxElementId": "SPDXRef-debsbom-all",
        "relationshipType": "DEPENDS_ON",
        "relatedSpdxElement": "SPDXRef-python3-license-expression-all",
    } in relationships
    assert {
        "spdxElementId": "SPDXRef-debsbom-0.8.1-1.bpo13.1-srcpkg",
        "relationshipType": "GENERATES",
        "relatedSpdxElement": "SPDXRef-debsbom-all",
    } in relationships
    assert {
        "spdxElementId": "SPDXRef-python3-cyclonedx-lib-all",
        "relationshipType": "DEPENDS_ON",
        "relatedSpdxElement": "SPDXRef-python3-py-serializable-all",
    } in relationships
    assert {
        "spdxElementId": "SPDXRef-python3-cyclonedx-lib-all",
        "relationshipType": "DEPENDS_ON",
        "relatedSpdxElement": "SPDXRef-python3-license-expression-all",
    } in relationships
    assert {
        "spdxElementId": "SPDXRef-python3-cyclonedx-lib-all",
        "relationshipType": "DEPENDS_ON",
        "relatedSpdxElement": "SPDXRef-python3-sortedcontainers-all",
    } in relationships
    assert {
        "spdxElementId": "SPDXRef-debsbom-0.8.1-1.bpo13.1-srcpkg",
        "relationshipType": "GENERATES",
        "relatedSpdxElement": "SPDXRef-debsbom-all",
    } in relationships
    assert {
        "spdxElementId": "SPDXRef-cyclonedx-python-lib-9.1.0-2-srcpkg",
        "relationshipType": "GENERATES",
        "relatedSpdxElement": "SPDXRef-python3-cyclonedx-lib-all",
    } in relationships
    assert {
        "spdxElementId": "SPDXRef-python-license-expression-30.4.1-1-srcpkg",
        "relationshipType": "GENERATES",
        "relatedSpdxElement": "SPDXRef-python3-license-expression-all",
    } in relationships
    assert {
        "spdxElementId": "SPDXRef-sortedcontainers-2.4.0-2-srcpkg",
        "relationshipType": "GENERATES",
        "relatedSpdxElement": "SPDXRef-python3-sortedcontainers-all",
    } in relationships
    assert {
        "spdxElementId": "SPDXRef-python-packageurl-0.16.0-2-srcpkg",
        "relationshipType": "GENERATES",
        "relatedSpdxElement": "SPDXRef-python3-packageurl-all",
    } in relationships
    assert {
        "spdxElementId": "SPDXRef-py-serializable-2.0.0-2-srcpkg",
        "relationshipType": "GENERATES",
        "relatedSpdxElement": "SPDXRef-python3-py-serializable-all",
    } in relationships


def test_cdx_filter_packages(tmpdir):
    _cyclonedx = pytest.importorskip("cyclonedx")

    from debsbom.resolver import PackageResolver
    from debsbom.graph.cdx import CdxGraphWalker
    from debsbom.filter.cdx import CdxSbomFilter

    resolver = PackageResolver.create(Path("tests/data/package-filter.cdx.json"))
    walker = CdxGraphWalker(resolver.document)
    purl = PackageURL.from_string("pkg:deb/debian/debsbom@0.8.1-1~bpo13+1?arch=all")
    pkgs = walker.descendants(purl)
    CdxSbomFilter.packages(
        resolver.document, PackageRepr(name="debsbom", ref=str(purl)), list(pkgs)
    )
    outdir = Path(tmpdir)
    bomfile = outdir / "filtered_packages.cdx.json"
    BomWriter.create(SBOMType.CycloneDX).write_to_file(resolver.document, bomfile, validate=False)

    with open(bomfile) as file:
        cdx_json = json.loads(file.read())

    components = cdx_json["components"]
    dependencies = cdx_json["dependencies"]

    assert all([unquote(component["purl"]) in EXPECTED_PURLS for component in components])
    assert all(
        [
            unquote(component["purl"]) != "pkg:deb/debian/dash@0.5.12-12?arch=amd64"
            for component in components
        ]
    )
    assert all(
        [
            unquote(component["purl"]) != "pkg:deb/debian/debianutils@5.23.2?arch=amd64"
            for component in components
        ]
    )
    assert {
        "dependsOn": [
            "pkg:deb/debian/debsbom@0.8.1-1~bpo13%2B1?arch=source",
            "pkg:deb/debian/python3-cyclonedx-lib@9.1.0-2?arch=all",
            "pkg:deb/debian/python3-license-expression@30.4.1-1?arch=all",
            "pkg:deb/debian/python3-packageurl@0.16.0-2?arch=all",
        ],
        "ref": "pkg:deb/debian/debsbom@0.8.1-1~bpo13%2B1?arch=all",
    } in dependencies
    assert {
        "dependsOn": [
            "pkg:deb/debian/cyclonedx-python-lib@9.1.0-2?arch=source",
            "pkg:deb/debian/python3-license-expression@30.4.1-1?arch=all",
            "pkg:deb/debian/python3-packageurl@0.16.0-2?arch=all",
            "pkg:deb/debian/python3-py-serializable@2.0.0-2?arch=all",
            "pkg:deb/debian/python3-sortedcontainers@2.4.0-2?arch=all",
        ],
        "ref": "pkg:deb/debian/python3-cyclonedx-lib@9.1.0-2?arch=all",
    } in dependencies
    assert {
        "dependsOn": ["pkg:deb/debian/python-license-expression@30.4.1-1?arch=source"],
        "ref": "pkg:deb/debian/python3-license-expression@30.4.1-1?arch=all",
    } in dependencies
    assert {
        "dependsOn": ["pkg:deb/debian/python-packageurl@0.16.0-2?arch=source"],
        "ref": "pkg:deb/debian/python3-packageurl@0.16.0-2?arch=all",
    } in dependencies
    assert {
        "dependsOn": ["pkg:deb/debian/py-serializable@2.0.0-2?arch=source"],
        "ref": "pkg:deb/debian/python3-py-serializable@2.0.0-2?arch=all",
    } in dependencies
    assert {
        "dependsOn": ["pkg:deb/debian/sortedcontainers@2.4.0-2?arch=source"],
        "ref": "pkg:deb/debian/python3-sortedcontainers@2.4.0-2?arch=all",
    } in dependencies
    assert {
        "dependsOn": ["pkg:deb/debian/debsbom@0.8.1-1~bpo13%2B1?arch=all"],
        "ref": "CDXRef-Debian",
    } in dependencies
