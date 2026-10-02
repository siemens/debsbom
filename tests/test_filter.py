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


import io
import sys
from unittest.mock import MagicMock

from debsbom.bomreader.bomreader import BomReader
from debsbom.cli import setup_parser
from debsbom.commands.filter import FilterCmd

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


def component(ref, name, version="1.0", arch="amd64"):
    pytest.importorskip("cyclonedx")
    from cyclonedx.model.component import Component

    return Component(
        name=name,
        version=version,
        bom_ref=ref,
        purl=PackageURL(
            type="deb", namespace="debian", name=name, version=version, qualifiers={"arch": arch}
        ),
    )


def dependency(ref, *refs):
    pytest.importorskip("cyclonedx")
    from cyclonedx.model.dependency import Dependency
    from cyclonedx.model.bom_ref import BomRef

    return Dependency(ref=BomRef(ref), dependencies=[Dependency(ref=BomRef(r)) for r in refs])


def document():
    """
    root -> alpha, beta
    alpha -> shared (source), libfoo
    beta -> beta (source), shared (source, Built-Using)
    libfoo -> libfoo-src (source), libbar
    libbar -> libfoo-src (source)
    unrelated (source) is not referenced
    """
    pytest.importorskip("cyclonedx")
    from cyclonedx.model.bom import Bom
    from cyclonedx.model.component import Component, ComponentType

    bom = Bom(
        components=[
            component("a", "alpha"),
            component("b", "beta"),
            component("lib", "libfoo"),
            component("bar", "libbar"),
            component("s", "shared", arch="source"),
            component("bs", "beta", arch="source"),
            component("ls", "libfoo-src", arch="source"),
            component("other", "unrelated", arch="source"),
        ]
    )
    bom.metadata.component = Component(
        name="Debian", type=ComponentType.OPERATING_SYSTEM, bom_ref="root"
    )
    bom.dependencies = [
        dependency("root", "a", "b"),
        dependency("a", "s", "lib"),
        dependency("b", "bs", "s"),
        dependency("lib", "ls", "bar"),
        dependency("bar", "ls"),
    ]
    return bom


ALL_REFS = {"a", "b", "lib", "bar", "s", "bs", "ls", "other"}


def refs(bom):
    return {str(c.bom_ref) for c in bom.components}


def edges(bom):
    return {(str(d.ref), str(c.ref)) for d in bom.dependencies for c in d.dependencies}


def run_filter(*args, json_report=False):
    options = ["--json"] if json_report else []
    FilterCmd.run(setup_parser().parse_args([*options, "filter", *map(str, args)]))


def test_binary_exclusion_prunes_packages_only_it_referenced():
    pytest.importorskip("cyclonedx")
    from debsbom.filter.cdx import CdxSbomFilter

    bom = document()
    report = CdxSbomFilter.exclude(bom, binary_patterns=["alpha"])
    # shared is still referenced by beta, libfoo and its dependencies only by alpha
    assert refs(bom) == {"b", "s", "bs", "other"}
    assert report["matched_patterns"] == ["alpha"]
    assert report["removed_binaries"] == ["a", "bar", "lib"]
    assert report["removed_sources"] == ["ls"]
    assert edges(bom) == {("root", "b"), ("b", "bs"), ("b", "s")}


def test_pattern_matches_entire_name():
    pytest.importorskip("cyclonedx")
    from debsbom.filter.cdx import CdxSbomFilter

    bom = document()
    report = CdxSbomFilter.exclude(bom, binary_patterns=["lib", "libfo+", "lib.*"])
    assert report["unmatched_patterns"] == ["lib"]
    assert report["matched_patterns"] == ["libfo+", "lib.*"]
    assert refs(bom) == ALL_REFS - {"lib", "bar", "ls"}


def test_package_referenced_by_retained_package_is_kept():
    pytest.importorskip("cyclonedx")
    from debsbom.filter.cdx import CdxSbomFilter

    bom = document()
    bom.dependencies = list(bom.dependencies) + [dependency("root", "bar")]
    CdxSbomFilter.exclude(bom, binary_patterns=["libfoo"])
    assert refs(bom) == ALL_REFS - {"lib"}


def test_exclude_everything_keeps_unreferenced_packages_and_root():
    pytest.importorskip("cyclonedx")
    from debsbom.filter.cdx import CdxSbomFilter

    bom = document()
    report = CdxSbomFilter.exclude(bom, binary_patterns=[".*"])
    assert refs(bom) == {"other"}
    assert report["removed_sources"] == ["bs", "ls", "s"]
    assert str(bom.metadata.component.bom_ref) == "root"
    assert not edges(bom)


def test_source_exclusion_keeps_binaries_and_built_using_consumers():
    pytest.importorskip("cyclonedx")
    from debsbom.filter.cdx import CdxSbomFilter

    bom = document()
    report = CdxSbomFilter.exclude(bom, source_packages=[("shared", "1.0")])
    assert refs(bom) == ALL_REFS - {"s"}
    assert ("a", "lib") in edges(bom)
    assert not any(target == "s" for _, target in edges(bom))
    assert report["matched_sources"] == [{"name": "shared", "version": "1.0"}]
    assert report["removed_binaries"] == []
    assert report["removed_sources"] == ["s"]


def test_source_exclusion_matches_exact_version_and_all_architectures():
    pytest.importorskip("cyclonedx")
    from debsbom.filter.cdx import CdxSbomFilter

    bom = document()
    bom.components.add(component("a-arm", "alpha", arch="arm64"))
    bom.components.add(component("old", "shared", version="0.9", arch="source"))
    bom.dependencies = list(bom.dependencies) + [dependency("a-arm", "s")]
    report = CdxSbomFilter.exclude(bom, source_packages=[("shared", "0:1.0")])
    assert "s" not in refs(bom)
    assert {"a", "a-arm"} <= refs(bom)
    assert "old" in refs(bom)
    assert report["matched_sources"] == [{"name": "shared", "version": "0:1.0"}]


def test_unreferenced_source_can_be_excluded():
    pytest.importorskip("cyclonedx")
    from debsbom.filter.cdx import CdxSbomFilter

    bom = document()
    report = CdxSbomFilter.exclude(bom, source_packages=[("unrelated", "1.0")])
    assert refs(bom) == ALL_REFS - {"other"}
    assert report["removed_sources"] == ["other"]


def test_unmatched_exclusions_do_not_change_document():
    pytest.importorskip("cyclonedx")
    from debsbom.filter.cdx import CdxSbomFilter

    bom = document()
    report = CdxSbomFilter.exclude(
        bom, binary_patterns=["alp", "missing"], source_packages=[("shared", "2.0")]
    )
    assert refs(bom) == ALL_REFS
    assert report["unmatched_patterns"] == ["alp", "missing"]
    assert report["unmatched_sources"] == [{"name": "shared", "version": "2.0"}]
    assert report["removed_binaries"] == report["removed_sources"] == []


@pytest.mark.parametrize(
    "kwargs", [{"binary_patterns": ["["]}, {"source_packages": [("shared", "a b")]}]
)
def test_invalid_exclusions_leave_document_unchanged(kwargs):
    pytest.importorskip("cyclonedx")
    from debsbom.filter.cdx import CdxSbomFilter

    bom = document()
    with pytest.raises(ValueError):
        CdxSbomFilter.exclude(bom, **kwargs)
    assert refs(bom) == ALL_REFS


def test_empty_result_is_a_readable_sbom(tmp_path):
    pytest.importorskip("cyclonedx")
    from debsbom.filter.cdx import CdxSbomFilter

    bom = document()
    bom.components = [c for c in bom.components if str(c.bom_ref) != "other"]
    CdxSbomFilter.exclude(bom, binary_patterns=[".*"])
    output = tmp_path / "out.cdx.json"
    BomWriter.create(SBOMType.CycloneDX).write_to_file(bom, output, validate=False)
    result = BomReader.create(output).read()
    assert not result.components
    assert result.metadata.component.name == "Debian"


def test_filter_cli_writes_sbom_and_single_line_report(tmp_path, capsys):
    pytest.importorskip("cyclonedx")
    jsonschema = pytest.importorskip("jsonschema")
    from debsbom.schema import filter_report

    original = tmp_path / "in.cdx.json"
    output = tmp_path / "out.cdx.json"
    BomWriter.create(SBOMType.CycloneDX).write_to_file(document(), original, validate=False)
    run_filter(original, output, "--exclude-binary", "alpha", json_report=True)
    data = json.loads(output.read_text())
    assert {c["bom-ref"] for c in data["components"]} == {"b", "s", "bs", "other"}
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 1
    result = json.loads(lines[0])
    jsonschema.validate(result, filter_report)
    assert result["removed_binaries"] == ["a", "bar", "lib"]


def test_filter_cli_reads_source_exclusions_as_package_list(tmp_path, capsys):
    pytest.importorskip("cyclonedx")
    sources = tmp_path / "sources.txt"
    sources.write_text("dash 0.5.12-12 source\nxz 1 source\n")
    output = tmp_path / "out.cdx.json"
    run_filter(
        "tests/data/filter.cdx.json",
        output,
        "--exclude-source-file",
        sources,
        json_report=True,
    )
    data = json.loads(output.read_text())
    assert any(c["name"] == "dash" for c in data["components"])
    assert not any(c["name"] == "dash" and "arch=source" in c["purl"] for c in data["components"])
    result = json.loads(capsys.readouterr().out)
    assert result["matched_sources"] == [{"name": "dash", "version": "0.5.12-12"}]
    assert result["unmatched_sources"] == [{"name": "xz", "version": "1"}]


@pytest.mark.parametrize(
    "text",
    [
        "dash",
        "dash 1",
        "Dash 1 source",
        "pkg:deb/debian/dash?arch=source",
        '{"name": "dash", "version": "1"}',
    ],
)
def test_cli_rejects_invalid_source_file_before_writing(tmp_path, text):
    pytest.importorskip("cyclonedx")
    sources = tmp_path / "sources.txt"
    sources.write_text(text)
    output = tmp_path / "out.cdx.json"
    with pytest.raises(ValueError, match="sources.txt"):
        run_filter("tests/data/filter.cdx.json", output, "--exclude-source-file", sources)
    assert not output.exists()


@pytest.mark.parametrize(
    "text",
    [
        "dash 1 source\ndash 1 source\nother 2 amd64\n",
        "pkg:deb/debian/dash@1?arch=source\npkg:deb/debian/other@2?arch=amd64\n",
        "dash|1|dash:amd64|1+b1\n",
        "Package: dash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1+b1\nSource: dash (1)\n\n",
    ],
)
def test_source_exclusions_use_universal_ingress(tmp_path, text):
    sources = tmp_path / "sources.txt"
    sources.write_text(text)
    assert FilterCmd.read_source_exclusions(sources) == [("dash", "1")]


@pytest.mark.parametrize(
    "options,match",
    [
        (["--package", "dash", "--exclude-binary", "dash"], "cannot be combined"),
        (["--exclude-binary", "["], "pattern"),
    ],
)
def test_cli_rejects_invalid_combinations(tmp_path, options, match):
    pytest.importorskip("cyclonedx")
    output = tmp_path / "out.cdx.json"
    with pytest.raises(ValueError, match=match):
        run_filter("tests/data/filter.cdx.json", output, *options)
    assert not output.exists()


def test_cli_rejects_spdx_exclusions(tmp_path):
    pytest.importorskip("spdx_tools")
    with pytest.raises(ValueError, match="CycloneDX"):
        run_filter("tests/data/filter.spdx.json", tmp_path / "out", "--exclude-binary", "dash")


def test_json_report_cannot_mix_with_sbom_on_stdout(tmp_path):
    pytest.importorskip("cyclonedx")
    with pytest.raises(ValueError, match="SBOM output file"):
        run_filter("tests/data/filter.cdx.json", "-", "--exclude-binary", "dash", json_report=True)


def test_cli_stdin_keeps_report_separate_from_sbom(tmp_path, monkeypatch, capsys):
    pytest.importorskip("cyclonedx")
    monkeypatch.setattr(sys, "stdin", io.StringIO(Path("tests/data/filter.cdx.json").read_text()))
    output = tmp_path / "out.cdx.json"
    run_filter("-t", "cdx", "-", output, "--exclude-binary", "dash", json_report=True)
    result = json.loads(output.read_text())
    assert result["bomFormat"] == "CycloneDX"
    assert all(c["name"] != "dash" for c in result["components"])
    assert json.loads(capsys.readouterr().out)["matched_patterns"] == ["dash"]


def test_filtered_sources_are_not_acquired(tmp_path, monkeypatch):
    pytest.importorskip("cyclonedx")
    from debsbom.commands.download import DownloadCmd
    from debsbom.commands import download

    output = tmp_path / "filtered.cdx.json"
    run_filter("tests/data/filter.cdx.json", output, "--exclude-binary", "dash")
    requested = []
    resolver = MagicMock()
    resolver._resolve_pkg.side_effect = lambda pkg: requested.append(pkg.name) or []
    monkeypatch.setitem(download.RESOLVERS, "debian-snapshot", lambda session: resolver)
    monkeypatch.setattr(download, "PackageDownloader", MagicMock())
    args = setup_parser().parse_args(
        ["--json", "download", str(output), "--sources", "--outdir", str(tmp_path / "downloads")]
    )
    DownloadCmd.run(args)
    assert requested
    assert "dash" not in requested


def test_filtered_sources_are_not_repacked(tmp_path, monkeypatch):
    pytest.importorskip("cyclonedx")
    from debsbom.commands.repack import RepackCmd
    from debsbom.commands import repack

    filtered = tmp_path / "filtered.cdx.json"
    run_filter("tests/data/filter.cdx.json", filtered, "--exclude-binary", "dash")
    requested = []
    packer = MagicMock()
    packer.repack.side_effect = lambda pkg, **kwargs: requested.append(pkg.name)

    # Consume the lazy package iterator just as the real packer does.
    def rewrite(transformer, packages):
        return transformer.transform(packages)

    packer.rewrite_sbom.side_effect = rewrite
    monkeypatch.setattr(repack.Packer, "from_format", lambda **kwargs: packer)
    monkeypatch.setattr(repack.sys.stdin, "isatty", lambda: True)
    RepackCmd.run(
        setup_parser().parse_args(
            [
                "repack",
                "--sources",
                str(filtered),
                str(tmp_path / "repacked.cdx.json"),
                "--dldir",
                str(tmp_path / "downloads"),
                "--outdir",
                str(tmp_path / "packed"),
            ]
        )
    )
    assert requested
    assert "dash" not in requested
