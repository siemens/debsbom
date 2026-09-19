# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

import io
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from packageurl import PackageURL

pytest.importorskip("cyclonedx")
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.dependency import Dependency
from cyclonedx.model.bom_ref import BomRef

from debsbom.bomreader.bomreader import BomReader
from debsbom.bomwriter.bomwriter import BomWriter
from debsbom.cli import setup_parser
from debsbom.commands.filter import FilterCmd
from debsbom.filter.cdx import CdxSbomFilter
from debsbom.sbom import SBOMType


def component(ref, name, version="1.0", arch="amd64"):
    return Component(
        name=name,
        version=version,
        bom_ref=ref,
        purl=PackageURL(
            type="deb", namespace="debian", name=name, version=version, qualifiers={"arch": arch}
        ),
    )


def dependency(ref, *refs):
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


def run_filter(*args):
    FilterCmd.run(setup_parser().parse_args(["filter", *map(str, args)]))


def test_binary_exclusion_prunes_packages_only_it_referenced():
    bom = document()
    report = CdxSbomFilter.exclude(bom, binary_patterns=["alpha"])
    # shared is still referenced by beta, libfoo and its dependencies only by alpha
    assert refs(bom) == {"b", "s", "bs", "other"}
    assert report["matched_patterns"] == ["alpha"]
    assert report["removed_binaries"] == ["a", "bar", "lib"]
    assert report["removed_sources"] == ["ls"]
    assert edges(bom) == {("root", "b"), ("b", "bs"), ("b", "s")}


def test_pattern_matches_entire_name():
    bom = document()
    report = CdxSbomFilter.exclude(bom, binary_patterns=["lib", "libfo+", "lib.*"])
    assert report["unmatched_patterns"] == ["lib"]
    assert report["matched_patterns"] == ["libfo+", "lib.*"]
    assert refs(bom) == ALL_REFS - {"lib", "bar", "ls"}


def test_package_referenced_by_retained_package_is_kept():
    bom = document()
    bom.dependencies = list(bom.dependencies) + [dependency("root", "bar")]
    CdxSbomFilter.exclude(bom, binary_patterns=["libfoo"])
    assert refs(bom) == ALL_REFS - {"lib"}


def test_exclude_everything_keeps_unreferenced_packages_and_root():
    bom = document()
    report = CdxSbomFilter.exclude(bom, binary_patterns=[".*"])
    assert refs(bom) == {"other"}
    assert report["removed_sources"] == ["bs", "ls", "s"]
    assert str(bom.metadata.component.bom_ref) == "root"
    assert not edges(bom)


def test_source_exclusion_removes_its_binaries_but_not_built_using_consumer():
    bom = document()
    report = CdxSbomFilter.exclude(bom, source_packages=[("shared", "1.0")])
    # beta is built from its own source and only uses shared (Built-Using)
    assert refs(bom) == {"b", "bs", "other"}
    assert report["matched_sources"] == [{"name": "shared", "version": "1.0"}]
    assert report["removed_binaries"] == ["a", "bar", "lib"]
    assert report["removed_sources"] == ["ls", "s"]


def test_source_exclusion_matches_exact_version_and_all_architectures():
    bom = document()
    bom.components.add(component("a-arm", "alpha", arch="arm64"))
    bom.components.add(component("old", "shared", version="0.9", arch="source"))
    bom.dependencies = list(bom.dependencies) + [dependency("a-arm", "s")]
    report = CdxSbomFilter.exclude(bom, source_packages=[("shared", "0:1.0")])
    assert {"a", "a-arm", "s"}.isdisjoint(refs(bom))
    assert "old" in refs(bom)
    assert report["matched_sources"] == [{"name": "shared", "version": "0:1.0"}]


def test_unreferenced_source_can_be_excluded():
    bom = document()
    report = CdxSbomFilter.exclude(bom, source_packages=[("unrelated", "1.0")])
    assert refs(bom) == ALL_REFS - {"other"}
    assert report["removed_sources"] == ["other"]


def test_unmatched_exclusions_do_not_change_document():
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
    bom = document()
    with pytest.raises(ValueError):
        CdxSbomFilter.exclude(bom, **kwargs)
    assert refs(bom) == ALL_REFS


def test_empty_result_is_a_readable_sbom(tmp_path):
    bom = document()
    bom.components = [c for c in bom.components if str(c.bom_ref) != "other"]
    CdxSbomFilter.exclude(bom, binary_patterns=[".*"])
    output = tmp_path / "out.cdx.json"
    BomWriter.create(SBOMType.CycloneDX).write_to_file(bom, output, validate=False)
    result = BomReader.create(output).read()
    assert not result.components
    assert result.metadata.component.name == "Debian"


def test_filter_cli_writes_sbom_and_single_line_report(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    from debsbom.schema import filter_report

    original = tmp_path / "in.cdx.json"
    output = tmp_path / "out.cdx.json"
    report = tmp_path / "report.json"
    BomWriter.create(SBOMType.CycloneDX).write_to_file(document(), original, validate=False)
    run_filter(original, output, "--exclude-binary", "alpha", "--exclusion-report", report)
    data = json.loads(output.read_text())
    assert {c["bom-ref"] for c in data["components"]} == {"b", "s", "bs", "other"}
    lines = report.read_text().splitlines()
    assert len(lines) == 1
    result = json.loads(lines[0])
    jsonschema.validate(result, filter_report)
    assert result["removed_binaries"] == ["a", "bar", "lib"]


def test_filter_cli_reads_source_exclusions_as_json_lines(tmp_path):
    sources = tmp_path / "sources.jsonl"
    sources.write_text(
        '{"name": "dash", "version": "0.5.12-12"}\n\n{"name": "xz", "version": "1"}\n'
    )
    output = tmp_path / "out.cdx.json"
    report = tmp_path / "report.json"
    run_filter(
        "tests/data/filter.cdx.json",
        output,
        "--exclude-source-file",
        sources,
        "--exclusion-report",
        report,
    )
    data = json.loads(output.read_text())
    assert all(c["name"] != "dash" for c in data["components"])
    result = json.loads(report.read_text())
    assert result["matched_sources"] == [{"name": "dash", "version": "0.5.12-12"}]
    assert result["unmatched_sources"] == [{"name": "xz", "version": "1"}]


INVALID_SOURCE_LINES = [
    "[]",
    "{}",
    '{"name": "dash"}',
    '{"name": "dash", "version": 1}',
    '{"name": "dash", "version": ""}',
    '{"name": "Dash", "version": "1"}',
    '{"name": "dash", "version": "1", "extra": true}',
]


@pytest.mark.parametrize("line", INVALID_SOURCE_LINES + ["{"])
def test_cli_rejects_invalid_source_file_before_writing(tmp_path, line):
    sources = tmp_path / "sources.jsonl"
    sources.write_text('{"name": "dash", "version": "1"}\n' + line + "\n")
    output = tmp_path / "out.cdx.json"
    with pytest.raises(ValueError, match="sources.jsonl:2"):
        run_filter("tests/data/filter.cdx.json", output, "--exclude-source-file", sources)
    assert not output.exists()


def test_source_exclusion_schema_matches_validation():
    jsonschema = pytest.importorskip("jsonschema")
    from debsbom.schema import filter_exclude

    jsonschema.validate({"name": "dash", "version": "0.5.12-12"}, filter_exclude)
    for line in INVALID_SOURCE_LINES:
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(json.loads(line), filter_exclude)


@pytest.mark.parametrize(
    "options,match",
    [
        (["--exclusion-report", "unused"], "requires exclusions"),
        (["--package", "dash", "--exclude-binary", "dash"], "cannot be combined"),
        (["--exclude-binary", "["], "pattern"),
    ],
)
def test_cli_rejects_invalid_combinations(tmp_path, options, match):
    output = tmp_path / "out.cdx.json"
    with pytest.raises(ValueError, match=match):
        run_filter("tests/data/filter.cdx.json", output, *options)
    assert not output.exists()


def test_cli_rejects_spdx_exclusions(tmp_path):
    pytest.importorskip("spdx_tools")
    with pytest.raises(ValueError, match="CycloneDX"):
        run_filter("tests/data/filter.spdx.json", tmp_path / "out", "--exclude-binary", "dash")


def test_report_cannot_overwrite_sbom(tmp_path):
    output = tmp_path / "out.cdx.json"
    with pytest.raises(ValueError, match="different file"):
        run_filter(
            "tests/data/filter.cdx.json",
            output,
            "--exclude-binary",
            "dash",
            "--exclusion-report",
            output,
        )
    assert not output.exists()


def test_cli_stdin_keeps_report_separate_from_sbom(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO(Path("tests/data/filter.cdx.json").read_text()))
    report = tmp_path / "report.json"
    run_filter("-t", "cdx", "-", "-", "--exclude-binary", "dash", "--exclusion-report", report)
    result = json.loads(capsys.readouterr().out)
    assert result["bomFormat"] == "CycloneDX"
    assert all(c["name"] != "dash" for c in result["components"])
    assert json.loads(report.read_text())["matched_patterns"] == ["dash"]


def test_filtered_sources_are_not_acquired(tmp_path, monkeypatch):
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
