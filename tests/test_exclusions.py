# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

import io
import pytest
from packageurl import PackageURL

pytest.importorskip("cyclonedx")
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.dependency import Dependency
from cyclonedx.model.bom_ref import BomRef
from debsbom.dpkg.package import Package
from debsbom.filter.cdx import CdxSbomFilter


def component(ref, name, version="1.0", arch="amd64"):
    return Component(
        name=name,
        version=version,
        bom_ref=ref,
        purl=PackageURL(
            type="deb", namespace="debian", name=name, version=version, qualifiers={"arch": arch}
        ),
    )


def document():
    comps = [
        component("a", "alpha"),
        component("b", "beta"),
        component("s", "shared", arch="source"),
        component("other", "unrelated", arch="source"),
    ]
    bom = Bom(components=comps)
    bom.metadata.component = Component(
        name="Debian", type=ComponentType.OPERATING_SYSTEM, bom_ref="root"
    )
    bom.dependencies = [
        Dependency(
            ref=BomRef("root"),
            dependencies=[Dependency(ref=BomRef("a")), Dependency(ref=BomRef("b"))],
        ),
        Dependency(
            ref=BomRef("a"), dependencies=[Dependency(ref=BomRef("s")), Dependency(ref=BomRef("b"))]
        ),
        Dependency(ref=BomRef("b"), dependencies=[Dependency(ref=BomRef("s"))]),
        Dependency(ref=BomRef("s")),
        Dependency(ref=BomRef("other")),
    ]
    return bom


def refs(bom):
    return {str(c.bom_ref) for c in bom.components}


def installed(extra=""):
    text = (
        "Package: alpha\nVersion: 1.0\nArchitecture: amd64\n"
        "Status: install ok installed\nSource: shared (1.0)\n\n"
        "Package: beta\nVersion: 1.0\nArchitecture: amd64\n"
        "Status: install ok installed\nSource: second (2.0)\n" + extra + "\n"
    )
    return list(Package._parse_dpkg_status(io.StringIO(text), force_no_apt=True))


def test_binary_exclusion_preserves_shared_source_and_cleans_edges():
    bom = document()
    report = CdxSbomFilter.exclude(bom, binary_patterns=["alpha"])
    assert refs(bom) == {"b", "s", "other"}
    assert report["removed_binaries"] == ["a"]
    assert report["unmatched_patterns"] == []
    assert all(str(d.ref) != "a" for d in bom.dependencies)
    assert all(str(c.ref) != "a" for d in bom.dependencies for c in d.dependencies)


def test_all_binary_exclusion_removes_only_related_orphan_sources():
    bom = document()
    report = CdxSbomFilter.exclude(bom, binary_patterns=[".*"])
    assert refs(bom) == {"other"}
    assert report["removed_sources"] == ["s"]
    assert str(bom.metadata.component.bom_ref) == "root"
    assert all(not d.dependencies for d in bom.dependencies)


@pytest.mark.parametrize("relation", ["Built-Using", "Static-Built-Using"])
def test_source_exclusion_does_not_remove_built_using_consumer(relation):
    bom = document()
    report = CdxSbomFilter.exclude(
        bom,
        source_packages=[("shared", "1.0")],
        installed_packages=installed(f"{relation}: shared (= 1.0)\n"),
    )
    assert refs(bom) == {"b", "s", "other"}
    assert report["matched_sources"] == [{"name": "shared", "version": "1.0"}]
    assert report["removed_binaries"] == ["a"]


def test_selected_installed_package_missing_from_bom_is_error_without_mutation():
    bom = document()
    bom.components = [c for c in bom.components if str(c.bom_ref) != "a"]
    before = refs(bom)
    with pytest.raises(ValueError, match="alpha"):
        CdxSbomFilter.exclude(
            bom, source_packages=[("shared", "1.0")], installed_packages=installed()
        )
    assert refs(bom) == before


@pytest.mark.parametrize("pattern", ["[", "("])
def test_invalid_pattern_leaves_document_unchanged(pattern):
    bom = document()
    with pytest.raises(ValueError, match="pattern"):
        CdxSbomFilter.exclude(bom, binary_patterns=[pattern])
    assert refs(bom) == {"a", "b", "s", "other"}


def test_source_exclusion_requires_installed_metadata():
    with pytest.raises(ValueError, match="installed"):
        CdxSbomFilter.exclude(document(), source_packages=[("shared", "1.0")])


def test_unmatched_exclusions_do_not_change_document():
    bom = document()
    report = CdxSbomFilter.exclude(
        bom,
        binary_patterns=["alp", "missing"],
        source_packages=[("shared", "2.0")],
        installed_packages=installed(),
    )
    assert refs(bom) == {"a", "b", "s", "other"}
    assert report["unmatched_patterns"] == ["alp", "missing"]
    assert report["unmatched_sources"] == [{"name": "shared", "version": "2.0"}]


def test_empty_result_preserves_root():
    bom = document()
    bom.components = [c for c in bom.components if str(c.bom_ref) != "other"]
    bom.dependencies = [d for d in bom.dependencies if str(d.ref) != "other"]
    CdxSbomFilter.exclude(bom, binary_patterns=[".*"])
    assert not bom.components
    assert {str(d.ref) for d in bom.dependencies} == {"root"}
    assert not next(iter(bom.dependencies)).dependencies


def test_ambiguous_installed_mapping_is_an_error():
    bom = document()
    bom.components.add(component("duplicate", "alpha"))
    with pytest.raises(ValueError, match="2 SBOM components"):
        CdxSbomFilter.exclude(bom, binary_patterns=["alpha"], installed_packages=installed())
    assert "a" in refs(bom)


def test_pattern_checks_selected_installed_packages_missing_from_sbom():
    bom = document()
    bom.components = [c for c in bom.components if str(c.bom_ref) != "a"]
    with pytest.raises(ValueError, match="0 SBOM components"):
        CdxSbomFilter.exclude(bom, binary_patterns=["alpha"], installed_packages=installed())


def test_exact_source_version_and_multiple_architectures():
    bom = document()
    bom.components.add(component("a-arm", "alpha", arch="arm64"))
    bom.components.add(component("old", "shared", version="0.9", arch="source"))
    packages = installed()
    from copy import deepcopy

    second_arch = deepcopy(packages[0])
    second_arch.architecture = "arm64"
    packages.append(second_arch)
    report = CdxSbomFilter.exclude(
        bom, source_packages=[("shared", "1.0")], installed_packages=packages
    )
    assert report["removed_binaries"] == ["a", "a-arm"]
    assert "old" in refs(bom)


@pytest.mark.parametrize("relation", ["Built-Using", "Static-Built-Using"])
@pytest.mark.parametrize("version", ["1.0", "0:1.0"])
def test_installed_metadata_preserves_source_even_without_graph_edge(relation, version):
    bom = document()
    bom.dependencies = [d for d in bom.dependencies if str(d.ref) != "b"]
    result = CdxSbomFilter.exclude(
        bom,
        source_packages=[("shared", "1.0")],
        installed_packages=installed(f"{relation}: shared (= {version})\n"),
    )
    assert "s" in refs(bom)
    assert result["retained_sources"] == ["s"]


@pytest.mark.parametrize("selector", [("Bad name", "1.0"), ("shared", "")])
def test_invalid_source_selector_leaves_document_unchanged(selector):
    bom = document()
    with pytest.raises(ValueError, match="invalid source package"):
        CdxSbomFilter.exclude(bom, source_packages=[selector], installed_packages=installed())
    assert refs(bom) == {"a", "b", "s", "other"}


def test_filtered_sources_are_not_repacked(tmp_path, monkeypatch):
    from unittest.mock import MagicMock
    from debsbom.cli import setup_parser
    from debsbom.commands.filter import FilterCmd
    from debsbom.commands.repack import RepackCmd
    from debsbom.commands import repack

    filtered = tmp_path / "filtered.cdx.json"
    FilterCmd.run(
        setup_parser().parse_args(
            ["filter", "tests/data/filter.cdx.json", str(filtered), "--exclude-binary", "dash"]
        )
    )
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


def test_standalone_source_can_be_excluded():
    bom = document()
    result = CdxSbomFilter.exclude(
        bom, source_packages=[("unrelated", "1.0")], installed_packages=[]
    )
    assert "other" not in refs(bom)
    assert result["removed_sources"] == ["other"]


def test_source_selector_handles_epoch_and_binary_rebuild_version():
    bom = document()
    alpha = next(c for c in bom.components if str(c.bom_ref) == "a")
    alpha.purl = PackageURL(
        type="deb",
        namespace="debian",
        name="alpha",
        version="2:1.0+b1",
        qualifiers={"arch": "amd64"},
    )
    source = next(c for c in bom.components if str(c.bom_ref) == "s")
    source.purl = PackageURL(
        type="deb",
        namespace="debian",
        name="shared",
        version="2:1.0",
        qualifiers={"arch": "source"},
    )
    packages = installed()
    from debian.debian_support import Version

    packages[0].version = Version("2:1.0+b1")
    packages[0].source.version = ("=", Version("2:1.0"))
    report = CdxSbomFilter.exclude(
        bom, source_packages=[("shared", "2:1.0")], installed_packages=packages
    )
    assert report["removed_binaries"] == ["a"]


def test_filter_cli_writes_sbom_and_separate_report(tmp_path):
    from debsbom.cli import setup_parser
    from debsbom.commands.filter import FilterCmd
    from debsbom.bomwriter.bomwriter import BomWriter
    from debsbom.sbom import SBOMType
    import json

    original = tmp_path / "in.cdx.json"
    output = tmp_path / "out.cdx.json"
    report = tmp_path / "report.json"
    BomWriter.create(SBOMType.CycloneDX).write_to_file(document(), original, validate=False)
    args = setup_parser().parse_args(
        [
            "filter",
            str(original),
            str(output),
            "--exclude-binary",
            "alpha",
            "--exclusion-report",
            str(report),
        ]
    )
    FilterCmd.run(args)
    data = json.loads(output.read_text())
    assert {c["bom-ref"] for c in data["components"]} == {"b", "s", "other"}
    assert json.loads(report.read_text())["removed_binaries"] == ["a"]


def test_filter_cli_expands_source_file(tmp_path):
    from debsbom.cli import setup_parser
    from debsbom.commands.filter import FilterCmd
    import json

    sources = tmp_path / "sources.json"
    sources.write_text('[{"name": "dash", "version": "0.5.12-12"}]')
    status = tmp_path / "status"
    status.write_text(
        "Package: dash\nVersion: 0.5.12-12\nArchitecture: amd64\nStatus: install ok installed\n\n"
    )
    output = tmp_path / "out.cdx.json"
    args = setup_parser().parse_args(
        [
            "filter",
            "tests/data/filter.cdx.json",
            str(output),
            "--exclude-source-file",
            str(sources),
            "--installed-status",
            str(status),
        ]
    )
    FilterCmd.run(args)
    data = json.loads(output.read_text())
    assert all(c["name"] != "dash" for c in data["components"])


@pytest.mark.parametrize(
    "contents",
    ["{}", "[{}]", '[{"name":"dash","version":1}]', '[{"name":"dash","version":"1","extra":true}]'],
)
def test_cli_rejects_invalid_source_file_before_writing(tmp_path, contents):
    from debsbom.cli import setup_parser
    from debsbom.commands.filter import FilterCmd

    src = tmp_path / "exclusions.json"
    src.write_text(contents)
    output = tmp_path / "out.cdx.json"
    args = setup_parser().parse_args(
        ["filter", "tests/data/filter.cdx.json", str(output), "--exclude-source-file", str(src)]
    )
    with pytest.raises(ValueError, match="source exclusion"):
        FilterCmd.run(args)
    assert not output.exists()


@pytest.mark.parametrize(
    "options,match",
    [
        (["--installed-status", "missing"], "require exclusions"),
        (["--exclusion-report", "unused"], "require exclusions"),
        (["--package", "dash", "--exclude-binary", "dash"], "cannot be combined"),
        (["--exclude-binary", "["], "pattern"),
    ],
)
def test_cli_rejects_invalid_combinations(tmp_path, options, match):
    from debsbom.cli import setup_parser
    from debsbom.commands.filter import FilterCmd

    output = tmp_path / "out.cdx.json"
    args = setup_parser().parse_args(
        ["filter", "tests/data/filter.cdx.json", str(output)] + options
    )
    with pytest.raises(ValueError, match=match):
        FilterCmd.run(args)
    assert not output.exists()


def test_cli_requires_status_for_source_file(tmp_path):
    from debsbom.cli import setup_parser
    from debsbom.commands.filter import FilterCmd

    src = tmp_path / "sources.json"
    src.write_text("[]")
    args = setup_parser().parse_args(
        [
            "filter",
            "tests/data/filter.cdx.json",
            str(tmp_path / "out"),
            "--exclude-source-file",
            str(src),
        ]
    )
    with pytest.raises(ValueError, match="requires --installed-status"):
        FilterCmd.run(args)


def test_cli_rejects_spdx_exclusions(tmp_path):
    pytest.importorskip("spdx_tools")
    from debsbom.cli import setup_parser
    from debsbom.commands.filter import FilterCmd

    args = setup_parser().parse_args(
        ["filter", "tests/data/filter.spdx.json", str(tmp_path / "out"), "--exclude-binary", "dash"]
    )
    with pytest.raises(ValueError, match="CycloneDX"):
        FilterCmd.run(args)


def test_report_cannot_overwrite_sbom(tmp_path):
    from debsbom.cli import setup_parser
    from debsbom.commands.filter import FilterCmd

    output = tmp_path / "out.cdx.json"
    args = setup_parser().parse_args(
        [
            "filter",
            "tests/data/filter.cdx.json",
            str(output),
            "--exclude-binary",
            "dash",
            "--exclusion-report",
            str(output),
        ]
    )
    with pytest.raises(ValueError, match="different file"):
        FilterCmd.run(args)
    assert not output.exists()


def test_empty_filtered_bom_is_valid_cyclonedx(tmp_path):
    from debsbom.bomwriter.bomwriter import BomWriter
    from debsbom.sbom import SBOMType
    from cyclonedx.validation.json import JsonStrictValidator
    from cyclonedx.schema import SchemaVersion

    bom = document()
    bom.components = [c for c in bom.components if str(c.bom_ref) != "other"]
    bom.dependencies = [d for d in bom.dependencies if str(d.ref) != "other"]
    CdxSbomFilter.exclude(bom, binary_patterns=[".*"])
    output = tmp_path / "out.cdx.json"
    BomWriter.create(SBOMType.CycloneDX).write_to_file(bom, output, validate=False)
    assert not JsonStrictValidator(SchemaVersion.V1_6).validate_str(output.read_text())


def test_filtered_sources_are_not_acquired(tmp_path, monkeypatch):
    from unittest.mock import MagicMock
    from debsbom.cli import setup_parser
    from debsbom.commands.filter import FilterCmd
    from debsbom.commands.download import DownloadCmd
    from debsbom.commands import download

    output = tmp_path / "filtered.cdx.json"
    args = setup_parser().parse_args(
        ["filter", "tests/data/filter.cdx.json", str(output), "--exclude-binary", "dash"]
    )
    FilterCmd.run(args)
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


def test_cli_stdin_keeps_report_separate_from_sbom(tmp_path, monkeypatch, capsys):
    from debsbom.cli import setup_parser
    from debsbom.commands.filter import FilterCmd
    from pathlib import Path
    import sys
    import json

    monkeypatch.setattr(sys, "stdin", io.StringIO(Path("tests/data/filter.cdx.json").read_text()))
    report = tmp_path / "report.json"
    args = setup_parser().parse_args(
        [
            "filter",
            "-t",
            "cdx",
            "-",
            "-",
            "--exclude-binary",
            "dash",
            "--exclusion-report",
            str(report),
        ]
    )
    FilterCmd.run(args)
    result = json.loads(capsys.readouterr().out)
    assert result["bomFormat"] == "CycloneDX"
    assert all(c["name"] != "dash" for c in result["components"])
    assert json.loads(report.read_text())["matched_patterns"] == ["dash"]
