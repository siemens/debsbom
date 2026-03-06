# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from debsbom.bomwriter.bomwriter import BomWriter
from debsbom.sbom import SBOMType
import json
from pathlib import Path
import pytest

# The filter SBOM was generated using:
# cat <<EOF | debsbom generate --from-pkglist
# > accountsservice 23.13.9-7 amd64
# > base-files 13.8+deb13u3 amd64
# > dash 0.5.12-12 amd64
# > libxtst6 2:1.2.3-1.1 amd64
# > x11vnc 0.9.16-9 amd64
# > EOF


def test_spdx_filter_sources(tmpdir):
    _spdx_tools = pytest.importorskip("spdx_tools")

    from debsbom.bomreader.spdxbomreader import SpdxBomFileReader
    from debsbom.resolver import PackageResolver
    from debsbom.commands.input import SourceBinaryInput

    resolver = PackageResolver.create(Path("tests/data/filter.spdx.json"))
    SourceBinaryInput.filter_sbom(resolver, sources=True, binaries=False)
    outdir = Path(tmpdir)
    bomfile = outdir / "filtered_sources.spdx.json"
    BomWriter.create(SBOMType.SPDX).write_to_file(resolver.document, bomfile, validate=False)

    with open(bomfile) as file:
        spdx_json = json.loads(file.read())

    packages = spdx_json["packages"]
    relationships = spdx_json["relationships"]
    assert any("srcpkg" in pkg["SPDXID"] for pkg in packages)
    assert all("srcpkg" in pkg["SPDXID"] for pkg in packages)
    assert any(rel["relationshipType"] == "DESCRIBES" for rel in relationships)
    assert any(rel["relationshipType"] == "DEPENDS_ON" for rel in relationships)


def test_spdx_filter_binaries(tmpdir):
    _spdx_tools = pytest.importorskip("spdx_tools")

    from debsbom.bomreader.spdxbomreader import SpdxBomFileReader
    from debsbom.resolver import PackageResolver
    from debsbom.commands.input import SourceBinaryInput

    resolver = PackageResolver.create(Path("tests/data/filter.spdx.json"))
    SourceBinaryInput.filter_sbom(resolver, sources=False, binaries=True)
    outdir = Path(tmpdir)
    bomfile = outdir / "filtered_binaries.spdx.json"
    BomWriter.create(SBOMType.SPDX).write_to_file(resolver.document, bomfile, validate=False)

    with open(bomfile) as file:
        spdx_json = json.loads(file.read())

    packages = spdx_json["packages"]
    assert any("srcpkg" not in pkg["SPDXID"] for pkg in packages)
    assert all("srcpkg" not in pkg["SPDXID"] for pkg in packages)


def test_cdx_filter_sources(tmpdir):
    _cyclonedx = pytest.importorskip("cyclonedx")

    from debsbom.resolver import PackageResolver
    from debsbom.commands.input import SourceBinaryInput

    resolver = PackageResolver.create(Path("tests/data/filter.cdx.json"))
    SourceBinaryInput.filter_sbom(resolver, sources=True, binaries=False)
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

    resolver = PackageResolver.create(Path("tests/data/filter.cdx.json"))
    SourceBinaryInput.filter_sbom(resolver, sources=False, binaries=True)
    outdir = Path(tmpdir)
    bomfile = outdir / "filtered_binaries.cdx.json"
    BomWriter.create(SBOMType.CycloneDX).write_to_file(resolver.document, bomfile, validate=False)

    with open(bomfile) as file:
        cdx_json = json.loads(file.read())

    components = cdx_json["components"]
    relationships = cdx_json["dependencies"]
    assert all("arch=source" not in comp["bom-ref"] for comp in components)
