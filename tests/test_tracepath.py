# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

import jsonschema
from packageurl import PackageURL
import json
from pathlib import Path
import pytest

from debsbom.tracepath.walker import GraphWalker, PackageRepr
from debsbom.commands.tracepath import TracePathCmd, PathOutputFormat
from debsbom.generate import SBOMType
from debsbom.schema import tracepath as schema_tracepath

from test_generation import sbom_generator


@pytest.mark.parametrize("sbom_type", list(SBOMType))
def test_tracepath_path(tmpdir, sbom_generator, sbom_type):
    match sbom_type:
        case SBOMType.SPDX:
            _spdx_tools = pytest.importorskip("spdx_tools")
        case SBOMType.CycloneDX:
            _cyclonedx = pytest.importorskip("cyclonedx")
        case _:
            assert False, "unreachable"

    dbom = sbom_generator("tests/root/dependency", sbom_types=[sbom_type])
    outdir = Path(tmpdir)
    dbom.generate(str(outdir / "sbom"), validate=False)

    walker = GraphWalker.create(outdir / f"sbom.{sbom_type}.json")
    src = PackageURL.from_string("pkg:deb/debian/libgcc-s1@12.2.0-14%2Bdeb12u1?arch=amd64")
    path = walker.shortest(src)
    assert len(path) == 2
    assert path[0].name == "libgcc-s1"
    assert path[1].name == "pytest-distro"

    paths = list(walker.all_shortest(src))
    assert len(paths) == 1
    assert len(paths[0]) == 2

    paths = list(walker.all_simple(src))
    assert len(paths) == 2
    assert any(len(p) == 2 for p in paths)
    assert any(len(p) == 3 for p in paths)


def test_tracepath_schema():
    path = [
        PackageRepr(name="test-src", ref="REF-test-src"),
        PackageRepr(name="test-middle", ref="REF-test-middle"),
        PackageRepr(name="test-root", ref="REF-root"),
    ]

    raw = next(TracePathCmd.iter_component_path(path, PathOutputFormat.JSON))
    data = json.loads(raw)
    assert len(data) == 3
    jsonschema.validate(data, schema=schema_tracepath)
