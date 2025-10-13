# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import io
from pathlib import Path
import pytest
import xml.etree.ElementTree as ET

from debsbom.export.exporter import GraphExporter, GraphOutputFormat
from debsbom.sbom import SBOMType
from test_generation import sbom_generator


def test_export_format_from_str():
    assert GraphOutputFormat.from_str("graphml") == GraphOutputFormat.GRAPHML
    with pytest.raises(RuntimeError):
        GraphOutputFormat.from_str("foo")


@pytest.mark.parametrize(
    "sbom_type",
    [
        "spdx",
        "cdx",
    ],
)
def test_export_graphml(tmpdir, sbom_generator, sbom_type):
    NAMESPACE = "http://graphml.graphdrawing.org/xmlns"

    def get_name(node):
        for data in node.findall(f"{{{NAMESPACE}}}data"):
            if data.get("key") == "d_name":
                return data.text
        return None

    dbom = sbom_generator("tests/root/tree", sbom_types=[SBOMType.from_str(sbom_type)])
    outdir = Path(tmpdir)
    dbom.generate(str(outdir / "sbom"), validate=False)

    exporter = GraphExporter.create(outdir / f"sbom.{sbom_type}.json", GraphOutputFormat.GRAPHML)
    buffer = io.BytesIO()
    with io.TextIOWrapper(buffer) as wrapper:
        exporter.export(wrapper)
        wrapper.flush()
        wrapper.seek(0)
        tree = ET.parse(wrapper)

    root = tree.getroot()
    assert root.tag == f"{{{NAMESPACE}}}graphml"
    node_tag = f"{{{NAMESPACE}}}node"
    assert any(map(lambda n: get_name(n) == "binutils", root.iter(node_tag)))

    edge_tag = f"{{{NAMESPACE}}}edge"
    assert any(map(lambda n: "binutils" in n.get("id"), root.iter(edge_tag)))
