# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import xml.etree.ElementTree as ET
from cyclonedx.model.bom import Bom, BomRef

from ..sbom import CDX_REF_PREFIX, CDXType
from .graphml import GraphMLExporter
from .exporter import GraphExporter


class CdxGraphExporter(GraphExporter, CDXType):
    """Base class for exporters processing an SPDX SBOM"""

    def __init__(self, document: Bom):
        self.document = document

    @staticmethod
    def _strip_id_prefix(bom_ref: BomRef) -> str:
        return bom_ref.value.replace(CDX_REF_PREFIX, "")


class CdxGraphMLExporter(GraphMLExporter, CdxGraphExporter):
    def get_document_id(self):
        return f"sbom-{self.document.serial_number}"

    def add_keys(self, graphml: ET.Element):
        def add_key(name, _type, _for):
            ET.SubElement(
                graphml,
                "key",
                {
                    "id": f"d_{name}",
                    "for": _for,
                    "attr.name": name,
                    "attr.type": _type,
                },
            )

        add_key("name", "string", "node")
        add_key("version", "string", "node")
        add_key("purl", "string", "node")
        add_key("type", "string", "node")

    def add_packages(self, graph: ET.Element):
        for p in self.document.components:
            node = ET.SubElement(
                graph,
                "node",
                {
                    "id": self._strip_id_prefix(p.bom_ref),
                },
            )
            ET.SubElement(node, "data", {"key": "d_name"}).text = p.name
            ET.SubElement(node, "data", {"key": "d_version"}).text = p.version
            ET.SubElement(node, "data", {"key": "d_purl"}).text = str(p.purl)
            ET.SubElement(node, "data", {"key": "d_type"}).text = p.type

    def add_dependencies(self, graph: ET.Element):
        for r in self.document.dependencies:
            if r.ref == self.document.metadata.component.bom_ref:
                continue
            for d in r.dependencies_as_bom_refs():
                _from = self._strip_id_prefix(r.ref)
                _to = self._strip_id_prefix(d)
                ET.SubElement(
                    graph,
                    "edge",
                    {
                        "source": _from,
                        "target": _to,
                        "id": f"{_from}--{_to}",
                    },
                )
