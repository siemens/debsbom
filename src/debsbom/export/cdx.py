# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import xml.etree.ElementTree as ET
from cyclonedx.model.bom import Bom, BomRef, Component, Dependency

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
    _components: dict[BomRef, Component] = {}

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
        add_key("section", "string", "node")
        add_key("essential", "string", "node")
        add_key("reltype", "string", "edge")

    def _add_package(self, graph: ET.Element, p: Component):
        self._components[p.bom_ref] = p
        node = ET.SubElement(
            graph,
            "node",
            {
                "id": self._strip_id_prefix(p.bom_ref),
            },
        )
        ET.SubElement(node, "data", {"key": "d_name"}).text = p.name
        ET.SubElement(node, "data", {"key": "d_version"}).text = p.version
        ET.SubElement(node, "data", {"key": "d_purl"}).text = str(p.purl or "")
        ET.SubElement(node, "data", {"key": "d_type"}).text = p.type
        section = "unknown"
        essential = "unknown"
        for prop in p.properties:
            if prop.name == "section":
                section = prop.value
            elif prop.name == "essential":
                essential = prop.value

        ET.SubElement(node, "data", {"key": "d_section"}).text = section
        ET.SubElement(node, "data", {"key": "d_essential"}).text = essential

    def _component_arch(self, dep: Dependency) -> str | None:
        comp = self._components[dep.ref]
        if comp.purl:
            return comp.purl.qualifiers.get("arch")
        return None

    def add_packages(self, graph: ET.Element):
        self._add_package(graph, self.document.metadata.component)
        for p in self.document.components:
            self._add_package(graph, p)

    def add_dependencies(self, graph: ET.Element):
        for source in self.document.dependencies:
            for target in source.dependencies:
                _from = self._strip_id_prefix(source.ref)
                _to = self._strip_id_prefix(target.ref)

                # reconstruct relation types from bomref and map similar to SPDX
                if self._component_arch(target) == "source":
                    reltype = "generates"
                    _from, _to = _to, _from
                elif not self._component_arch(source):
                    reltype = "package_of"
                    _from, _to = _to, _from
                else:
                    reltype = "depends_on"

                edge = ET.SubElement(
                    graph,
                    "edge",
                    {
                        "source": _from,
                        "target": _to,
                        "id": f"{_from}--{_to}",
                    },
                )
                ET.SubElement(edge, "data", {"key": "d_reltype"}).text = str(reltype)
