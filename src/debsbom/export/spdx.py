# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import xml.etree.ElementTree as ET
from spdx_tools.spdx.model.document import Document
import spdx_tools.spdx.model.package as spdx_package

from ..sbom import SPDX_REF_PREFIX, SPDXType
from .graphml import GraphMLExporter
from .exporter import GraphExporter


class SpdxGraphExporter(GraphExporter, SPDXType):
    """Base class for exporters processing an SPDX SBOM"""

    def __init__(self, document: Document):
        self.document = document
        self._spdx_to_id = {}

    @staticmethod
    def _get_purl(package: spdx_package.Package) -> str:
        ref = next(
            filter(
                lambda ref: ref.category == spdx_package.ExternalPackageRefCategory.PACKAGE_MANAGER,
                package.external_references,
            ),
            None,
        )
        if ref and ref.reference_type == "purl":
            return ref.locator
        return ""

    @staticmethod
    def _strip_id_prefix(spdx_id: str) -> str:
        return spdx_id.replace(SPDX_REF_PREFIX, "")


class SpdxGraphMLExporter(GraphMLExporter, SpdxGraphExporter):
    def get_document_id(self):
        return f"sbom-{self.document.creation_info.name}"

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
        add_key("purpose", "string", "node")
        add_key("reltype", "string", "edge")

    def add_packages(self, graph: ET.Element):
        for p in self.document.packages:
            node = ET.SubElement(
                graph,
                "node",
                {
                    "id": self._strip_id_prefix(p.spdx_id),
                },
            )
            ET.SubElement(node, "data", {"key": "d_name"}).text = p.name
            ET.SubElement(node, "data", {"key": "d_version"}).text = p.version
            ET.SubElement(node, "data", {"key": "d_purl"}).text = self._get_purl(p)
            ET.SubElement(node, "data", {"key": "d_purpose"}).text = str(
                p.primary_package_purpose.name
            ).lower()

    def add_dependencies(self, graph: ET.Element):
        for r in self.document.relationships:
            if r.spdx_element_id == self.document.creation_info.spdx_id:
                continue
            _from = self._strip_id_prefix(r.spdx_element_id)
            _to = self._strip_id_prefix(r.related_spdx_element_id)
            edge = ET.SubElement(
                graph,
                "edge",
                {
                    "source": _from,
                    "target": _to,
                    "id": f"{_from}--{_to}",
                },
            )
            ET.SubElement(edge, "data", {"key": "d_reltype"}).text = str(
                r.relationship_type.name
            ).lower()
