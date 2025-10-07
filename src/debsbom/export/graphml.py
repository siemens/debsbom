# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from abc import abstractmethod
from typing import IO
import xml.etree.ElementTree as ET


class GraphMLExporter:
    """
    Base class for exporting a graph as GraphML.
    Implementations need to provide add_keys, add_packages and add_dependencies.
    """

    def get_document_id(self) -> str:
        return "sbom"

    def _create_root_node(self):
        root = ET.Element(
            "graphml",
            {
                "xmlns": "http://graphml.graphdrawing.org/xmlns",
                "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
                "xsi:schemaLocation": "http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd",
            },
        )
        self.add_keys(root)
        self._add_graph_node(root)
        return root

    def _add_graph_node(self, root):
        graph = ET.SubElement(
            root,
            "graph",
            {
                "id": self.get_document_id(),
                "edgedefault": "directed",
            },
        )
        self.add_packages(graph)
        self.add_dependencies(graph)
        return root

    def export(self, output: IO):
        root = self._create_root_node()
        tree = ET.ElementTree(root)
        ET.indent(tree, level=0)
        tree.write(output, xml_declaration=True, encoding="unicode")
        output.write("\n")
        output.flush()

    @abstractmethod
    def add_keys(self, graphml: ET.Element):
        """Add the graphml keys. Abstract method."""
        raise NotImplementedError()

    @abstractmethod
    def add_packages(self, graph: ET.Element):
        """Add all packages from the sbom as nodes. Abstract method."""
        raise NotImplementedError()

    @abstractmethod
    def add_dependencies(self, graph: ET.Element):
        """Add the inter-package dependencies as edges. Abstract method."""
        raise NotImplementedError()
