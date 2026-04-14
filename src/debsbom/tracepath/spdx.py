# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Iterable
import logging

import networkx as nx
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.relationship import RelationshipType
from spdx_tools.spdx.model.package import Package, PackagePurpose
from packageurl import PackageURL

from ..resolver.spdx import SpdxPackageResolver
from ..sbom import SPDXType
from .walker import GraphWalker, NoRootNodeError, PackageRepr

logger = logging.getLogger(__name__)


class SpdxGraphWalker(GraphWalker, SPDXType):
    def __init__(self, document: Document):
        self.document = document
        self.graph = nx.DiGraph()
        self.component_map = {}
        self._import()
        self._locate_root()

    def _import(self) -> None:
        document = self.document

        for c in document.packages:
            self.graph.add_node(c.spdx_id)
            self.component_map[c.spdx_id] = c

        for r in document.relationships:
            if r.relationship_type in (
                RelationshipType.DEPENDS_ON,
                RelationshipType.GENERATED_FROM,
            ):
                # add edge in reverse as we want to find a path to the root component
                self.graph.add_edge(r.related_spdx_element_id, r.spdx_element_id)
            elif r.relationship_type in (
                RelationshipType.PACKAGE_OF,
                RelationshipType.GENERATES,
            ):
                self.graph.add_edge(r.spdx_element_id, r.related_spdx_element_id)

    def _locate_root(self):
        root_candidates = [
            node
            for node, degree in self.graph.out_degree()
            if degree == 0
            and self.component_map[node].primary_package_purpose == PackagePurpose.OPERATING_SYSTEM
        ]
        if not root_candidates:
            raise NoRootNodeError()
        if len(root_candidates) > 1:
            logger.warning("SBOM has multiple root nodes, choose %s", root_candidates[0])
        self.root = self.component_map.get(root_candidates[0])

    def _source_node_from_purl(self, purl: PackageURL) -> Package:
        for p in self.document.packages:
            pm = SpdxPackageResolver.package_manager_ref(p)
            if not pm:
                continue
            src = PackageURL.from_string(pm.locator)
            if src == purl:
                return p
        raise RuntimeError(f"Component with PURL {str(purl)} not found")

    def _to_package_repr(self, path: list[str]) -> list[PackageRepr]:
        def convert(spdx_id):
            c = self.component_map.get(spdx_id)
            p = PackageRepr(
                name=c.name,
                ref=spdx_id,
                maintainer=SpdxPackageResolver.get_maintainer(c),
                version=c.version,
            )
            if SpdxPackageResolver.is_debian_pkg(c):
                _p = SpdxPackageResolver.create_package(c)
                p.name = _p.name
                p.version = str(_p.version)
                p.maintainer = _p.maintainer
                p.purl = str(_p.purl())
            return p

        return list(map(convert, path))

    def shortest(self, source: PackageURL) -> list[PackageRepr]:
        src = self._source_node_from_purl(source)
        path = nx.shortest_path(self.graph, source=src.spdx_id, target=self.root.spdx_id)
        return self._to_package_repr(path)

    def all_shortest(self, source: PackageURL) -> Iterable[list[PackageRepr]]:
        src = self._source_node_from_purl(source)
        paths = nx.all_shortest_paths(self.graph, source=src.spdx_id, target=self.root.spdx_id)
        yield from map(self._to_package_repr, paths)

    def all_simple(self, source: PackageURL) -> Iterable[list[PackageRepr]]:
        src = self._source_node_from_purl(source)
        paths = nx.all_simple_paths(self.graph, source=src.spdx_id, target=self.root.spdx_id)
        yield from map(self._to_package_repr, paths)
