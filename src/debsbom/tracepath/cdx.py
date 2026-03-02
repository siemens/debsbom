# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Iterable

from cyclonedx.model.bom import Bom, BomRef
from cyclonedx.model.component import Component
from packageurl import PackageURL
import networkx as nx

from ..resolver.cdx import CdxPackageResolver
from ..sbom import CDXType
from .walker import GraphWalker, PackageRepr


class CdxGraphWalker(GraphWalker, CDXType):
    def __init__(self, document: Bom):
        self.document = document
        self.graph = nx.DiGraph()
        self.component_map = {}
        self._import()

    def _import(self) -> None:
        document = self.document
        root = document.metadata.component

        self.graph.add_node(root)
        self.component_map[root.bom_ref] = root
        for c in document.components:
            self.graph.add_node(c.bom_ref)
            self.component_map[c.bom_ref] = c

        for source in document.dependencies:
            for target in source.dependencies:
                # add edge in reverse as we want to find a path
                # to the root component
                self.graph.add_edge(target.ref, source.ref)

    def _source_node_from_purl(self, purl: PackageURL) -> Component:
        try:
            src = next(filter(lambda p: p.purl == purl, self.document.components))
        except StopIteration:
            raise RuntimeError(f"Component with PURL {str(purl)} not found")
        return src

    def _to_package_repr(self, path: list[BomRef]) -> list[PackageRepr]:
        def convert(bom_ref):
            c = self.component_map.get(bom_ref)
            p = PackageRepr(
                name=c.name, ref=str(bom_ref), maintainer=CdxPackageResolver.get_maintainer(c)
            )
            if CdxPackageResolver.is_debian_pkg(c):
                _p = CdxPackageResolver.create_package(c)
                p.name = _p.name
                p.version = str(_p.version)
                p.maintainer = _p.maintainer
                p.purl = str(_p.purl())
            return p

        return list(map(convert, path))

    def shortest(self, source: PackageURL) -> list[PackageRepr]:
        src = self._source_node_from_purl(source)
        dst = self.document.metadata.component
        path = nx.shortest_path(self.graph, source=src.bom_ref, target=dst.bom_ref)
        return self._to_package_repr(path)

    def all_shortest(self, source: PackageURL) -> Iterable[list[PackageRepr]]:
        src = self._source_node_from_purl(source)
        dst = self.document.metadata.component
        paths = nx.all_shortest_paths(self.graph, source=src.bom_ref, target=dst.bom_ref)
        yield from map(self._to_package_repr, paths)

    def all_simple(self, source: PackageURL) -> Iterable[list[PackageRepr]]:
        src = self._source_node_from_purl(source)
        dst = self.document.metadata.component
        paths = nx.all_simple_paths(self.graph, source=src.bom_ref, target=dst.bom_ref)
        yield from map(self._to_package_repr, paths)
