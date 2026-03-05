# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Iterable
import dataclasses
from enum import Enum
import json
import sys
from typing import TextIO

from packageurl import PackageURL

from ..tracepath.walker import PackageRepr
from .input import SbomInput


class PathOutputFormat(Enum):
    """Enum of supported path formats"""

    TEXT = (0,)
    JSON = (1,)
    REFERENCE = (2,)
    DOT = (3,)

    @classmethod
    def from_str(cls, name: str) -> "PathOutputFormat":
        match name.lower():
            case "text":
                return cls.TEXT
            case "json":
                return cls.JSON
            case "ref":
                return cls.REFERENCE
            case "dot":
                return cls.DOT
            case _:
                raise RuntimeError(f"Unsupported output format: '{name}'")


class TracePathCmd(SbomInput):
    """
    Processes an SBOM and a package identifier and emits paths
    from this package to the root. The textual outputs (text and ref)
    are not considered stable and should not be parsed. The JSON output
    is in json-lines format, whereby each line adheres to the
    ``schema-download.json`` schema.
    """

    @classmethod
    def run(cls, args):
        from ..tracepath.walker import GraphWalker

        if args.json:
            format = PathOutputFormat.JSON
        else:
            format = PathOutputFormat.from_str(args.format)

        walkers: list[GraphWalker] = cls.create_sbom_processors(args, GraphWalker)
        source = PackageURL.from_string(args.source)
        for walker in walkers:
            if args.mode == "all-shortest":
                paths = walker.all_shortest(source)
            elif args.mode == "all":
                paths = walker.all_simple(source)
            elif args.mode == "shortest":
                paths = [walker.shortest(source)]
            if format == PathOutputFormat.DOT:
                cls.dump_as_dot_graph(paths, sys.stdout)
            else:
                for p in paths:
                    for cp in cls.iter_component_path(p, format):
                        print(cp)

    @classmethod
    def iter_component_path(
        cls, path: list[PackageRepr], format: PathOutputFormat
    ) -> Iterable[str]:
        json_path = []
        for p in path:
            if format == PathOutputFormat.REFERENCE:
                yield p.ref
            elif format == PathOutputFormat.TEXT:
                yield str(p)
            elif format == PathOutputFormat.JSON:
                json_path.append(dataclasses.asdict(p))

        if format == PathOutputFormat.JSON:
            yield json.dumps(json_path)

    @classmethod
    def dump_as_dot_graph(cls, paths: Iterable[list[PackageRepr]], out):
        def make_name(n):
            return f"{n.name}@{n.version}" if n.version else n.name

        nodes = set()
        edges = set()
        for p in paths:
            nodes.update(p)
            for i in range(len(p) - 1):
                edges.add((p[i], p[i + 1]))

        # Create mapping from PackageRepr to node ID
        node_to_id = {n: i for i, n in enumerate(nodes)}
        nodes_defs = [
            f'{i} [label="{make_name(n)}\\n{n.maintainer}"]' for (i, n) in enumerate(nodes)
        ]
        edges_defs = [f"{node_to_id[src]} -> {node_to_id[dst]};" for (src, dst) in edges]

        out.write("digraph\n{\n")
        for n in nodes_defs:
            out.write(f"\t{n}\n")
        for e in edges_defs:
            out.write(f"\t{e}\n")
        out.write("}\n")

    @classmethod
    def setup_parser(cls, parser):
        cls.parser_add_sbom_input_args(parser)
        parser.add_argument("source", type=str, help="source node (PURL)")
        parser.add_argument(
            "--format",
            help="path output format (default: %(default)s)",
            choices=["text", "json", "ref", "dot"],
            default="text",
        )
        parser.add_argument(
            "--mode", choices=["shortest", "all-shortest", "all"], default="shortest"
        )
