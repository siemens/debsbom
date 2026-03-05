# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Iterable
import dataclasses
from enum import Enum
import json

from packageurl import PackageURL

from ..tracepath.walker import PackageRepr
from .input import SbomInput


class PathOutputFormat(Enum):
    """Enum of supported path formats"""

    TEXT = (0,)
    JSON = (1,)
    REFERENCE = (2,)

    @classmethod
    def from_str(cls, name: str) -> "PathOutputFormat":
        match name.lower():
            case "text":
                return cls.TEXT
            case "json":
                return cls.JSON
            case "ref":
                return cls.REFERENCE
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
    def setup_parser(cls, parser):
        cls.parser_add_sbom_input_args(parser)
        parser.add_argument("source", type=str, help="source node (PURL)")
        parser.add_argument(
            "--format",
            help="path output format (default: %(default)s)",
            choices=["text", "json", "ref"],
            default="text",
        )
        parser.add_argument(
            "--mode", choices=["shortest", "all-shortest", "all"], default="shortest"
        )
