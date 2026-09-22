# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

import logging
import json
import re

from ..dpkg.package import Package
from ..graph.walker import PackageRepr
from .output import SbomOutput
from .input import SbomInput, SourceBinaryInput
from ..sbom import Reference, SBOMType

logger = logging.getLogger(__name__)

SOURCE_NAME_RE = re.compile(r"[a-z0-9][a-z0-9+.-]+")


class FilterCmd(SbomInput, SourceBinaryInput):
    """Filter SBOMs."""

    @classmethod
    def run(cls, args):
        resolvers = cls.get_sbom_resolvers(args)
        patterns = args.exclude_binary or []
        source_file = args.exclude_source_file
        sources = cls.read_source_exclusions(source_file) if source_file else []
        exclusions = bool(patterns or source_file)
        if args.json and args.bomout == "-":
            raise ValueError("--json requires an SBOM output file to keep the report separate")
        if exclusions:
            if args.package:
                raise ValueError("--package cannot be combined with exclusions")
            if any(r.sbom_type() != SBOMType.CycloneDX for r in resolvers):
                raise ValueError("package exclusions currently require a CycloneDX SBOM")

        def get_package_repr(sbom_type: SBOMType) -> tuple[PackageRepr, str]:
            candidates = list(
                filter(lambda c: c.is_binary(), resolver.component_by_name(args.package))
            )
            if not len(candidates):
                raise ValueError(f"no binary package can be found for name {args.package}")
            else:
                chosen = candidates[0]
                purl = chosen.purl()
                if len(candidates) > 1:
                    logger.warning(
                        f"multiple binary packages match given package name, choosing '{purl}'"
                    )
            if sbom_type == SBOMType.SPDX:
                return (
                    PackageRepr(
                        name=chosen.name,
                        ref=str(Reference.make_from_pkg(chosen).as_str(sbom_type)),
                    ),
                    purl,
                )
            elif sbom_type == SBOMType.CycloneDX:
                return (
                    PackageRepr(
                        name=chosen.name,
                        ref=str(purl),
                    ),
                    purl,
                )

        for resolver in resolvers:
            if exclusions:
                from ..filter.cdx import CdxSbomFilter

                report = CdxSbomFilter.exclude(
                    resolver.document, binary_patterns=patterns, source_packages=sources
                )
                logger.info(
                    "Excluded %d binaries and %d sources",
                    len(report["removed_binaries"]),
                    len(report["removed_sources"]),
                )
            if args.package:
                if resolver.sbom_type() == SBOMType.CycloneDX:
                    from ..filter.cdx import CdxSbomFilter
                    from ..graph.cdx import CdxGraphWalker

                    walker = CdxGraphWalker(resolver.document)
                    root_repr, purl = get_package_repr(SBOMType.CycloneDX)
                    CdxSbomFilter.packages(
                        resolver.document, root_repr, list(walker.descendants(purl))
                    )
                elif resolver.sbom_type() == SBOMType.SPDX:
                    from ..filter.spdx import SpdxSbomFilter
                    from ..graph.spdx import SpdxGraphWalker

                    walker = SpdxGraphWalker(resolver.document)
                    root_repr, purl = get_package_repr(SBOMType.SPDX)
                    SpdxSbomFilter.packages(
                        resolver.document, root_repr, list(walker.descendants(purl))
                    )

            cls.filter_binary_source(resolver, args.sources, args.binaries)
            SbomOutput.write_out_arg(
                resolver.document, resolver.sbom_type(), args.bomout, args.validate
            )
            if exclusions and args.json:
                print(json.dumps(report))

    @staticmethod
    def read_source_exclusions(filename) -> list[tuple[str, str]]:
        """Read exact source names and versions using universal package ingress."""
        sources = []
        with open(filename, "rb") as stream:
            try:
                for package in Package.parse_pkglist_stream(stream):
                    if not package.is_source():
                        continue
                    version = str(package.version)
                    if not SOURCE_NAME_RE.fullmatch(package.name) or not re.match(
                        r"[0-9]", version
                    ):
                        raise ValueError("source exclusions require a valid name and exact version")
                    entry = (package.name, version)
                    if entry not in sources:
                        sources.append(entry)
            except ValueError as error:
                raise ValueError(f"{filename}: invalid source package input: {error}") from error
        return sources

    @classmethod
    def setup_parser(cls, parser):
        from ..cli import arg_mark_as_file

        cls.parser_add_sbom_input_args(parser, required=True)
        cls.parser_add_source_binary_args(parser)
        arg_mark_as_file(
            parser.add_argument("bomout", help="sbom output file. Use '-' to write to stdout")
        )
        parser.add_argument(
            "--validate",
            help="validate generated SBOM (only for SPDX)",
            action="store_true",
        )
        parser.add_argument(
            "-p",
            "--package",
            type=str,
            help="filter the SBOM by only including the package and its dependency subgraph",
        )

        parser.add_argument(
            "--exclude-binary",
            action="append",
            metavar="REGEX",
            help="exclude binary packages whose entire Debian name matches REGEX; repeatable",
        )
        arg_mark_as_file(
            parser.add_argument(
                "--exclude-source-file",
                metavar="FILE",
                help="exclude exact source packages from universal package input",
            )
        )
