# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

import logging

from ..graph.walker import PackageRepr
from .output import SbomOutput
from .input import SbomInput, SourceBinaryInput
from ..sbom import Reference, SBOMType

logger = logging.getLogger(__name__)


class FilterCmd(SbomInput, SourceBinaryInput):
    """Filter SBOMs."""

    @classmethod
    def run(cls, args):
        resolvers = cls.get_sbom_resolvers(args)

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
