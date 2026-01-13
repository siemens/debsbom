# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from .output import SbomOutput
from ..bomreader.bomreader import BomReader
from .input import GenerateInput, SbomInput
from ..sbom import SBOMType
from ..util.progress import progress_cb


class MergeCmd(GenerateInput, SbomInput):
    """Merge multiple SBOMs into a single one."""

    @classmethod
    def run(cls, args):
        readers = cls.create_sbom_processors(
            args, BomReader, sbom_args=["sboms"], sbom_allow_multiple=True
        )
        sbom_types = set([r.sbom_type() for r in readers])
        if len(sbom_types) > 1:
            raise ValueError("can not merge mixed SPDX and CycloneDX documents")
        sbom_type = readers[0].sbom_type()

        docs = [r.read() for r in readers]
        if sbom_type == SBOMType.SPDX:
            SBOMType.SPDX.validate_dependency_availability()
            from ..merge.spdx import SpdxSbomMerger

            sbom_merger = SpdxSbomMerger(
                distro_name=args.distro_name,
                distro_supplier=args.distro_supplier,
                distro_version=args.distro_version,
                base_distro_vendor=args.base_distro_vendor,
                spdx_namespace=args.spdx_namespace,
                cdx_serialnumber=args.cdx_serialnumber,
                timestamp=args.timestamp,
            )
            bom = sbom_merger.merge(docs, progress_cb=progress_cb if args.progress else None)
            SbomOutput.write_out_arg(bom, sbom_type, args.out, args.validate)
        elif sbom_type == SBOMType.CycloneDX:
            SBOMType.CycloneDX.validate_dependency_availability()
            from ..merge.cdx import CdxSbomMerger

            sbom_merger = CdxSbomMerger(
                distro_name=args.distro_name,
                distro_supplier=args.distro_supplier,
                distro_version=args.distro_version,
                base_distro_vendor=args.base_distro_vendor,
                spdx_namespace=args.spdx_namespace,
                cdx_serialnumber=args.cdx_serialnumber,
                timestamp=args.timestamp,
            )
            bom = sbom_merger.merge(docs, progress_cb=progress_cb if args.progress else None)
            SbomOutput.write_out_arg(bom, sbom_type, args.out, args.validate)

    @classmethod
    def setup_parser(cls, parser):
        cls.parser_add_generate_input_args(parser, default_out="merged")
        cls.parser_add_sbom_input_args(parser, required=True, sbom_args=["sboms"], multi_input=True)
