# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from ..compare.compare import SbomComparator
from .output import SbomOutput
from .input import GenerateInput, SbomInput
from ..bomreader.bomreader import BomReader


class CompareCmd(GenerateInput, SbomInput):
    """
    Compare two SBOMs and generate a new SBOM containing only the additional components found in the target
    """

    @classmethod
    def run(cls, args):
        readers = cls.create_sbom_processors(
            args, BomReader, sbom_args=["base_sbom", "target_sbom"], sbom_allow_multiple=True
        )
        if len(readers) != 2:
            raise ValueError("can only compare exactly two SBOMs")

        sbom_types = set([r.sbom_type() for r in readers])
        if len(sbom_types) > 1:
            raise ValueError("can not compare mixed SPDX and CycloneDX documents")
        sbom_type = readers[0].sbom_type()

        docs = [r.read() for r in readers]

        sbom_comparator = SbomComparator.create(
            sbom_type=sbom_type,
            distro_name=args.distro_name,
            distro_supplier=args.distro_supplier,
            distro_version=args.distro_version,
            base_distro_vendor=args.base_distro_vendor,
            spdx_namespace=args.spdx_namespace,
            cdx_serialnumber=args.cdx_serialnumber,
            timestamp=args.timestamp,
        )
        bom = sbom_comparator.compare(base_sbom=docs[0], target_sbom=docs[1])
        SbomOutput.write_out_arg(bom, sbom_type, args.out, args.validate)

    @classmethod
    def setup_parser(cls, parser):
        cls.parser_add_generate_input_args(parser, default_out="extras")
        cls.parser_add_sbom_input_args(
            parser, required=True, sbom_args=["base_sbom", "target_sbom"]
        )
