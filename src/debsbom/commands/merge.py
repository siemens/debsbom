# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import json
from pathlib import Path
import sys

from ..bomwriter import BomWriter
from .input import GenerateInput, SbomInput, warn_if_tty
from ..sbom import SBOMType
from ..util.progress import progress_cb


class MergeCmd(GenerateInput, SbomInput):
    """Merge multiple SBOMs into a single one."""

    @staticmethod
    def run(args):
        spdx_paths = []
        cdx_paths = []
        json_sboms = []
        for sbom in args.sboms:
            if sbom == "-":
                warn_if_tty()
                if args.sbom_type is None:
                    raise ValueError("option --sbom-type is required when reading SBOMs from stdin")
                decoder = json.JSONDecoder()
                s = sys.stdin.read()
                len_s = len(s)
                read_total = 0
                while read_total < len_s:
                    json_obj, read = decoder.raw_decode(s[read_total:])
                    read_total += read
                    json_sboms.append(json_obj)
            else:
                sbom_path = Path(sbom)
                if ".spdx" in sbom_path.suffixes:
                    SBOMType.SPDX.validate_dependency_availability()
                    spdx_paths.append(sbom_path)
                elif ".cdx" in sbom_path.suffixes:
                    SBOMType.CycloneDX.validate_dependency_availability()
                    cdx_paths.append(sbom_path)

        docs = []
        if len(spdx_paths) > 0 and len(cdx_paths) > 0:
            raise ValueError("can not merge mixed SPDX and CycloneDX documents")
        elif len(spdx_paths) > 0 or args.sbom_type == "spdx":
            SBOMType.SPDX.validate_dependency_availability()
            from ..bomreader.spdxbomreader import SpdxBomReader
            from ..merge.spdx import SpdxSbomMerger

            if json_sboms:
                for obj in json_sboms:
                    docs.append(SpdxBomReader.from_json(obj))
            for path in spdx_paths:
                docs.append(SpdxBomReader.read_file(path))
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
            if args.out == "-":
                BomWriter.write_to_stream(bom, SBOMType.SPDX, sys.stdout, args.validate)
            else:
                out = args.out
                if not out.endswith(".spdx.json"):
                    out += ".spdx.json"
                BomWriter.write_to_file(bom, SBOMType.SPDX, Path(out), args.validate)
        elif len(cdx_paths) > 0 or args.sbom_type == "cdx":
            SBOMType.CycloneDX.validate_dependency_availability()
            from ..bomreader.cdxbomreader import CdxBomReader
            from ..merge.cdx import CdxSbomMerger

            if json_sboms:
                for obj in json_sboms:
                    docs.append(CdxBomReader.from_json(obj))
            for path in cdx_paths:
                docs.append(CdxBomReader.read_file(path))
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
            if args.out == "-":
                BomWriter.write_to_stream(bom, SBOMType.CycloneDX, sys.stdout, args.validate)
            else:
                out = args.out
                if not out.endswith(".cdx.json"):
                    out += ".cdx.json"
                BomWriter.write_to_file(bom, SBOMType.CycloneDX, Path(out), args.validate)

    @classmethod
    def setup_parser(cls, parser):
        cls.parser_add_generate_input_args(parser, default_out="merged")
        cls.parser_add_sbom_input_args(parser, required=True, sbom_args=["sboms"], multi_input=True)
