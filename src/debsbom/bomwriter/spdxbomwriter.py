# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

import os.path
import sys
from io import TextIOWrapper
from pathlib import Path

import spdx_tools.spdx.formats as spdx_formats
import spdx_tools.spdx.writer.write_anything as spdx_write_anything
import spdx_tools.spdx3.payload as spdx3_payload
import spdx_tools.spdx3.validation.json_ld.shacl_validation as spdx3_json_shacl_validation
import spdx_tools.spdx3.writer.json_ld.json_ld_writer as spdx3_json_ld_writer
from spdx_tools.spdx.writer.json import json_writer
from spdx_tools.spdx.writer.rdf import rdf_writer
from spdx_tools.spdx.writer.tagvalue import tagvalue_writer
from spdx_tools.spdx.writer.xml import xml_writer
from spdx_tools.spdx.writer.yaml import yaml_writer

from ..sbom import SPDXType
from .bomwriter import BomWriter, SerializerOpts

output_format_map: dict[str, spdx_formats.FileFormat] = {
    "rdf": spdx_formats.FileFormat.RDF_XML,
    "rdf.xml": spdx_formats.FileFormat.RDF_XML,
    "tag": spdx_formats.FileFormat.TAG_VALUE,
    "spdx": spdx_formats.FileFormat.TAG_VALUE,
    "json": spdx_formats.FileFormat.JSON,
    "xml": spdx_formats.FileFormat.XML,
    "yaml": spdx_formats.FileFormat.YAML,
    "yml": spdx_formats.FileFormat.YAML,
}


class SpdxSerializerOpts(SerializerOpts):
    def __init__(self, **kwargs):
        of = kwargs.get("spdx_output_format", None)
        self.output_format: spdx_formats.FileFormat | None = output_format_map.get(of, None)


class SpdxBomWriter(BomWriter, SPDXType):
    @staticmethod
    def write_to_file(bom, filename: Path, validate: bool, opts: SpdxSerializerOpts | None = None):
        filename_str = str(filename)
        if isinstance(bom, spdx3_payload.Payload):
            # spdx_tools.spdx3 wants to call the file xxx.jsonld
            filename_str = filename_str.rstrip(".json")
            spdx3_json_ld_writer.write_payload(bom, filename_str)
            if validate:

                # validation fails -- spdx_tools migh not be fully fleshed out
                conforms, report_graph, report_text = (
                    spdx3_json_shacl_validation.validate_against_shacl_from_file(
                        data_file=filename_str + ".jsonld",
                        shacl_file=os.path.dirname(
                            sys.modules["spdx_tools.spdx3.writer.json_ld"].__file__
                        )
                        + "/"
                        + "model.ttl",
                    )
                )
                if not conforms:
                    raise ValueError(
                        f"Document is not valid. The following errors were detected: {report_text}"
                    )
        else:
            if opts is None or opts.output_format is None:
                spdx_write_anything.write_file(bom, filename_str, validate)
            elif opts.output_format == spdx_formats.FileFormat.JSON:
                json_writer.write_document_to_file(bom, filename_str, validate)
            elif opts.output_format == spdx_formats.FileFormat.YAML:
                yaml_writer.write_document_to_file(bom, filename_str, validate)
            elif opts.output_format == spdx_formats.FileFormat.XML:
                xml_writer.write_document_to_file(bom, filename_str, validate)
            elif opts.output_format == spdx_formats.FileFormat.TAG_VALUE:
                tagvalue_writer.write_document_to_file(bom, filename_str, validate)
            elif opts.output_format == spdx_formats.FileFormat.RDF_XML:
                rdf_writer.write_document_to_file(bom, filename_str, validate)

    @staticmethod
    def write_to_stream(
        bom, f: TextIOWrapper, validate: bool, opts: SpdxSerializerOpts | None = None
    ):
        if isinstance(bom, spdx3_payload.Payload):
            raise NotImplementedError("spdx_tools.spdx3 cannot write to a stream")

        if opts is None:
            opts = SpdxSerializerOpts(spdx_output_format=spdx_formats.FileFormat.JSON)
        elif opts.output_format is None:
            opts.output_format = spdx_formats.FileFormat.JSON
        if opts.output_format == spdx_formats.FileFormat.JSON:
            json_writer.write_document_to_stream(bom, f, validate)
        elif opts.output_format == spdx_formats.FileFormat.YAML:
            yaml_writer.write_document_to_stream(bom, f, validate)
        elif opts.output_format == spdx_formats.FileFormat.XML:
            xml_writer.write_document_to_stream(bom, f, validate)
        elif opts.output_format == spdx_formats.FileFormat.TAG_VALUE:
            tagvalue_writer.write_document_to_stream(bom, f, validate)
        elif opts.output_format == spdx_formats.FileFormat.RDF_XML:
            rdf_writer.write_document_to_stream(bom, f, validate)
        f.write("\n")
