# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Iterable
from pathlib import Path

from ..bomreader import BomReader
from ..transform import BomTransformer
from ..sbom import SBOMType


class Enricher(BomTransformer):
    """
    Enriches an SBOM with additional information.
    """

    def __init__(
        self,
        document,
        with_checksums: bool,
        with_omniborid: bool,
        with_swhid: bool,
        with_download_loc: bool,
    ):
        self._document = document
        self.with_checksums = with_checksums
        self.with_omniborid = with_omniborid
        self.with_swhid = with_swhid
        self.with_download_loc = with_download_loc

    @staticmethod
    def create_from_reader(
        reader: BomReader,
        with_checksums: bool,
        with_omniborid: bool,
        with_swhid: bool,
        with_download_loc: bool,
    ) -> "Enricher":
        if reader.sbom_type() == SBOMType.SPDX:
            from .spdx import SpdxEnricher

            return SpdxEnricher(
                reader.document, with_checksums, with_omniborid, with_swhid, with_download_loc
            )
        elif reader.sbom_type() == SBOMType.CycloneDX:
            from .cdx import CdxEnricher

            return CdxEnricher(
                reader.document, with_checksums, with_omniborid, with_swhid, with_download_loc
            )
        else:
            raise ValueError("unknown SBOM type")

    def incomplete_components(self, component) -> Iterable:
        """
        Returns an iterator of incomplete packages/components.
        """
        raise NotImplementedError()

    def enrich_component(component, artifacts: list[(Path, str | None)]):
        """Enriches a package/component with information from the given artifacts."""
        raise NotImplementedError()
