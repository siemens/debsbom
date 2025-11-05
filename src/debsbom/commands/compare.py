# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import json
import os
import uuid
from .input import SbomInput
from datetime import datetime

import logging


logger = logging.getLogger(__name__)


class CompareCmd(SbomInput):
    """
    Compare two SBOMs and generate a new SBOM containing only the additional components found in the target
    """

    @classmethod
    def run(cls, args):
        with open(args.base_sbom) as f:
            base_sbom_data = json.load(f)
        with open(args.target_sbom) as f:
            target_sbom_data = json.load(f)

        base_sbom_fmt = cls.detect_sbom_format(base_sbom_data)
        target_sbom_fmt = cls.detect_sbom_format(target_sbom_data)

        if not base_sbom_fmt or not target_sbom_fmt:
            raise ValueError("can not detect SBOM format for one or both files")

        if base_sbom_fmt != target_sbom_fmt:
            raise ValueError("can not compare mixed SPDX and CycloneDX documents")

        if target_sbom_fmt == "spdx":
            base_sbom_comp, base_sbom = cls.load_spdx_sbom(args.base_sbom)
            target_sbom_comp, target_sbom = cls.load_spdx_sbom(args.target_sbom)
            extra_pkgs = cls.compare_items(base_sbom_comp, target_sbom_comp, "pkg")

            ref_creation_info = base_sbom.get("creationInfo", {
                "creators": ["Tool: sbom-diff-generator 1.0"],
                "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            })
            result = cls.build_extra_spdx(extra_pkgs, ref_creation_info)


        elif target_sbom_fmt == "cdx":
            base_sbom_comp, base_sbom = cls.load_cdx_sbom(args.base_sbom)
            target_sbom_comp, target_sbom = cls.load_cdx_sbom(args.target_sbom)

            extra_components = cls.compare_items(base_sbom_comp, target_sbom_comp, "component")
            result = cls.build_extra_cdx(extra_components, target_sbom)


        else:
            raise ValueError(f"Unsupported SBOM format: {new_fmt}")

        out_dir = os.path.dirname(args.out_file)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)

        with open(args.out_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=4)


    @classmethod
    def detect_sbom_format(cls, data):
        """
        Detect SBOM format based on known top-level keys.
        Returns 'spdx' or 'cdx' or None.
        """
        if "spdxVersion" in data:
            return "spdx"
        if data.get("bomFormat", "").lower() == "cyclonedx":
            return "cdx"
        return None


    @classmethod
    def load_spdx_sbom(cls, path):
        """Return packages keyed by purl or fallback name@version."""
        with open(path) as f:
            data = json.load(f)

        packages = {}
        for pkg in data.get("packages", []):
            purl = next(
                (ref["referenceLocator"]
                 for ref in pkg.get("externalRefs", [])
                 if ref.get("referenceType") == "purl"),
                None
            )
            if not purl:
                version = pkg.get("versionInfo", "")
                purl = f"{pkg.get('name')}@{version}"

            sha256 = next(
                (c["checksumValue"]
                 for c in pkg.get("checksums", [])
                 if c.get("algorithm", "").upper() == "SHA256"),
                None
            )

            packages[purl] = {"pkg": pkg, "sha256": sha256}

        return packages, data


    @classmethod
    def build_extra_spdx(cls, extra_pkgs, ref_creation_info):
        """Build minimal SPDX 2.3 JSON document."""
        return {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "Extra Components SBOM",
            "dataLicense": "CC0-1.0",
            "documentNamespace": f"https://example.org/spdx/extra-{uuid.uuid4()}",
            "creationInfo": ref_creation_info,
            "packages": extra_pkgs
        }


    @classmethod
    def load_cdx_sbom(cls, path):
        """Return components keyed by purl or fallback name@version."""
        with open(path) as f:
            data = json.load(f)

        components = {}
        for comp in data.get("components", []):
            purl = comp.get("purl") or f"{comp.get('name')}@{comp.get('version', '')}"
            sha256 = next(
                (h["content"]
                 for h in comp.get("hashes", [])
                 if h.get("alg", "").upper() == "SHA-256"),
                None
            )
            components[purl] = {"component": comp, "sha256": sha256}

        return components, data


    @classmethod
    def build_extra_cdx(cls, extra_components, new_metadata=None):
        """Build minimal CycloneDX 1.5 JSON SBOM."""
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "components": extra_components
        }
        if new_metadata and "metadata" in new_metadata:
            sbom["metadata"] = new_metadata["metadata"]
        else:
            sbom["metadata"] = {
                "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "tools": [{"name": "sbom-diff-generator", "version": "1.0"}]
            }
        return sbom


    @classmethod
    def compare_items(cls, base_sbom_comp, target_sbom_comp, key_name):
        """Generic comparison for SPDX or CDX items keyed by purl."""
        extra = []
        for key, new_info in target_sbom_comp.items():
            base_info = base_sbom_comp.get(key)
            new_sha = (new_info["sha256"] or "").lower().strip()
            ref_sha = ((base_info or {}).get("sha256") or "").lower().strip()

            if base_info is None or (ref_sha and new_sha and ref_sha != new_sha):
                extra.append(new_info[key_name])
        return extra


    @classmethod
    def setup_parser(cls, parser):
        cls.parser_add_sbom_input_args(parser)
        parser.add_argument(
            "-b",
            "--base-sbom",
            required=True,
            help="Path to the base (reference) SBOM file"
        )

        parser.add_argument(
            "-n",
            "--target-sbom",
            required=True,
            help="Path to the target (new) SBOM file"
        )

        parser.add_argument(
            "-o",
            "--out-file",
            default="uncleared_components.json",
            help="Path to the output JSON file (default: uncleared_components.json)"
        )
