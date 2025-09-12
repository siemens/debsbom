# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from datetime import datetime, timezone
from importlib.metadata import version
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlparse
from uuid import uuid4

from debsbom.generate import Debsbom, SBOMType


def test_tree_generation():
    url = urlparse("http://example.org")
    uuid = uuid4()
    timestamp = datetime(1970, 1, 1, tzinfo=timezone.utc)

    dbom = Debsbom(
        distro_name="pytest-distro",
        sbom_types=[SBOMType.SPDX, SBOMType.CycloneDX],
        root="tests/root/tree",
        spdx_namespace=url,
        cdx_serialnumber=uuid,
        timestamp=timestamp,
    )

    with TemporaryDirectory() as outdir:
        outdir = Path(outdir)
        dbom.generate(str(outdir / "sbom"), validate=True)
        with open(outdir / "sbom.spdx.json") as file:
            spdx_json = json.loads(file.read())
            assert spdx_json["SPDXID"] == "SPDXRef-DOCUMENT"
            assert spdx_json["creationInfo"] == {
                "created": timestamp.isoformat().replace("+00:00", "Z"),
                "creators": ["Tool: debsbom-{}".format(version("debsbom"))],
            }
            assert spdx_json["documentNamespace"] == "http://example.org"
            assert len(spdx_json["packages"]) == 21
            assert len(spdx_json["relationships"]) == 66
        with open(outdir / "sbom.cdx.json") as file:
            cdx_json = json.loads(file.read())
            assert len(cdx_json["components"]) == 21 - 7  # 6 source packages, 1 distro package
            deps_total = 0
            for dep_entry in cdx_json["dependencies"]:
                if dep_entry.get("dependsOn"):
                    deps_total += len(dep_entry["dependsOn"])
            assert deps_total == 66 - 15  # 1 distro package, 14 binary<->src
            assert cdx_json["serialNumber"] == "urn:uuid:{}".format(uuid)


def test_dependency_generation():
    url = urlparse("http://example.org")
    uuid = uuid4()
    timestamp = datetime(1970, 1, 1, tzinfo=timezone.utc)

    dbom = Debsbom(
        distro_name="pytest-distro",
        sbom_types=[SBOMType.SPDX, SBOMType.CycloneDX],
        root="tests/root/dependency",
        spdx_namespace=url,
        cdx_serialnumber=uuid,
        timestamp=timestamp,
    )
    with TemporaryDirectory() as outdir:
        outdir = Path(outdir)
        dbom.generate(str(outdir / "sbom"), validate=True)
        with open(outdir / "sbom.spdx.json") as file:
            spdx_json = json.loads(file.read())
            relationships = spdx_json["relationships"]
            assert relationships[0] == {
                "spdxElementId": "SPDXRef-libc6-amd64",
                "relatedSpdxElement": "SPDXRef-pytest-distro",
                "relationshipType": "PACKAGE_OF",
            }
            assert relationships[1] == {
                "spdxElementId": "SPDXRef-libc6-amd64",
                "relatedSpdxElement": "SPDXRef-libgcc-s1-amd64",
                "relationshipType": "DEPENDS_ON",
            }
            assert relationships[2] == {
                "spdxElementId": "SPDXRef-glibc-2.36-9.deb12u10-srcpkg",
                "relatedSpdxElement": "SPDXRef-libc6-amd64",
                "relationshipType": "GENERATES",
            }
            assert relationships[3] == {
                "spdxElementId": "SPDXRef-libgcc-s1-amd64",
                "relatedSpdxElement": "SPDXRef-pytest-distro",
                "relationshipType": "PACKAGE_OF",
            }
            assert relationships[4] == {
                "spdxElementId": "SPDXRef-libgcc-s1-amd64",
                "relatedSpdxElement": "SPDXRef-libc6-amd64",
                "relationshipType": "DEPENDS_ON",
            }
            assert relationships[5] == {
                "spdxElementId": "SPDXRef-gcc-12-12.2.0-14.deb12u1-srcpkg",
                "relatedSpdxElement": "SPDXRef-libgcc-s1-amd64",
                "relationshipType": "GENERATES",
            }
            assert relationships[6] == {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": "SPDXRef-pytest-distro",
                "relationshipType": "DESCRIBES",
            }
        with open(outdir / "sbom.cdx.json") as file:
            cdx_json = json.loads(file.read())
            deps = cdx_json["dependencies"]
            assert deps[0] == {
                "dependsOn": ["CDXRef-libgcc-s1-amd64"],
                "ref": "CDXRef-libc6-amd64",
            }
            assert deps[1] == {
                "dependsOn": ["CDXRef-libc6-amd64"],
                "ref": "CDXRef-libgcc-s1-amd64",
            }
            assert deps[2] == {
                "dependsOn": ["CDXRef-libc6-amd64", "CDXRef-libgcc-s1-amd64"],
                "ref": "CDXRef-pytest-distro",
            }


def test_homepage_regression():
    url = urlparse("http://example.org")
    uuid = uuid4()
    timestamp = datetime(1970, 1, 1, tzinfo=timezone.utc)

    dbom = Debsbom(
        distro_name="pytest-distro",
        sbom_types=[SBOMType.SPDX, SBOMType.CycloneDX],
        root="tests/root/homepage-lowercase",
        spdx_namespace=url,
        cdx_serialnumber=uuid,
        timestamp=timestamp,
    )

    with TemporaryDirectory() as outdir:
        outdir = Path(outdir)
        dbom.generate(str(outdir / "sbom"), validate=True)
        # if we get here the validation should have caught uppercase letters
        # in the hostname, but we make sure it is lowercase nonetheless
        with open(outdir / "sbom.spdx.json") as file:
            spdx_json = json.loads(file.read())
            packages = spdx_json["packages"]
            for package in packages:
                if package["name"] == "r-recommended":
                    assert package["homepage"] == "http://www.r-project.org/"


def test_apt_source_pkg():
    url = urlparse("http://example.org")
    uuid = uuid4()
    timestamp = datetime(1970, 1, 1, tzinfo=timezone.utc)

    dbom = Debsbom(
        distro_name="pytest-distro",
        sbom_types=[SBOMType.SPDX, SBOMType.CycloneDX],
        root="tests/root/apt-sources",
        spdx_namespace=url,
        cdx_serialnumber=uuid,
        timestamp=timestamp,
    )

    with TemporaryDirectory() as outdir:
        outdir = Path(outdir)
        dbom.generate(str(outdir / "sbom"), validate=True)
        with open(outdir / "sbom.spdx.json") as file:
            spdx_json = json.loads(file.read())
            packages = spdx_json["packages"]
            for pkg in packages:
                if pkg["SPDXID"].endswith("-srcpkg"):
                    assert pkg["supplier"] != "NOASSERTION"
