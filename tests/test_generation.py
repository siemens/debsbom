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

from debsbom.apt.cache import ExtendedStates
from debsbom.generate import Debsbom, SBOMType
from debsbom.sbom import BOM_Standard


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
            assert len(cdx_json["components"]) == 20  # 14 binary + 6 source
            deps_total = 0
            for dep_entry in cdx_json["dependencies"]:
                if dep_entry.get("dependsOn"):
                    deps_total += len(dep_entry["dependsOn"])
            assert deps_total == 65
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
            assert {
                "spdxElementId": "SPDXRef-libc6-amd64",
                "relatedSpdxElement": "SPDXRef-pytest-distro",
                "relationshipType": "PACKAGE_OF",
            } in relationships
            assert {
                "spdxElementId": "SPDXRef-libc6-amd64",
                "relatedSpdxElement": "SPDXRef-libgcc-s1-amd64",
                "relationshipType": "DEPENDS_ON",
            } in relationships
            assert {
                "spdxElementId": "SPDXRef-glibc-2.36-9.deb12u10-srcpkg",
                "relatedSpdxElement": "SPDXRef-libc6-amd64",
                "relationshipType": "GENERATES",
            } in relationships
            assert {
                "spdxElementId": "SPDXRef-libgcc-s1-amd64",
                "relatedSpdxElement": "SPDXRef-pytest-distro",
                "relationshipType": "PACKAGE_OF",
            } in relationships
            assert {
                "spdxElementId": "SPDXRef-libgcc-s1-amd64",
                "relatedSpdxElement": "SPDXRef-libc6-amd64",
                "relationshipType": "DEPENDS_ON",
            } in relationships
            assert {
                "spdxElementId": "SPDXRef-gcc-12-12.2.0-14.deb12u1-srcpkg",
                "relatedSpdxElement": "SPDXRef-libgcc-s1-amd64",
                "relationshipType": "GENERATES",
            } in relationships
            assert {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": "SPDXRef-pytest-distro",
                "relationshipType": "DESCRIBES",
            } in relationships
        with open(outdir / "sbom.cdx.json") as file:
            cdx_json = json.loads(file.read())
            deps = cdx_json["dependencies"]
            libc_ref = "pkg:deb/debian/libc6@2.36-9%2Bdeb12u10?arch=amd64"
            libgcc_s1_ref = "pkg:deb/debian/libgcc-s1@12.2.0-14%2Bdeb12u1?arch=amd64"
            glibc_src_ref = "pkg:deb/debian/glibc@2.36-9%2Bdeb12u10?arch=source"
            gcc_src_ref = "pkg:deb/debian/gcc-12@12.2.0-14%2Bdeb12u1?arch=source"
            assert {
                "dependsOn": [glibc_src_ref, libgcc_s1_ref],
                "ref": libc_ref,
            } in deps
            assert {
                "dependsOn": [gcc_src_ref, libc_ref],
                "ref": libgcc_s1_ref,
            } in deps
            assert {
                "dependsOn": [libc_ref, libgcc_s1_ref],
                "ref": "CDXRef-pytest-distro",
            } in deps


def test_standard_bom():
    dbom = Debsbom(
        distro_name="pytest-distro",
        sbom_types=[SBOMType.CycloneDX],
        root="tests/root/dependency",
        spdx_namespace=urlparse("http://example.org"),
        cdx_serialnumber=uuid4(),
        timestamp=datetime(1970, 1, 1, tzinfo=timezone.utc),
        cdx_standard=BOM_Standard.STANDARD_BOM,
    )
    with TemporaryDirectory() as outdir:
        outdir = Path(outdir)
        dbom.generate(str(outdir / "sbom"), validate=True)
        with open(outdir / "sbom.cdx.json") as file:
            cdx_json = json.loads(file.read())
            s_bom = cdx_json["definitions"]["standards"][0]
            assert s_bom["bom-ref"] == "standard-bom"
            assert s_bom["owner"] == "Siemens AG"


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
            assert next(
                filter(lambda p: p["SPDXID"].endswith("binutils-arm-none-eabi-amd64"), packages)
            )
            for pkg in packages:
                if pkg["SPDXID"].endswith("-srcpkg"):
                    assert pkg["supplier"] != "NOASSERTION"
                if pkg["SPDXID"].endswith("binutils-arm-none-eabi-amd64"):
                    assert {
                        "algorithm": "MD5",
                        "checksumValue": "041580298095f940c2c9c130e0d6e149",
                    } in pkg["checksums"]


def test_apt_pkgs_stream():
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
        with open("tests/data/pkgs-stream", "r") as stream:
            outdir = Path(outdir)
            dbom.generate(str(outdir / "sbom"), validate=True, pkgs_stream=stream)
        with open(outdir / "sbom.spdx.json") as file:
            spdx_json = json.loads(file.read())
        packages = spdx_json["packages"]
        binutils_bpf = next(filter(lambda p: p["SPDXID"].endswith("binutils-bpf-amd64"), packages))
        assert binutils_bpf["versionInfo"] == "2.40-2+1"
        assert binutils_bpf["summary"].startswith("GNU binary")
        assert binutils_bpf["supplier"].startswith("Organization:")

        bu_bpf_src = next(
            filter(lambda p: p["SPDXID"].endswith("binutils-bpf-10-srcpkg"), packages)
        )
        assert bu_bpf_src["versionInfo"] == "10"
        assert bu_bpf_src["summary"].startswith("Debian source")
        assert bu_bpf_src["supplier"].startswith("Organization: Debian GCC")


def test_apt_extended_states():
    es = ExtendedStates.from_file("tests/root/apt-sources/var/lib/apt/extended_states")
    assert not es.is_manual("binutils-arm-none-eabi", "amd64")
    # no information about riscv64, assume manual
    assert es.is_manual("binutils-bpf", "amd64")

    noes = ExtendedStates(set())
    assert noes.is_manual("foo", "amd64")
