# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from datetime import datetime, timezone
from importlib.metadata import version
import json
import os
from pathlib import Path
import pytest
import subprocess
from urllib.parse import urlparse
from uuid import UUID, uuid4

from debsbom.apt.cache import ExtendedStates
from debsbom.util.compression import Compression
from debsbom.generate import Debsbom, SBOMType
from debsbom.sbom import BOM_Standard


@pytest.fixture
def sbom_generator():
    def setup_sbom_generator(
        test_root: Path,
        uuid: UUID = None,
        timestamp: datetime | None = None,
        sbom_types: [SBOMType] = [SBOMType.SPDX, SBOMType.CycloneDX],
    ) -> Debsbom:
        url = urlparse("http://example.org")
        if uuid is None:
            uuid = uuid4()
        if timestamp is None:
            timestamp = datetime(1970, 1, 1, tzinfo=timezone.utc)

        return Debsbom(
            distro_name="pytest-distro",
            sbom_types=sbom_types,
            root=str(test_root),
            spdx_namespace=url,
            cdx_serialnumber=uuid,
            timestamp=timestamp,
        )

    return setup_sbom_generator


def test_tree_generation(tmpdir, sbom_generator):
    timestamp = datetime(1970, 1, 1, tzinfo=timezone.utc)
    uuid = uuid4()
    dbom = sbom_generator("tests/root/tree", uuid, timestamp)
    outdir = Path(tmpdir)
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


def test_dependency_generation(tmpdir, sbom_generator):
    dbom = sbom_generator("tests/root/dependency")
    outdir = Path(tmpdir)
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


def test_standard_bom(tmpdir):
    dbom = Debsbom(
        distro_name="pytest-distro",
        sbom_types=[SBOMType.CycloneDX],
        root="tests/root/dependency",
        spdx_namespace=urlparse("http://example.org"),
        cdx_serialnumber=uuid4(),
        timestamp=datetime(1970, 1, 1, tzinfo=timezone.utc),
        cdx_standard=BOM_Standard.STANDARD_BOM,
    )
    outdir = Path(tmpdir)
    dbom.generate(str(outdir / "sbom"), validate=True)
    with open(outdir / "sbom.cdx.json") as file:
        cdx_json = json.loads(file.read())
        s_bom = cdx_json["definitions"]["standards"][0]
        assert s_bom["bom-ref"] == "standard-bom"
        assert s_bom["owner"] == "Siemens AG"


def test_homepage_regression(tmpdir, sbom_generator):
    dbom = sbom_generator("tests/root/homepage-lowercase")
    outdir = Path(tmpdir)
    dbom.generate(str(outdir / "sbom"), validate=True)
    # if we get here the validation should have caught uppercase letters
    # in the hostname, but we make sure it is lowercase nonetheless
    with open(outdir / "sbom.spdx.json") as file:
        spdx_json = json.loads(file.read())
        packages = spdx_json["packages"]
        for package in packages:
            if package["name"] == "r-recommended":
                assert package["homepage"] == "http://www.r-project.org/"


def test_apt_source_pkg(tmpdir, sbom_generator):
    dbom = sbom_generator("tests/root/apt-sources")
    outdir = Path(tmpdir)
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


def test_apt_pkgs_stream(tmpdir, sbom_generator):
    dbom = sbom_generator("tests/root/apt-sources")
    with open("tests/data/pkgs-stream", "r") as stream:
        outdir = Path(tmpdir)
        dbom.generate(str(outdir / "sbom"), validate=True, pkgs_stream=stream)
    with open(outdir / "sbom.spdx.json") as file:
        spdx_json = json.loads(file.read())
    packages = spdx_json["packages"]
    binutils_bpf = next(filter(lambda p: p["SPDXID"].endswith("binutils-bpf-amd64"), packages))
    assert binutils_bpf["versionInfo"] == "2.40-2+1"
    assert binutils_bpf["summary"].startswith("GNU binary")
    assert binutils_bpf["supplier"].startswith("Organization:")

    bu_bpf_src = next(filter(lambda p: p["SPDXID"].endswith("binutils-bpf-10-srcpkg"), packages))
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


compressions = ["bzip2", "gzip", "xz", "zstd", "lz4"]


@pytest.mark.parametrize("tool", compressions)
def test_apt_lists_compression(tmpdir, sbom_generator, tool):
    comp = Compression.from_tool(tool)

    # create a temporary rootfs copied from tests/root/apt-sources and
    # compress the _Sources and _Packages there
    root = tmpdir / f"root-{comp.tool}"
    base = Path("tests/root/apt-sources")
    in_release_file = "deb.debian.org_debian_dists_bookworm_InRelease"
    lists_dir = root / "var/lib/apt/lists"
    os.makedirs(lists_dir)
    dpkg_dir = root / "var/lib/dpkg"
    os.makedirs(dpkg_dir)
    # simply symlink the InRelease and status file
    os.symlink(
        (base / f"var/lib/apt/lists/{in_release_file}").resolve(), lists_dir / in_release_file
    )
    os.symlink((base / "var/lib/dpkg/status").resolve(), dpkg_dir / "status")
    sources_file = "var/lib/apt/lists/deb.debian.org_debian_dists_bookworm_main_source_Sources"
    binaries_file = (
        "var/lib/apt/lists/deb.debian.org_debian_dists_bookworm_main_binary-amd64_Packages"
    )
    with open(root / sources_file + comp.fileext, "w") as f, open(base / sources_file) as in_f:
        compressor = subprocess.Popen(
            [comp.tool] + comp.compress,
            stdin=in_f,
            stdout=f,
        )
        _, stderr = compressor.communicate()
        assert compressor.wait() == 0
    with open(root / binaries_file + comp.fileext, "w") as f, open(base / binaries_file) as in_f:
        compressor = subprocess.Popen(
            [comp.tool] + comp.compress,
            stdin=in_f,
            stdout=f,
        )
        _, stderr = compressor.communicate()
        assert compressor.wait() == 0

    dbom = sbom_generator(root)
    dbom.generate(str(tmpdir / "sbom"), validate=True)
    with open(tmpdir / "sbom.spdx.json") as file:
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


def test_pkglist_apt_cache(tmpdir, sbom_generator):
    dbom = sbom_generator("tests/root/apt-sources")
    with open("tests/data/pkgs-custom-stream", "r") as stream:
        outdir = Path(tmpdir)
        dbom.generate(str(outdir / "sbom"), validate=True, pkgs_stream=stream)
    with open(outdir / "sbom.spdx.json") as file:
        spdx_json = json.loads(file.read())
    packages = spdx_json["packages"]
    binutils_bpf = next(filter(lambda p: p["SPDXID"].endswith("binutils-bpf-amd64"), packages))
    assert binutils_bpf["versionInfo"] == "2.40-2+1-custom"
    # make sure we have no additional information
    assert binutils_bpf["supplier"] == "NOASSERTION"
