# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Callable
from datetime import datetime, timezone
from importlib.metadata import version
import json
import os
from pathlib import Path
import pytest
import subprocess
from urllib.parse import urlparse
from uuid import UUID, uuid4
from debian import deb822
from io import TextIOWrapper

from debsbom.apt.cache import ExtendedStates, Repository
from debsbom.bomwriter.bomwriter import BomWriter
from debsbom.dpkg.package import ChecksumAlgo
from debsbom.util.compression import Compression
from debsbom.generate import Debsbom, SBOMType
from debsbom.sbom import BOM_Standard


class DebsbomLegacyProxy(Debsbom):
    def __init__(self, sbom_types: set[SBOMType] | list[SBOMType] = [SBOMType.SPDX], **kwargs):
        super().__init__(**kwargs)
        self._sbom_types = sbom_types

    def generate(
        self,
        out: str,
        progress_cb: Callable[[int, int, str], None] | None = None,
        validate: bool = False,
        pkgs_stream: TextIOWrapper | None = None,
    ):
        self.scan(pkgs_stream)
        for t in self._sbom_types:
            outfile = out
            if not outfile.endswith(f".{t}.json"):
                outfile += f".{t}.json"
            bom = super().generate(t, progress_cb)
            BomWriter.create(t).write_to_file(bom, Path(outfile), validate)


@pytest.fixture
def sbom_generator():
    def setup_sbom_generator(
        test_root: Path,
        uuid: UUID | None = None,
        timestamp: datetime | None = None,
        with_licenses: bool = False,
        sbom_types: list[SBOMType] = list(SBOMType),
    ) -> Debsbom:
        url = urlparse("http://example.org")
        if uuid is None:
            uuid = uuid4()
        if timestamp is None:
            timestamp = datetime(1970, 1, 1, tzinfo=timezone.utc)

        return DebsbomLegacyProxy(
            distro_name="pytest-distro",
            distro_arch="amd64",
            sbom_types=sbom_types,
            root=str(test_root),
            spdx_namespace=url,
            cdx_serialnumber=uuid,
            timestamp=timestamp,
            with_licenses=with_licenses,
        )

    return setup_sbom_generator


def test_tree_generation(tmpdir, sbom_generator):
    _spdx_tools = pytest.importorskip("spdx_tools")
    _cyclonedx = pytest.importorskip("cyclonedx")

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
    _spdx_tools = pytest.importorskip("spdx_tools")
    _cyclonedx = pytest.importorskip("cyclonedx")

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
    _cyclonedx = pytest.importorskip("cyclonedx")

    dbom = Debsbom(
        distro_name="pytest-distro",
        distro_arch="amd64",
        root="tests/root/dependency",
        spdx_namespace=urlparse("http://example.org"),
        cdx_serialnumber=uuid4(),
        timestamp=datetime(1970, 1, 1, tzinfo=timezone.utc),
        cdx_standard=BOM_Standard.STANDARD_BOM,
    )
    dbom.scan()
    outdir = Path(tmpdir)
    bom = dbom.generate(SBOMType.CycloneDX)
    bomfile = outdir / "sbom.cdx.json"
    BomWriter.create(SBOMType.CycloneDX).write_to_file(bom, bomfile, validate=True)
    with open(bomfile) as file:
        cdx_json = json.loads(file.read())
        s_bom = cdx_json["definitions"]["standards"][0]
        assert s_bom["bom-ref"] == "standard-bom"
        assert s_bom["owner"] == "Siemens AG"


def test_homepage_regression(tmpdir, sbom_generator):
    _spdx_tools = pytest.importorskip("spdx_tools")
    _cyclonedx = pytest.importorskip("cyclonedx")

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
    _spdx_tools = pytest.importorskip("spdx_tools")
    _cyclonedx = pytest.importorskip("cyclonedx")

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
            if pkg["SPDXID"].endswith("binutils-2.40-2-srcpkg"):
                assert pkg["supplier"] != "NOASSERTION"
                assert {
                    "algorithm": "MD5",
                    "checksumValue": "6adb372f47c7b4b980d6c0bffae3f691",
                } in pkg["checksums"]
                assert {
                    "algorithm": "SHA256",
                    "checksumValue": "cd75da7829d819189ba6154d408666373b307e222b393223804c4c4a7156f421",
                } in pkg["checksums"]
                externalRefs = pkg["externalRefs"]
                assert len(externalRefs) == 2
                for ref in externalRefs:
                    if ref["referenceType"] == "vcs":
                        assert (
                            ref["referenceLocator"]
                            == "https://salsa.debian.org/toolchain-team/binutils.git"
                        )
            if pkg["SPDXID"].endswith("binutils-arm-none-eabi-amd64"):
                assert {
                    "algorithm": "MD5",
                    "checksumValue": "041580298095f940c2c9c130e0d6e149",
                } in pkg["checksums"]
                assert {
                    "algorithm": "SHA256",
                    "checksumValue": "c8f9da2a434366bfe5a66a8267cb3b1df028f1d95278715050c222b43e1c221c",
                }
    with open(outdir / "sbom.cdx.json") as file:
        spdx_json = json.loads(file.read())
        packages = spdx_json["components"]
        for pkg in packages:
            if pkg["bom-ref"].endswith("binutils@2.40-2?arch=source"):
                externalRefs = pkg["externalReferences"]
                assert len(externalRefs) == 2
                for ref in externalRefs:
                    if ref["type"] == "vcs":
                        assert ref["url"] == "https://salsa.debian.org/toolchain-team/binutils.git"


def test_apt_pkgs_stream(tmpdir, sbom_generator):
    _spdx_tools = pytest.importorskip("spdx_tools")
    _cyclonedx = pytest.importorskip("cyclonedx")

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


def test_apt_cache_parsing():
    apt_lists_dir = "tests/root/apt-sources/var/lib/apt/lists"
    repo = next(Repository.from_apt_cache(apt_lists_dir))
    src_pkgs = list(repo.sources(lambda p: p.name == "binutils"))
    assert len(src_pkgs) == 1
    # this data is only available in apt sources deb822 data
    assert "binutils-for-host" in src_pkgs[0].binaries
    assert (
        src_pkgs[0].checksums[ChecksumAlgo.SHA256SUM]
        == "cd75da7829d819189ba6154d408666373b307e222b393223804c4c4a7156f421"
    )


compressions = ["bzip2", "gzip", "xz", "zstd", "lz4"]


@pytest.mark.parametrize("tool", compressions)
def test_apt_lists_compression(tmpdir, sbom_generator, tool):
    _spdx_tools = pytest.importorskip("spdx_tools")
    _cyclonedx = pytest.importorskip("cyclonedx")

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
                assert {
                    "algorithm": "SHA512",
                    "checksumValue": "98432f5466d899b96031702e3bb3d75b398a691b295bc248edbc5254f5460f1f4affce98246e95cd51f10e09636e7cdee0b6df2423842179314236485b3fb1d1",
                } in pkg["checksums"]


def test_pkglist_apt_cache(tmpdir, sbom_generator):
    _spdx_tools = pytest.importorskip("spdx_tools")
    _cyclonedx = pytest.importorskip("cyclonedx")

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


def test_residual_config_packages(tmpdir, sbom_generator):
    _spdx_tools = pytest.importorskip("spdx_tools")
    _cyclonedx = pytest.importorskip("cyclonedx")

    dbom = sbom_generator("tests/root/apt-sources")
    outdir = Path(tmpdir)
    dbom.generate(str(outdir / "sbom"), validate=True)
    with open(outdir / "sbom.spdx.json") as file:
        spdx_json = json.loads(file.read())
        packages = spdx_json["packages"]
        assert "openssh-server" not in [p["name"] for p in packages]
        # source package for openssh-server
        assert "openssh" not in [p["name"] for p in packages]
    with open(outdir / "sbom.cdx.json") as file:
        spdx_json = json.loads(file.read())
        components = spdx_json["components"]
        assert "openssh-server" not in [c["name"] for c in components]
        # source package for openssh-server
        assert "openssh" not in [c["name"] for c in components]


def test_illformed_sources():
    srcfile = "tests/root/illformed-sources/source_Sources"
    srcpkgs = list(Repository._parse_sources(srcfile))
    assert any(filter(lambda p: p.name == "argon2", srcpkgs))
    assert any(filter(lambda p: p.name == "at-spi2-core", srcpkgs))

    # parse incomplete packages. Must not raise
    assert len(list(Repository._make_srcpkgs([deb822.Packages()]))) == 0
    assert len(list(Repository._make_binpkgs([deb822.Packages()]))) == 0


def test_license_information(tmpdir, sbom_generator):
    _spdx_tools = pytest.importorskip("spdx_tools")
    _cyclonedx = pytest.importorskip("cyclonedx")
    _component_evidence = pytest.importorskip("cyclonedx.model.component_evidence")

    dbom = sbom_generator("tests/root/copyright", with_licenses=True)
    outdir = Path(tmpdir)
    dbom.generate(str(outdir / "sbom"), validate=True)
    with open(outdir / "sbom.spdx.json") as file:
        spdx_json = json.loads(file.read())
        apt_pkg = None
        packages = spdx_json["packages"]
        for package in packages:
            for ref in package.get("externalRefs") or []:
                if (
                    ref["referenceCategory"] == "PACKAGE_MANAGER"
                    and "arch=source" in ref["referenceLocator"]
                ):
                    apt_pkg = package
                    break
            if apt_pkg:
                break
        assert apt_pkg
        assert (
            apt_pkg["licenseDeclared"]
            == "BSD-3-Clause AND GPL-2.0-only AND GPL-2.0-or-later AND MIT"
        )
    with open(outdir / "sbom.cdx.json") as file:
        spdx_json = json.loads(file.read())
        apt_component = list(filter(lambda c: "arch=source" in c["purl"], spdx_json["components"]))[
            0
        ]
        lic = apt_component["evidence"]["licenses"][0]
        assert lic["acknowledgement"] == "declared"
        assert lic["expression"] == "BSD-3-Clause AND GPL-2.0-only AND GPL-2.0-or-later AND MIT"


def test_virtual_package(tmpdir, sbom_generator):
    _spdx_tools = pytest.importorskip("spdx_tools")
    _cyclonedx = pytest.importorskip("cyclonedx")

    dbom = sbom_generator("tests/root/virtual-packages", with_licenses=True)
    outdir = Path(tmpdir)
    dbom.generate(str(outdir / "sbom"), validate=True)
    with open(outdir / "sbom.spdx.json") as file:
        spdx_json = json.loads(file.read())
        relationships = spdx_json["relationships"]

        found = False
        for relationship in relationships:
            if (
                relationship["spdxElementId"] == "SPDXRef-foo-amd64"
                and relationship["relationshipType"] == "DEPENDS_ON"
            ):
                assert relationship["relatedSpdxElement"] == "SPDXRef-bar-plus-amd64"
                found = True
                break
        assert found

    with open(outdir / "sbom.cdx.json") as file:
        cdx_json = json.loads(file.read())

        found = False
        for dependency in cdx_json["dependencies"]:
            if dependency["ref"] == "pkg:deb/debian/foo@1.0?arch=amd64":
                for dep in dependency["dependsOn"]:
                    assert (
                        dep == "pkg:deb/debian/bar-plus@1.0?arch=amd64"
                        or dep == "pkg:deb/debian/foo@1.0?arch=source"
                    )
                found = True
                break
        assert found
