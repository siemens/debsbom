# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Iterable
import io
import json
from pathlib import Path
from unittest.mock import Mock
from zstandard import open as zstd_open

from debian.debian_support import Version
import jsonschema
import pytest

from debsbom.commands import security_scan as security_scan_cmd
from debsbom.dpkg.package import BinaryPackage, Dependency, Package, SourcePackage

from debsbom.schema import secscan, tracepath as schema_tracepath
from debsbom.securityscan.scanner import CveStatus, CveUrgency, SecurityScanner
from debsbom.securityscan.writer import ScanResultWriter
from debsbom.graph.walker import GraphWalker, PackageRepr

# Note, that this data is completely made up
DB_PATH = Path("tests/data/security-tracker.fake.json")
TRACKER_URL = "https://tracker.example.com"
BUGS_URL = "https://bugs.example.com"


@pytest.fixture(scope="session")
def compressed_db(tmp_path_factory):
    db_path = tmp_path_factory.mktemp("security-db") / "security-tracker.fake.json.zst"
    with zstd_open(db_path, "wb") as f:
        f.write(DB_PATH.read_bytes())
    return db_path


@pytest.fixture
def scanner(compressed_db):
    return SecurityScanner(db=compressed_db, distro="trixie")


def test_download_db_compresses_on_the_fly(tmp_path, monkeypatch):
    response = Mock()
    response.iter_content.return_value = [DB_PATH.read_bytes()]
    monkeypatch.setattr(security_scan_cmd, "HAS_REQUESTS_DEP", True)
    monkeypatch.setattr(
        security_scan_cmd,
        "requests",
        Mock(get=Mock(return_value=response)),
        raising=False,
    )

    db_path = tmp_path / "security-tracker.json.zst"
    security_scan_cmd.SecurityScanCmd.download_db(TRACKER_URL, db_path)

    assert db_path.read_bytes().startswith(b"\x28\xb5\x2f\xfd")
    results = SecurityScanner(db_path, distro="trixie").scan(
        [SourcePackage(name="fake-shell", version="5.2.37-2")]
    )
    assert len(list(results)) == 2


def test_upgrade_uncompressed_db(tmp_path):
    legacy = tmp_path / "security-tracker.json"
    legacy.write_bytes(DB_PATH.read_bytes())

    db_path = security_scan_cmd.SecurityScanCmd.upgrade_legacy_db(legacy)

    assert db_path == tmp_path / "security-tracker.json.zst"
    assert db_path.read_bytes().startswith(b"\x28\xb5\x2f\xfd")
    results = SecurityScanner(db_path, distro="trixie").scan(
        [SourcePackage(name="fake-shell", version="5.2.37-2")]
    )
    assert len(list(results)) == 2


def test_scan_uncompressed_custom_db_warns(tmp_path, caplog):
    db_path = tmp_path / "custom-tracker.json"
    db_path.write_bytes(DB_PATH.read_bytes())

    results = SecurityScanner(db_path, distro="trixie").scan(
        [SourcePackage(name="fake-shell", version="5.2.37-2")]
    )

    assert len(list(results)) == 2
    assert "uncompressed" in caplog.text
    assert db_path.read_bytes() == DB_PATH.read_bytes()


@pytest.fixture(scope="module")
def vex_schema():
    with open("tests/data/openvex_json_schema_0.2.0.json") as f:
        return json.load(f)


class GraphWalkerStub(GraphWalker):
    def __init__(self, pkg_path: list[Package]):
        self.pkg_path = pkg_path

    def all_shortest(self, _) -> Iterable[list[PackageRepr]]:
        return [[PackageRepr(name=p.name, ref=f"Ref-{p.name}") for p in self.pkg_path]]


def test_scan_finds_vulnerabilities(scanner):
    pkgs = [SourcePackage(name="fake-shell", version="5.2.37-2")]
    results = list(scanner.scan(pkgs, min_urgency=CveUrgency.NOT_YET_ASSIGNED))
    cves = {r.vulnerability.cve for r in results}
    assert "CVE-0000-0001" in cves
    assert "TEMP-0000-000001" in cves
    assert len(results) == 2


def test_scan_affected_resolved_not_affected(scanner):
    """Package version >= fixed_version -> not affected."""
    pkgs = [SourcePackage(name="fake-shell", version="5.2.37-2")]
    results = list(scanner.scan(pkgs))
    by_cve = {r.vulnerability.cve: r for r in results}
    assert not by_cve["CVE-0000-0001"].affected


def test_scan_affected_open_no_fix(scanner):
    """Open status with no fixed_version -> affected."""
    pkgs = [SourcePackage(name="fake-shell", version="5.2.37-2")]
    results = list(scanner.scan(pkgs))
    by_cve = {r.vulnerability.cve: r for r in results}
    assert by_cve["TEMP-0000-000001"].affected


def test_scan_affected_resolved_outdated(scanner):
    """Package version < fixed_version -> affected despite resolved status."""
    pkgs = [SourcePackage(name="fake-crypto", version="3.4.0-1")]
    results = list(scanner.scan(pkgs))
    by_cve = {r.vulnerability.cve: r for r in results}
    assert by_cve["CVE-0000-1001"].affected
    assert by_cve["CVE-0000-1003"].affected


def test_scan_affected_resolved_up_to_date(scanner):
    """Package version >= fixed_version -> not affected."""
    pkgs = [SourcePackage(name="fake-crypto", version="3.5.0-1")]
    results = list(scanner.scan(pkgs))
    by_cve = {r.vulnerability.cve: r for r in results}
    assert not by_cve["CVE-0000-1001"].affected
    assert not by_cve["CVE-0000-1003"].affected


def test_scan_affected_open_always(scanner):
    """Open status -> always affected regardless of version."""
    pkgs = [SourcePackage(name="fake-crypto", version="99.0-1")]
    results = list(scanner.scan(pkgs, min_urgency=CveUrgency.NOT_YET_ASSIGNED))
    by_cve = {r.vulnerability.cve: r for r in results}
    assert by_cve["CVE-0000-1002"].affected


def test_scan_unknown_package(scanner):
    pkgs = [SourcePackage(name="nonexistent", version="1.0-1")]
    results = list(scanner.scan(pkgs))
    assert len(results) == 0


def test_scan_urgency_high(scanner):
    """Only high urgency CVEs returned when min_urgency=HIGH."""
    pkgs = [SourcePackage(name="fake-crypto", version="3.4.0-1")]
    results = list(scanner.scan(pkgs, min_urgency=CveUrgency.HIGH))
    assert len(results) == 1
    assert results[0].vulnerability.cve == "CVE-0000-1001"
    assert results[0].vulnerability.urgency == CveUrgency.HIGH


def test_scan_urgency_medium(scanner):
    """High and medium urgency CVEs returned when min_urgency=MEDIUM."""
    pkgs = [SourcePackage(name="fake-crypto", version="3.4.0-1")]
    results = list(scanner.scan(pkgs, min_urgency=CveUrgency.MEDIUM))
    cves = {r.vulnerability.cve for r in results}
    assert cves == {"CVE-0000-1001", "CVE-0000-1002"}


def test_scan_urgency_low(scanner):
    """All three fake-crypto CVEs returned when min_urgency=LOW."""
    pkgs = [SourcePackage(name="fake-crypto", version="3.4.0-1")]
    results = list(scanner.scan(pkgs, min_urgency=CveUrgency.LOW))
    assert len(results) == 3


def test_scan_urgency_end_of_life(scanner):
    pkgs = [SourcePackage(name="fake-compress", version="1:1.3.0-1")]
    results = list(scanner.scan(pkgs, min_urgency=CveUrgency.END_OF_LIFE))
    assert len(results) == 1
    assert results[0].vulnerability.urgency == CveUrgency.END_OF_LIFE


def test_scan_min_urgency_filtering(scanner):
    pkgs = [SourcePackage(name="fake-shell", version="5.2.37-2")]
    # TEMP-0000-000001 urgency=unimportant
    results = list(scanner.scan(pkgs, min_urgency=CveUrgency.UNIMPORTANT))
    assert len(results) == 1


def test_scan_multiple_packages(scanner):
    pkgs = [
        SourcePackage(name="fake-shell", version="5.2.37-2"),
        SourcePackage(name="fake-crypto", version="3.4.0-1"),
        SourcePackage(name="fake-compress", version="1:1.3.0-1"),
    ]
    results = list(scanner.scan(pkgs))
    packages = {r.package.name for r in results}
    assert packages == {"fake-shell", "fake-crypto", "fake-compress"}
    assert len(results) == 6  # fake-shell:2 + fake-crypto:3 + fake-compress:1


def test_scan_name_filter(scanner):
    pkgs = [
        SourcePackage(name="fake-shell", version="5.2.37-2"),
        SourcePackage(name="fake-crypto", version="3.4.0-1"),
    ]
    results = list(scanner.scan(pkgs, name_filter="fake-crypto"))
    assert all(r.package.name == "fake-crypto" for r in results)
    assert len(results) == 3


def test_scan_name_filter_no_match(scanner):
    pkgs = [SourcePackage(name="fake-shell", version="5.2.37-2")]
    results = list(scanner.scan(pkgs, name_filter="other"))
    assert len(results) == 0


def test_scan_distro_bookworm(compressed_db):
    """bookworm only has fake-crypto CVE-0000-1001."""
    scanner = SecurityScanner(db=compressed_db, distro="bookworm")
    pkgs = [
        SourcePackage(name="fake-shell", version="5.2.37-2"),
        SourcePackage(name="fake-crypto", version="3.0.14-1"),
    ]
    results = list(scanner.scan(pkgs))
    assert len(results) == 1
    assert results[0].vulnerability.cve == "CVE-0000-1001"
    assert results[0].affected


def test_scan_distro_no_entries(compressed_db):
    scanner = SecurityScanner(db=compressed_db, distro="stretch")
    pkgs = [SourcePackage(name="fake-shell", version="5.2.37-2")]
    results = list(scanner.scan(pkgs))
    assert len(results) == 0


def test_scan_vulnerability_fields(scanner):
    """Verify all fields on returned CveEntry are populated correctly."""
    pkgs = [SourcePackage(name="fake-crypto", version="3.4.0-1")]
    results = list(scanner.scan(pkgs, min_urgency=CveUrgency.HIGH))
    v = results[0].vulnerability
    assert v.cve == "CVE-0000-1001"
    assert v.description == "Buffer overflow in fake-crypto allowing remote code execution."
    assert v.status == CveStatus.RESOLVED
    assert v.fixed_version == "3.5.0-1"
    assert v.urgency == CveUrgency.HIGH


def test_scan_result_matches_schema(scanner):
    """Validate that JSON output of scan results conforms to the schema."""
    pkgs = [
        SourcePackage(name="fake-shell", version="5.2.37-2"),
        SourcePackage(name="fake-crypto", version="3.4.0-1"),
        SourcePackage(name="fake-compress", version="1:1.3.0-1"),
    ]
    results = list(scanner.scan(pkgs, min_urgency=CveUrgency.NOT_YET_ASSIGNED))

    buf = io.StringIO()
    with ScanResultWriter.create("json", sdo_url=TRACKER_URL, bdo_url=BUGS_URL, file=buf) as writer:
        for r in results:
            writer.write(r)

    lines = buf.getvalue().strip().splitlines()
    assert len(lines) > 0
    for line in lines:
        data = json.loads(line)
        jsonschema.validate(instance=data, schema=secscan)


def test_scan_result_path_matches_schema(scanner):
    """
    Validate that JSON output (with path) of scan results conforms to the schema.

    As the schema uses an external reference, we need a registry for resolving.
    This requires a fairly new version of jsonschema with the referencing support,
    which is not widely available across distros (it is a pure-test dependency).
    To allow to run the testsuite against older versions as well, we disable
    the test conditionally.
    """
    pytest.importorskip("referencing")

    from referencing import Registry, Resource

    _secscan_registry = Registry().with_resource(
        schema_tracepath["$id"], Resource.from_contents(schema_tracepath)
    )

    src_pkg = SourcePackage(name="fake-shell", version="5.2.37-2")
    bin_pkg = BinaryPackage(
        name="fake-shell-bin",
        version="5.2.37-2",
        source=Dependency(name="fake-shell", version=("=", Version("5.2.37-2"))),
    )
    pkgs = [src_pkg, bin_pkg]
    results = list(scanner.scan([src_pkg], min_urgency=CveUrgency.NOT_YET_ASSIGNED))
    gw = GraphWalkerStub(pkgs)

    buf = io.StringIO()
    with ScanResultWriter.create(
        "json", sdo_url=TRACKER_URL, bdo_url=BUGS_URL, graph_walker=gw, file=buf
    ) as writer:
        for r in results:
            writer.write(r)

    lines = buf.getvalue().strip().splitlines()
    assert len(lines) > 0
    validator = jsonschema.protocols.Validator(secscan, registry=_secscan_registry)
    for line in lines:
        data = json.loads(line)
        validator.validate(data)


def test_scan_result_with_tracker_matches_schema(scanner):
    """Validate schema conformance when tracker URL is present."""
    pkgs = [SourcePackage(name="fake-crypto", version="3.4.0-1")]
    results = list(scanner.scan(pkgs, min_urgency=CveUrgency.HIGH))

    buf = io.StringIO()
    with ScanResultWriter.create("json", sdo_url=TRACKER_URL, bdo_url=BUGS_URL, file=buf) as writer:
        for r in results:
            writer.write(r)

    lines = buf.getvalue().strip().splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])
    jsonschema.validate(instance=data, schema=secscan)
    assert data["vulnerability"]["tracker"] == f"{TRACKER_URL}/CVE-0000-1001"


def test_vex_output_matches_schema(scanner, vex_schema):
    """Validate that VEX output conforms to the OpenVEX JSON schema."""
    pkgs = [
        SourcePackage(name="fake-shell", version="5.2.37-2"),
        SourcePackage(name="fake-crypto", version="3.4.0-1"),
    ]
    results = list(scanner.scan(pkgs, min_urgency=CveUrgency.NOT_YET_ASSIGNED))

    buf = io.StringIO()
    with ScanResultWriter.create(
        "vex", sdo_url=TRACKER_URL, bdo_url=BUGS_URL, author="test-author", file=buf
    ) as writer:
        for r in results:
            writer.write(r)

    data = json.loads(buf.getvalue())
    jsonschema.validate(instance=data, schema=vex_schema)
    assert data["author"] == "test-author"
    assert len(data["statements"]) == len(results)


def test_vex_output_includes_binary_products(scanner, vex_schema):
    """VEX products include binary packages mapped to the affected source package."""
    src = SourcePackage(name="fake-crypto", version="3.4.0-1")
    pkgs = [src]
    results = list(scanner.scan(pkgs, min_urgency=CveUrgency.HIGH))
    assert len(results) == 1

    bin1 = BinaryPackage(
        name="libfake-crypto3", version="3.4.0-1", architecture="amd64", source=Dependency(src.name)
    )
    bin2 = BinaryPackage(
        name="libfake-crypto-dev",
        version="3.4.0-1",
        architecture="amd64",
        source=Dependency(src.name),
    )
    src.binaries = [bin1.name, bin2.name]
    pkgs = [src, bin1, bin2]

    buf = io.StringIO()
    with ScanResultWriter.create(
        "vex",
        sdo_url=TRACKER_URL,
        bdo_url=BUGS_URL,
        author="test-author",
        file=buf,
        packages=pkgs,
    ) as writer:
        for r in results:
            writer.write(r)

    data = json.loads(buf.getvalue())
    jsonschema.validate(instance=data, schema=vex_schema)

    products = data["statements"][0]["products"]
    product_purls = [p["identifiers"]["purl"] for p in products]
    assert str(src.purl()) in product_purls
    assert str(bin1.purl()) in product_purls
    assert str(bin2.purl()) in product_purls
    assert len(products) == 3


def test_vex_output_no_binary_map(scanner, vex_schema):
    """VEX output without source_binary_map still works (only source product)."""
    src = SourcePackage(name="fake-crypto", version="3.4.0-1")
    results = list(scanner.scan([src], min_urgency=CveUrgency.HIGH))

    buf = io.StringIO()
    with ScanResultWriter.create(
        "vex", sdo_url=TRACKER_URL, bdo_url=BUGS_URL, author="test-author", file=buf
    ) as writer:
        for r in results:
            writer.write(r)

    data = json.loads(buf.getvalue())
    jsonschema.validate(instance=data, schema=vex_schema)
    products = data["statements"][0]["products"]
    assert len(products) == 1
    assert products[0]["identifiers"]["purl"] == str(src.purl())


def test_vex_with_product(scanner, vex_schema):
    """VEX output with automatically derived product."""
    src = SourcePackage(name="fake-crypto", version="3.4.0-1")
    results = list(scanner.scan([src], min_urgency=CveUrgency.HIGH))

    buf = io.StringIO()
    with ScanResultWriter.create(
        "vex",
        sdo_url=TRACKER_URL,
        bdo_url=BUGS_URL,
        author="test-author",
        file=buf,
        product="Product",
    ) as writer:
        for r in results:
            writer.write(r)

    data = json.loads(buf.getvalue())
    jsonschema.validate(instance=data, schema=vex_schema)

    statement = data["statements"][0]
    product = statement["products"][0]
    assert product["@id"] == "Product"
    assert "deb/debian/fake-crypto" in product["subcomponents"][0]["@id"]


def test_distro_from_package(scanner, vex_schema):
    """Test if CVEs get assigned correctly based on package distribution information."""
    package = SourcePackage(name="fake-shell", version="5.2.37-2")
    package.distro = "forky"

    results = list(scanner.scan([package], min_urgency=CveUrgency.NOT_YET_ASSIGNED))
    cves = {r.vulnerability.cve for r in results}
    assert "TEMP-0000-000001" in cves
    assert len(results) == 1

    package.distro = "sid"
    results = list(scanner.scan([package], min_urgency=CveUrgency.NOT_YET_ASSIGNED))
    cves = {r.vulnerability.cve for r in results}
    assert "TEMP-0000-000001" in cves
    assert "CVE-0000-0001" in cves
    assert len(results) == 2
