# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

import io
import json
from pathlib import Path

import jsonschema
import pytest

from debsbom.dpkg.package import SourcePackage
from debsbom.schema import secscan
from debsbom.securityscan.scanner import CveStatus, CveUrgency, SecurityScanner
from debsbom.securityscan.writer import ScanResultWriter

# Note, that this data is completely made up
DB_PATH = Path("tests/data/security-tracker.fake.json")
TRACKER_URL = "https://tracker.example.com"
BUGS_URL = "https://bugs.example.com"


@pytest.fixture
def scanner():
    return SecurityScanner(db=DB_PATH, distro="trixie")


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


def test_scan_distro_bookworm():
    """bookworm only has fake-crypto CVE-0000-1001."""
    scanner = SecurityScanner(db=DB_PATH, distro="bookworm")
    pkgs = [
        SourcePackage(name="fake-shell", version="5.2.37-2"),
        SourcePackage(name="fake-crypto", version="3.0.14-1"),
    ]
    results = list(scanner.scan(pkgs))
    assert len(results) == 1
    assert results[0].vulnerability.cve == "CVE-0000-1001"
    assert results[0].affected


def test_scan_distro_no_entries():
    scanner = SecurityScanner(db=DB_PATH, distro="stretch")
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


def test_vex_output_matches_schema(scanner):
    """Validate that VEX output conforms to the OpenVEX JSON schema."""
    with open("tests/data/openvex_json_schema_0.2.0.json") as f:
        vex_schema = json.load(f)

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
