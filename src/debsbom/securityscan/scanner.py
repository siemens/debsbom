# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
import json
import logging
from pathlib import Path
from debian.debian_support import version_compare

from ..dpkg.package import SourcePackage
from enum import IntEnum

logger = logging.getLogger(__name__)


class CveUrgency(IntEnum):
    HIGH = 0
    MEDIUM = 1
    LOW = 2
    UNIMPORTANT = 3
    END_OF_LIFE = 4
    NOT_YET_ASSIGNED = 5

    @classmethod
    def from_string(cls, s: str) -> "CveUrgency":
        return cls[s.upper().replace(" ", "_").replace("-", "_")]

    def __str__(self) -> str:
        return self.name.lower().replace("_", "-")


class CveStatus(IntEnum):
    RESOLVED = 0
    UNDETERMINED = 1
    OPEN = 2

    @classmethod
    def from_string(cls, s: str) -> "CveStatus":
        return cls[s.upper()]

    def __str__(self) -> str:
        return self.name.lower()


@dataclass
class CveEntry:
    cve: str
    debianbug: int | None
    description: str | None
    status: CveStatus
    fixed_version: str | None
    urgency: CveUrgency
    nodsa: str | None


@dataclass
class ScanResultItem:
    package: SourcePackage
    vulnerability: CveEntry
    affected: bool


class CveTriage:
    def __init__(self, db, distro):
        self.db = db
        self.distro = distro

    def candidates(self, p: SourcePackage) -> Iterator[CveEntry]:
        vulns = self.db.get(p.name)
        if not vulns:
            return
        for k, v in vulns.items():
            v_distr = v["releases"].get(self.distro)
            if not v_distr:
                continue
            yield CveEntry(
                cve=k,
                debianbug=v.get("debianbug"),
                description=v.get("description"),
                status=CveStatus.from_string(v_distr["status"]),
                fixed_version=v_distr.get("fixed_version"),
                urgency=CveUrgency.from_string(v_distr.get("urgency")),
                nodsa=v_distr.get("nodsa"),
            )

    @staticmethod
    def affected_by(p: SourcePackage, c: CveEntry) -> bool:
        if c.status != CveStatus.RESOLVED or not c.fixed_version:
            return True
        elif version_compare(c.fixed_version, str(p.version)) > 0:
            return True
        return False


class SecurityScanner:
    """
    A security scanner that checks source packages against a Debian
    security database for known vulnerabilities.
    """

    def __init__(self, db: Path, distro: str = "trixie"):
        with open(db, "r") as f:
            self.ct = CveTriage(json.load(f), distro=distro)

    def scan(
        self,
        src_pkgs: Iterable[SourcePackage],
        min_urgency: CveUrgency = CveUrgency.NOT_YET_ASSIGNED,
        name_filter: str | None = None,
    ) -> Iterable[ScanResultItem]:
        for p in src_pkgs:
            if name_filter and p.name != name_filter:
                continue

            vulns = self.ct.candidates(p)
            for v in vulns:
                if v.urgency > min_urgency:
                    continue
                yield ScanResultItem(package=p, vulnerability=v, affected=self.ct.affected_by(p, v))
