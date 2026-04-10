# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from abc import abstractmethod
from collections import defaultdict
import dataclasses
from datetime import datetime, timezone
from importlib.metadata import version, metadata
import json
import os
from pathlib import Path
import sys

from ..tracepath.walker import GraphWalker
from ..dpkg.package import BinaryPackage, SourcePackage, Package, filter_binaries
from .scanner import CveEntry, CveStatus, CveUrgency, ScanResultItem

_CHECKSUM_TO_VEX_HASH = {
    "MD5SUM": "md5",
    "SHA1SUM": "sha1",
    "SHA256SUM": "sha-256",
    "SHA512SUM": "sha-512",
}

SARIF_SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"
VEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
VEX_SCHEMA_ID = "https://openvex.dev/docs/public/vex-adc52fe6c8d2ba0feee7f4343f9b40c90e8cdb077817f880a6650502aece82bc"


class ScanResultWriter:
    """
    Emit the security scan results in the specified format.
    All instances should be used with a context manager.
    """

    @classmethod
    def create(
        cls,
        format: str,
        sdo_url: str,
        bdo_url: str,
        packages: list[Package] | None = None,
        graph_walker: GraphWalker | None = None,
        author: str | None = None,
        input_filename: Path | None = None,
        file=sys.stdout,
    ) -> "ScanResultWriter":
        match format.lower():
            case "text":
                return ScanResultTextWriter(
                    packages=[], sdo_url=sdo_url, bdo_url=bdo_url, file=file
                )
            case "json":
                return ScanResultJsonWriter(
                    packages=[],
                    sdo_url=sdo_url,
                    bdo_url=bdo_url,
                    graph_walker=graph_walker,
                    file=file,
                )
            case "sarif":
                return ScanResultSarifWriter(
                    packages=packages or [],
                    sdo_url=sdo_url,
                    bdo_url=bdo_url,
                    path=input_filename,
                    file=file,
                )
            case "vex":
                return ScanResultVexWriter(
                    packages=packages or [],
                    sdo_url=sdo_url,
                    bdo_url=bdo_url,
                    author=author,
                    file=file,
                )
            case _:
                raise RuntimeError(f'No formatter for "{format}"')

    def __init__(self, packages: list[Package], sdo_url: str, bdo_url: str, file=sys.stdout):
        self.sdo_url = sdo_url
        self.bdo_url = bdo_url
        self.out = file
        # compute source -> binary relations as vulns are filed against src packages
        # but systems have binary packages installed
        binaries = list(filter_binaries(packages))
        self._name_to_pkg_map: dict[str, BinaryPackage] = {p.name: p for p in binaries}
        # note, that the source packages are only stubs with an equal hash / purl
        self._built_using_map: dict[SourcePackage, list[BinaryPackage]] = defaultdict(list)
        for bp in binaries:
            for dep in bp.built_using:
                self._built_using_map[SourcePackage(dep.name, dep.version[1])].append(bp)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def close(self) -> None:
        pass

    def affected_binaries(self, src_pkg: SourcePackage) -> list[BinaryPackage]:
        """Return binary packages built from or built-using the given source package."""
        candidates = set(map(lambda name: self._name_to_pkg_map.get(name), src_pkg.binaries))
        return list(candidates | set(self._built_using_map.get(src_pkg, [])))

    @abstractmethod
    def write(self, v: ScanResultItem) -> None:
        raise NotImplementedError()


class ScanResultTextWriter(ScanResultWriter):
    def write(self, r: ScanResultItem) -> None:
        if not r.affected:
            return

        v = r.vulnerability
        if self.sdo_url:
            print(
                f"{r.package} {v.cve} {v.status} ({v.fixed_version or 'no version'}) {v.urgency} {self.sdo_url}/{v.cve}",
                file=self.out,
            )
        else:
            print(
                f"{r.package} {v.cve} {v.status} ({v.fixed_version or 'no version'}) {v.urgency}",
                file=self.out,
            )


class ScanResultJsonWriter(ScanResultWriter):
    def __init__(self, graph_walker: GraphWalker | None = None, **args):
        super().__init__(**args)
        self.graph_walker = graph_walker

    def write(self, r: ScanResultItem) -> None:
        if not r.affected:
            return

        v = r.vulnerability
        data = {
            "package": str(r.package),
            "purl": str(r.package.purl()),
            "vulnerability": {
                "id": v.cve,
                "status": str(v.status),
                "urgency": str(v.urgency),
                "tracker": f"{self.sdo_url}/{v.cve}",
            },
        }
        if v.fixed_version:
            data["vulnerability"]["fixed-in"] = v.fixed_version
            data["vulnerability"]["desc"] = v.description
        if v.debianbug:
            data["vulnerability"]["debianbug"] = v.debianbug
            data["vulnerability"]["bugreport"] = f"{self.bdo_url}?bug={v.debianbug}"
        if self.graph_walker:
            allShortest = self.graph_walker.all_shortest(r.package.purl())
            data["pathsToRoot"] = {
                "allShortest": [[dataclasses.asdict(_s) for _s in s] for s in allShortest]
            }

        json.dump(data, self.out)
        self.out.write("\n")


class ScanResultSarifWriter(ScanResultWriter):
    def __init__(self, path: Path, **args):
        super().__init__(**args)
        self.frame = self._create_skeleton()
        self.path = path

    def close(self) -> None:
        json.dump(self.frame, self.out)
        self.out.write("\n")

    @classmethod
    def _create_skeleton(cls) -> dict:
        def get_project_url():
            url_node = metadata("debsbom").get("Project-URL")
            if not url_node:
                return None
            return url_node.split(",")[-1].strip()

        return {
            "version": "2.1.0",
            "$schema": SARIF_SCHEMA_URL,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "debsbom",
                            "version": version("debsbom"),
                            "informationUri": get_project_url(),
                            "rules": [],
                        },
                    },
                    "results": [],
                }
            ],
        }

    def write(self, r: ScanResultItem) -> None:
        if not r.affected:
            return

        v = r.vulnerability
        rule_id = f"{v.cve}-{r.package.name}"
        rule = {
            "id": rule_id,
            "name": "OsPackageVulnerability",
            "shortDescription": {
                "text": f"{v.cve} {v.urgency} vulnerability for {r.package.name} package"
            },
            "help": {
                "text": f"Vulnerability {v.cve}\n"
                f"Severity: {v.urgency}\n"
                f"Package: {r.package.name}\n"
                f"Version: {r.package.version}\n"
                f"Fix Version: {v.fixed_version or '(unfixed)'}\n"
                f"Link: [{v.cve}]({self.sdo_url}/{v.cve})"
            },
            "properties": {
                "tracker": f"{self.sdo_url}/{v.cve}",
            },
        }
        if v.description:
            rule["fullDescription"] = {"text": v.description}
        if v.debianbug:
            rule["properties"]["debianbug"] = v.debianbug
            rule["properties"]["bugreport"] = f"{self.bdo_url}?bug={v.debianbug}"
        if v.fixed_version:
            rule["properties"]["fixVersion"] = v.fixed_version
        self.frame["runs"][0]["tool"]["driver"]["rules"].append(rule)

        for bin_pkg in self.affected_binaries(r.package):
            result = {
                "ruleId": rule_id,
                "level": "warning" if v.urgency == CveUrgency.HIGH else "note",
                "message": {
                    "text": f"The SBOM reports {bin_pkg.name} at version {bin_pkg.version} which is a vulnerable deb package affected by {v.cve}",
                },
                "locations": [
                    {
                        "logicalLocations": [
                            {
                                "name": str(bin_pkg),
                                "fullyQualifiedName": str(bin_pkg.purl()),
                            },
                        ],
                    },
                ],
                "properties": {
                    "PURL": str(bin_pkg.purl()),
                },
            }
            if self.path:
                result["locations"][0]["physicalLocation"] = {
                    "artifactLocation": {"uri": f"file://{self.path.resolve()}"},
                }
            self.frame["runs"][0]["results"].append(result)


class ScanResultVexWriter(ScanResultWriter):
    def __init__(self, author, **args):
        super().__init__(**args)
        sde = os.environ.get("SOURCE_DATE_EPOCH")
        if sde:
            self.ts = datetime.fromtimestamp(float(sde))
        else:
            self.ts = datetime.now(timezone.utc)
        if not author:
            raise RuntimeError("No author information provided (needed for VEX)")
        self.author = author
        self.frame = self._create_skeleton()

    def close(self) -> None:
        json.dump(self.frame, self.out)
        self.out.write("\n")

    def _create_skeleton(self) -> dict:
        return {
            "@context": VEX_CONTEXT,
            "@id": VEX_SCHEMA_ID,
            "author": self.author,
            "timestamp": self.ts.isoformat(),
            "version": 1,
            "tooling": "debsbom {}".format(version("debsbom")),
            "statements": [],
        }

    def _vuln_to_vex(self, r: ScanResultItem) -> dict:
        def _get_status(v: CveEntry, affected):
            if not affected:
                return "not_affected"
            elif v.status == CveStatus.UNDETERMINED:
                return "under_investigation"
            else:
                return "affected"

        v = r.vulnerability
        status = _get_status(v, r.affected)
        purl = str(r.package.purl())
        product = {
            "@id": purl,
            "identifiers": {
                "purl": purl,
            },
        }
        if r.package.checksums:
            product["hashes"] = {
                _CHECKSUM_TO_VEX_HASH[algo.name]: value
                for algo, value in r.package.checksums.items()
                if algo.name in _CHECKSUM_TO_VEX_HASH
            }
        products = [product]
        for bin_pkg in self.affected_binaries(r.package):
            bin_purl = str(bin_pkg.purl())
            bin_product = {
                "@id": bin_purl,
                "identifiers": {
                    "purl": bin_purl,
                },
            }
            if bin_pkg.checksums:
                bin_product["hashes"] = {
                    _CHECKSUM_TO_VEX_HASH[algo.name]: value
                    for algo, value in bin_pkg.checksums.items()
                    if algo.name in _CHECKSUM_TO_VEX_HASH
                }
            products.append(bin_product)
        vex = {
            "vulnerability": {
                "@id": f"{self.sdo_url}/{v.cve}",
                "name": v.cve,
            },
            "products": products,
            "status": status,
        }
        if v.description:
            vex["vulnerability"]["description"] = v.description
        if status == "not_affected":
            # The Debian tracker does not distinguish between fixed due to inline mitigations
            # and not affected because the code is not in use. Once upstream gives more
            # precise information, we can optimize this.
            # Ref: https://salsa.debian.org/security-tracker-team/security-tracker/-/issues/38
            vex["justification"] = "inline_mitigations_already_exist"
        if status == "affected":
            if v.status == CveStatus.RESOLVED:
                vex["action_statement"] = f"update package to {v.fixed_version}"
            else:
                vex["action_statement"] = "apply inline mitigations"
        return vex

    def write(self, r: ScanResultItem) -> None:
        self.frame["statements"].append(self._vuln_to_vex(r))
