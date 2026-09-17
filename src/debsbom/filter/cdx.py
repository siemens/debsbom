# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

import re
from debian.debian_support import Version

from cyclonedx.model.dependency import Dependency
from cyclonedx.model.bom import Bom

from .filter import SbomFilter
from ..graph.walker import PackageRepr


class CdxSbomFilter(SbomFilter):

    @classmethod
    def binary_pkgs(cls, document: Bom):
        document.components = [
            comp for comp in document.components if "arch=source" not in str(comp.bom_ref.value)
        ]

        document.dependencies = [
            dep for dep in document.dependencies if "arch=source" not in str(dep.ref.value)
        ]
        for dep in document.dependencies:
            dep.dependencies = [
                deps for deps in dep.dependencies if "arch=source" not in str(deps.ref.value)
            ]

    @classmethod
    def source_pkgs(cls, document: Bom):
        document.components = [
            comp for comp in document.components if "arch=source" in str(comp.bom_ref.value)
        ]

        root_ref = document.metadata.component.bom_ref
        source_refs = [Dependency(ref=comp.bom_ref) for comp in document.components]
        if root_ref:
            document.dependencies = [Dependency(ref=root_ref, dependencies=source_refs)]
        else:
            document.dependencies = []

    @classmethod
    def packages(cls, document: Bom, source_pkg: PackageRepr, packages: list[PackageRepr]):
        components = {str(comp.bom_ref): comp for comp in document.components}
        new_components = []
        for package in packages:
            new_components.append(components[package.ref])
        document.components = new_components

        packages_set = set(map(lambda p: p.ref, packages))

        root_ref = document.metadata.component.bom_ref
        source_ref = components[source_pkg.ref].bom_ref
        new_deps = [Dependency(ref=root_ref, dependencies=[Dependency(ref=source_ref)])]
        # throw out any references to packages that are not in our package set
        for dependency in document.dependencies:
            if str(dependency.ref) not in packages_set:
                continue
            new_dep = Dependency(ref=dependency.ref)
            for dep in dependency.dependencies:
                if str(dep.ref) in packages_set:
                    new_dep.dependencies.add(Dependency(ref=dep.ref))
            new_deps.append(new_dep)

        document.dependencies = new_deps

    @classmethod
    def exclude(
        cls, document: Bom, *, binary_patterns=None, source_packages=None, installed_packages=None
    ) -> dict:
        """Exclude Debian binaries and prune their unneeded sources in-place.

        Binary patterns match the entire package name. Source selectors are exact
        (name, version) pairs and require installed dpkg metadata: CycloneDX does
        not distinguish the primary source from Built-Using dependencies.
        Validation and package mapping complete before the document is changed.
        """
        patterns = list(dict.fromkeys(binary_patterns or []))
        compiled = []
        for pattern in patterns:
            try:
                compiled.append(re.compile(pattern))
            except re.error as error:
                raise ValueError(
                    f"invalid binary exclusion pattern {pattern!r}: {error}"
                ) from error
        sources = list(dict.fromkeys(source_packages or []))
        for name, version in sources:
            if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", name) or not version:
                raise ValueError(f"invalid source package selector: {name!r} {version!r}")
            Version(version)
        if sources and installed_packages is None:
            raise ValueError("source exclusions require installed package metadata")

        components = {str(c.bom_ref): c for c in document.components}
        debian = {ref: c for ref, c in components.items() if c.purl and c.purl.type == "deb"}
        source_refs = {
            ref for ref, c in debian.items() if c.purl.qualifiers.get("arch") == "source"
        }
        binary_refs = set(debian) - source_refs
        dependencies = {
            str(d.ref): {str(child.ref) for child in d.dependencies} for d in document.dependencies
        }

        def identity(c):
            return (c.purl.name, c.purl.version, c.purl.qualifiers.get("arch"))

        binary_index = {}
        for ref in binary_refs:
            binary_index.setdefault(identity(debian[ref]), set()).add(ref)
        source_index = {}
        for ref in source_refs:
            source_index.setdefault(debian[ref].purl.name, set()).add(ref)

        removed = set()
        matched_patterns = set()
        matched_sources = {
            (name, version)
            for name, version in sources
            if any(
                c.purl.name == name and Version(c.purl.version) == Version(version)
                for ref, c in debian.items()
                if ref in source_refs
            )
        }
        candidates = set()
        for ref in binary_refs:
            for pattern in compiled:
                if pattern.fullmatch(debian[ref].purl.name):
                    removed.add(ref)
                    matched_patterns.add(pattern.pattern)

        installed = list(installed_packages or [])
        installed_refs = {}
        for package in installed:
            key = (package.name, str(package.version), package.architecture)
            matching_patterns = {p.pattern for p in compiled if p.fullmatch(package.name)}
            primary_source = package.source_package()
            selected_sources = set()
            if primary_source:
                selected_sources = {
                    (name, version)
                    for name, version in sources
                    if name == primary_source.name and Version(version) == primary_source.version
                }
            matches = binary_index.get(key, set())
            if matching_patterns or selected_sources:
                if len(matches) != 1:
                    raise ValueError(
                        f"selected installed package {package.name} "
                        f"{package.version} {package.architecture} maps to "
                        f"{len(matches)} SBOM components"
                    )
                removed.update(matches)
                matched_patterns.update(matching_patterns)
                matched_sources.update(selected_sources)
            for ref in matches:
                installed_refs[ref] = package

        for ref in removed:
            candidates.update(dependencies.get(ref, set()) & source_refs)
        for ref in source_refs:
            c = debian[ref]
            if any(
                c.purl.name == name and Version(c.purl.version) == Version(version)
                for name, version in matched_sources
            ):
                candidates.add(ref)

        needed_sources = set()
        for ref in binary_refs:
            package = installed_refs.get(ref)
            related_sources = set(dependencies.get(ref, set()) & source_refs)
            if package:
                relations = list(package.built_using) + list(package.static_built_using)
                if package.source:
                    relations.append(package.source)
                for relation in relations:
                    if relation.version:
                        related_sources.update(
                            source_ref
                            for source_ref in source_index.get(relation.name, set())
                            if Version(debian[source_ref].purl.version) == relation.version[1]
                        )
            if ref in removed:
                candidates.update(related_sources)
            else:
                needed_sources.update(related_sources)
        removed_sources = candidates - needed_sources
        removed.update(removed_sources)

        report = {
            "matched_patterns": [p for p in patterns if p in matched_patterns],
            "unmatched_patterns": [p for p in patterns if p not in matched_patterns],
            "matched_sources": [
                {"name": n, "version": v} for n, v in sources if (n, v) in matched_sources
            ],
            "unmatched_sources": [
                {"name": n, "version": v} for n, v in sources if (n, v) not in matched_sources
            ],
            "removed_binaries": sorted(removed - removed_sources),
            "removed_sources": sorted(removed_sources),
            "retained_sources": sorted(candidates & needed_sources),
        }
        if not removed:
            return report

        document.components = [c for c in document.components if str(c.bom_ref) not in removed]
        document.dependencies = [d for d in document.dependencies if str(d.ref) not in removed]
        for dependency in document.dependencies:
            dependency.dependencies = [
                d for d in dependency.dependencies if str(d.ref) not in removed
            ]
        return report
