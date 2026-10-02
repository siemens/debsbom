# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

import re
from debian.debian_support import Version

from cyclonedx.model.dependency import Dependency
from cyclonedx.model.bom import Bom

from .filter import SbomFilter
from ..graph.walker import PackageRepr
from ..resolver.cdx import CdxPackageResolver


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
    def exclude(cls, document: Bom, *, binary_patterns=(), source_packages=()) -> dict:
        """Exclude packages and prune the dependency graph in-place.

        Binary packages whose entire name matches one of ``binary_patterns`` are
        removed. ``source_packages`` holds exact ``(name, version)`` pairs; a
        matching source package is removed. Afterwards, packages that are no longer
        referenced by any remaining package are removed as well, until no more
        packages become unreferenced.
        """
        patterns = list(dict.fromkeys(binary_patterns))
        compiled = []
        for pattern in patterns:
            try:
                compiled.append(re.compile(pattern))
            except re.error as error:
                raise ValueError(
                    f"invalid binary exclusion pattern {pattern!r}: {error}"
                ) from error
        sources = list(dict.fromkeys(source_packages))
        selectors = [(name, Version(version)) for name, version in sources]

        def is_source(component):
            return component.purl.qualifiers.get("arch") == "source"

        debian = {
            str(c.bom_ref): c for c in document.components if CdxPackageResolver.is_debian_pkg(c)
        }
        removed = set()
        matched_patterns = set()
        matched_sources = set()
        for ref, component in debian.items():
            name = component.purl.name
            if is_source(component):
                version = Version(component.purl.version)
                for selector, (sel_name, sel_version) in zip(sources, selectors):
                    if name == sel_name and version == sel_version:
                        removed.add(ref)
                        matched_sources.add(selector)
                continue
            for pattern in compiled:
                if pattern.fullmatch(name):
                    removed.add(ref)
                    matched_patterns.add(pattern.pattern)

        # repeatedly remove packages that are only referenced by removed packages
        components = {str(c.bom_ref) for c in document.components}
        children = {
            str(d.ref): {str(child.ref) for child in d.dependencies} for d in document.dependencies
        }
        frontier = set(removed)
        while frontier:
            candidates = set().union(*(children.get(ref, set()) for ref in frontier))
            referenced = set().union(
                *(refs for ref, refs in children.items() if ref not in removed)
            )
            frontier = (candidates & components) - removed - referenced
            removed |= frontier

        removed_sources = {ref for ref in removed if ref in debian and is_source(debian[ref])}
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
