# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

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
