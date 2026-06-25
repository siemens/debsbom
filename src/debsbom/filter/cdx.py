# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from cyclonedx.model.dependency import Dependency
from cyclonedx.model.bom import Bom

from .filter import SbomFilter


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
