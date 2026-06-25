# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from abc import ABC


class SbomFilter(ABC):

    @classmethod
    def binary_pkgs(cls, document):
        """Remove any non-binary packages from the document."""
        raise NotImplementedError()

    @classmethod
    def source_pkgs(cls, document):
        """Remove any non-source packages from the document."""
        raise NotImplementedError()
