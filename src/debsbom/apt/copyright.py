# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Iterable
from debian.copyright import Copyright as DebCopyright, License
from license_expression import LicenseExpression, get_spdx_licensing
import logging
from pathlib import Path


logger = logging.getLogger(__name__)

# well-known list of expressions conversions, see
# https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/#license-specification
WELL_KNOWN_EXPRESSIONS = {
    "AGPL-1": "AGPL-1.0-only",
    "AGPL-1+": "AGPL-1.0-or-later",
    "AGPL-3": "AGPL-3.0-only",
    "AGPL-3+": "AGPL-3.0-or-later",
    "Apache-1": "Apache-1.0",
    "Apache-2": "Apache-2.0",
    "Artistic": "Artistic-1.0",
    "Artistic-1": "Artistic-1.0",
    "Artistic-2": "Artistic-2.0",
    "BSD-2": "BSD-2-Clause",
    "BSD-3": "BSD-3-Clause",
    "BSD-4": "BSD-4-Clause",
    "BSL": "BSL-1.0",
    "BSL-1": "BSL-1.0",
    "CC-BY": "CC-BY-1.0",
    "CC-BY-1": "CC-BY-1.0",
    "CC-BY-2": "CC-BY-2.0",
    "CC-BY-3": "CC-BY-3.0",
    "CC-BY-4": "CC-BY-4.0",
    "CC-BY-NC": "CC-BY-NC-1.0",
    "CC-BY-NC-1": "CC-BY-NC-1.0",
    "CC-BY-NC-2": "CC-BY-NC-2.0",
    "CC-BY-NC-3": "CC-BY-NC-3.0",
    "CC-BY-NC-4": "CC-BY-NC-4.0",
    "CC-BY-NC-ND": "CC-BY-NC-ND-1.0",
    "CC-BY-NC-ND-1": "CC-BY-NC-ND-1.0",
    "CC-BY-NC-ND-2": "CC-BY-NC-ND-2.0",
    "CC-BY-NC-ND-3": "CC-BY-NC-ND-3.0",
    "CC-BY-NC-ND-4": "CC-BY-NC-ND-4.0",
    "CC-BY-NC-SA": "CC-BY-NC-SA-1.0",
    "CC-BY-NC-SA-1": "CC-BY-NC-SA-1.0",
    "CC-BY-NC-SA-2": "CC-BY-NC-SA-2.0",
    "CC-BY-NC-SA-3": "CC-BY-NC-SA-3.0",
    "CC-BY-NC-SA-4": "CC-BY-NC-SA-4.0",
    "CC-BY-SA": "CC-BY-SA-1.0",
    "CC-BY-SA-1": "CC-BY-SA-1.0",
    "CC-BY-SA-2": "CC-BY-SA-2.0",
    "CC-BY-SA-3": "CC-BY-SA-3.0",
    "CC-BY-SA-4": "CC-BY-SA-4.0",
    "CC0": "CC0-1.0",
    "CC0-1": "CC0-1.0",
    "CDDL": "CDDL-1.0",
    "CDDL-1": "CDDL-1.0",
    "CPL": "CPL-1.0",
    "CPL-1": "CPL-1.0",
    "EFL": "EFL-1.0",
    "EFL-1": "EFL-1.0",
    "EFL-2": "EFL-2.0",
    "EPL": "EPL-1.0",
    "EPL-1": "EPL-1.0",
    "EPL-2": "EPL-2.0",
    "Expat": "MIT",
    "GFDL": "GFDL-1.1-only",
    "GFDL+": "GFDL-1.1-or-later",
    "GFDL-1.1": "GFDL-1.1-only",
    "GFDL-1.1+": "GFDL-1.1-or-later",
    "GFDL-1.2": "GFDL-1.2-only",
    "GFDL-1.2+": "GFDL-1.2-or-later",
    "GFDL-1.3": "GFDL-1.3-only",
    "GFDL-1.3+": "GFDL-1.3-or-later",
    "GFDL-NIV": "GFDL-1.1-no-invariants-only",
    "GFDL-NIV+": "GFDL-1.1-no-invariants-or-later",
    "GFDL-NIV-1.1": "GFDL-1.1-no-invariants-only",
    "GFDL-NIV-1.1+": "GFDL-1.1-no-invariants-or-later",
    "GFDL-NIV-1.2": "GFDL-1.2-no-invariants-only",
    "GFDL-NIV-1.2+": "GFDL-1.2-no-invariants-or-later",
    "GFDL-NIV-1.3": "GFDL-1.3-no-invariants-only",
    "GFDL-NIV-1.3+": "GFDL-1.3-no-invariants-or-later",
    "GPL": "GPL-1.0-only",
    "GPL+": "GPL-1.0-or-later",
    "GPL-1": "GPL-1.0-only",
    "GPL-1+": "GPL-1.0-or-later",
    "GPL-2": "GPL-2.0-only",
    "GPL-2+": "GPL-2.0-or-later",
    "GPL-3": "GPL-3.0-only",
    "GPL-3+": "GPL-3.0-or-later",
    "GPL3+": "GPL-3.0-or-later",
    "LGPL": "LGPL-1.0-only",
    "LGPL+": "LGPL-1.0-or-later",
    "LGPL-1": "LGPL-1.0-only",
    "LGPL-1+": "LGPL-1.0-or-later",
    "LGPL-2": "LGPL-2.0-only",
    "LGPL-2+": "LGPL-2.0-or-later",
    "LGPL-3": "LGPL-3.0-only",
    "LGPL-3+": "LGPL-3.0-or-later",
    "LPGL-2.1": "LGPL-2.1-only",
    "LPGL-2.1+": "LGPL-2.1-or-later",
    "LPPL": "LPPL-1.0",
    "LPPL-1": "LPPL-1.0",
    "MPL": "MPL-1.0",
    "MPL-1": "MPL-1.0",
    "MPL-2": "MPL-2.0",
    "PSF-2": "PSF-2.0",
    "Perl": "Artistic-1.0-Perl",
    "Python": "Python-2.0",
    "QPL": "QPL-1.0",
    "QPL-1": "QPL-1.0",
    "RubyLicense": "Ruby",
    "SIL-1": "OFL-1.0",
    "SIL-1.1": "OFL-1.1",
    "SIL-OFL-1": "OFL-1.0",
    "SIL-OFL-1.1": "OFL-1.1",
    "Zope": "ZPL-1.0",
    "Zope-1": "ZPL-1.0",
    "Zope-2": "ZPL-2.0",
}


class UnknownLicenseError(Exception):
    """License is unknown to the SPDX standard."""

    pass


class Copyright(DebCopyright):
    """Copyright information for a source package."""

    def __init__(self, path: Path):
        with open(path) as f:
            self.inner = DebCopyright(f)
        self.licensing = get_spdx_licensing()

    def _replace_unknown_symbols(self, expr: str) -> LicenseExpression:
        """Replace symbols that are not known to the SPDX standard."""
        spdx_expr = self.licensing.parse(expr)

        unknown_keys = self.licensing.unknown_license_keys(spdx_expr)
        if len(unknown_keys) > 0:
            unreplaced = []
            for unknown_key in unknown_keys:
                replacement = WELL_KNOWN_EXPRESSIONS.get(unknown_key)
                if replacement:
                    expr = expr.replace(unknown_key, replacement)
                else:
                    unreplaced.append(unknown_key)

            if len(unreplaced) > 0:
                s = ", ".join(unreplaced)
                raise UnknownLicenseError(f"unknown license keys: {s}")
            return self.licensing.parse(expr, validate=True)
        else:
            return spdx_expr

    @classmethod
    def _convert_expression(cls, line: str) -> str:
        """Convert a Debian license expression to the equivalent SPDX syntax."""

        # in the Debian copyright format ',' are used for disambiguation
        # that means (with 'and' having precedence over 'or'):
        # A or B and C <=> A or (B and C)
        # A or B, and C <=> (A or B) and C
        # for more information see
        # https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/#license-specification
        tokens = line.split(" ")
        indices = []
        for i, token in enumerate(tokens):
            if token.endswith(","):
                tokens[i] = token[:-1]
                indices.append(i)

        # keep track of inserted tokens
        inserted = 0
        for i in range(len(indices)):
            # the opening brace can be inserted always at the beginning
            tokens.insert(0, "(")
            # and the closing brace after the token that had the comma
            tokens.insert(indices[i] + inserted + 2, ")")
            inserted += 2

        return " ".join(tokens)

    def licenses(self) -> Iterable[License]:
        """Return all licenses found in the copyright file."""
        lic = self.inner.header.license
        if lic:
            yield lic

        for paragraph in self.inner.all_files_paragraphs():
            yield paragraph.license

    def spdx_license_expressions(self) -> Iterable[LicenseExpression]:
        """Return all licenses as SPDX license expressions."""
        yielded = 0
        for lic in self.licenses():
            if not lic.synopsis:
                raise UnknownLicenseError("only license text is available")

            expr = self._convert_expression(lic.synopsis)
            spdx_lic = self.licensing.parse(expr)
            unknown_keys = self.licensing.unknown_license_keys(spdx_lic)
            # TODO: how do we handle `public-domain` licensing?
            # TODO: license exceptions
            if len(unknown_keys) > 0:
                # unknown keys in the license expression, try to replace them
                # with well-known representations
                unreplaced = []
                for unknown_key in unknown_keys:
                    replacement = WELL_KNOWN_EXPRESSIONS.get(unknown_key)
                    if replacement:
                        expr = expr.replace(unknown_key, replacement)
                    else:
                        unreplaced.append(unknown_key)

                if len(unreplaced) > 0:
                    s = ", ".join(unreplaced)
                    raise UnknownLicenseError(f"unknown license keys: {s}")
                yield self.licensing.parse(expr, validate=True)
            else:
                yield spdx_lic
            yielded += 1

        if yielded == 0:
            raise UnknownLicenseError("no license information available")


class CopyrightDirectory:
    """Directory of Debian copyright information."""

    def __init__(self, path: Path):
        self.copyright_root = path

    @classmethod
    def for_rootdir(cls, root: Path) -> "CopyrightDirectory":
        return CopyrightDirectory(root / "usr/share/doc")

    def copyright(self, bin_pkg) -> Copyright:
        """Get the copyright information for a binary package."""
        copyright_path = self.copyright_root / bin_pkg.name / "copyright"
        return Copyright(copyright_path)
