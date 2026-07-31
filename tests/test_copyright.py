# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from debsbom.apt.copyright import Copyright, UnknownLicenseError
from pathlib import Path
import pytest


def test_copyright():
    cr = Copyright(Path("tests/data/copyright"))

    licenses = list(map(lambda lic: lic.synopsis, cr.licenses()))
    assert len(licenses) == 4
    assert "GPL-2+" in licenses
    assert "GPL-2" in licenses
    assert "BSD-3-clause" in licenses
    assert "Expat" in licenses

    spdx_licenses = list(map(lambda lic: str(lic), cr.spdx_license_expressions()))
    assert len(spdx_licenses) == 4
    assert "GPL-2.0-or-later" in spdx_licenses
    assert "GPL-2.0-only" in spdx_licenses
    assert "BSD-3-Clause" in spdx_licenses
    assert "MIT" in spdx_licenses


def test_non_spdx_copyright():
    cr = Copyright(Path("tests/data/non-spdx-copyright"))

    licenses = list(map(lambda lic: lic.synopsis, cr.licenses()))
    # we have some non-SPDX licenses, make sure they are in there
    assert "OPL-1+" in licenses
    assert "Vim-Regexp" in licenses
    assert "Compaq" in licenses
    assert "XPM" in licenses
    assert "EDL-1" in licenses

    with pytest.raises(UnknownLicenseError):
        list(cr.spdx_license_expressions())


def test_spdx_lic_expressions():
    cr = Copyright(Path("tests/data/lic-expr-copyright"))

    spdx_licenses = set(map(lambda lic: str(lic), cr.spdx_license_expressions()))
    assert "BSD-3-Clause OR GPL-2.0-or-later" in spdx_licenses
    assert "BSD-3-Clause OR GPL-2.0-only" in spdx_licenses


def test_spdx_license_exceptions():
    cr = Copyright(Path("tests/data/exception-copyright"))

    spdx_licenses = set(map(str, cr.spdx_license_expressions()))
    assert spdx_licenses == {
        "GPL-3.0-or-later WITH Bison-exception-2.2",
        "GPL-2.0-only WITH Linux-syscall-note",
        "GPL-3.0-or-later WITH Texinfo-exception",
        "GPL-3.0-or-later WITH Autoconf-exception-macro",
        "BSD-3-Clause WITH PCRE2-exception",
        "MIT",
        "GPL-3.0-or-later WITH Bison-exception-2.2 OR MIT",
        "MIT OR (GPL-3.0-or-later WITH Bison-exception-2.2 AND BSD-3-Clause)",
    }


def test_ambiguous_license_exception_rejects_all_licenses():
    cr = Copyright(Path("tests/data/unknown-exception-copyright"))

    with pytest.raises(UnknownLicenseError):
        list(cr.spdx_license_expressions())


def test_license_exception_substring_rejects_all_licenses():
    cr = Copyright(Path("tests/data/exception-substring-copyright"))

    with pytest.raises(UnknownLicenseError):
        list(cr.spdx_license_expressions())


def test_public_domain_with_supported_exception_rejects_all_licenses():
    cr = Copyright(Path("tests/data/exception-public-domain-copyright"))

    with pytest.raises(UnknownLicenseError):
        list(cr.spdx_license_expressions())


def test_late_parse_error_yields_no_licenses():
    """A late parse error must not leak licenses parsed before the error."""
    cr = Copyright(Path("tests/data/late-parse-error-copyright"))

    assert [lic.synopsis for lic in cr.licenses()] == []


def test_late_parse_error_rejects_all_licenses():
    """A malformed copyright file must not emit a partial SPDX expression."""
    cr = Copyright(Path("tests/data/late-parse-error-copyright"))

    with pytest.raises(UnknownLicenseError):
        list(cr.spdx_license_expressions())


def test_repaired_late_parse_error_emits_all_licenses():
    """A valid equivalent must still expose every declared license."""
    cr = Copyright(Path("tests/data/late-parse-ok-copyright"))

    assert [lic.synopsis for lic in cr.licenses()] == ["Expat", "Apache-2.0", "GPL-2+"]
    assert list(map(str, cr.spdx_license_expressions())) == [
        "MIT",
        "Apache-2.0",
        "GPL-2.0-or-later",
    ]


def test_copyright_is_parsed_as_utf8_regardless_of_locale(c_ctype_locale):
    """DEP-5 mandates UTF-8, so parsing must not depend on the process locale."""
    copyright = Copyright(Path("tests/data/utf8-copyright"))

    assert [license.synopsis for license in copyright.licenses()] == ["BSD-3-clause"]
