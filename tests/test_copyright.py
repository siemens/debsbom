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
