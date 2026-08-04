# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

import subprocess
import sys


def test_control_file_parsers_do_not_use_the_default_encoding():
    code = """
from pathlib import Path
import warnings

from debsbom.apt import cache as apt_cache
from debsbom.apt.cache import ExtendedStates, Repository
from debsbom.apt.copyright import Copyright
from debsbom.dpkg import package as dpkg_package
from debsbom.dpkg.package import BinaryPackage

apt_cache.HAS_PYTHON_APT = False
dpkg_package.HAS_PYTHON_APT = False
source_root = Path(apt_cache.__file__).resolve().parents[1]

with warnings.catch_warnings(record=True) as caught:
    warnings.simplefilter("always", EncodingWarning)
    list(Copyright(Path("tests/data/utf8-copyright")).licenses())
    list(BinaryPackage.parse_status_file(Path("tests/data/utf8-status")))
    ExtendedStates.from_file("tests/root/apt-sources/var/lib/apt/extended_states")
    list(Repository.from_apt_cache("tests/root/utf8-apt-lists"))
    list(Repository._parse_sources("tests/data/utf8-Sources"))
    list(Repository._parse_packages("tests/data/utf8-Packages"))

source_warnings = [
    f"{warning.filename}:{warning.lineno}: {warning.message}"
    for warning in caught
    if warning.category is EncodingWarning
    and Path(warning.filename).resolve().is_relative_to(source_root)
]
if source_warnings:
    raise AssertionError("\\n".join(source_warnings))
"""

    result = subprocess.run(
        [sys.executable, "-X", "warn_default_encoding", "-c", code],
        capture_output=True,
        encoding="utf-8",
    )

    assert result.returncode == 0, result.stderr
