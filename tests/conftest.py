# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from importlib.metadata import version
from beartype.claw import beartype_package
import locale
import pytest
import requests
import sys

from debsbom.snapshot.client import SnapshotDataLake

beartype_package("debsbom")


@pytest.fixture
def c_ctype_locale():
    if sys.flags.utf8_mode:
        pytest.skip("Python UTF-8 mode overrides the locale encoding")

    previous_locale = locale.setlocale(locale.LC_CTYPE)
    try:
        # LC_CTYPE is process-global, so restore it as soon as the test completes.
        locale.setlocale(locale.LC_CTYPE, "C")
        yield
    finally:
        locale.setlocale(locale.LC_CTYPE, previous_locale)


@pytest.fixture(scope="session")
def http_session():
    with requests.Session() as rs:
        rs.headers.update({"User-Agent": f"debsbom/{version('debsbom')}+test"})
        yield rs


@pytest.fixture(scope="module")
def sdl(http_session):
    return SnapshotDataLake(session=http_session)
