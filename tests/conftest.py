# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from importlib.metadata import version
from beartype.claw import beartype_package
import pytest
import requests

from debsbom.snapshot.client import SnapshotDataLake

beartype_package("debsbom")


@pytest.fixture(scope="module")
def http_session():
    rs = requests.Session()
    rs.headers.update({"User-Agent": f"debsbom/{version('debsbom')}+test"})
    return rs


@pytest.fixture(scope="module")
def sdl(http_session):
    return SnapshotDataLake(session=http_session)
