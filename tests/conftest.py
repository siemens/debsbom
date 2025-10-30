# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from importlib.metadata import version
from io import BufferedReader, BytesIO
from typing import IO
from beartype import BeartypeConf, FrozenDict
from beartype.claw import beartype_package
import pytest
import requests

from debsbom.snapshot.client import SnapshotDataLake

# Fix the incomplete type hierarchy of the IO module
bt_conf = BeartypeConf(
    hint_overrides=FrozenDict(
        {IO: IO | BytesIO | BufferedReader, IO[bytes]: IO[bytes] | BufferedReader}
    )
)

beartype_package("debsbom", conf=bt_conf)


@pytest.fixture(scope="module")
def http_session():
    with requests.Session() as rs:
        rs.headers.update({"User-Agent": f"debsbom/{version('debsbom')}+test"})
        yield rs


@pytest.fixture(scope="module")
def sdl(http_session):
    return SnapshotDataLake(session=http_session)
