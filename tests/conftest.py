# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from importlib.metadata import version
from beartype.claw import beartype_package
import io
import locale
import pytest
import requests
from requests.adapters import BaseAdapter
from requests.structures import CaseInsensitiveDict
import sys

from debsbom.snapshot.client import SnapshotDataLake
from debsbom.download.adapters import LocalFileAdapter

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


class FakeHTTPAdapter(BaseAdapter):
    """
    Serves canned responses for exact URLs and records all requests.
    Unknown URLs are answered with a 404. A route body can also be a readable
    object (used as raw stream) or an exception (raised on request).
    """

    def __init__(self):
        super().__init__()
        self.routes = {}
        self.requests = []

    def add(self, url, body=b"", status=200, headers=None):
        self.routes[url] = (status, body, headers or {})

    @property
    def urls(self):
        return [r.url for r in self.requests]

    def send(self, request, **kwargs):
        self.requests.append(request)
        status, body, headers = self.routes.get(request.url, (404, b"not found", {}))
        if isinstance(body, Exception):
            raise body
        response = requests.Response()
        response.request = request
        response.url = request.url
        response.status_code = status
        response.reason = "fake"
        response.headers = CaseInsensitiveDict(headers)
        response.raw = body if hasattr(body, "read") else io.BytesIO(body)
        return response

    def close(self):
        pass


@pytest.fixture
def fake_http():
    """
    Session serving canned HTTP(S) responses and local files.
    Returns the session and the fake adapter.
    """
    adapter = FakeHTTPAdapter()
    with requests.Session() as rs:
        rs.mount("http://", adapter)
        rs.mount("https://", adapter)
        rs.mount("file:///", LocalFileAdapter())
        yield rs, adapter
