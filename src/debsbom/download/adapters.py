# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import errno
from io import BytesIO
import locale
from pathlib import Path
from requests import Response, Request, Session, codes
from requests.adapters import BaseAdapter
from urllib.parse import unquote, urlparse


class LocalFileAdapter(BaseAdapter):
    """Adapter for local file access."""

    def send(self, request, **kwargs) -> Response:
        if request.method != "GET":
            raise ValueError(f"Request method {request.method} is not supported")

        response = Response()
        response.request = request
        response.url = request.url

        path = Path(unquote(urlparse(request.url).path))
        try:
            response.raw = open(path, "rb")
            # make sure we properly close the file when we are done
            response.raw.release_conn = response.raw.close
            response.status_code = codes.ok
        except IOError as e:
            if e.errno == errno.EACCES:
                response.status_code = codes.forbidden
            elif e.errno == errno.ENOENT:
                response.status_code = codes.not_found
            else:
                response.status_code = codes.bad_request
            response.raw = BytesIO(str(e).encode(locale.getpreferredencoding()))
            response.reason = str(e)

        return response

    def close(self):
        pass
