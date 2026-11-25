``download`` command
====================

.. automodule:: debsbom.commands.download.DownloadCmd

.. argparse::
    :module: debsbom.cli
    :func: setup_parser
    :prog: debsbom
    :path: download

JSON Output Schema
------------------

When the application is run with JSON output enabled (via the ``--json`` flag),
status messages are emitted as single-line JSON objects to standard output.
Each line represents one file of a resolved package, or a package that could not be resolved.

The schema for these JSON objects is as follows:

.. literalinclude:: ../../../src/debsbom/schema/schema-download.json
   :language: json

Fields
~~~~~~

Only **status** and **package** are always present. Other fields are omitted if their
value is not available, instead of being set to an empty string or ``null``.

*   **status**:
    The status of the download operation. This field will contain one of the
    following predefined values from the :py:class:`DownloadStatus` enum:

    *   ``"ok"``: The file was either successfully downloaded or found in the cache, and the checksum was verified.
    *   ``"checksum_mismatch"``: The downloaded file's checksum did not match the expected value.
    *   ``"not_found"``: The requested file or package could not be located.

*   **package**:
    An object identifying the package, with its ``name``, its ``version`` as a string
    and its package URL (``purl``).

*   **filename**:
    The name of the processed file, if known.

*   **path**:
    The absolute path to the downloaded file. Only present if the status is ``"ok"``.

*   **source**:
    The URL selected for downloading the file.
    Required for ``"ok"`` and ``"checksum_mismatch"``; optional for ``"not_found"``.

For example, a package that could not be resolved is reported as:

.. code-block:: json

    {"status": "not_found", "package": {"name": "example-package", "version": "1.0-1", "purl": "pkg:deb/debian/example-package@1.0-1?arch=amd64"}}
