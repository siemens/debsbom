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
Each line represents a distinct package download operation.

The schema for these JSON objects is as follows:

.. literalinclude:: ../../../src/debsbom/schema/schema-download.json
   :language: json

Fields
~~~~~~

*   **status**:
    The status of the download operation. This field will contain one of the
    following predefined values from the :py:class:`DownloadStatus` enum:

    *   ``"ok"``: The file was either successfully downloaded or found in the cache, and the checksum was verified.
    *   ``"checksum_mismatch"``: The downloaded file's checksum did not match the expected value.
    *   ``"not_found"``: The requested file or package could not be located.

*   **package**:
    An object identifying the package, including the name and the version as a string.

*   **filename**:
    The name of the processed file or an empty string if the package is unavailable.

*   **path**:
    The absolute path to the downloaded file or an empty string if nothing could be downloaded.
