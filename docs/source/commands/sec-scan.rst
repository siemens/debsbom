``sec-scan`` command
====================

The command reads an SBOM and checks all referenced source packages for vulnerability
based on the Debian security tracker data. The output can be written in various formats,
including OpenVEX and SARIF.

.. note::
    This command can be executed in an air-gapped environment if the db
    is already downloaded.

.. automodule:: debsbom.commands.security_scan.SecurityScanCmd

.. argparse::
    :module: debsbom.cli
    :func: setup_parser
    :prog: debsbom
    :path: sec-scan

JSON Output Schema
------------------

When the application is run with JSON output enabled (via the ``--json`` flag),
status messages are emitted as single-line JSON objects to standard output.
Each line represents a distinct scan result (e.g. vulnerability affecting a package).

The schema for these JSON objects is as follows:

.. literalinclude:: ../../../src/debsbom/schema/schema-sec-scan.json
   :language: json
