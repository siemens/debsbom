``trace-path`` command
======================

.. automodule:: debsbom.commands.tracepath.TracePathCmd

.. argparse::
    :module: debsbom.cli
    :func: setup_parser
    :prog: debsbom
    :path: trace-path

JSON Output Schema
------------------

When the application is run with JSON output enabled (via the ``--json`` flag),
status messages are emitted as single-line JSON objects to standard output.
Each line represents a single path from the package to the root.

The schema for these JSON objects is as follows:

.. literalinclude:: ../../../src/debsbom/schema/schema-trace-path.json
   :language: json
