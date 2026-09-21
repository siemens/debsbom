``filter`` command
==================

.. automodule:: debsbom.commands.filter.FilterCmd

.. argparse::
    :module: debsbom.cli
    :func: setup_parser
    :prog: debsbom
    :path: filter

Package exclusions (CycloneDX)
------------------------------

Use ``--exclude-binary REGEX`` to exclude binary packages by their Debian package
name. Each expression must match the **entire** name, and the option may be
repeated. The same name matches all versions and architectures present in the
SBOM. An invalid regular expression is an error.

For example, filter out kernel image packages before acquiring sources::

    debsbom --json filter input.cdx.json filtered.cdx.json \
        --exclude-binary 'linux-image-.*' > exclusions.json
    debsbom download --sources --outdir downloads filtered.cdx.json
    debsbom repack --sources --dldir downloads filtered.cdx.json repacked.cdx.json

To exclude source packages by exact name and Debian version, pass a file with one
JSON object per line to ``--exclude-source-file``:

.. code-block:: json

    {"name": "linux", "version": "6.12.73-1"}
    {"name": "example-source", "version": "2:1.0-1"}

Each line follows this schema:

.. literalinclude:: ../../../src/debsbom/schema/schema-filter-exclude.json
   :language: json

A matching source package is excluded without removing binaries built from it.
Dependencies of excluded packages are removed only when no retained package
references them.

The global ``--json`` option writes the exclusion report to standard output.
Use an SBOM output file when requesting a report so that the two JSON documents
do not share standard output. Unmatched exclusions do not fail the command.
The report follows this schema:

.. literalinclude:: ../../../src/debsbom/schema/schema-filter-report.json
   :language: json

Exclusions can be combined with ``--sources`` or ``--binaries``; the exclusions
are applied first. They cannot be combined with ``--package``, which selects a
dependency subgraph. SPDX exclusions are not supported.
