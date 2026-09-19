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

    debsbom filter input.cdx.json filtered.cdx.json \
        --exclude-binary 'linux-image-.*' --exclusion-report exclusions.json
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

A matching source package is excluded together with the binary packages built
from it. As CycloneDX does not distinguish a binary's own source from its
``Built-Using`` sources, the binaries of a source are determined the same way as
when debsbom reads a CycloneDX SBOM: a source with the name of the binary is
preferred, otherwise the first referenced source is used.

The exclusion works on the dependency graph of the SBOM:

1. the packages matching the exclusions are removed together with all references to them
2. packages that are no longer referenced by any remaining package are removed
3. step 2 is repeated until no more packages are removed

This removes the sources and dependencies of the excluded packages unless they are
still referenced by a retained package, for example through ``Built-Using`` or
``Static-Built-Using``. Packages that were already unreferenced in the input are
kept. Excluding all packages produces a valid empty SBOM that retains the root
metadata component.

The optional ``--exclusion-report`` is written as a single JSON object to a
separate file, also when the SBOM is read from or written to standard input/output.
Unmatched exclusions do not fail the command. The report follows this schema:

.. literalinclude:: ../../../src/debsbom/schema/schema-filter-report.json
   :language: json

Exclusions can be combined with ``--sources`` or ``--binaries``; the exclusions
are applied first. They cannot be combined with ``--package``, which selects a
dependency subgraph. SPDX exclusions are not supported.
