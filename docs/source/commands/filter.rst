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

To exclude source packages by exact name and Debian version, pass a file to
``--exclude-source-file`` using the same universal ingress formats as
`From Package List <../examples.html#from-package-list>`_: package lists, Debian PURLs,
Isar manifests, or dpkg status files. Only source entries are selected; binary
entries in a manifest or status file are not excluded. Source versions must be
specified explicitly.

For example, a package list marks sources with the ``source`` architecture::

    linux 6.12.73-1 source
    example-source 2:1.0-1 source

The equivalent PURL input is::

    pkg:deb/debian/linux@6.12.73-1?arch=source
    pkg:deb/debian/example-source@2:1.0-1?arch=source

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
