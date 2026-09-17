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

For exact source-package exclusions, provide a JSON array of source names and
Debian versions using ``--exclude-source-file``. For example:

.. code-block:: json

    [
      {"name": "linux", "version": "6.12.73-1"},
      {"name": "example-source", "version": "2:1.0-1"}
    ]

Source exclusions require the **matching system's** dpkg status file::

    debsbom filter input.cdx.json filtered.cdx.json \
        --exclude-source-file sources.json \
        --installed-status rootfs/var/lib/dpkg/status \
        --exclusion-report exclusions.json

The status file identifies the binaries actually produced by each source,
including cases where source and binary names or versions differ. This is needed
because CycloneDX dependency edges do not distinguish a binary's own source from
its ``Built-Using`` sources. The command does not implicitly inspect the host
system. A selected installed binary must map to exactly one component with the
same name, version and architecture in the input SBOM; a missing or ambiguous
mapping is an error. The status file can also be supplied with binary patterns to
check that every matching installed binary is represented in the input.

Excluded components and all their dependency references are removed. A source
still needed by a retained binary is preserved, including ``Built-Using`` and
``Static-Built-Using`` relationships. Unrelated source components are preserved.
Excluding all represented binaries and their unneeded sources produces a valid
empty inventory while retaining the root metadata component.

The optional JSON report contains ``matched_patterns``, ``unmatched_patterns``,
``matched_sources`` and ``unmatched_sources``. Source selectors are reported as
name/version objects. ``removed_binaries``, ``removed_sources`` and
``retained_sources`` contain component reference strings; the last field identifies
source candidates kept because retained binaries still need them. Unmatched
selectors do not fail the command. The report is written to a separate file,
including when the SBOM is read from or written to standard input/output.

Exclusions can be combined with ``--sources`` or ``--binaries``; exclusion and
shared-source analysis happen first. They cannot be combined with ``--package``,
which selects a dependency subgraph. SPDX exclusions are not supported.
