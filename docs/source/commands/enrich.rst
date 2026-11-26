``enrich`` command
==================

The command enriches an SBOM with additional information retrieved from non-local sources.
Internally the infrastructure from the ``download`` command is used. This means binary and source packages are retrieved with the selected resolver: from the snapshot mirror by default, or from an APT repository with the ``debian-mirror`` resolver and its options, which are described in the :doc:`/commands/download`.
If no information is missing on a package the download will be skipped, and the package is not resolved either.

The download location added to a package is the URL that the resolver selected for its ``.deb`` or ``.dsc`` file. With the ``debian-mirror`` resolver, this URL points into the repository and is not necessarily a permanent location, as mirrors remove old versions. It can be omitted with ``--no-download-location``.

.. note::
   This command might require internet access, depending on the resolver that is used.

.. automodule:: debsbom.commands.enrich.EnrichCmd

.. argparse::
    :module: debsbom.cli
    :func: setup_parser
    :prog: debsbom
    :path: enrich
