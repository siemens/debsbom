``enrich`` command
==================

The command enriches an SBOM with additional information retrieved from non-local sources.
Internally the infrastructure from the ``download`` command is used. This means binary and source packages are retrieved from the snapshot mirror.
If no information is missing on a package the download will be skipped.

.. note::
   This command might require internet access, depending on the resolver that is used.

.. automodule:: debsbom.commands.enrich.EnrichCmd

.. argparse::
    :module: debsbom.cli
    :func: setup_parser
    :prog: debsbom
    :path: enrich
