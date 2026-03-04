``delta`` command
=================

.. include:: delta-description.inc

.. note::
   Only SBOMs of the same type can be compared. Specifying both SPDX and CDX SBOMs will cause an error.

.. automodule:: debsbom.commands.delta.DeltaCmd

.. argparse::
    :module: debsbom.cli
    :func: setup_parser
    :prog: debsbom
    :path: delta
