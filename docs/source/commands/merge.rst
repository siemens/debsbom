``merge`` command
========================

.. include:: merge-description.inc

.. note::
   Only SBOMs of the same type can be merged. Specifying both SPDX and CDX SBOMs will cause an error.

.. automodule:: debsbom.commands.merge.MergeCmd

.. argparse::
    :module: debsbom.cli
    :func: setup_parser
    :prog: debsbom
    :path: merge

