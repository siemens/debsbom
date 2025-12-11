:orphan:

debsbom generate
================

.. argparse::
    :module: debsbom.cli
    :func: setup_parser
    :prog: debsbom
    :path: generate
    :manpage:

    The command creates comprehensive SBOMs that include all installed software packages and their dependencies.
    This command can be executed in an air-gapped environment.

SEE ALSO
--------

:manpage:`debsbom-decisions(1)`

.. include:: _debsbom-man-footer.inc
