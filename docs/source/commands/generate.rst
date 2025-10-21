``generate`` command
====================

The command creates comprehensive SBOMs that include all installed software packages and their dependencies
(binary, source package and `built-using <https://www.debian.org/doc/debian-policy/ch-relationships.html#s-built-using>`_).
These SBOM outputs are designed to serve as reliable input for vulnerability management systems and license compliance checks.

.. note::
    This command can be executed in an air-gapped environment.

.. automodule:: debsbom.commands.generate.GenerateCmd

.. argparse::
    :module: debsbom.cli
    :func: setup_parser
    :prog: debsbom
    :path: generate
