Getting Started
===============

Below are two possible approaches to use the ``debsbom`` tool.

Virtual Environment
-------------------

1. Create a new virtual environment:
   
   ``python3 -m venv --system-site-packages <env_name>``

2. Activate the virtual environment:

   ``source <env_name>/bin/activate``

3. Install the dependencies in the virtual environment with one of the following commands:

   - ``pip3 install -e .``
        Installs the dependencies for the generate command.

   - ``pip3 install -e .[download]``
        Installs the dependencies for all four commands (generate, download, source-merge and repack).

   - ``pip3 install -e .[dev]``
        Installs the dependencies for all four commands (generate, download, source-merge and repack), as well as dependencies for testing and documentation building

4. test installation with:

   ``debsbom -h``

Container Image
---------------

The ``debsbom`` tool is available as a container image at ``ghcr.io/siemens/debsbom:<latest|tag>``.
It runs as root inside the container, allowing mounted directories (e.g., the download directory) to be owned by the invoking user in rootless environments, simplifying CI usage.

The container image is built in a bit‑for‑bit reproducible manner.
This can be verified by forking the repository, executing the CI pipeline, and comparing the hashes of the resulting container manifest.
