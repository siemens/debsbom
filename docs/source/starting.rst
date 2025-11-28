Getting Started
===============

Below are two possible approaches to use the ``debsbom`` tool.

Virtual Environment
-------------------

1. Create a new virtual environment:
   
   ``python3 -m venv --system-site-packages <env_name>``

2. Activate the virtual environment:

   ``source <env_name>/bin/activate``

3. Install debsbom and its dependencies in the virtual environment with one of the following commands:

   - Installs the debsbom pip package with its core dependencies:

      ``pip3 install debsbom[cdx,spdx,download]``

      If you do not need CycloneDX, SPDX, or download support, you can omit the respective extras.

   - Installs the debsbom package in editable mode with all dependencies, including development dependencies for testing and documentation building:

      ``pip3 install -e .[dev]``

      Replace the dot (.) with the path to the debsbom source code if not executing from within the source directory.

4. Test the installation with:

   ``debsbom -h``

**Optional**: To significantly speed up the parsing of deb822 data, it is recommended to install the system package python3-apt (e.g., ``apt install python3-apt`` on Debian-based systems)

Container Image
---------------

The ``debsbom`` tool is available as a container image at ``ghcr.io/siemens/debsbom:<latest|tag>``.
It runs as root inside the container, allowing mounted directories (e.g., the download directory) to be owned by the invoking user in rootless environments, simplifying CI usage.

The container image is built in a bit‑for‑bit reproducible manner.
This can be verified by forking the repository, executing the CI pipeline, and comparing the hashes of the resulting container manifest.
