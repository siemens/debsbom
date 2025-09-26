Examples
========

The following examples are based on common use-cases.

Generate
~~~~~~~~

Generation happens fully offline and can run against an arbitrary root directory.

Local System
^^^^^^^^^^^^

Generate a CycloneDX SBOM of the current system.

.. code-block:: bash

    debsbom --progress generate -t cdx -o sbom
    # output in sbom.cdx.json

Container Rootfs using Podman
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Create the SBOM of a rootless example container.
The ``debsbom`` tool hereby is used from the host (e.g. from a Python venv).

.. code-block:: bash

    CRT=$(podman create debian:bookworm)
    CHROOT=$(podman unshare podman mount $CRT)
    podman unshare debsbom generate -t spdx --root $CHROOT

Download
~~~~~~~~

Lookup all packages on the ``snapshot.debian.org`` mirror and download all binary and source artifacts referenced in an SBOM:

.. code-block:: bash

    debsbom --progress \
        download --outdir downloads --sources --binaries sbom.cdx.json
    find downloads -mindepth 1 -maxdepth 1
    # downloads/.cache   <- debsbom metadata to map packages to artifacts
    # downloads/sources  <- files related to source packages (e.g. .dsc, .orig.tar)
    # downloads/binaries <- .deb files

Merge Source Packages
~~~~~~~~~~~~~~~~~~~~~

Debian source packages consist of a ``.dsc`` file along with one or more related artifacts.
The :doc:`commands/source-merge` takes care of merging all referenced artifacts of a debian source package into a single archive.
All referenced files have to be downloaded upfront, by using the :doc:`commands/download`.

.. note::
    Internally, the ``dpkg-source`` command from the ``dpkg-dev`` package is used to perform the merge.

The following example merges all debian source packages referenced in the ``sbom.cdx.json``, applies the debian patches and compresses the new artifacts with ZStandard.

.. code-block:: bash

    debsbom --progress \
        source-merge \
            --compress zstd \
            --apply-patches \
            sbom.cdx.json

Repack Artifacts
~~~~~~~~~~~~~~~~

The :doc:`commands/repack` is similar to the :doc:`commands/source-merge` but performs additional steps to re-layout the downloaded artifacts and recreate the SBOM.
The following example generates a ``standard-bom`` source distribution archive.

.. code-block:: bash

    debsbom --progress repack \
        --dldir downloads \
        --outdir source-archive \
        --compress zstd \
        --apply-patches \
        --validate \
        sbom.spdx.json sbom.packed.spdx.json
