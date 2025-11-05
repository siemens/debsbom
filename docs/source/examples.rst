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

From Package List
^^^^^^^^^^^^^^^^^

Create the SBOM from a package list. The so provided packages will still be enriched with any available data from the apt cache.

.. code-block:: bash

    echo "htop 3.4.1-5 amd64" | debsbom generate --from-pkglist
    # or in isar manifest format
    echo "json-c|0.16-2|libjson-c5:amd64|0.16-2" | debsbom generate --from-pkglist
    # or with PURLs
    echo "pkg:deb/debian/htop@3.4.1-5?arch=amd64" | debsbom generate --from-pkglist

It further is possible to inject a dpkg status file via stdin (e.g. if you only have that file).
The data is then also resolved from the apt-cache (if available), but this usually only makes sense if you don't have a
chroot and want to create the sbom just from the data in the file.

.. code-block:: bash

    cat path/to/dpkg/status | debsbom generate --from-pkglist

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

It is also possible to download multiple packages by name, version and architecture:

.. code-block:: bash

    cat <<EOF | debsbom download --binaries --sources
    cpp 4:12.2.0-3 amd64
    guestfs-tools 1.52.3-1 source
    EOF

Alternatively, the download can be executed from the container image:

.. code-block:: bash

    echo "guestfs-tools 1.52.3-1 source" | \
    docker run -v$(pwd)/downloads:/mnt/downloads -i ghcr.io/siemens/debsbom:latest \
        debsbom download --outdir /mnt/downloads --sources

Merge Source Packages
~~~~~~~~~~~~~~~~~~~~~

Debian source packages consist of a ``.dsc`` file along with one or more related artifacts.
The :doc:`/commands/source-merge` takes care of merging all referenced artifacts of a debian source package into a single archive.
All referenced files have to be downloaded upfront, by using the :doc:`/commands/download`.

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

The :doc:`/commands/repack` is similar to the :doc:`/commands/source-merge` but performs additional steps to re-layout the downloaded artifacts and recreate the SBOM.
The following example generates a ``standard-bom`` source distribution archive.

.. code-block:: bash

    debsbom --progress repack \
        --dldir downloads \
        --outdir source-archive \
        --compress zstd \
        --apply-patches \
        --validate \
        sbom.cdx.json sbom.packed.cdx.json

It further is possible to only repack (and update in the SBOM) a subset of packages.
For that, provide both an SBOM, as well as a set of "to-be-processed" packages via stdin.

.. code-block:: bash

    echo "bash 5.2.37-2 source" | debsbom -v repack sbom-in.json sbom-out.json

Compare SBOMs
~~~~~~~~~~~~~

The :doc:`/commands/compare` compares a base (reference) SBOM with a target (new) SBOM and produces
a new SBOM containing only the components present in the target. The typical use-case is identifying
newly added or changed components between two builds or releases.

Identify new Components
^^^^^^^^^^^^^^^^^^^^^^^

Use ``debsbom compare`` when you only want to see changed or added components, e.g., to generate an
SBOM for license clearance.

.. code-block:: bash

   debsbom compare sbom.old.cdx.json sbom.cdx.json extras.cdx.json

You can also pass SBOMs via stdin, but you also have to pass the SBOM type in this case:

.. code-block:: bash

   cat sbom.old.spdx.json sbom.spdx.json | debsbom compare -t spdx - - -o -

Export as Graph
~~~~~~~~~~~~~~~

The :doc:`/commands/export` allows to convert the SBOM into various graph representations.
These can be used as input to graph visualization and analysis tooling (like Gephi).

.. note::
    We recommend to use the SPDX format as input, as this describes inter package relations
    more precisely.

Convert the SPDX SBOM to GraphML:

.. code-block:: bash

    debsbom export sbom.spdx.json sbom-graph.graphml

Merging multiple SBOMs
~~~~~~~~~~~~~~~~~~~~~~

The :doc:`/commands/merge` merges multiple SBOMs hierarchically. The intended use-case is to
combine multiple SBOMs describing a Debian-based distribution. A good example is the rootfs
and the initrd of a Linux distribution.

Merge two SBOMs representing the above case:

.. code-block:: bash

    debsbom merge rootfs.spdx.json initrd.spdx.json -o merged.spdx.json

You can also pass SBOMs via stdin, but you also have to pass the SBOM type in this case:

.. code-block:: bash

    cat rootfs.spdx.json initrd.spdx.json | debsbom merge -t spdx -o merged.spdx.json -

License-Clearing Workflow
~~~~~~~~~~~~~~~~~~~~~~~~~

``debsbom`` can be used for license clearing. The license clearing workflow could look like this:

First, generate a CycloneDX SBOM of a rootfs:

.. code-block:: bash

    debsbom --progress generate -r path/to/the/rootfs -t cdx -o sbom
    # output in sbom.cdx.json

Use the generated SBOM to download all source packages:

.. code-block:: bash

    debsbom --progress download --outdir downloads --sources sbom.cdx.json
    # the downloaded files will be in downloads/sources/<archive>

You will notice that there is no single file for each source package. Instead there is multiple:
the .dsc file, an .orig.tar tarball, maybe some patches and more. ``debsbom`` provides an easy
way to combine them into a single tarball that can be used in most license clearing platforms:

.. code-block:: bash

    debsbom --progress source-merge --compress zstd --apply-patches sbom.cdx.json
    # merged and patched compressed tarballs are in downloads/sources/<archive>

Now there is a single compressed file for each source package.

.. note::
    If you only need to work on a smaller subset of packages you can pass a package list
    via stdin. See the above sections for concrete examples how to do that.

Alternatively you can use the :doc:`/commands/repack` to rewrite the SBOM and repack the downloaded
artifacts in a format-specific way:

.. code-block:: bash

    debsbom --progress repack \
        --format standard-bom \
        --dldir downloads \
        --compress zstd \
        --apply-patches \
        --validate \
        sbom.cdx.json sbom.packed.cdx.json

This step is very specific to the actual use-case you have. Right now the only available format
is ``standard-bom``, which created a directory structure and rewrites the SBOM to reference
all source packages directly in there. If you want to see more formats you can open an issue,
or even better, contribute it directly.
