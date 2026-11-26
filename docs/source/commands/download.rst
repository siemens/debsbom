``download`` command
====================

.. automodule:: debsbom.commands.download.DownloadCmd

.. argparse::
    :module: debsbom.cli
    :func: setup_parser
    :prog: debsbom
    :path: download

Resolvers
---------

Before anything is downloaded, all selected packages are resolved: the resolver selected with ``--resolver`` determines the files of each package and the locations to download them from. The :doc:`/commands/enrich` uses the same resolvers.

*   ``debian-snapshot`` (default): looks up packages on the Debian snapshot archive (snapshot.debian.org).
*   ``debian-mirror``: looks up packages in the indexes of an APT repository, like a Debian mirror or a repository created with ``reprepro``.

Further resolvers can be provided by :doc:`/plugins`. Packages that are excluded with ``--sources``, ``--binaries`` or ``--skip-pkgs`` are filtered before they are resolved, so no resolver receives any information about them.

APT Repositories
~~~~~~~~~~~~~~~~

The ``debian-mirror`` resolver looks up packages in a single APT repository. It is configured explicitly by the archive root of the repository (``--mirror-url``), and the suites (``--mirror-suite``) and components (``--mirror-component``) to search:

.. code-block:: bash

    debsbom --json download \
        --resolver debian-mirror \
        --mirror-url https://deb.debian.org/debian \
        --mirror-suite trixie \
        --mirror-component main \
        --sources --binaries \
        sbom.spdx.json

The archive root is an ``http``, ``https`` or ``file`` URL (with an absolute path), without credentials, query or fragment. Nothing is derived from the SBOM, from an apt configuration or from the host. The configuration is validated before the input is read and before any request is made.

Suites and components can be repeated. They are searched in the given order, suite by suite and component by component, and the first matching package is used. The indexes of a suite are located below ``dists``:

*   ``<root>/dists/<suite>/<component>/source/Sources``
*   ``<root>/dists/<suite>/<component>/binary-<arch>/Packages``

A suite ending with ``/`` is an exact path relative to the archive root, as used by flat repositories, e.g. ``./`` or ``sub/dir/``. Its indexes are ``<root>/<path>/Sources`` and ``<root>/<path>/Packages``, and it has no components. Suites with and without an exact path cannot be combined.

Each index is retrieved in the first available variant: compressed with xz, compressed with gzip, or uncompressed. Only missing variants are skipped, an invalid one is an error. A missing index is treated like an empty one, so incomplete repositories are supported, e.g. repositories created with ``reprepro`` that contain only some packages or architectures, or no sources. The files are located by the paths in the indexes (``Directory`` and ``Filename``), which are relative to the archive root.

Only one archive root is searched. For example, Debian security updates are published in a separate archive, with the archive root ``https://security.debian.org/debian-security`` and suites like ``trixie-security``, which is not searched along with the main archive.

Packages are matched exactly by name and full version, including the epoch and binNMU suffix, and binary packages also by architecture. Other versions are never used. If the SBOM contains checksums of a package, packages of the repository with a different checksum are skipped. The strongest algorithm known to both is compared (``SHA512``, ``SHA256``, ``SHA1``, ``MD5``), and its result is final. If the checksums of a binary package have no algorithm in common, the package is used, and its checksum from the SBOM is verified after downloading it. Without checksums, the first matching package is used.

For a source package, the ``.dsc`` file is retrieved while resolving. It must match its size and checksums in the index, describe the same source package, and list the same other files as the index, with the same sizes and checksums. A ``.dsc`` file that contradicts the index is an error. If the SBOM contains a checksum of the source package, the ``.dsc`` file must match it, otherwise the next matching package is tried. This checksum identifies the complete ``.dsc`` file, including its signature, which is not verified: a ``.dsc`` file with a different checksum is not used, even if only its signature differs. Without a checksum in the SBOM, the identity of a source package is imprecise, and the first matching one of the repository is used. The ``.dsc`` file and all files it lists, e.g. multiple upstream tarballs and their signatures, are downloaded into the same directory.

Binary packages of the architecture ``all`` are listed either in the indexes of the other architectures of a suite, or in a separate ``binary-all`` index. The ``binary-all`` index is searched if the ``Release`` (or ``InRelease``) file of the suite announces it (``all`` in ``Architectures``, unless ``No-Support-for-Architecture-all: Packages`` is set), or if the suite has no ``Release`` file. Then the indexes of the architectures given with ``--mirror-architecture`` are searched or, without this option, the ones of the architectures listed in the ``Release`` file. For a repository with many architectures, like a Debian mirror, give the architectures of the SBOM, as otherwise packages that are not found are searched in the indexes of all its architectures. If ``all`` is given with ``--mirror-architecture``, exactly the given indexes are searched. If no architecture is known, the package cannot be resolved, which is an error: the architecture of the host is never assumed. Binary packages of other architectures are only searched in the index of their architecture. Suites with an exact path have a single ``Packages`` index for all architectures, so ``--mirror-architecture`` cannot be used with them.

Snapshot Fallback
~~~~~~~~~~~~~~~~~

A mirror usually only provides the latest versions of packages. With ``--snapshot-fallback``, packages that are not found in the repository are looked up on snapshot.debian.org instead. This sends the names and versions of these packages to snapshot.debian.org, a public service, which is why there is no fallback by default. ``--no-snapshot-fallback`` states this explicitly. Packages found in the repository, and packages that are excluded, are not looked up there.

Only packages that are not found fall back: the repository has no package with that name, version and architecture, or only ones with a different checksum than in the SBOM. Other errors are not hidden by the fallback, e.g. authentication or server errors, timeouts, missing architectures, malformed or unsafe metadata, and files that contradict their metadata. They are reported in the warning for the package, which is not downloaded. In the JSON output, such a package also has the status ``not_found``. All files of a package are resolved by the same resolver, so a source package never consists of files from both the repository and snapshot.debian.org.

The fallback only applies to resolving. All packages are resolved before the download starts. If a file of the repository cannot be downloaded afterwards, e.g. because it was removed from the mirror in the meantime, the download fails with an error, and the file is not downloaded from snapshot.debian.org instead.

Caching
~~~~~~~

The ``debian-snapshot`` resolver stores its results, including packages that are not found, in ``<outdir>/.cache/debian-snapshot``. The Snapshot fallback uses the same cache, unless the ``debian-snapshot`` resolver is replaced by a plugin. A result cached for snapshot.debian.org never takes precedence over the repository, which is always searched first.

Results of the ``debian-mirror`` resolver are not stored, as this cache is keyed by the package only, not by the repository configuration, and the content of a repository changes over time. Instead, each index is retrieved and parsed at most once per run, when it is needed for the first time. Errors when retrieving or parsing an index are remembered as well, but only until the end of the run.

Trust and Limits
~~~~~~~~~~~~~~~~

The ``debian-mirror`` resolver validates the metadata it uses: the indexes must be well-formed UTF-8 and contain only safe relative paths, consistent sizes and well-formed checksums, and every file must have a checksum of a supported algorithm. Paths containing ``.`` or ``..`` segments are normalized, but must not leave the archive root. Each downloaded file is verified against its size and strongest checksum in the index, or in the ``.dsc`` file for the other files of a source package, and binary packages and ``.dsc`` files also against their checksum in the SBOM.

This detects corrupted and inconsistent data, but it does not authenticate the repository: neither the signatures of the ``Release`` and ``InRelease`` files nor the checksums of the indexes listed there are verified. The ``Release`` file is only used to find the indexes of ``Architecture: all`` packages. Thus, the repository, or anybody who can modify the connection to it, can provide other packages with consistent metadata, which is only detected by the checksums in the SBOM. Verifying the signatures of repositories is tracked in `issue #282 <https://github.com/siemens/debsbom/issues/282>`__.

While resolving, requests time out after 10 seconds when connecting and after 60 seconds without receiving data, but there is no limit for the total duration of a request. After removing any HTTP content encoding, index files are limited to 128 MiB, and their content to 512 MiB after decompression (decompressing xz data uses at most 256 MiB of memory). ``Release`` and ``InRelease`` files are limited to 16 MiB, and ``.dsc`` files to 4 MiB. These limits apply to each file, they do not limit the memory used for the parsed indexes, which are kept until the end of the run. Package files must not exceed their size in the index.

Download Locations
~~~~~~~~~~~~~~~~~~

Files are stored in ``<outdir>/sources/<archive>/`` and ``<outdir>/binaries/<archive>/``. For the ``debian-mirror`` resolver, ``<archive>`` is derived from the URL of the repository, e.g. ``mirror_deb.debian.org_debian``, while files found on snapshot.debian.org are stored as with the ``debian-snapshot`` resolver. All files of a source package are stored in the same directory, as required by the :doc:`/commands/source-merge`. The names of these directories only group the files, they do not state the origin of a package.

The ``source`` of a download result is the URL that the resolver selected to download the file from. It is not necessarily a permanent location, as mirrors remove old versions, and it does not state the origin of the package. It also does not prove that the file was retrieved in this run, as it may have been downloaded before. The PURL and the other information about a package are not changed because a mirror provides it.

JSON Output Schema
------------------

When the application is run with JSON output enabled (via the ``--json`` flag),
status messages are emitted as single-line JSON objects to standard output.
Each line represents one file of a resolved package, or a package that could not be resolved.

The schema for these JSON objects is as follows:

.. literalinclude:: ../../../src/debsbom/schema/schema-download.json
   :language: json

Fields
~~~~~~

Only **status** and **package** are always present. Other fields are omitted if their
value is not available, instead of being set to an empty string or ``null``.

*   **status**:
    The status of the download operation. This field will contain one of the
    following predefined values from the :py:class:`DownloadStatus` enum:

    *   ``"ok"``: The file was either successfully downloaded or found in the cache.
        Its size and checksum were verified if the expected values were known.
    *   ``"checksum_mismatch"``: The downloaded file's size or checksum did not match
        the expected value.
    *   ``"not_found"``: The requested file or package could not be located.

*   **package**:
    An object identifying the package, with its ``name``, its ``version`` as a string
    and its package URL (``purl``).

*   **filename**:
    The name of the processed file, if known.

*   **path**:
    The absolute path to the downloaded file. Only present if the status is ``"ok"``.

*   **source**:
    The URL selected for downloading the file (see `Download Locations`_).
    Required for ``"ok"`` and ``"checksum_mismatch"``; optional for ``"not_found"``.

For example, a package that could not be resolved is reported as:

.. code-block:: json

    {"status": "not_found", "package": {"name": "example-package", "version": "1.0-1", "purl": "pkg:deb/debian/example-package@1.0-1?arch=amd64"}}
