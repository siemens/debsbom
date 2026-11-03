Introduction
============

.. include:: /intro-basics.inc

Scope of the tool
-----------------

The primary goal is to generate Software Bills of Materials (SBOMs) for Debian-based systems, focusing on security and license clearing requirements.
The ``generate`` command operates entirely offline, making it suitable for use in air-gapped networks or environments where internet connectivity is restricted.

Goals
~~~~~

The tool provides auxiliary commands for package source retrieval. These enable users to:

1. Retrieve packages from Debian's upstream repositories and report missing packages.
2. Convert the multi-archive source packages into a single artifact (one archive per source package)

At its core, this tool was designed to fulfill these SBOM generation requirements while maintaining:

1. A minimal dependency footprint: avoid huge dependency graph of external software ecosystems (like Go or Rust)
2. Strict focus on Debian-specific package formats
3. Clear separation between binary packages and their corresponding source packages
4. Use official SPDX / CycloneDX libraries to ensure syntactic and semantic correctness

Non-Goals
~~~~~~~~~

- License and copyright text extraction from source packages
- Real-time vulnerability database integration
- Signing and attestation of generated artifacts

Package Relationships
---------------------

A Debian distribution is composed of source packages and binary packages.
Binary packages are installed into the root filesystem, while the source packages are the originals from which those binaries are built.

Some binary packages are installed explicitly by the user; others appear automatically as dependencies of the explicitly‑installed packages.
The SBOM mirrors this relationship, using the ``distro-package`` entry as the single central node for traversing the package graph.

Relationship hierarchy::

    distro-package
    ├─ binary-package-foo
    ├─── source-package-foo
    ├─── binary-dep-of-foo
    ├─ binary-package-bar
    ├─── source-package-bar
    └─── binary-dep-of-bar

Source-Binary
~~~~~~~~~~~~~

To differentiate binary and source packages in the SBOM a different approach for each SBOM standard is required.

CycloneDX
^^^^^^^^^

In the CDX format it is currently not possible to mark a component as a source package.
There is an ongoing discussion [#f1]_ which, while looking promising, will not land in the standard for quite some time.
In the meantime source packages can only be identified by their PURL by looking at the ``arch=source`` qualifier.
The relationships between a binary and its source package is done with a simple dependency.

SPDX
^^^^

We differentiate a source package by setting ``"primaryPackagePurpose": "SOURCE"`` as opposed to ``LIBRARY`` for binary packages.
Their relationship is expressed with the ``GENERATES`` relation.
For packages that are marked as ``Built-Using`` in the dpkg status file, we use the ``GENERATED_FROM`` relation.
This expresses the same semantic in SPDX, but this way it can still be identified if it is a proper source/binary relationship or a built-using one.

Limitations
-----------

Vendor Packages
~~~~~~~~~~~~~~~

Vendor packages are currently not identified.
Identifying them is important to emit the correct PURL.
Right now we make no difference between vendor and official packages.
That means we emit potentially incorrect PURLs for vendor packages.

Reliably and correctly identifying if a package is a vendor package or not is non-trivial without access to the internet. For this reason we do not attempt it. If you have vendor packages in your distribution we assume you know them, and if not you can identify them in postprocessing. A simple way is to use `debsbom download` and look for any packages that failed to download, or whose checksums do not match.


.. rubric:: Footnotes

.. [#f1] https://github.com/CycloneDX/specification/issues/612


Standards Compliance
--------------------

BSI TR-03183 Compliance
~~~~~~~~~~~~~~~~~~~~~~~

The switch ``--bsi-tr-031893`` activates additional fields required by
BSI Technical Recommendataion TR-03183.

However there are some limitations:

Licenses are out of scope for Debsbom. Effective (aka concluded) licenses are
at the discretion of the end user in any case.

CycloneDX
^^^^^^^^^

For CycloneDX, the ``compositions`` section is not set (see
Table 9, row "Dependencies on other components") because the underlying
CycloneDX Python library does not support ``compositions``.

The Source Code URI  resp. URI of the deployable form of the component
is currently filled with the package's source PURL resp. PURL (see Table 11).
It is envisioned to fill this with a reference to the package on ``snapshots.debian.org``
in future.

SPDX
^^^^

For SPDX, ``Relationships`` are not marked with a ``Completeness``, as the underlying
library sets this to ``None``.

The underlying spdx-tools library serializes to a JSON-LD format that does not pass validation
against the official SPDX 3 ``model.ttl`` SHACL constraints.
It also does not validate against the official JSON schema.
SPDX 3.x support (a precondition for BSI TR-03183)
is therefore marked EXPERIMENTAL.

NTIA Minimum Elements for an SBOM using SPDX / US Executive Order 14028
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As stated in https://github.com/spdx/using/blob/main/docs/comply-with-norms.md,
the SPDX 3 specification fullfills NTIA if certain fields are filled.
Debsbom fills these fields, namely

- ``Core/Classes/CreationInfo.createdBy``,
- ``Core/Classes/Artifact.suppliedBy``,
- ``Software/Classes/Package.name``,
- ``Software/Classes/Package/packageVersion``,
- ``Core/Classes/Element.verifiedUsing``,
- ``Software/Classes/Pacakge/PackageUrl``,
- ``Core/Classes/Releationship``,
- ``Core/Classes/CreationInfo.created``.
