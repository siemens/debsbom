Design Decisions
================

The goal of this page is to explicitly document and give reasoning for design decisions that were made in this project.

"We don't guess" Philosophy
---------------------------

The philosophy for ``debsbom`` when accruing information from a distribution is simple: "We don't guess". That means that ``debsbom`` always prefers providing less information to providing unverified information. In other words: if anything in the SBOM is wrong, it is a bug.

Offline SBOM Generation
-----------------------

``debsbom`` generates SBOMs without accessing any resource from the internet. It is intended to be used for airgapped build environments, where Internet access is not possible. This also ensures the SBOM generation is reproducible.

What this also means is that some information that would theoretically be available by a simple lookup on e.g. snapshot.debian.org is not available in the generated SBOM.

This restriction does not go for other commands, e.g. the ``download`` command requires Internet access of course.

Information Sources
-------------------

``debsbom`` only uses data available from ``dpkg`` and ``apt``. It does not rely on the command line utilities, but instead directly parses its internal data. When using the ``generate`` command the following files are accessed:

..  csv-table::
    :header: File, Reason
    :widths: 15, 15

    /var/lib/dpkg/status, Contains the installed package list for the distribution; is required unless ``--from-pkglist`` is used
    /var/lib/dpkg/arch-native, Contains the native architecture for the distribution; required unless ``--distro-arch`` is specified
    /var/lib/apt/lists/*, "Contains apt-cache information, used for enrichment of source and binary packages; optional"
    /var/lib/apt/extended-states, Contains information which packages are manually installed; used for building of the dependency graph; optional

Mapping of Debian Binary Packages to SBOM Packages/Components
-------------------------------------------------------------

The following table shows how fields in a Debian binary package are mapped to fields in a SBOM component or package.

..  csv-table:: Debian Binary Packages to SBOM Mappings
    :header: Debian Package Field, SPDX Package Field, CDX Component Field
    :widths: 15, 15, 15

    ``Package`` [#always_there]_, ``name``, ``name``
    ``Status``, [#status]_, [#status]_
    ``Priority``, \-, \-
    ``Section``, \-, ``properties``
    ``Installed\-Size``, \-, \-
    ``Maintainer``, ``supplier``, ``supplier``
    ``Architecture`` [#always_there]_, [#architecture]_, [#architecture]_
    ``Multi-Arch``, \-, \-
    ``Source``, [#source]_, [#source]_
    ``Version`` [#always_there]_, ``versionInfo``, ``version``
    ``Breaks``, \-, \-
    ``Replaces``, \-, \-
    ``Provides``, \-, \-
    ``Conflicts``, \-, \-
    ``Conffiles``, \-, \-
    ``Depends``, [#depends]_, [#depends]_
    ``Recommends``, \-, \-
    ``Pre-Depends``, \-, \-
    ``Suggests``, \-, \-
    ``Description``, ``summary`` and ``description`` [#description]_,  ``description``
    ``Built-Using``, [#built_using_spdx]_, [#built_using_cdx]_
    ``Homepage``, ``homepage``, ``externalReferences.type`` = ``website``
    ``Description\-md5``, \-, \-
    ``SHA256``, ``checksums``, ``hashes``
    ``Size``, \-, \-
    ``Filename``, \-, \-

.. [#status] If the status is not ``install ok installed`` it is not placed in the SBOM
.. [#architecture] The architecture is only part of the PURL
.. [#source] When a ``Source`` is specified it gets a separate entry in the SBOM and the dependency is added
.. [#depends] When a ``Dependency`` is specified a dependency is created for the related packages
.. [#description] The synopsis (first line) is the ``summary``, the rest goes into the ``description``
.. [#built_using_spdx] Any ``Built-Using`` dependency gets a separate entry and the ``GENERATED_FROM`` relationship is used
.. [#built_using_cdx] Any ``Built-Using`` dependency gets a separate entry and the dependency is added

Mapping of Debian Source Packages to SBOM Packages/Components
-------------------------------------------------------------

In the same fashion, this table shows how fields in a Debian source package are mapped to fields in a SBOM component or package.

..  csv-table:: Debian Source Packages to SBOM Mappings
    :header: "Debian Package Field", "SPDX Package Field", "CDX Component Field"
    :widths: 15, 15, 15

    ``Package`` [#always_there]_, ``name``, ``name``
    ``Binary``, \-, \-
    ``Version`` [#always_there]_, ``versionInfo``, ``version``
    ``Maintainer``, ``supplier``, ``supplier``
    ``Uploaders``, \-, \-
    ``Build-Depends``, [#build_depends_source]_, [#build_depends_source]_
    ``Build-Depends-Indep``, \-, \-
    ``Architecture``, \-, \-
    ``Standards-Version``, \-, \-
    ``Format``, \-, \-
    ``Files``, \-, \-
    ``Vcs-Browser``, \-, \-
    ``Vcs-<type>``, ``externalRefs.referenceType`` = ``vcs``, ``externalReferences.type`` = ``vcs``
    ``Checksums-Sha256``, ``checksums``, ``hashes``
    ``Homepage``, ``homepage``, ``externalReferences.type`` = ``website``
    ``Package-List``, \-, \-
    ``Directory``, \-, \-
    ``Priority``, \-, \-
    ``Section``, \-, ``properties``

.. [#build_depends_source] Correctly resolving the ``Build-Depends`` requires downloading the ``.buildinfo`` for a package, which is not possible offline
.. [#always_there] This field is always present in the SBOM

Relationships between Binary Packages, Source Packages and ``Built-Using``
--------------------------------------------------------------------------

A binary package can have three types of relationships: a binary dependency that points simply to another binary package, a source dependency that points to a source package, and a ``Built-Using`` relationship that also points to a source package. For the exact meaning of these relationships please refer to the `Debian documentation <https://www.debian.org/doc/debian-policy/ch-relationships.html#>`__.

In CylconeDX SBOMs all relationships are only expressed as the same dependencies. There is no way to differentiate a source dependency and a ``Built-Using`` dependency.

For SPDX refer to the following table:

..  csv-table::
    :header: "Relationship", "SPDX"
    :widths: 15, 15

    Binary Dependency, ``relationshipType = DEPENDS_ON``
    Source Dependency, ``relationshipType = GENERATES``
    ``Built-Using``, ``relationshipType = "GENERATED FROM`` and ``comment = built-using`` [#built_using_relationship]_

.. [#built_using_relationship] The subject and object of the relationship are reversed compared to the source dependency

Classification of Components/Packages
-------------------------------------

For CycloneDX SBOMs each component has a ``type`` associated with it. We would like to differentiate between a source and binary package with this, but unfortunately there is not yet a good way to do that. There is `ongoing work <https://github.com/CycloneDX/specification/issues/612>`__, which would make it possibly to do that by introducing a new ``classifier`` field for components. As it stands that new field is not going to be included in the spec in the foreseeable future, so the only way to know what kind of package type a component is describing is by looking at the PURL and see if there is a qualifier ``arch=source``.

For SPDX SBOMs it is possible to differentiate them: we use ``primaryPackagePurpose = LIBRARY`` for binary packages and ``primaryPackagePurpose = SOURCE`` for source packages.

Checksums
---------

``debsbom`` includes checksums in components/packages. For binary packages these refer to the checksum of the ``.deb`` file.

The situation is more complex for source packages, as these consist of multiple files and there is no checksum given for the collection of them. ``debsbom`` uses the checksum of the ``.dsc`` file in each source package, as this file describes the whole source package and its contents, together with checksums for all other included files. This makes it possible to verify that every file in a source package is as expected.

When there are multiple checksums of different algorithms available ``debsbom`` checks them in a specific internal order. The first algorithm that is supported is checked. The result of this check is final. The order from highest to lowest is ``SHA256``, ``SHA1``, ``MD5``.

Uniqueness of a Debian Package
------------------------------

What makes a Debian package unique is surprisingly complicated. For binary packages the triplet of package name, version and architecture should be enough to uniquely identify a package, but a package can both be found under that same triplet on different archives: the normal ``debian`` archive and ``debian-ports``.

For source packages the situation should also be simple: a tuple of package name and version is enough. Unfortunately `there are situations where that is also not the case <https://lists.debian.org/debian-snapshot/2025/10/threads.html#00000>`__.

``debsbom`` generally uses the simple assumption that package name, version and architecture (for binary packages) uniquely describes the package. If a checksum is available, this checksum is always verified to make sure this assumption actually holds. Where no checksum is available there is no way to be certain that the package is correctly identified.

There is a unique case for source packages: even if the checksum does not match it could still be content-equal, as is the case with the above example on the mailing list. There, only the signature date changed, which leads to the different checksums. In theory one could verify the content of a source package, as all checksums referenced in the ``.dsc`` would still be the same, but that is not done for the sake of simplicity.

There is also the problem of package identification. This is relevant for the ``merge`` command, as there components or packages from two different SBOMs need to be merged, if they are identical. The identification of packages, as we have just learned, is complicated and ``debsbom`` simply uses the PURL for identification purposes there, additionally checksums are checked if they are available. This is consistent with the general approach of package identification, as the PURL contains the package name, version and architecture.

Distribution Architecture
-------------------------

One could assume that the knowledge of the actual architecture of the distribution is not required when generating an SBOM, as the binary packages contain their architecture and we should be able to resolve everything from there. Unfortunately this is not the case and we need to know for which architecture the SBOM is generated.

The reason for that is the dependency resolution for packages which have the ``all`` architecture. Take for example the ``lmodern`` package:

.. code-block::

    Package: lmodern
    Status: install ok installed
    Priority: optional
    Section: fonts
    Installed-Size: 33268
    Maintainer: Debian TeX Task Force <debian-tex-maint@lists.debian.org>
    Architecture: all
    Multi-Arch: foreign
    Version: 2.005-1
    Replaces: lm, lmodern-x11
    Depends: tex-common (>= 6.13), xfonts-utils, fonts-lmodern (= 2.005-1)
    [...]

We can see that the ``Depends`` line does not specify which architecture the dependencies have. The Debian policy in these cases is that both native and ``all`` architecture are possible. The ``xfonts-utils`` dependency could thus resolve to multiple packages. In this case we would need to resolve to the native architecture version of the package, and for that we need to know what the architecture actually is. ``debsbom`` tries to parse the distribution architecture from the used rootfs, but if that is not possible it needs to be specified on the command line.

Universal Ingress and Apt-Cache
-------------------------------

The universal ingress, often seen with the ``--from-pkglist`` option, has some caveats when dealing with enrichment from the apt-cache. A naive assumption might be that these two commands produce the same output:

.. code-block::

   debsbom generate -r /my-root

   cat /my-root/var/lib/dpkg/status | debsbom generate -r /my-root --from-pkglist

In fact, there are subtle differences: in the first case the information from the ``extended_states`` file is used to find out which packages are manually installed and which are automatically pulled in as dependencies. In the second command all packages in the status file are considered manually installed, which would affect the dependency graph.

That is because we assume that with the ``--from-pkglist`` option the rootfs and the packages are not directly related. We can still find packages from the universal ingress in the apt-cache and enrich their entries, but any other local information does not apply to them. In general you should be careful when using universal ingress, as depending on the rootfs you are using and the state of the apt-cache in there, you might have reproducability issues.
