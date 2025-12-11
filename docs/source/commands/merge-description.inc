The ``merge`` command merges multiple SBOMs hierarchically. The most common use-case is combining
multiple parts of a Debian-based Linux distribution, like a rootfs and a initrd.

The merged SBOM contains the root components/packages of the input SBOMs at the first dependency
level. The following structure in two SBOMs

.. code-block::

    doc1-root
    |- binary-dep1
    |  |- source-dep1
    |- binary-dep2

    doc2-root
    |- binary-dep3
    |  |- source-dep3
    |- binary-dep4

would turn into this:

.. code-block::

    merged-doc-root
    |- doc1-root
    |  |- binary-dep1
    |  |  |- source-dep1
    |  |- binary-dep2
    |- doc2-root
    |  |- binary-dep3
    |  |  |- source-dep3
    |  |- binary-dep4

Any duplicated components are identified solely by their PURL. If it is missing from a
component/package, it can not be matched and is treated as a completely unique. If a
component/package can be identified as identical, their contents are merged and their SBOM
reference IDs in the merged document are combined too. The ID will be replaced with the one
appearing first in the passed list of SBOMs. Any duplicate entries and dependencies are
also removed.
