The ``compare`` command compares two SBOMs and produces a new SBOM containing only the components
that are present in the target SBOM but not in the base (reference) SBOM.

The most common use-case is identifying new or added components between two builds, images, or
distribution states (for example, comparing a previous release SBOM against a newer one),
including filtering out already license-cleared components to generate an SBOM containing only
components pending license clearance.

The comparison is directional:

* Base SBOM – treated as the reference
* Target SBOM – treated as the new or updated SBOM

Given the following structure:

Base SBOM

.. code-block::

    base-root
    |- binary-dep1
    |  |- source-dep1
    |- binary-dep2

Target SBOM

.. code-block::

    target-root
    |- binary-dep1
    |  |- source-dep1
    |- binary-dep2
    |- binary-dep3
    |  |- source-dep3

Running compare would produce:

.. code-block::

    compare-doc-root
    |- binary-dep3
    |  |- source-dep3

Components are considered the same if they share the same PURL (Package URL). Only components
that are new in the target SBOM, along with their nested dependencies, are included in the
resulting SBOM.
