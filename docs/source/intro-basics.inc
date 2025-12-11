``debsbom`` generates SBOMs (Software Bill of Materials) for distributions based on Debian in the two standard formats `SPDX <https://www.spdx.org>`_ and `CycloneDX <https://www.cyclonedx.org>`_.

The generated SBOM includes all installed binary packages and also contains `Debian Source packages <https://www.debian.org/doc/debian-policy/ch-source.html>`_.

Source packages are especially relevant for security as CVEs in the Debian ecosystem are filed not against the installed binary packages, but source packages.
The names of source and binary packages must not always be the same, and in some cases a single source package builds a number of binary packages.
