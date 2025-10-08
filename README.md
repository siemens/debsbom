[![Tests](https://github.com/siemens/debsbom/actions/workflows/test.yml/badge.svg)](https://github.com/siemens/debsbom/actions/workflows/test.yml)
[![Documentation](https://github.com/siemens/debsbom/actions/workflows/docs.yml/badge.svg)](https://siemens.github.io/debsbom)

# debsbom - SBOM generator for Debian-based distributions

`debsbom` generates SBOMs (Software Bill of Materials) for distributions based on Debian in the two standard formats [SPDX](https://www.spdx.org) and [CycloneDX](https://www.cyclonedx.org).

The generated SBOM includes all installed binary packages and also contains [Debian Source packages](https://www.debian.org/doc/debian-policy/ch-source.html).

Source packages are especially relevant for security as CVEs in the Debian ecosystem are filed not against the installed binary packages, but source packages. The names of source and binary packages must not always be the same, and in some cases a single source package builds a number of binary packages.

## Usage

```
usage: debsbom [-h] [--version] [-v] [--progress] {generate,download,source-merge,repack,export} ...

SBOM tool for Debian systems.

positional arguments:
  {generate,download,source-merge,repack,export}
                        sub command help
    generate            generate a SBOM for a Debian system
    download            download referenced packages
    source-merge        merge referenced source packages
    repack              repack sources and sbom
    export              export SBOM as graph

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -v, --verbose         be more verbose
  --progress            report progress
```

## Scope of the tool

The primary goal is to generate Software Bills of Materials (SBOMs) for Debian-based systems, focusing on security and license clearing requirements.
The `generate` command operates entirely offline, making it suitable for use in air-gapped networks or environments where internet connectivity is restricted.

### Goals

The `generate` command creates comprehensive SBOMs that include all installed software packages and their dependencies (binary, source package and
`built-using`[[1]](https://www.debian.org/doc/debian-policy/ch-relationships.html#s-built-using)).
These SBOM outputs are designed to serve as reliable input for vulnerability management systems and license compliance checks.

The tool provides auxiliary commands for package source retrieval. These enable users to:
1. Retrieve packages from Debian's upstream repositories and report missing packages.
2. Convert the multi-archive source packages into a single artifact (one archive per source package)

At its core, this tool was designed to fulfill these SBOM generation requirements while maintaining:
1. A minimal dependency footprint: avoid huge dependency graph of external software ecosystems (like Go or Rust)
2. Strict focus on Debian-specific package formats
3. Clear separation between binary packages and their corresponding source packages
4. Use official SPDX / CycloneDX libraries to ensure syntactic and semantic correctness

### Non Goals

- License and copyright text extraction from source packages
- Real-time vulnerability database integration
- Signing and attestation of generated artifacts

## Package Relations

A Debian distribution is composed of source packages and binary packages.
Binary packages are installed into the root filesystem, while the source packages are the originals from which those binaries are built.

Some binary packages are installed explicitly by the user; others appear automatically as dependencies of the explicitly‑installed packages.
The SBOM mirrors this relationship, using the `distro-package` entry as the single central node for traversing the package graph.

```
distro-package
├─ binary-package-foo
├─── source-package-foo
├─── binary-dep-of-foo
├─ binary-package-bar
├─── source-package-bar
└─── binary-dep-of-bar
```

### Source-Binary

To differentiate binary and source packages in the SBOM a different approach for each SBOM standard is required.

#### CycloneDX

In the CDX format it is currently not possible to mark a component as a source package. There is an ongoing discussion [[2]](https://github.com/CycloneDX/specification/issues/612) which, while looking promising, will not land in the standard for quite some time. In the meantime source packages can only be identified by their PURL by looking at the `arch=source` qualifier. The relationships between a binary and its source package is done with a simple dependency.

#### SPDX

We differentiate a source package by setting `"primaryPackagePurpose": "SOURCE"` as opposed to `LIBRARY` for binary packages. Their relationship is expressed with the `GENERATES` relation. For packages that are marked as `Built-Using` in the dpkg status file, we use the `GENERATED_FROM` relation. This expresses the same semantic in SPDX, but this way it can still be identified if it is a proper source/binary relationship or a built-using one.

## Generate from Package List

In addition to parsing the list of installed packages from the dpkg status file, we also support to provide a list of packages that should be resolved
from the apt-cache: When running `debsbom generate --from-pkglist`, the tool
processes package entries passed via stdin as line separated items. The format
for each entry is:

```
<package-name> <package-version> <package-arch>
```

Example:

```bash
cat <<EOF | debsbom generate --from-pkglist -t cdx -t spdx -o sbom
cpp 4:15.2.0-4 amd64
htop 3.4.1-5 amd64
EOF
```

## Limitations

### License Information

License information in Debian is stored in `/usr/share/doc/**/copyright`. The format of these files is not required to be machine-interpretable. For most packages this is the case and they are machine-readable, but there are some cases where the exact license determination is hard.
To prevent any false license information to be included in the SBOM they are not emitted for now.

### Vendor Packages

Vendor packages are currently not identified. Identifying them is important to emit the correct PURL. Right now we make no difference between vendor and official packages. That means we emit potentially incorrect PURLs for vendor packages.

Reliably and correctly identifying if a package is a vendor package or not is non-trivial without access to the internet. For this reason we do not attempt it. If you have vendor packages in your distribution we assume you know them, and if not you can identify them in postprocessing. A simple way is to use `debsbom download` and look for any packages that failed to download, or whose checksums do not match.
