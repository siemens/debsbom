# debsbom - SBOM generator for Debian-based distributions

`debsbom` generates SBOMs (Software Bill of Materials) for distributions based on Debian in the two standard formats [SPDX](https://www.spdx.org) and [CycloneDX](https://www.cyclonedx.org).

The generated SBOM includes all installed binary packages and also contains [Debian Source packages](https://www.debian.org/doc/debian-policy/ch-source.html) (currently only for SPDX SBOMs, support for CycloneDX is coming [when some specification related problems are resolved](https://github.com/CycloneDX/specification/issues/612)).

Source packages are especially relevant for security as CVEs in the Debian ecosystem are filed not against the installed binary packages, but source packages. The names of source and binary packages must not always be the same, and in some cases a single source package builds a number of binary packages.

## Usage

```
usage: debsbom [-h] [--version] [-v] [--progress] {generate,download,source-merge} ...

SBOM tool for Debian systems.

positional arguments:
  {generate,download,source-merge}
                        sub command help
    generate            generate a SBOM for a Debian system
    download            download referenced packages
    source-merge        merge referenced source packages

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

## Limitations

### License Information

License information in Debian is stored in `/usr/share/doc/**/copyright`. The format of these files is not required to be machine-interpretable. For most packages this is the case and they are machine-readable, but there are some cases where the exact license determination is hard.
To prevent any false license information to be included in the SBOM they are not emitted for now.

### Vendor Packages

Vendor packages can currently not identified. `debsbom` only parses the dpkg information which does not include the source of a package. This is especially problematic when we emit the PURL for these packages, since it is just wrong for vendor packages right now. The information from which repository a package comes from is available in apt, so it should be possible to fix this issue.

### Package checksums

Checksums for packages are currently missing, which makes it impossible to verify the integrity of installed packages. This data is also available in apt but needs to be parsed and included.
