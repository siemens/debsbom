# Security Policy

The debsbom community takes the security of its code seriously. If you think you
have found a security vulnerability, please read the next sections and follow
the instructions to report your finding.

## Security Context

Unless stated otherwise, all input to debsbom is considered trusted.
Data from external services (e.g. the Debian snapshot service) is sanitized on a best-effort basis:
its meta-data is untrusted and sanitized by debsbom, while the file content itself is considered trusted.
If an SBOM provides checksums for an artifact (e.g. a source or binary package), the downloaded artifact is verified against them, including transitive checksums such as those in a ``.dsc`` file;
without checksums, artifacts are considered trusted and not verified.
All debsbom plugins are considered trusted code.

## Reporting a Vulnerability

Please DO NOT report any potential security vulnerability via a public channel (mailing list, github issue etc.).
Instead, create a report via https://github.com/siemens/debsbom/security/advisories/new or contact the maintainers via email directly.
Please provide a detailed description of the issue, the steps to reproduce it, the affected versions and, if already available, a proposal for a fix.
You should receive a response within 5 working days.
If the issue is confirmed as a vulnerability by us, we will open a Security Advisory on GitHub and give credits for your report if desired.
This project follows a 90 day disclosure timeline.
