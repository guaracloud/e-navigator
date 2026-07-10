# Security Policy

## Supported Versions

The latest released `0.1.x` version receives security fixes. Release candidates
receive best-effort fixes until the corresponding stable version ships.

| Version | Support |
| --- | --- |
| Latest `0.1.x` | Supported |
| `0.1.0-rc.*` | Best effort until `0.1.0` |
| Older versions | Unsupported |

## Reporting A Vulnerability

Do not open a public issue for a suspected vulnerability. Use a private
[GitHub Security Advisory](https://github.com/guaracloud/e-navigator/security/advisories/new)
instead.

Include the affected release tag or image digest, operating system and kernel,
relevant configuration with secrets removed, expected and observed behavior,
and a minimal reproduction when practical.

We aim to acknowledge reports within 72 hours, provide an initial assessment
within seven days, and coordinate a fix and disclosure timeline based on
severity and exploitability.

## Security Scope

Examples of in-scope reports include:

- kernel or host impact caused by E-Navigator's eBPF programs or privileged
  runtime integration;
- parser, reassembly, or profiling inputs that cause unbounded work, memory
  growth, panics, or silent corruption;
- raw secrets or captured payloads escaping the documented redaction and
  bounded-export rules;
- capture-filter bypasses that violate the configured cgroup policy;
- Kubernetes privilege escalation beyond the documented chart posture;
- bypasses of the release signing, digest, SBOM, or manifest verification
  chain.

Behavior explicitly documented as unsupported in
[`documentation/boundaries.md`](documentation/boundaries.md) is not a security
guarantee. A boundary that is stated incorrectly or fails open in a way that
exposes sensitive data is still reportable.

## Release Verification

Every release publishes SHA-256 checksums, SPDX SBOMs, keyless Cosign
signatures, and an immutable-digest release manifest. Verify these artifacts
using [`documentation/release-verification.md`](documentation/release-verification.md)
before deployment.
