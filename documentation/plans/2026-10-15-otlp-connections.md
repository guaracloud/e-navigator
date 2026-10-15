# OTLP connection implementation plan

## Approved design

Preserve existing flat endpoint, enable, queue and delivery settings. Add optional
per-family auth, header and TLS tables. Bearer, Basic and custom headers use typed
literal/environment/file references. Credentials never enter durable payloads or
Debug/error output. No runtime plugins or vendor-specific transport code.

## Work and verification

- [x] Core schema: failing parse/validation/redaction tests, additive types and defaults,
  source/header bounds, ambiguous input rejection, TLS pairing; run core tests.
- [x] HTTP transport: failing local receiver tests, resolve enabled destinations before
  workers start, typed sensitive headers, bearer/Basic, reserved headers, HTTPS policy,
  no redirects, CA/mTLS, bounded file rotation per attempt, same durable path.
- [x] Packaging: existing Secret mounts, schema and rendered chart tests; document
  Positron configuration, rotation, failure behavior and existing endpoint semantics.
- [x] Local verification: real HTTP/TLS receiver smoke with CLI-generated records,
  credential rotation, rejection, destination isolation; workspace gate and supply chain.
- [x] Fresh branch review, fixes and reruns; prepare the feature branch for PR.

## Decisions

Environment source references resolve once at exporter construction; file sources
resolve in blocking work on every HTTP attempt, including retries and durable replay.
Credential read failure prevents sending. Certificates load once and require restart.
Header names are case-insensitive, duplicates and protocol-owned headers are rejected.
Auth may be absent. Plaintext with auth/custom headers requires explicit per-family
allow_plaintext_auth. Existing plaintext export without headers remains valid.
Standard OTEL environment auto-configuration is a separate feature, as established
in the additive design discussion. This change only reads explicitly named variables.
TLS files are bounded; no process-wide environment mutation. Redirects disabled.
Credentials are never persisted. Existing spool endpoint/tenant reassignment semantics
are documented, not silently changed by credential support.

## Review and local evidence

The workspace test run passed 1,688 Rust tests. Actual CLI transport smoke passed
bearer/Basic, custom headers, signal isolation, rotation, custom/wrong CA, mTLS,
redirect refusal, and FIFO rejection. Durable tests inspect nonempty spool bytes,
then rotate the token and replay the same payload with current credentials.

Fresh review found a FIFO open that could block and TOML diagnostics retaining
source excerpts. Both now have red-to-green regressions. Request errors also strip
endpoint URLs before storage. A subprocess used to create FIFO unit fixtures
caused intermittent inherited spool-lock interference on macOS. The macOS FIFO
check now runs in the separate CLI smoke; Linux uses a process-free Rust fixture.
Eight consecutive sink-suite reruns passed after that test correction.

Certificate rotation requires restart; automatic OTEL environment configuration
and dynamic OAuth/signing providers remain separate features. No live Positron
query/retention, Kubernetes runtime, or privileged capture qualification is claimed.

The final full `scripts/quality.sh` run passed with no skip flags, including
format/lint/docs, all workspace tests, the CLI transport smoke, fuzz harness
checks, supply-chain tools, Docker build/smoke, Helm checks, Kubernetes schema
validation and website links. An additional rendered chart with a Secret mount
passed strict kubeconform validation for all six resources.
