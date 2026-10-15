# Configure OTLP authentication and TLS

OTLP/HTTP connections use the existing flat `[otlp_http]` endpoint and enable
fields. Optional signal-specific tables add authentication, headers, and TLS.
Replace `logs` with `metrics`, `traces`, or `profiles` to configure another signal.
Credentials and custom headers are never inherited between signals.

## Send logs and traces to Positron

Add the following settings to the existing configuration. Keep the existing
source and generator modules that produce the signals you need.

```toml
[otlp_http]
enabled = true
logs_enabled = true
logs_endpoint = "https://positron.example.com:4318/v1/logs"
traces_enabled = true
traces_endpoint = "https://positron.example.com:4318/v1/traces"
metrics_enabled = false
profiles_enabled = false

[otlp_http.logs_auth]
type = "bearer"
token = { file = "/var/run/secrets/e-navigator/positron/token" }

[otlp_http.traces_auth]
type = "bearer"
token = { file = "/var/run/secrets/e-navigator/positron/token" }

[[modules]]
name = "sink.otlp_http"
enabled = true
```

Enable log collection separately if required. `logs_enabled` controls export,
not collection. Positron log and trace support does not establish metrics or
profile support. Qualify an actual Positron deployment by querying ingested
records and checking timestamps, attributes, trace IDs, and span IDs.
A local HTTP receiver test establishes the exporter contract, not deployed
backend acceptance or privileged source qualification.

Endpoints are used literally. A signal endpoint falls back to `endpoint` when
its signal-specific endpoint is empty. No signal path is appended.
Standard `OTEL_EXPORTER_OTLP_*` environment variables are not automatically
imported. Use explicit `env` references where needed.

## Select authentication and headers

Authentication defaults to `type = "none"`. Bearer authentication requires
`token`. Basic authentication requires both `username` and `password`:

```toml
[otlp_http.metrics_auth]
type = "basic"
username = { env = "METRICS_USERNAME" }
password = { file = "/var/run/secrets/e-navigator/metrics/password" }

[otlp_http.metrics_headers]
"X-Scope-OrgID" = { literal = "observability" }
"X-API-Key" = { env = "METRICS_API_KEY" }
```

Each value reference contains exactly one of `literal`, `env`, or `file`.
Prefer files or environment references for secrets. Literal credentials can
leak through configuration storage even though runtime diagnostics redact them.
Environment references are resolved at startup. Files are read with bounded
limits before each request attempt, including retries and durable replay.
Replace token files atomically. Missing or invalid refreshed credentials prevent
sending the request. An in-flight request can finish with its existing values.
Restart the process after changing an environment value.

Header names are case-insensitive. Duplicate names, invalid HTTP values, and
transport-controlled headers are rejected. Typed authentication cannot be
combined with an explicit `Authorization` header. The limits are 64 headers,
128 bytes per name, 4096 bytes per value, and 32 KiB combined header bytes.
Credentials are resolved at send time and are not written into durable payloads.

## Configure TLS

```toml
[otlp_http.logs_tls]
ca_file = "/var/run/secrets/e-navigator/positron/ca.pem"
client_certificate_file = "/var/run/secrets/e-navigator/positron/client.pem"
client_key_file = "/var/run/secrets/e-navigator/positron/client-key.pem"
insecure_skip_verify = false
allow_plaintext_auth = false
```

The CA bundle and client identity use PEM format. Configure the client
certificate and key together. Restart after rotating TLS files.
Per-signal `insecure_skip_verify` overrides the existing global
`tls_insecure_skip_verify` field. Verification remains enabled by default.

Credential-bearing plaintext HTTP requires an explicit per-signal
`allow_plaintext_auth = true`. Use that override only for an intentionally
trusted local connection. Export requests do not follow redirects. Endpoint
URLs must not contain user information.

## Mount an existing Kubernetes Secret

The Helm chart mounts complete Secret directories read-only. It does not create
Secrets or copy secret material into the ConfigMap. Add these chart values:

```yaml
secretMounts:
  - name: positron
    secretName: positron-ingest
    mountPath: /var/run/secrets/e-navigator/positron
    defaultMode: 256 # 0400 in decimal
```

The Secret must already exist in the release namespace. Its `token` key becomes
`/var/run/secrets/e-navigator/positron/token`. Whole-directory mounts allow
Kubernetes Secret volume updates to become visible. Do not use `subPath` mounts
for rotating tokens. Kubernetes propagation is asynchronous.

Mount paths must be distinct, non-overlapping directories beneath
`/var/run/secrets/e-navigator/`. The chart accepts modes 256, 288, and 292
(decimal equivalents of 0400, 0440, and 0444). Match permissions to the configured
container user. The default chart runs as root and can read mode 0400.
For environment references, existing `extraEnv` values accept
`valueFrom.secretKeyRef`. Environment-based credentials require a pod restart
when their Secret changes.

## Verify locally

Run `cargo build --locked -p e-navigator-cli`, then
`python3 tests/smoke_otlp_auth.py`. The smoke uses the compiled CLI, temporary
loopback receivers, and a temporary CA with signed server and client certificates.
It exercises authentication, custom headers, signal isolation, token rotation,
TLS verification, mTLS, and redirect refusal. Python 3 and `openssl` are required.
The full `scripts/quality.sh` gate includes this smoke after building the CLI.

File values accept one trailing LF or CRLF, then reject empty values, controls,
invalid UTF-8, and values over the byte limit. Secret sources must resolve to
regular files. PEM files are limited to 1 MiB each. TLS files are loaded before
any export worker starts. Configuration Debug and serialized value sources are
redacted, so serialized configurations containing these references are diagnostic
output and cannot be used to reconstruct their original values.

HTTP 401 and 403 are permanent rejections under the existing export contract.
They increment permanent-response and failed-export counters without transient
retries. Durable entries rejected permanently are removed, as for other permanent
receiver rejections. Missing refreshed credentials prevent the request and leave
durable entries for later delivery, subject to the existing spool age/size bounds.
Inspect native export counters to distinguish receiver rejection from local failure.

Credential changes do not rewrite durable payloads. Replay uses current credentials.
Do not repoint a nonempty spool to another backend or tenant: drain it first, or
use a separate spool directory and explicitly manage the retained data. A tenant
header change can redirect replay even when the endpoint URL stays the same.
