# Helm Install

E-Navigator's production packaging path is the OCI Helm chart published to GHCR.
The chart renders a capability-scoped Linux DaemonSet plus the ServiceAccount,
pod list/watch RBAC, ConfigMap, and hostPath mounts required by the current eBPF
and attribution model.

## Install From OCI

```bash
helm upgrade --install e-navigator oci://ghcr.io/guaracloud/charts/e-navigator \
  --version 0.1.1 \
  --namespace e-navigator-system \
  --create-namespace
```

The default chart uses `ghcr.io/guaracloud/e-navigator:<chart appVersion>`. For
dev-channel testing before a release tag exists, use the rolling image:

```bash
helm upgrade --install e-navigator charts/e-navigator \
  --namespace e-navigator-system \
  --create-namespace \
  --set image.tag=main
```

## Pin A Verified Image

After verifying `release-manifest.json`, pin the release digest:

```yaml
image:
  repository: ghcr.io/guaracloud/e-navigator
  digest: sha256:<image-digest>
```

## Tune The Runtime Config

The default `config.toml` matches `deploy/kubernetes/configmap.yaml`. Override it
with a values file when changing source modules, bounded limits, or sinks:

```yaml
config:
  toml: |
    log_level = "info"
    queue_capacity = 8192

    [source_supervisor]
    # Keep healthy telemetry families alive when one source terminates.
    failure_policy = "isolate"
    shutdown_timeout_millis = 10000

    [argv_capture]
    enabled = false

    [[modules]]
    name = "source.aya_exec"
    enabled = true
```

Top-level runtime bounds are validated before startup:
`log_level` must be non-empty, contain no control characters, and be at most 512 bytes.
`queue_capacity` must be at most 65,536,
`max_derived_signals_per_input` at most 4,096, and
`max_derived_signal_depth` at most 64.
`source_supervisor.failure_policy` accepts `fail_fast` or `isolate`, and
`source_supervisor.shutdown_timeout_millis` must be greater than zero and at
most 300,000. The chart selects `isolate`; the Rust config default remains
`fail_fast` for backward compatibility.
`runtime_security.kubernetes_api_endpoints` must contain at most 32 entries.
Filesystem path settings under `attribution`, `attribution.kubernetes`, and
`resource_source` must be at most 4,096 bytes.

For DNS capture, `dns_source.max_preview_bytes` must be less than or equal to
`dns_source.max_packet_bytes`; the preview limit is only for diagnostics and
cannot exceed the packet capture bound.

For HTTP capture, `http_source.max_request_line_bytes` and
`http_source.max_tracestate_bytes` must be less than or equal to
`http_source.max_header_bytes`, which is the outer captured header bound.

Kubernetes attribution can be scoped with generic selectors. Empty lists and
maps keep the default permissive behavior; non-empty values are exact-match
filters applied before pod metadata enters the attribution cache:

```toml
[attribution.kubernetes]
namespace_allowlist = ["payments", "checkout"]
namespace_denylist = ["kube-system"]
node_name_allowlist = ["worker-a"]
node_name_denylist = []
pod_label_selector = { "app.kubernetes.io/name" = "checkout" }
pod_label_exclude_selector = { "observability.e-navigator.dev/exclude" = "true" }
```

One shared controller performs a bounded Pod list, watches from its
`resourceVersion`, and relists after the bounded watch timeout or an expired
resource version. The list is node-scoped by default. Set
`require_node_name=false` and `allow_cluster_wide_pod_list=true` together when
cross-node Pod attribution is required; local Pods are retained first if the
Pod bound is reached. The same controller lists Services and EndpointSlices at
each reconciliation. Capture filtering and production attribution consume that
same snapshot; attribution does not perform a second Kubernetes API request.
The chart RBAC therefore grants Pod and Service list/watch plus EndpointSlice
list/watch. Kubernetes attribution also validates response and cache bounds
before runtime:
`attribution.kubernetes.max_response_bytes` must be at most 33,554,432,
`max_pods` at most 65,536, `max_cache_entries` at most 262,144 across the
combined container-ID and Pod-IP metadata indexes and separately across the
workload-owner/address topology indexes, and `max_labels_per_pod` at most 128.
Kubernetes selector lists and pod-label selector maps must each contain at most
128 entries. Each selector string, key, or value must be non-empty, must not
contain whitespace or control characters, and must be at most 253 bytes.
`NODE_NAME` remains required to prioritize local Pods and scope the default Pod
list. It must be a DNS subdomain; unsafe values are rejected before a request is
built.

Pod IPs resolve to qualified stable controller owners where Kubernetes exposes
one. Service ClusterIPs resolve to a qualified `namespace/name` owner of type
`service`; they are not attributed to a guessed backend Pod. Ready EndpointSlice
addresses provide a Service-owner fallback only when no Pod identity exists.
Services and EndpointSlices refresh at the controller's bounded relist (at most
five minutes by default), while Pod changes are watched continuously.

The optional capture filter controls which workloads the eBPF sources *probe*,
which is distinct from `[attribution.kubernetes]` selectors (those only scope
which pods enter the enrichment cache). The capture filter evaluates against the
raw node pod list, so it can exclude a namespace even when attribution scoping
would have dropped it. It is disabled by default; when enabled it needs the same
`NODE_NAME` and pod-read RBAC as Kubernetes attribution, because namespace and
label rules depend on the node pod list:

```toml
[capture_filter]
enabled = true
# Verdict for a resolved pod that matches no rule, and for cgroups that cannot
# yet be resolved to a pod (bootstrap window, host processes, API unavailable).
default_posture = "deny"   # "allow" or "deny"
unknown_cgroup = "deny"    # "allow" or "deny"
# Namespaces support exact names and `*`/`?` globs. Precedence: exclude wins,
# then the include gate, then default_posture.
namespace_include = ["proj-*"]
namespace_exclude = ["proj-secret"]
# Equality, inequality, existence/non-existence, and set membership compose
# with AND at the top level. This is the Guara paid-tier policy:
label_in = { "guara.cloud/tier" = ["starter", "pro", "business", "enterprise"] }
label_not_exists = ["guara.cloud/catalog-slug"]
label_exclude = { "observability.e-navigator.dev/probe" = "false" }
# Identity exclusions apply when that identity is known at the decision point.
process_exclude = ["*exporter", "otelcol*"]
container_exclude = ["istio-proxy"]

# `[[capture_filter.any_of]]` adds complete OR alternatives to the include
# gate; `[[capture_filter.exclude_any]]` adds exclude-wins OR alternatives.
[[capture_filter.any_of]]
label_equal = { "team" = "payments" }

[[capture_filter.any_of]]
label_exists = ["observability.e-navigator.dev/include"]
```

An allowlist posture (`default_posture`/`unknown_cgroup = "deny"` with
`namespace_include`) leaves a brief coverage gap for a newly started included
pod; a denylist posture (`"allow"` with `namespace_exclude`) leaves a brief
capture leak for a newly started excluded pod. Pod identity arrives through the
watch; both windows are bounded mainly by the two-second local cgroup scan and
are minimized by resolving the pod UID from the cgroup path. Capture-filter namespace pattern and
label selector lists each accept at most 128 and 64 entries respectively; set
selectors accept at most 64 values per key and OR selectors at most 32 groups.
Each entry must be non-empty, free of whitespace and control characters, and at
most 253 bytes. Exclude namespace/label groups and process/container exclusions
always win before the include gate.

Host resource sampling validates its scan bounds before runtime:
`resource_source.sample_interval_millis` must be greater than zero and at most
3,600,000, `max_processes` and `max_cgroups` at most 65,536,
`max_fds_per_process` at most 1,048,576, and `max_file_bytes` at most
1,048,576.

Request correlation generates valid native trace and span identifiers for
uninstrumented traffic by default while retaining a missing/malformed-context
warning. Set `request_correlation.generate_trace_ids = false` only when a
downstream contract intentionally accepts non-exportable spans without IDs.

Metric generator cardinality bounds are validated before runtime:
`resource_metrics.max_keys`, `network_metrics.max_metric_keys`,
`dns_metrics.max_counters`, `dns_metrics.max_latencies`, and
`dns_metrics.max_edges` must each be at most 262,144. `dns_metrics.max_domains`
must be at most 65,536, and `network_metrics.max_active_connections` at most
1,048,576.

The chart does not expose port `9090` by default. Enable the Service only when a
real HTTP surface is configured, for example when `sink.prometheus_http` and
`[prometheus_http] enabled = true` are present in `config.toml`:

```toml
[prometheus_http]
enabled = true
bind_address = "0.0.0.0"
port = 9090
max_metric_lines = 4096
metrics_enabled = true
profiles_enabled = true
```

```yaml
prometheusHttp:
  enabled: true
service:
  enabled: true
serviceMonitor:
  enabled: true
```

`serviceMonitor.enabled=true` renders a `ServiceMonitor` only with both
`service.enabled=true` and `prometheusHttp.enabled=true`.

Set `health.enabled=true` only with the same real Prometheus HTTP surface. It
adds startup, liveness, and readiness probes against `/healthz` and `/readyz`;
it does not create a second health server. The default chart keeps both the
port and probes disabled so a custom config cannot be marked unhealthy merely
because it does not register `sink.prometheus_http`.

The chart's operational defaults reserve `150m` CPU and `384Mi` memory, cap the
container at `2` CPUs and `960Mi`, roll at most `10%` of nodes at once, require
10 ready seconds, retain five DaemonSet revisions, and allow 30 seconds for
termination. Linux sources listen for both SIGINT and SIGTERM, stop their perf
readers, and then let bounded sink shutdown drain already accepted export
batches. Override these values only with workload measurements from the target
cluster.

Prometheus latest-metric storage is also validated before startup:
`prometheus_http.max_metric_lines` must be at most 262,144, and
`prometheus_http.bind_address` must not contain whitespace or control
characters, must not include a port, and must not exceed 253 bytes.

OTLP HTTP export is configured inside the same `config.toml` override. The
single `endpoint` remains the fallback for backward compatibility; set
per-family endpoints only when metrics, traces, or profiles should route to
different OTLP HTTP receivers:

```toml
[otlp_http]
enabled = true
endpoint = "http://otel-collector:4318"
metrics_endpoint = "http://otel-collector:4318/v1/metrics"
traces_endpoint = "http://otel-collector:4318/v1/traces"
profiles_endpoint = "http://otel-collector:4318/v1development/profiles"
metrics_enabled = true
traces_enabled = true
profiles_enabled = true
compression = "gzip"
```

Profiles can bypass a collector and go directly to the Guara-pinned Pyroscope
server:

```toml
[otlp_http]
enabled = true
profiles_endpoint = "http://pyroscope.guara-observability.svc.cluster.local:4040/v1development/profiles"
metrics_enabled = false
traces_enabled = false
profiles_enabled = true
compression = "gzip"
```

This route is pinned to Pyroscope `1.20.3` and OTLP Profiles
`v1development` module `v0.3.0`; see ADR 0003. Profile samples use the standard
`samples/count` plus `cpu/nanoseconds` period shape that Pyroscope exposes as
`process_cpu:cpu:nanoseconds:cpu:nanoseconds`. Upgrading either side requires
rerunning `tests/smoke_pyroscope_otlp.sh`. Native cumulative profile-session
signals are intentionally not sent to this endpoint, avoiding repeat export of
the same window.

Metric host, container, and Kubernetes identity remains encoded as canonical
OTLP resource attributes and is also mirrored into each data point. The mirror
keeps independent DaemonSet nodes and workloads distinct when an
OTLP-to-Prometheus collector does not enable resource-to-telemetry conversion;
without it, otherwise identical metric attributes can collide during remote
write. Treat the mirrored keys as bounded identity, not arbitrary label
promotion.

### Guara standalone replacement preset

`charts/e-navigator/values-guara-production.yaml` is the opinionated Guara
replacement overlay. It keeps the existing Alloy OTLP HTTP receiver for
metrics and traces, sends profiles directly to the pinned Pyroscope server,
enables all real sources in one `unified` process, profiles at 10 Hz, and
enforces the production source policy:

```text
namespace = proj-*
AND guara.cloud/tier IN (starter, pro, business, enterprise)
AND guara.cloud/catalog-slug DOES NOT EXIST
```

The overlay also excludes exporter/collector processes and build-pool nodes,
enables health probes and the Prometheus scrape surface, and uses a 150m CPU /
384 MiB memory request with a 2 CPU / 960 MiB hard ceiling. It deliberately
does not choose an image version. Render or install only with a digest verified
from the release manifest:

```sh
helm template e-navigator charts/e-navigator \
  --values charts/e-navigator/values-guara-production.yaml \
  --set image.digest=sha256:<verified-release-digest>
```

The compatibility port lists are explicit and conservative. In particular,
TLS application classification remains port-based: HTTP/1 uses 443 while h2
uses 8443 in this preset. Do not claim same-port ALPN discrimination until the
TLS source implements and validates it.

If a family-specific endpoint is omitted, that enabled family uses
`otlp_http.endpoint`. Disabled families do not require an endpoint and do not
export requests. Every configured OTLP endpoint must be an `http://` or
`https://` URL with a host, without whitespace or control characters, and at
most 2,048 bytes.

OTLP export never performs collector I/O on the shared signal path. Metrics,
traces, and profiles use separate bounded workers with size-or-time batching.
`compression = "gzip"` compresses the protobuf body on Tokio's blocking pool
and sends the required `Content-Encoding: gzip`; `"none"` preserves the
uncompressed OTLP/HTTP body. The Guara production preset enables gzip for all
three family workers.
Metric sums are cumulative, and repeated cumulative updates for the same
resource/data-point identity are coalesced to the latest window within each
export batch. Across batches, the metrics worker retains only the latest point
for each receiver millisecond and flushes that point when the series advances,
the configured interval expires, or shutdown begins. Pending series are bound
by the configured queue capacity. This prevents duplicate receiver timestamps
without leaving the terminal cumulative value stale. The Guara preset uses a
4,096-record batch, a one-second flush interval, and a bounded 8,192-record
queue.
Queue overflow, invalid trace identity, exhausted export batches, and open
circuit drops are exposed through the live Prometheus endpoint using fixed
`e_navigator_export_*` names and the bounded `signal_family` label. These
metrics read the worker atomics directly and therefore remain available when
an OTLP destination is down. Timestamp-series, pending-series, coalesced-point,
out-of-order, and eviction counts use the same feedback-safe registry. A worker
drains its accepted queue and latest pending metric points during bounded
shutdown.

Every destination attempt also updates
`e_navigator_export_request_duration_seconds`, a native Prometheus histogram
with fixed latency buckets and the bounded `signal_family` label. The histogram
includes failed attempts and timeouts, so use it with the retry, failure, and
drop counters when diagnosing a slow backend.

The worker accepts only HTTP 200 as an OTLP acknowledgement and decodes at most
64 KiB of the family-specific protobuf response. Populated partial-success
responses are not retried. Their rejected-item and warning fields increment
`e_navigator_export_rejected_items_total`,
`e_navigator_export_partial_success_total`, and
`e_navigator_export_partial_warning_total`. Only transport failures, timeouts,
and HTTP 429/502/503/504 are retried; other statuses are permanent. Native
`e_navigator_export_retryable_responses_total`,
`e_navigator_export_permanent_responses_total`, and
`e_navigator_export_invalid_responses_total` counters make that classification
visible. Numeric `Retry-After` seconds are honored up to
`retry_max_backoff_millis`.

Alert at minimum on sustained increases in
`e_navigator_export_dropped_queue_full_total`,
`e_navigator_export_dropped_failure_total`, or
`e_navigator_export_dropped_circuit_open_total`; on any increase in
`e_navigator_export_rejected_items_total`,
`e_navigator_export_permanent_responses_total`, or
`e_navigator_export_invalid_responses_total`; on any increase in
`e_navigator_export_invalid_trace_records_total` (a signal declared a trace or
span ID but it failed OTLP identity validation); and when
`e_navigator_export_queue_depth / e_navigator_export_queue_capacity` remains
above 0.8 for five minutes. Retry or circuit-open counters alone are early
degradation signals; the drop counters mean telemetry was irrecoverably lost.

For the workload controller, alert when
`e_navigator_kubernetes_controller_ready == 0`, when
`e_navigator_kubernetes_controller_freshness_seconds > 60`, on increases in
`e_navigator_kubernetes_controller_relist_failures_total` or
`e_navigator_kubernetes_controller_watch_failures_total`, and when
`e_navigator_capture_filter_unresolved_cgroups` remains nonzero. Resource-version
expiration alone is recoverable; pair it with readiness/freshness before paging.

For the source supervisor, alert when a configured
`e_navigator_source_running{source="..."}` series remains zero while the agent
is ready, and on increases in `e_navigator_source_failures_total`. The bounded
`source` label comes only from statically registered modules. Clean exits are
reported separately in `e_navigator_source_clean_exits_total`; during normal
termination they must not be interpreted as source failures. Running state is
supervisor lifecycle evidence, not proof that every optional kernel or TLS
attachment succeeded.

For Linux Aya sources, a running source should reach
`e_navigator_ebpf_source_initialized{source="..."} == 1` after its base eBPF
load, program attachment, perf-buffer setup, and reader startup path completes.
Alert on any increase in `e_navigator_ebpf_source_send_failures_total` or
`e_navigator_ebpf_source_lost_perf_events_total`, and investigate sustained
growth in `e_navigator_ebpf_source_invalid_samples_total`. These counters are
cumulative; the periodic structured log retains delta semantics. Initialization
does not prove that every optional target attached. The cumulative
`e_navigator_ebpf_source_filtered_samples_total` records well-formed samples
that userspace intentionally rejects after resolving capture scope, such as an
accepted server socket whose recovered port has no configured protocol parser;
it is separate from corrupt or undecodable input. Use the bounded
`e_navigator_ebpf_source_optional_targets_discovered_total`,
`e_navigator_ebpf_source_optional_targets_ready_total`,
`e_navigator_ebpf_source_optional_targets_unsupported_total`,
`e_navigator_ebpf_source_optional_probe_attachments_total`,
`e_navigator_ebpf_source_optional_attachment_failures_total`,
`e_navigator_ebpf_source_optional_rescans_total`, and
`e_navigator_ebpf_source_optional_capacity_rejections_total` series for that
coverage. Any increase in unsupported targets, attachment failures, or capacity
rejections is a blind-spot signal. TLS candidates are accepted only for the
documented OpenSSL 1.1.1/3 and GnuTLS ABI 30 surfaces after architecture and
complete-export preflight; an unknown or incomplete library is rejected rather
than partially attached.

OTLP export runtime bounds are validated before startup:
`otlp_http.queue_capacity` must be at most 65,536, `batch_size` at most 4,096
and no larger than the queue, `flush_interval_millis` at most 60,000,
`timeout_millis` at most 300,000, and `max_retries` at most 16. Retry backoff,
circuit cooldown, and shutdown timeouts are positive and capped at 300,000
milliseconds; initial retry backoff cannot exceed its maximum. The circuit
failure threshold is positive and at most 1,024.

## Raw Manifest Fallback

Raw YAML remains in `deploy/kubernetes/` for development and review, but Helm is
the preferred install surface for published releases.

```bash
kubeconform -strict -summary deploy/kubernetes/*.yaml
helm template e-navigator charts/e-navigator | kubeconform -strict -summary -
```

## Validation

```bash
helm lint charts/e-navigator
helm template e-navigator charts/e-navigator
helm template e-navigator charts/e-navigator --set image.tag=main
helm template e-navigator charts/e-navigator \
  --set image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000
```

Helm rendering, schema validation, and successful installs do not prove live
eBPF behavior, Prometheus scrape success, OTLP ingestion, reduced privilege, or
production readiness. Runtime proof requires a capable Linux node or cluster and
observed Aya/eBPF output.
