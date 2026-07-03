# Helm Install

E-Navigator's production packaging path is the OCI Helm chart published to GHCR.
The chart renders a privileged Linux DaemonSet plus the ServiceAccount, pod-list
RBAC, ConfigMap, and hostPath mounts required by the current eBPF and attribution
model.

## Install From OCI

```bash
helm upgrade --install e-navigator oci://ghcr.io/e-navigator/charts/e-navigator \
  --version 0.1.0 \
  --namespace e-navigator-system \
  --create-namespace
```

The default chart uses `ghcr.io/e-navigator/e-navigator:<chart appVersion>`. For
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
  repository: ghcr.io/e-navigator/e-navigator
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

    [argv_capture]
    enabled = false

    [[modules]]
    name = "source.aya_exec"
    enabled = true
```

Top-level runtime bounds are validated before startup:
`queue_capacity` must be at most 65,536,
`max_derived_signals_per_input` at most 4,096, and
`max_derived_signal_depth` at most 64.
`runtime_security.kubernetes_api_endpoints` must contain at most 32 entries.

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

Kubernetes attribution also validates response and cache bounds before runtime:
`attribution.kubernetes.max_response_bytes` must be at most 33,554,432,
`max_pods` at most 65,536, `max_cache_entries` at most 262,144, and
`max_labels_per_pod` at most 128.
Kubernetes selector lists and pod-label selector maps must each contain at most
128 entries, and each selector string, key, or value must be at most 253 bytes.

Host resource sampling validates its scan bounds before runtime:
`resource_source.sample_interval_millis` must be greater than zero and at most
3,600,000, `max_processes` and `max_cgroups` at most 65,536,
`max_fds_per_process` at most 1,048,576, and `max_file_bytes` at most
1,048,576.

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

Prometheus latest-metric storage is also validated before startup:
`prometheus_http.max_metric_lines` must be at most 262,144.

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
```

If a family-specific endpoint is omitted, that enabled family uses
`otlp_http.endpoint`. Disabled families do not require an endpoint and do not
export requests. Every configured OTLP endpoint must be an `http://` or
`https://` URL without whitespace and at most 2,048 bytes.

OTLP export runtime bounds are validated before startup:
`otlp_http.queue_capacity` must be at most 65,536, `batch_size` at most 4,096,
`timeout_millis` at most 300,000, and `max_retries` at most 16.

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
