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

The chart does not expose port `9090` by default. Enable the Service only when a
real HTTP surface is configured, for example when `sink.prometheus_http` and
`[prometheus_http] enabled = true` are present in `config.toml`:

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
