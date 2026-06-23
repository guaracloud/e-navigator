# Local Sample: Required Image Exporter Version Boundary

Run:

- `20260623-101950-required-image-exporter-version-boundary`

Raw evidence lives under
`benchmarks/results/raw/20260623-101950-required-image-exporter-version-boundary/`.

Scope: local parser/config proof only. No Kubernetes resources were created,
updated, or deleted for this run.

Image:

- Required benchmark tag: `ghcr.io/guaracloud/e-navigator:sha-8ab271c`
- Required benchmark image digest from prior live runs:
  `sha256:249ad67fa8578ade9ecc1279bcf52a52ae6038a342b7c68844ebfd7a38d4e34e`

Probes:

- `prometheus-required-image-probe.toml` enables `[prometheus_http]` and
  `sink.prometheus_http`.
- `otlp-required-image-probe.toml` enables `[otlp_http]` and `sink.otlp_http`
  with metric export only.
- Both probes keep newer source modules omitted and otherwise use the
  older-compatible shape from prior required-image runs.

Commands:

- `cargo run --locked -p e-navigator-cli -- --source synthetic --config benchmarks/results/raw/20260623-101950-required-image-exporter-version-boundary/prometheus-required-image-probe.toml --validate-config`
- `cargo run --locked -p e-navigator-cli -- --source synthetic --config benchmarks/results/raw/20260623-101950-required-image-exporter-version-boundary/otlp-required-image-probe.toml --validate-config`
- `docker run --rm --platform linux/amd64 -v "$PWD/benchmarks/results/raw/20260623-101950-required-image-exporter-version-boundary/prometheus-required-image-probe.toml:/tmp/e-navigator.toml:ro" ghcr.io/guaracloud/e-navigator:sha-8ab271c --source synthetic --config /tmp/e-navigator.toml --validate-config`
- `docker run --rm --platform linux/amd64 -v "$PWD/benchmarks/results/raw/20260623-101950-required-image-exporter-version-boundary/otlp-required-image-probe.toml:/tmp/e-navigator.toml:ro" ghcr.io/guaracloud/e-navigator:sha-8ab271c --source synthetic --config /tmp/e-navigator.toml --validate-config`

Observed evidence:

- Current-head CLI validation exited `0` for both probes, proving the current
  checkout accepts `sink.prometheus_http` and `sink.otlp_http`.
- The `sha-8ab271c` container validation exited `1` for the Prometheus probe
  with `unknown module 'sink.prometheus_http'`.
- The `sha-8ab271c` container validation exited `1` for the OTLP probe with
  `unknown module 'sink.otlp_http'`.
- The required image's known module list contains `sink.json_stdout` only among
  sink modules.

Outcome: `blocked` for live required-image Prometheus HTTP or OTLP HTTP export
on `sha-8ab271c` because that image predates both registered exporter modules.
A live rollout cannot prove either exporter on that tag without changing the
required benchmark image.

Not proven:

- Prometheus `/metrics`, `/healthz`, `/readyz`, Service, ServiceMonitor, active
  targets, scrape samples, or emitted Prometheus series on `sha-8ab271c`.
- OTLP metric, trace, or profile export on `sha-8ab271c`.
- Any Kubernetes runtime behavior for this run; this was local parser proof
  only.
- Feature parity between `sha-8ab271c` and newer images that have proven
  Prometheus and OTLP surfaces.
