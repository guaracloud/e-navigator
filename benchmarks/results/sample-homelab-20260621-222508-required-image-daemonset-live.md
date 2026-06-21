# Homelab Required Image DaemonSet Sample: 20260621-222508

This is a curated summary of the raw artifacts in
`benchmarks/results/20260621-222508-required-image-daemonset-live/`.

## Scope

- Context: `staging`
- Namespace: `e-navigator-bench`
- Release: `e-navigator-bench`
- Required image tested: `ghcr.io/guaracloud/e-navigator:sha-8ab271c`
- Required image digest observed on both nodes:
  `ghcr.io/guaracloud/e-navigator@sha256:249ad67fa8578ade9ecc1279bcf52a52ae6038a342b7c68844ebfd7a38d4e34e`
- Pull secret name used: `ghcr-e-navigator-pull`
- Config: older compatible runtime config from
  `20260621-170331-live-validation`
- Cleanup: no evidence resources were deleted

No secret contents, tokens, auth headers, or Docker config JSON were captured.

## Live Rollout

Helm revision `26` deployed `sha-8ab271c` as the live DaemonSet and reached
`2/2` Ready:

- `e-navigator-bench-jvgtq` on `homelab-02`
- `e-navigator-bench-tl7pl` on `homelab-01`

The controlled workload `e-nav-required-workload-222834` completed `1/1` in
`3m6s` on `homelab-01`. Its TTL was removed afterward so Kubernetes would not
automatically clean up the evidence resource.

## Runtime Output

The required-image DaemonSet emitted live JSON stdout records during the run.
Captured counts from `e-navigator-logs-since-required-image-final.txt`:

- `source.aya_network`: `11`
- `generator.network_metrics`: `4`
- `generator.trace_correlation`: `10`
- `network_connection_failure`: `11`
- `network_counter_metric`: `4`
- `service_interaction_span_observation`: `5`
- `trace_correlation_warning`: `5`

Attribution was mixed. Some records included Kubernetes/container attribution
for `kube-system` CoreDNS. Other host-level records logged
`trace_correlation_warning` with `missing_attribution`.

The same captured window did not show:

- `source.aya_exec`
- `source.aya_cpu_profile`
- `source.host_resource`
- `generator.dns_metrics`
- `generator.profiling`
- controlled workload pod name attribution

## Resource And Privilege Snapshot

Ten `kubectl top` samples were recorded while the required image was live.
Observed E-Navigator pod ranges were `12m` to `43m` CPU and `36Mi` to `46Mi`
working memory.

Both pods ran as UID/GID `0`, with `NoNewPrivs: 1`, `Seccomp: 0`, and effective
capability mask `000001c401283004`, decoded as:

- `CAP_DAC_READ_SEARCH`
- `CAP_NET_ADMIN`
- `CAP_NET_RAW`
- `CAP_SYS_PTRACE`
- `CAP_SYS_ADMIN`
- `CAP_SYS_RESOURCE`
- `CAP_SYSLOG`
- `CAP_PERFMON`
- `CAP_BPF`
- `CAP_CHECKPOINT_RESTORE`

This is not reduced-privilege proof.

## Restore

Helm revision `27` restored the release to the pre-run values:

- image `ghcr.io/guaracloud/e-navigator:sha-5c417c0`
- digest
  `ghcr.io/guaracloud/e-navigator@sha256:553f2008f53f6da5ec05b0a45102ab8eb1f8bf4c640b2d61ce4d958ed6470cc3`
- `2/2` Ready on `homelab-01` and `homelab-02`
- `source.aya_dns`, `sink.prometheus_http`, and `sink.otlp_http` present again
  in the restored config
- Service `e-navigator-bench`, endpoints on port `9090`, and
  `ServiceMonitor/e-navigator-bench` restored

## Proof Boundary

This run proves that the required image can be deployed as the homelab
DaemonSet, remains Ready on both nodes, and emits live Aya network-derived JSON
stdout records with network metrics and trace-correlation observations.

This run does not prove:

- live exec output on `sha-8ab271c`;
- live DNS packet capture;
- live CPU profile output;
- live host-resource output;
- Prometheus HTTP export on `sha-8ab271c`;
- OTLP, Tempo, Pyroscope, Alloy, or Beyla compatibility;
- controlled workload attribution for `sha-8ab271c`;
- reduced overhead or reduced privilege.
