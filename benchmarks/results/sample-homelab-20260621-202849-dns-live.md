# Homelab DNS Live Validation Summary: 20260621-202849

Curated summary for raw local artifacts under
`benchmarks/results/20260621-202849-dns-live/`.

## Scope

- Context: `staging`
- Namespace: `e-navigator-bench`
- Release: `e-navigator-bench`
- Required image: `ghcr.io/e-navigator/e-navigator:sha-8ab271c`
- Configured image: `ghcr.io/e-navigator/e-navigator:sha-5c417c0`
- Image substitution: yes
- Pull secret: namespace GHCR pull secret configured
- Runtime config: `source.aya_dns` enabled with Prometheus HTTP enabled
- Cleanup: not run

## Result

The DNS-enabled rollout failed. Both DaemonSet pods entered
`CrashLoopBackOff`, and previous logs showed:

`module failed: source.aya_dns: Aya DNS packet capture is registered but live kernel attachment is not implemented in this build`

The release was restored to the working Prometheus-enabled `aya-exec` config
after failure capture, and the restored DaemonSet reached `2/2` Ready.

## Proven

- `source.aya_dns` is registered and config-valid when explicitly enabled.
- The current image does not implement live DNS kernel attachment.
- Runtime DNS packet capture remains negative evidence, not proof.
- The cluster was restored after the failed run.

## Not Proven

- Live `dns_query` or `dns_response` capture.
- Controlled workload DNS attribution.
- DNS metric generation from live eBPF DNS packets.
- DNS replacement readiness.

## Evidence

- Config validation: `validate-config.txt`
- Failed rollout: `rollout.txt`
- Failure logs: `logs-previous-after-rollout-failure.txt`
- Restore proof: `restore-rollout.txt`, `daemonset-after-restore.txt`,
  `pods-after-restore.txt`
