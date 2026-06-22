# Homelab DNS Message-Path Live Summary: 20260622-013602

Raw evidence is under `benchmarks/results/20260622-013602-dns-msg-live/`.

## Scope

- Kubernetes context: `staging`
- Namespace: `e-navigator-bench`
- Image: `ghcr.io/guaracloud/e-navigator:sha-10b81e6`
- Image index digest: `sha256:bef701f15eda33275c4275431dc4f4519200057c833a9d146fd127f04b54de35`
- Linux/amd64 manifest: `sha256:ebd60a95b6aa66710afaac48ae9450300fba20393cfd995dbf660dbd8981e7c8`
- Helm release: `e-navigator-bench`, revision `38`

## Code And Image

Commit `10b81e6` broadened live Aya DNS capture from `sendto`/`recvfrom`
to include `sendmsg`/`recvmsg` tracepoints.

Local checks before push:

- `cargo fmt --all -- --check`
- `cargo test --locked -p e-navigator-sources-ebpf-aya dns -- --nocapture`
- `cargo clippy --locked -p e-navigator-sources-ebpf-aya -p e-navigator-cli --all-targets -- -D warnings`
- `docker build -f Containerfile -t e-navigator:dns-live-msg .`
- `scripts/quality.sh`

GitHub checks for `10b81e6`:

- `CI`: success
- `publish-images`: success

## Deployment

The homelab DaemonSet rolled out successfully:

- `e-navigator-bench-ntlqh` on `homelab-01`
- `e-navigator-bench-24chn` on `homelab-02`

Both pods reported image ID
`ghcr.io/guaracloud/e-navigator@sha256:bef701f15eda33275c4275431dc4f4519200057c833a9d146fd127f04b54de35`,
restart count `0`, and Ready `true`.

## DNS Workload

Two BusyBox jobs completed:

- `e-nav-dns-msg-013602-homelab-01` on `homelab-01`
- `e-nav-dns-msg-013602-homelab-02` on `homelab-02`

The workload logs repeatedly resolved:

- `kubernetes.default.svc.cluster.local`
- `e-navigator-bench.e-navigator-bench.svc.cluster.local`

## Observed DNS Output

Full pod logs captured live DNS source and generator records.

`homelab-01`:

- `dns_query`: `92`
- `dns_response`: `144`
- `dns_counter_metric`: `236`
- `dns_latency_metric`: `144`
- `dependency_edge`: `352`
- `trace_service_path_observation`: `352`

`homelab-02`:

- `dns_query`: `154`
- `dns_response`: `0`
- `dns_counter_metric`: `154`
- `dns_latency_metric`: `0`
- `dependency_edge`: `29`
- `trace_service_path_observation`: `29`

Observed DNS records included Kubernetes/container attribution for CoreDNS and
Pi-hole activity. Prometheus `/metrics` also exposed DNS metric series,
including `dns_query_count`, `dns_response_code_count`, and
`dns_lookup_duration_*`.

## Negative Evidence

The controlled BusyBox DNS workload did not appear in DNS-attributed logs.
Searches for the workload pod names, workload pod IPs, and the two queried
service names returned no DNS attribution evidence.

This means the run proves live DNS packet capture for observed CoreDNS/Pi-hole
paths, but it does not prove complete client-to-CoreDNS workload DNS capture.
The likely remaining gap is connected UDP client paths such as `write`/`read`
after `connect`, not just `sendto`/`sendmsg`.

## Health, Metrics, And Resources

The live service returned:

- `/healthz`: `ok`
- `/readyz`: `ready`

Service, Endpoints, and ServiceMonitor existed for the release.

Five `kubectl top` samples showed:

- `homelab-01`: `44m`-`47m`, `68Mi`
- `homelab-02`: `15m`-`18m`, `59Mi`

Capability/security posture remained:

- `allowPrivilegeEscalation: false`
- `privileged: false`
- `readOnlyRootFilesystem: true`
- `runAsUser: 0`
- `NoNewPrivs: 1`
- `Seccomp: 0`
- effective capability mask `000001c401283004`

This is not reduced-privilege or reduced-overhead proof.

## Proof Boundary

This run proves:

- pushed GHCR image `sha-10b81e6` was generated and rolled out to the guarded
  homelab namespace;
- `source.aya_dns` can attach and emit live DNS records on homelab nodes;
- `generator.dns_metrics`, DNS dependency edges, and trace service-path
  observations can be produced from live DNS signals;
- Prometheus HTTP health/readiness/metrics stayed reachable.

This run does not prove:

- controlled client workload DNS attribution;
- complete DNS syscall/path coverage;
- DNS replacement readiness;
- Beyla, Tempo, Pyroscope, or Alloy replacement readiness;
- reduced privilege;
- reduced overhead versus the existing homelab observability stack.
