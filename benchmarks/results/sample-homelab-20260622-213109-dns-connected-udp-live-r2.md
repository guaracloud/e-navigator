# Homelab DNS Connected-UDP Live Summary: 20260622-213109

Raw evidence is under
`benchmarks/results/20260622-213109-dns-connected-udp-live-r2/`.

## Scope

- Kubernetes context: `staging`
- Namespace: `e-navigator-bench`
- Image: `ghcr.io/guaracloud/e-navigator:sha-94e808c`
- Image index digest:
  `sha256:583fa478c6944b0489170cdecc7c93d0ec9b43aee419a6406d276c452a5e4f6a`
- Linux/amd64 manifest:
  `sha256:d38375108711bd747b42f2b13412decf99790146dd3c1210268c357852c4b8a2`
- Helm release: `e-navigator-bench`
- Temporary proof revision: `45`
- Restored revision: `46`, rollback to pre-proof revision `44`

## Code And Image

Commit `f512b8a` added connected UDP DNS `write`/`read` capture paths.
Follow-up commit `94e808c` added DNS-local `connect` and `close` tracking so
the DNS eBPF object can resolve connected UDP peers without relying on maps
owned by the network source object.

Local checks before push:

- `bash tests/dns_connected_udp_guard_test.sh`
- `cargo fmt --all -- --check`
- `cargo test --locked -p e-navigator-sources-ebpf-aya dns -- --nocapture`
- `cargo clippy --locked -p e-navigator-sources-ebpf-aya --all-targets -- -D warnings`
- `docker build -f Containerfile -t e-navigator:dns-connected-udp-r2 .`
- `tests/smoke_docker.sh e-navigator:dns-connected-udp-r2`
- `scripts/quality.sh`

GitHub checks for `94e808c`:

- `CI`: success
- `publish-images`: success

## Deployment

The proof upgraded the release from revision `44` to revision `45` with only
these intended changes:

- image digest changed from `sha256:90b571...` to `sha256:583fa4...`;
- image tag changed from `sha-622e1aa` to `sha-94e808c`;
- `source.aya_dns` changed from `false` to `true`;
- `generator.dns_metrics` changed from `false` to `true`.

The DNS-enabled DaemonSet rolled out successfully:

- `e-navigator-bench-g66db` on `homelab-01`
- `e-navigator-bench-9gkh8` on `homelab-02`

Both pods ran the pushed digest and stayed Ready with restart count `0`.

## Controlled Workloads

Two short connected-UDP Python jobs completed first:

- `e-nav-dns-connected-udp-r2-20260622-213109-homelab-01`
- `e-nav-dns-connected-udp-r2-20260622-213109-homelab-02`

Each emitted `80` successful DNS response lines.

Two warmed connected-UDP Python jobs then completed after a `30` second
attribution-cache warmup:

- `e-nav-dns-connected-udp-r3-20260622-213109-homelab-01`
- `e-nav-dns-connected-udp-r3-20260622-213109-homelab-02`

Each emitted `120` successful DNS response lines after the warmup marker.
The queried names were:

- `kubernetes.default.svc.cluster.local`
- `e-navigator-bench.e-navigator-bench.svc.cluster.local`

## Observed DNS Output

The first short run proved connected-UDP DNS source and generator output for the
controlled Python client path on `homelab-02`, but those early records only had
container attribution and `kubernetes: null`.

The warmed run then produced structured controlled-client DNS evidence on
`homelab-02`:

| Host | Kind | Kubernetes attribution | Count |
| --- | --- | --- | ---: |
| `homelab-02` | `dns_query` | `e-nav-dns-connected-udp-r3-20260622-213109-homelab-02-5thbm` | 120 |
| `homelab-02` | `dns_response` | `e-nav-dns-connected-udp-r3-20260622-213109-homelab-02-5thbm` | 120 |

The same structured pass also retained the short-run container-only evidence:

| Host | Kind | Kubernetes attribution | Count |
| --- | --- | --- | ---: |
| `homelab-02` | `dns_query` | `kubernetes: null` | 80 |
| `homelab-02` | `dns_response` | `kubernetes: null` | 80 |

The matched controlled pod container ID was:

```text
5bebd0085a918b39846e5be48945462d0794615abee500b6c5145e0d09f69c4c
```

It matched pod:

```text
e-nav-dns-connected-udp-r3-20260622-213109-homelab-02-5thbm
```

with pod IP `10.42.134.19` on `homelab-02`.

For the controlled names, the structured count by query was:

| Host | Kind | Query | Count |
| --- | --- | --- | ---: |
| `homelab-02` | `dns_query` | `e-navigator-bench.e-navigator-bench.svc.cluster.local` | 100 |
| `homelab-02` | `dns_query` | `kubernetes.default.svc.cluster.local` | 100 |
| `homelab-02` | `dns_response` | `e-navigator-bench.e-navigator-bench.svc.cluster.local` | 100 |
| `homelab-02` | `dns_response` | `kubernetes.default.svc.cluster.local` | 100 |

Every structured controlled event used `server_address = 10.43.0.10` and
`server_port = 53`.

## Negative Evidence

The controlled `homelab-01` Python DNS jobs completed successfully, but the
structured controlled-client DNS pass found no matching `python` DNS records for
their pod name, pod IP, or container ID in the final `homelab-01` log window.

The same `homelab-01` proof window did contain live DNS source records for other
workloads, including records with Kubernetes attribution, so the node was not
classified as having no DNS source activity. The run does not prove symmetric
controlled-client DNS capture across both homelab nodes.

The DNS perf buffer also reported dropped events during the high-volume window,
so this is not a lossless DNS capture proof.

## Cleanup

All proof jobs labeled `app.kubernetes.io/name=e-nav-dns-connected-udp-proof`
were deleted from `e-navigator-bench`.

The release was rolled back from revision `45` to revision `46`, described by
Helm as `Rollback to 44`. After rollback, the running pods were:

- `e-navigator-bench-9g976` on `homelab-01`
- `e-navigator-bench-qnmj6` on `homelab-02`

## Proof Boundary

This run proves:

- pushed GHCR image `sha-94e808c` was generated, published, and rolled out to
  the guarded homelab namespace;
- connected UDP DNS client traffic using `connect` plus `write`/`read` can emit
  live `source.aya_dns` `dns_query` and `dns_response` records;
- `generator.dns_metrics` can derive `dns_counter_metric`,
  `dns_latency_metric`, and dependency edges from those records;
- the observed `homelab-02` controlled Python client path carried container and
  Kubernetes pod attribution after a warmup window.

This run does not prove:

- symmetric controlled-client DNS capture across both homelab nodes;
- lossless DNS event capture under high volume;
- complete DNS syscall/path coverage;
- DNS replacement readiness;
- Beyla, Tempo, Pyroscope, Prometheus, or Alloy replacement readiness;
- reduced privilege;
- reduced overhead versus the existing homelab observability stack.
