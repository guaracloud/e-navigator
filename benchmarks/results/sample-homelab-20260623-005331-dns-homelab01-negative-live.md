# Homelab DNS Homelab-01 Negative Live Summary: 20260623-005331

## Scope

- Kubernetes context: `staging`
- Namespace: `e-navigator-bench`
- Target node: `homelab-01`
- Helm release: `e-navigator-bench`
- Baseline revision before this slice: `73`
- trace backendrary proof revisions: `74`, `75`, and `76`
- Restored revision: `77`, described by Helm as `Rollback to 73`

## Code And Image

Commit `635819e` added a connected DNS receive-peer guard for null-address
`recvfrom` and `recvmsg` paths, so connected UDP DNS responses can use the
tracked peer instead of decoding arbitrary response payloads without a peer.

Local checks before push:

- `bash tests/dns_connected_udp_guard_test.sh`
- `cargo fmt --all -- --check`
- `cargo test --locked -p e-navigator-sources-ebpf-aya dns -- --nocapture`
- `cargo clippy --locked -p e-navigator-sources-ebpf-aya --all-targets -- -D warnings`
- `docker build -f Containerfile -t e-navigator:dns-recv-peer-r11 .`
- `tests/smoke_docker.sh e-navigator:dns-recv-peer-r11`
- `git diff --check`
- `scripts/quality.sh`

GitHub checks for `635819e` completed successfully:

- `CI` run `28000557537`
- `publish-images` run `28000557540`

The published image used for the final live attempt was:

- tag: `ghcr.io/e-navigator/e-navigator:sha-635819e`
- image index digest:
  `sha256:eb8a9c70560a4a7a3a94766963c272846bc66a613e1ef85edd46591bc3ef1485`
- linux/amd64 manifest:
  `sha256:e63fe80d2f4a68ef8ff7fb13db2f43883b56d44af08abdf89a519a7ea0323f71`

## Deployment

The release was first upgraded to the previous current image `sha-040f9e6`.
Revision `74` did not actually enable `source.aya_dns` or
`generator.dns_metrics`, so workload `e-nav-dns-homelab01-r10` is not counted as
DNS proof.

Revision `75` corrected the config and enabled both DNS modules. Revision `76`
then rolled out image `sha-635819e` at linux/amd64 digest
`sha256:e63fe80d2f4a68ef8ff7fb13db2f43883b56d44af08abdf89a519a7ea0323f71`.
Both DaemonSet pods were Ready with restart count `0`.

The release was restored to revision `77`, rollback to `73`, with baseline image
digest:

```text
sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc
```

After restore, the DaemonSet was `2/2` Ready and the DNS modules were disabled
again in the release values.

## Controlled Workloads

The valid connected-UDP proof workload before the fix was
`e-nav-dns-homelab01-r11` on `homelab-01`. The Python client completed `20`
warmup DNS responses and `40` proof DNS responses from `10.43.0.10:53` with no
application errors. The E-Navigator homelab-01 logs contained no records for the
workload pod name, pod IP, container ID, command `python`, or exact query names.

The fixed-image connected-UDP proof workload was `e-nav-dns-homelab01-r12` on
`homelab-01`. The pod was:

```text
e-nav-dns-homelab01-r12-hjmkh
```

with pod IP `10.42.248.195` and container ID:

```text
8e5eaee2cece4cab0efa68555ac9f2dcef246e498ffa6530c0eae8e0665a2a88
```

It completed `20` warmup DNS responses and `40` proof DNS responses from
`10.43.0.10:53` with no application errors. The E-Navigator homelab-01 logs
again contained no controlled-client DNS records for the pod name, pod IP,
container ID, command `python`, or exact query names.

A strace diagnostic job, `e-nav-dns-strace-r12`, proved the workload syscall
shape on `homelab-01`:

```text
connect(3, {AF_INET, 10.43.0.10:53}, 16) = 0
sendto(3, <54-byte DNS query>, 54, 0, NULL, 0) = 54
recvfrom(3, <DNS response>, 512, 0, NULL, NULL) = 106
```

A final explicit-sockaddr workload, `e-nav-dns-sendto-homelab01-r13`, used
unconnected UDP `sendto(packet, ("10.43.0.10", 53))` and `recvfrom(512)` on
`homelab-01`. It completed `10` DNS responses from `10.43.0.10:53` with zero
application errors. Its pod was:

```text
e-nav-dns-sendto-homelab01-r13-kj2bj
```

with pod IP `10.42.248.194` and container ID:

```text
50523ddeffaedd07831221ad3d1b87bbf332b348dcc1b6f669ebd8a0ab76423f
```

The E-Navigator homelab-01 logs contained no records for the r13 query names,
pod name, pod IP, container ID, or command `python`.

## Negative Evidence

This run did not prove controlled-client DNS capture on `homelab-01`.

The DNS source did emit ambient DNS records during the same windows, so the
negative result is not classified as a total DNS-source outage on the node.
However, the exact controlled Python workloads were not observed.

The DNS perf buffer reported dropped events during the DNS-enabled windows,
including `lost_perf_events=83` in the r11 window and `lost_perf_events=29` in
the r12 window, with additional warning counts. This run is not a lossless DNS
capture proof.

## Cleanup

The following proof jobs were deleted from `e-navigator-bench`:

- `e-nav-dns-homelab01-r10`
- `e-nav-dns-homelab01-r11`
- `e-nav-dns-homelab01-r12`
- `e-nav-dns-strace-r12`
- `e-nav-dns-sendto-homelab01-r13`

The final cluster check stayed within context `staging` and namespace
`e-navigator-bench`.

## Proof Boundary

This run proves:

- pushed image `sha-635819e` was generated, published, and rolled out to the
  guarded homelab namespace;
- the local code and packaging gates listed above passed before publish;
- the controlled Python clients on `homelab-01` received DNS responses from
  CoreDNS at `10.43.0.10:53`;
- the release was restored to the previous baseline digest and DNS-disabled
  config after the live attempts.

This run does not prove:

- controlled-client DNS capture on `homelab-01`;
- symmetric controlled-client DNS capture across both homelab nodes;
- lossless DNS event capture;
- complete connected-UDP DNS syscall coverage;
- DNS replacement readiness;
- external flow agent, trace backend, external profile backend, Prometheus, or Alloy replacement readiness;
- reduced privilege;
- reduced overhead versus the existing homelab observability stack.
