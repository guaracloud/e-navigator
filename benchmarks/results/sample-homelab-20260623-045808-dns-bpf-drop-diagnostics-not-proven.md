# Homelab DNS BPF Drop Diagnostics Not Proven 20260623-045808

## Scope

- Context: `staging`
- Namespace: `e-navigator-bench`
- Raw evidence directory:
  `benchmarks/results/20260623-045808-dns-bpf-drop-diagnostics-live/`
- Baseline image digest:
  `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`
- Final restored Helm revision: `89`, described by Helm as `Rollback to 87`

## Attempted Change

The slice attempted to explain the previous `homelab-01` controlled-client DNS
negative result by adding DNS BPF drop diagnostics around the raw packet
capture path.

The tested commits were:

- `0f5595e` (`fix: expose dns bpf drop diagnostics`)
- `8460cc4` (`fix: avoid dns bpf packet scratch memset`)
- `6686165` (`fix: avoid dns bpf scratch zeroing`)

Each image was pushed and published before live rollout:

- `ghcr.io/e-navigator/e-navigator:sha-0f5595e`
  - image index:
    `sha256:0a5c2439564cf140d99dce97250108dded3139bad61fde06cbc9bf70dbae5156`
  - linux/amd64:
    `sha256:af61da53a10844172d4f352b3810077fdb01c1aaa959fe602fc78d00ded60b54`
- `ghcr.io/e-navigator/e-navigator:sha-8460cc4`
  - image index:
    `sha256:cb91f52fd22c7b3faa72a8cb3458fc240ec0826840dd0195b612c014e4d21bb2`
  - linux/amd64:
    `sha256:960f6cb602d6d428704c0904e78bbe99f0738dc7922ab6c601a705b8a9b11051`
- `ghcr.io/e-navigator/e-navigator:sha-6686165`
  - image index:
    `sha256:54084a563523c54d119772c645be026adc20aebd651d272bd33781d7432f5f12`
  - linux/amd64:
    `sha256:cf4b2794d604a0201ddcc2c3cca3a3513e3a84e501d42ad2b994ae1f41fecaf5`

## Live Result

The first two live attempts failed to load `source.aya_dns` on the homelab
nodes. Both logs reported:

```text
Error: module failed: source.aya_dns: the BPF_PROG_LOAD syscall returned Argument list too long (os error 7).
Verifier output: reg type unsupported for arg#0 function tracepoint_recvfrom_exit#82
```

The verifier trace also pointed at:

```text
reg type unsupported for arg#0 function try_tracepoint_dns_recvfrom_exit#78
```

The final diagnostic attempt moved the failure earlier into the shared network
source path. Both homelab node logs reported:

```text
Error: module failed: source.aya_network: the BPF_PROG_LOAD syscall returned Argument list too long (os error 7).
Verifier output: reg type unsupported for arg#0 function tracepoint_read_exit#76
```

Because the diagnostic images made required BPF modules unloadable on the live
nodes, they are negative proof for this diagnostic approach.

## Revert And Restore

Commit `e3bc6f2` (`revert: remove dns bpf drop diagnostics`) removed the
diagnostic changes and was pushed after the failed live attempts.

GitHub checks for the revert completed successfully:

- `CI` run `28004511957`
- `publish-images` run `28004511962`

The published revert image was:

- tag: `ghcr.io/e-navigator/e-navigator:sha-e3bc6f2`
- image index:
  `sha256:8d328fc2ce9f0262a71974f695044c080b72c07cb1f7f60cd6628dfa225cf757`
- linux/amd64:
  `sha256:94323460a190149450bff8290ad53d66fcd065ff4cd3c5d71135dac1b926b9a9`

The Helm release was restored to the baseline digest
`sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`.
The final recorded DaemonSet pods were Ready on both homelab nodes with zero
restarts.

## Proof Status

Proven:

- three diagnostic images were published and rolled out only to
  `staging/e-navigator-bench`;
- the diagnostic BPF changes were not verifier-safe on the homelab kernel;
- the failed diagnostic changes were reverted in `e3bc6f2`;
- the release was restored to the previous baseline digest and two Ready
  DaemonSet pods.

Not proven:

- DNS BPF drop diagnostic events;
- the root cause of the missing `homelab-01` controlled-client DNS records;
- controlled-client DNS capture on `homelab-01`;
- symmetric controlled-client DNS attribution across both homelab nodes;
- lossless DNS capture;
- DNS replacement readiness;
- reduced privilege or reduced overhead.
