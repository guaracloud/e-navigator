# Local Sample: Required Image DNS Version Boundary

Run:

- `20260623-101215-required-image-dns-version-boundary`

Raw evidence lives under
`benchmarks/results/raw/20260623-101215-required-image-dns-version-boundary/`.

Scope: local parser/config proof only. No Kubernetes resources were created,
updated, or deleted for this run.

Image:

- Required benchmark tag: `ghcr.io/e-navigator/e-navigator:sha-8ab271c`
- Required benchmark image digest from prior live runs:
  `sha256:249ad67fa8578ade9ecc1279bcf52a52ae6038a342b7c68844ebfd7a38d4e34e`

Probe:

- Config: `dns-required-image-probe.toml`
- The config enables `source.aya_dns` and `generator.dns_metrics` while keeping
  newer exporter config sections omitted, matching the older-compatible style
  used by prior required-image runs.

Commands:

- `cargo run --locked -p e-navigator-cli -- --source synthetic --config benchmarks/results/raw/20260623-101215-required-image-dns-version-boundary/dns-required-image-probe.toml --validate-config`
- `docker run --rm --platform linux/amd64 -v "$PWD/benchmarks/results/raw/20260623-101215-required-image-dns-version-boundary/dns-required-image-probe.toml:/tmp/e-navigator.toml:ro" ghcr.io/e-navigator/e-navigator:sha-8ab271c --source synthetic --config /tmp/e-navigator.toml --validate-config`

Observed evidence:

- Current-head CLI validation exited `0`, proving the current checkout accepts
  `source.aya_dns` in the config.
- The `sha-8ab271c` container validation exited `1` with:
  `unknown module 'source.aya_dns'`.
- The required image's known module list includes `generator.dns_metrics` but
  not `source.aya_dns`.

Outcome: `blocked` for live required-image DNS source output on `sha-8ab271c`
because that image predates the `source.aya_dns` runtime module. A live rollout
cannot prove DNS source output on that tag without changing the required
benchmark image.

Not proven:

- Live DNS capture, DNS response capture, DNS metrics, or controlled workload
  DNS attribution on `sha-8ab271c`.
- Any Kubernetes runtime behavior for this run; this was local parser proof
  only.
- Feature parity between `sha-8ab271c` and newer images that have proven
  `source.aya_dns` live.
