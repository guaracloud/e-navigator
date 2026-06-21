# Homelab Required Image Availability Sample: 20260621-221944

This is a curated summary of the raw artifacts in
`benchmarks/results/20260621-221944-required-image-live/`.

## Scope

- Context: `staging`
- Namespace: `e-navigator-bench`
- Image checked: `ghcr.io/guaracloud/e-navigator:sha-8ab271c`
- Pod: `e-nav-image-check-8ab271c-20260621`
- Pull secret name used: `ghcr-e-navigator-pull`
- Helm release mutation: none
- Cleanup: not performed

No secret contents, tokens, auth headers, or Docker config JSON were captured.

## Result

The required image is currently pullable and runnable in the homelab namespace.

What was recorded:

- The check Pod reached `Succeeded`.
- Kubelet successfully pulled
  `ghcr.io/guaracloud/e-navigator:sha-8ab271c`.
- The pulled image digest was
  `ghcr.io/guaracloud/e-navigator@sha256:249ad67fa8578ade9ecc1279bcf52a52ae6038a342b7c68844ebfd7a38d4e34e`.
- The container ran `/usr/local/bin/e-navigator --help`.
- The container exited with code `0`.
- Captured logs printed the E-Navigator CLI help.
- The live Helm release was not changed and remained `2/2` Ready on
  `ghcr.io/guaracloud/e-navigator:sha-5c417c0`.

## Cleanup

No cleanup was performed because cleanup requires explicit approval. The
completed Pod `e-nav-image-check-8ab271c-20260621` was left in
`e-navigator-bench` as evidence.

## Proof Boundary

This run proves only that `sha-8ab271c` can be pulled in `staging` /
`e-navigator-bench` with the namespace pull secret and that the image can start
far enough to print CLI help.

This run does not prove:

- DaemonSet rollout of `sha-8ab271c`;
- live Aya exec, network, DNS, profile, or host-resource behavior on
  `sha-8ab271c`;
- Prometheus HTTP, OTLP HTTP, Tempo, Pyroscope, Alloy, or Beyla compatibility;
- replacement readiness;
- reduced overhead or reduced privilege.
