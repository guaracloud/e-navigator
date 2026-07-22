# Cgroup Hierarchy Boundary Proof

Date: 2026-07-22

Context: `homelab`

Namespace: `e-navigator-bench`

Candidate: `docker.io/library/e-navigator:gap6-cgroup-amd64` at
`sha256:115e972bb993bf9f3bdc50fcefe437be0083fe152d215cf06ba7937934282bb2`

## Question

Does the capture filter accept only the cgroup hierarchy whose inode ids can
be joined safely to `bpf_get_current_cgroup_id()`, and does it deny all unknown
cgroups before program attachment when a legacy layout is detected?

## Method

The guarded `homelab-cgroup-hierarchy.sh` harness used one image and the same
`source.aya_exec` configuration for two arms on `homelab-01`, a NixOS node
running kernel 6.6.68 and k3s 1.30.4.

The first arm mounted the node's real `/sys/fs/cgroup`. The second mounted a
ConfigMap containing the legacy-only `tasks` marker at the same configured
path. Both arms deliberately configured `unknown_cgroup = "allow"`. A bounded
Job made 300 external exec attempts after both deployments became ready. The
harness waited past the 30-second kernel accounting interval, collected native
Prometheus metrics and normalized logs, validated the expected state, deleted
all proof objects, and verified the namespace was empty.

This is behavioral validation of the v1 detector and failure posture on the
homelab. It is not a v1-node compatibility run and does not promote a cgroup v1
support claim.

## Result

The real host mount reported `unified_v2`, compatibility `1`, fail-closed count
`0`, and control word `1`. The Aya exec source initialized, decoded and sent
3,135 signals, lost no transport events, and reported zero filter drops.

The legacy fixture reported `legacy_v1`, compatibility `0`, fail-closed count
`1`, and an error stating that all unknown cgroups were denied. The configured
allow posture was replaced with control word `2` before attachment. The same
Aya source initialized but decoded and sent zero signals while the kernel
accounted 3,012 suppressed handler invocations. Transport loss remained zero.

An earlier candidate exposed one attachment-time event before the applier set
the control map. That candidate was rejected. The final implementation seeds
the posture centrally in the common eBPF object loader, before any source can
attach a program, and the accepted run demonstrates zero decoded or sent
signals in the legacy arm.

## Claim

E-Navigator now detects unified v2, legacy v1, hybrid, and unavailable cgroup
roots using a bounded startup probe. Cgroup v1 and hybrid capture filtering
remain deliberate non-claims. When filtering is enabled on an unsupported
layout, the runtime degrades loudly and denies all unknown cgroups before Aya
program attachment. The committed evidence proves the exec-source boundary;
it does not claim a real v1-node run or full source-family runtime coverage.

## Cleanup

The proof namespace contained no resources after the run. The standing
`e-navigator` Argo CD application remained `Synced` and `Healthy`. All commands
used explicit context `homelab`; no production context or namespace was read or
mutated.
