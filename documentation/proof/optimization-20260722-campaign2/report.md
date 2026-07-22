# Evidence-Driven Optimization Campaign, Corrected Rerun

Date: 2026-07-22

Status: local campaign complete, homelab baseline and A/B blocked pending
explicit deployment authorization.

No comparative CPU, RSS, allocation, throughput, or latency result is claimed
by this report. The earlier 33-run result is invalidated by the adjacent
[`erratum`](../optimization-20260722/ERRATUM.md).

## Baseline Integrity Correction

The workload Redis proxy previously retained one backend connection created
during deployment readiness. Because collector attachment occurred later, the
server-node eBPF source could not observe Redis traffic on that socket. The
corrected proxy keeps readiness probing separate and creates and closes one
backend client for each load connection.

The analyzer now computes a cumulative protocol-operation floor from successful
warmup and measured work. E-Navigator arms fail validation when
`source_signals_sent` is lower than that floor. CPU-profile work is excluded
from the floor because it is frequency sampled and has its own positive-sample
and export gates.

The previous run would now fail all Redis and later E-Navigator arms. Its three
Redis arms sent 10,800 signals against a 20,400 floor. PostgreSQL arms sent
22,874, 22,845, and 22,874 against 23,400. Profile arms sent 23,151, 23,323,
and 23,008 against 23,400.

## Retained Changes

All percentages below are local Criterion median point estimates. They are
hot-path evidence, not whole-agent overhead claims.

| Change | Baseline | Candidate | Median change | Result |
| --- | ---: | ---: | ---: | --- |
| One-pass three-seed identity hashing plus allocation-free peer fingerprinting | 3,287.346 ns | 2,649.607 ns | -19.399819% | retained |
| Request dedupe at the 8,192-entry bound with allocation-free peer fingerprinting | 1,564.175 ns | 1,317.739 ns | -15.755034% | retained |
| Preallocated sorted HTTP/2 in-flight index, 32-stream cycle | 3,204.246 ns | 3,123.268 ns | -2.527201% | retained |
| OTLP write for a warning that cannot carry trace identity | 1,608.556 ns | 1.509 ns | -99.906209% | retained |

Generated trace and span IDs have a golden exact-value assertion. All 32
request-correlation tests, 41 protocol-source tests, and 39 OTLP sink tests
passed after the retained changes. HTTP/2 multiplexed out-of-order matching,
bounded eviction, valid and invalid trace identity accounting, retry, queue,
compression, and export behavior remain covered.

The attempted inline method fingerprint removed a common small string
allocation but increased structure size and slowed the at-capacity benchmark
from 1,323.4 ns to 1,383.8 ns in the trial. It was reverted.

## Prepared Runtime Inputs

The images were built locally for `linux/amd64` and were not pushed.

| Input | Image reference | OCI archive SHA-256 |
| --- | --- | --- |
| Baseline collector from commit `49fef26b0755ca0d4cacba8efbed84e3ebb66771` | `docker.io/library/e-navigator:campaign2-base-amd64` | `d2c13a47362c4328190559962f11bcd9c856b72b061be5fe7739f9f55f92bbb2` |
| Optimized collector | `docker.io/library/e-navigator:campaign2-opt-amd64` | `e667aa867740ba07733dbe22351aba1e25df6e24e366bd1475b289efe3e7413a` |
| Corrected workload | `docker.io/library/e-navigator-head-to-head:campaign2-fixed-amd64` | `4c4b7ee1039e521b6315e63a0bc78ea5209d062d904779dc80d4a73fcc2a4957` |

The intended rerun uses the corrected workload for both the clean baseline and
optimized candidate, with identical pinned Beyla and Alloy inputs, offered
rates, placement, warmup, measurement, counterbalanced order, and loss gates.

## Validation

`scripts/quality.sh` passed with no skip environment variables. This covered
formatting, documentation and release checks, strict Clippy, workspace tests,
supply-chain checks, the Docker build and smoke, Helm and Kubernetes schema
validation, website checks, and `git diff --check`.

The final OTLP benchmark rerun changed only the measured evidence value in this
report. The documentation checker, head-to-head guard, and `git diff --check`
then passed again against that evidence-only update.

## Runtime Blocker

The repository image-loader is a privileged DaemonSet with a host-root mount.
Creating it and the ephemeral benchmark collectors is a deployment. The
request explicitly prohibited deployment without separate authorization, so
the attempted loader creation was rejected before execution and no cluster
resource was created. The agent did not work around that boundary.

A full 33-arm baseline or candidate run, allocator probe, and fresh Linux perf
profile therefore remain pending. Until explicit authorization is provided,
the corrected comparative verdict is `INDETERMINATE`.
