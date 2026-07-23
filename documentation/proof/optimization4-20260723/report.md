# Evidence-Driven Optimization Campaign 4

Date: 2026-07-23

Status: **RETAINED**. Three profile-routed optimizations and three
correctness fixes are retained on the candidate tree. The corrected homelab
head-to-head measured the candidate at 86.391 millicores
against 148.235 millicores for the v0.2.0 baseline, a 41.719%
whole-agent CPU reduction at the final cumulative stage with unchanged RSS
and zero hard loss. Against combined Beyla plus Alloy the candidate CPU gap
closed from +87.933255% to +6.998686%, while the RSS advantage
held at -63.866085%. The dual objective of beating the
comparison stack on both CPU and memory is therefore not met on CPU by 5.651 millicores, while the memory objective holds with a wide margin.

## Profile-First Routing

A local 997 Hz whole-agent perf capture under a fixed-rate Redis workload
(OrbStack arm64, kernel 7.0.11) routed candidate selection. Its leading
attributions were:

- the HTTP source's event handling closure, 15.42% self time, under a
  Redis-only workload that contains no HTTP traffic;
- kernel wake chains (`wake_up_q`, `eventfd_write`, futex syscalls) from
  per-event reader wakeups, roughly an eighth of agent CPU;
- SipHash writes 2.51%, malloc plus free 4.7%, `append_trace_attributes`
  and envelope sanitization near 2% each.

The first attribution exposed a structural defect rather than a hot loop:
the HTTP source emitted a payload event for every write on every tracked
client connection and every read on every accepted server connection with
no HTTP check on the tracked path, so every non-HTTP protocol syscall paid
an in-kernel payload copy, a ring output, a reader wakeup, and a userspace
decode and reassembly rejection.

## Retained Changes

| Commit | Change | Qualification evidence |
| --- | --- | --- |
| `f0cc9bf` + `00a9b0d` | Classify each tracked connection once, in kernel, from its first captured payload; non-HTTP connections skip HTTP payload capture for their lifetime, with skips counted by the new `non_http_connection_skip` diagnostic. The verdict is stored in place through the map value pointer to stay inside the kernel's 512-byte combined call-stack limit | Local paired whole-agent A/B: 82.437 to 61.652 millicores median, -25.2%, four pairs, byte-identical protocol counters; HTTP correctness arm decoded the same request volume as the baseline (22,360 versus 22,268 samples for 9,000 operations) |
| `5414e7b` | Apply the perf readers' proven 25 ms coalescing window to ring-buffer readers, batching poll wakeups, drains, and downstream channel wakes | Local paired whole-agent A/B against the classification commit: 69.876 to 34.445 millicore mean, -50.7%, four pairs, zero transport, queue, or export loss |
| `2c174e1` | Remove the per-key lowercase String allocation from the trace sensitive-key deny check and share one allocation-free helper across the signals, sink, and profiling variants | Criterion regression benchmark `signal/sensitive_trace_key_checks` improved 56.145% (702 to 311 nanoseconds, p = 0.00); three-pair whole-agent A/B showed no regression; mixed-case filtering locked by new unit tests |

## Correctness Fixes Found By The Campaign

- `eacf867`: the protocol iovec emit tail program walked all forty iovec
  slots in one program and exceeded the one-million-instruction verifier
  budget on an arm64 kernel 7.0 verifier, which failed the whole protocol
  source on such hosts. Emission is now chunked eight slots per tail-call
  round. Verifier-loaded and live-proven on arm64 (8,032 samples decoded,
  zero loss) and on the amd64 homelab kernel through the full campaign.
- `00a9b0d`: the first candidate campaign attempt failed on the homelab
  amd64 kernel 6.6 verifier with a combined call stack of 608 bytes over
  the 512-byte limit, because the classification helper carried a mutable
  copy of the connection struct across a map re-insert call. The in-place
  store fixed it; the failed attempt's artifacts are retained locally under
  `benchmarks/results/optimization4-cand-20260723-failed-verifier`.
- `d45f3a9`: both MongoDB benchmark fixtures carried a stray byte that made
  the frames one byte longer than their declared length, so the unfiltered
  `hot_paths` benchmark binary had panicked at setup since strict OP_MSG
  section validation landed. The full Criterion suite runs again.

## Reproducible Inputs And Method

- Base source: `d83c7bb` (v0.2.0). Candidate source: `00a9b0d`.
- Baseline image `docker.io/library/e-navigator:opt4-base-amd64`, runtime
  image ID
  `sha256:67b060f4ae2cca2af2cdfa7cef6b3acc3362c0e72eae47a6ba9db489d38d5824`,
  binary SHA-256
  `95ff74cfa408b9c7ec41e0569590d8bd7ebe3115a2017e68c50827417e518266`.
- Candidate image `docker.io/library/e-navigator:opt4-cand2-amd64`, runtime
  image ID
  `sha256:c7f4873ba41843c85bd6fea51171b68b81f2fcf53927e0a01ca00993ef02ace4`,
  binary SHA-256
  `d7b4e743df9ac6f55ee64a9d7ac1b5a0814c863721446597a3683795635f69d6`.
- Workload image `docker.io/library/e-navigator-head-to-head:opt4-amd64`,
  runtime image ID
  `sha256:9cdef1fa9b13c8f8f7c7718974fb0e01b5baf11d6dc9247c713437af67c7660e`.
- Beyla chart 1.16.10 and Alloy at the same pinned digests as the
  2026-07-23 corrected campaign; cluster exactly `homelab`, k3s v1.30.4,
  two amd64 NixOS nodes, Linux 6.6.68; load on `homelab-01`, servers and
  collectors on `homelab-02`; images imported node-locally, never pushed.
- Both campaigns used the corrected workload contract: three
  counterbalanced repetitions of no-agent, E-Navigator, and Beyla arms over
  cumulative HTTP, gRPC, Redis, PostgreSQL, and 10 Hz profile stages at
  fixed offered rates of 100, 80, 160, 50, and 8 operations per second,
  each with 15 seconds of warmup and 45 measured seconds. The candidate
  campaign was interrupted externally after 31 validated arms; the two
  remaining arms were completed with the harness's resume mode, which
  reuses only arms that already passed validation and re-runs the rest.
  The full standing-environment isolation and restore assertions held on
  both exits, including one manual restore after the interruption that
  returned Argo CD automation and the standing DaemonSet to their recorded
  state before the resume.

## Final Resource Result

Values are means plus or minus sample standard deviation across three
repetitions of each arm. CPU is millicores and memory is MiB of container
RSS over the same late measurement window used by the prior campaigns.

| Cumulative stage | Baseline E-Navigator CPU | Candidate E-Navigator CPU | Change |
| --- | ---: | ---: | ---: |
| HTTP | 30.788 +/- 0.991 | 21.178 +/- 0.803 | -31.21% |
| plus gRPC | 63.016 +/- 4.186 | 37.983 +/- 2.011 | -39.72% |
| plus Redis | 118.357 +/- 2.388 | 63.543 +/- 2.139 | -46.31% |
| plus PostgreSQL | 139.430 +/- 0.799 | 76.646 +/- 0.729 | -45.03% |
| plus profiles | 148.235 +/- 1.174 | 86.391 +/- 1.826 | -41.72% |

| Stack | Final CPU | Final RSS |
| --- | ---: | ---: |
| Beyla plus Alloy (baseline campaign) | 78.876 +/- 2.580 | 138.5 |
| Beyla plus Alloy (candidate campaign) | 80.740 +/- 2.545 | 131.2 |
| E-Navigator baseline | 148.235 +/- 1.174 | 47.1 |
| E-Navigator candidate | 86.391 +/- 1.826 | 47.4 |

## Signal Completeness

The three candidate final-stack arms decoded 151,808 protocol samples,
18,000 HTTP samples (exactly the 18,000 offered HTTP operations), and 721
profile samples, and sent 80,379, 18,000, and 721 signals respectively.
Hard loss was zero across transport loss, perf loss, ring reservation
failures, send failures, source failures, export queue drops, failure
drops, circuit-open drops, and worker-closed drops. The exporter enqueued
98,379 traces and sent 98,368, an asynchronous scrape-boundary difference,
and enqueued and sent all 721 profiles.

## Tradeoffs And Non-Claims

- Ring-buffer coalescing adds up to 25 milliseconds to export-visible
  observation latency, well inside the one-second default flush interval;
  event timestamps remain kernel-assigned.
- The HTTP source no longer captures HTTP/1 requests on a connection whose
  first captured payload does not start like an HTTP/1 request. That
  boundary is documented in `capabilities.md`, and the HTTP/2 preface
  deliberately classifies as non-HTTP because h2 belongs to the
  port-scoped protocol source.
- Local whole-agent numbers are OrbStack directional evidence, not
  production proof. Three repetitions on one shared homelab cluster remain
  a descriptive comparison, not a universal production estimate.
- Allocation diagnostics were not re-run this campaign. The 2026-07-23
  corrected campaign's allocator baseline still describes the v0.2.0
  binary; the retained changes remove allocations by construction (one
  String per scanned attribute key, per-event mirror decode buffers), but
  no new cross-runtime allocator comparison is claimed.
- The perf-buffer transport lost all events in a local arm64 OrbStack smoke
  (16 KiB page kernel); the ring transport, which `auto` selects on every
  supported kernel here, was unaffected. Recorded as an open follow-up, not
  fixed in this campaign.

## Remaining Bottlenecks

- Static attribute keys are still materialized three times per span
  (parser `Vec<TraceAttribute>`, sink `BTreeMap<String, serde_json::Value>`,
  prost `KeyValue`), with BTreeMap node churn and re-truncation at encode.
- SipHash fingerprint hashing in request correlation.
- The hex trace-identity round trip (formatted at generation, re-parsed to
  bytes at encode).
- Gzip remains visible at compression level fast.
- Resource grouping at encode compares full resource maps pairwise.

## Validation And Cleanup

`scripts/quality.sh` passed with no skip variables at the final tree
(`00a9b0d`), covering formatting, documentation and release checks, strict
Clippy, rustdoc warnings, workspace tests, builds, fuzz checks, repository
guards, supply-chain checks, the container build and runtime smoke, Helm
lint and rendering, strict Kubernetes schema validation, website links, and
diff hygiene. All benchmark resources, the temporary image-importer pods,
and all four campaign image references were removed from both node
containerd stores and local Docker after the campaign. `root-app` and
`e-navigator` returned to automated prune plus self-heal, Synced and
Healthy, and the standing DaemonSet returned 2/2 Ready. No code or image
was pushed, and no release was created.

The raw arm, Prometheus, workload, image, quality, and local A/B evidence
remains local under ignored `benchmarks/results/optimization4-*`
directories. [`summary.json`](summary.json) is the machine-readable result.
