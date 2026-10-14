# CPU runtime qualification for issue 52

Issue [52](https://github.com/guaracloud/e-navigator/issues/52) adds registration
safety and a reproducible per-cell CPU quality gate. It does not establish
Guara replacement readiness. The deployment matrix and acceptance thresholds
remain owner inputs under the [replacement contract](replacement-acceptance.md).
Issue [48](https://github.com/guaracloud/e-navigator/issues/48) owns the complete
qualification suite. [ADR 0016](adr/0016-non-intrusive-profiling-parity.md)
continues to require recorded verifier, capture, and backend evidence.

## Registration and migration

Native frame-pointer and bounded `.eh_frame` CFI paths remain independent of
interpreter walking. Native rows have immutable source-lifetime placements;
refresh order cannot overwrite a row used by an in-flight tail call. Failed
publication retries rewrite unpublished slots. Process registrations and raw
samples carry a generation checked at walker chunks and before/after userspace
symbolization. Exec, exit, and mapping-changing syscalls invalidate registrations.
In-flight mapping-changing syscalls (including brk, shared-memory mappings,
remap_file_pages and pkey_mprotect) and execve/execveat block new registrations.
Successful non-leader exec cleans up the original TID marker using old_pid.
Attachment requires validated tracefs sys_enter/id and sched_process_exec/old_pid
layouts; unreadable or incompatible formats reject the source.
A changed generation preserves CPU weight and marks user frames unresolved.

Python walks now require an operator-attested ELF build descriptor. An empty
`cpu_profile_source.python_builds` list disables Python memory reads; it does
not disable native CPU capture. This intentionally replaces automatic selection
by a `python3.11` or `libpython3.12` filename. Existing installations must attest
their binaries before re-enabling interpreter walks. Candidate layouts are
release CPython **3.11.13** and **3.12.13**, ELF64 little-endian x86-64 or arm64.
These are adapter candidates, not a declaration of required Guara cells.

For each approved interpreter binary, add a `[[cpu_profile_source.python_builds]]`
entry with its lowercase GNU ELF `build_id`, exact `version`, and `architecture`
(`x86_64` or `aarch64`). Configuration accepts at most 64 unique descriptors.
The source verifies the build ID, ELF architecture, defined `Py_Version` numeric
value, `_PyRuntime`, and absence of known debug/trace-reference layout markers.
Attestation must cover compiler/layout options as well as the build ID; the
source cannot infer every compiler option from ELF symbols. Unsupported versions,
unattested images, missing metadata, and failed reads retain explicit degradation.
No runtime flags, agents, allocation providers, or security-policy changes are
introduced. A pre-existing perf map supplies names only, never proof of JIT
unwinding.

Metadata reads are bounded: maps 256 KiB, ELF images 64 MiB, descriptor/module
caches 512 identities, CFI rows 262,144, and existing per-process mapping/frame
budgets. Process generation storage has 1,024 non-evicting entries for sampled targets over the source
lifetime. Unrelated lifecycle events do not allocate entries. First enrollment
inserts the epoch before checking bounded pre-enrollment operation markers.
Exhaustion rejects new PID registrations and reports identity rejection;
it cannot evict a pending operation and accidentally reopen the fence. The
4,096-entry pending-operation map tracks global mapping syscalls; losing an
enter due to exhaustion poisons runtime registrations for the source lifetime. A source restart
resets these lifetime pools. These limits must be exercised in qualification,
especially under process/module churn. Hash-map syscall hooks, namespace
translation, verifier behavior, shared address spaces, and overhead require
capable-host execution; container compilation is not that evidence.

## Per-cell assertions

`scripts/qualify_cpu_profiles.py` uses only Python's standard library. Its
[synthetic fixtures](../tests/fixtures/cpu-qualification/cells.json) demonstrate
the input shape and are not workload evidence. Run the saved-response example:

```sh
python3 scripts/qualify_cpu_profiles.py \
  --cells tests/fixtures/cpu-qualification/cells.json \
  --capture tests/fixtures/cpu-qualification/capture.json \
  --profiles tests/fixtures/cpu-qualification/profiles.json \
  --output /tmp/cpu-qualification.json
```

Each `WC-CPU-dddd` cell specifies exact runtime/version/build/architecture/image
identity, process oracle, bounded millisecond query window, workload label
selector, expected root-to-leaf application caller chain with frame domains,
and six owner-approved thresholds. Fractions use basis points (10,000 = 100%).
Minimum CPU weight and useful coverage must be positive. There are no implicit
acceptance defaults. Native SignalEnvelope captures retain leaf-to-root frames;
the checker converts the oracle order for native comparisons.

Native sample weight is `sample_count * sampling_period_nanos`. Unknown,
truncated, failed, and useful weights are evaluated separately per cell; a good
native cell cannot hide a failed interpreter cell. Only periodic on-CPU samples
are accepted. Event-driven off-CPU/lock durations do not enter this CPU gate.
Stored SelectMergeStacktraces flamegraphs must conserve nanosecond weight and
contain the application caller chain, not merely its names in unrelated nodes.
Stored unknown weight and native/backend weight error have independent limits.
Missing cells, identity/window mismatches, wrong domains, malformed or oversized
JSON, and excessive degradation fail the gate.

Replace `--profiles` with `--pyroscope-url` for authorized read-only queries to
`querier.v1.QuerierService/SelectMergeStacktraces`. The URL must omit credentials,
query, and fragment. This mode supports an already-accessible endpoint; it does
not provision a backend, configure authorization, or deploy workloads. Requests
use the [documented Pyroscope API](https://grafana.com/docs/pyroscope/latest/reference-server-api/)
and bounded responses. The result records input SHA-256 digests, mode, per-cell
weights, and verdict. Both modes keep `replacement_qualified: false`: matching
JSON does not establish capture provenance, runtime attachment, approved targets,
or overhead. Retain original captures, query responses, image/build attestations,
verifier logs, and commands alongside the result in the issue 48 evidence bundle.

## Acceptance status

| Requirement | Repository implementation | Remaining proof |
| --- | --- | --- |
| Immutable descriptors and bounded independent walkers | Attested Python ELF descriptors, native CFI/FP, immutable rows and generation checks | Exact approved deployment cells and layout attestations |
| Useful application callers and visible partial failures | Native/replay fixtures and per-cell weighted caller/degradation assertions | Optimized, namespace, JIT, and churn captures for every required cell |
| CPU weight, timing and domains through exports | Existing pprof/OTLP contracts retained; internal event ABI updated consistently | Stored Pyroscope outputs from the approved execution window |
| Replay and negative qualification | Automatic config, ELF, registration, decoder, and checker tests in the full quality gate | Privileged verifier/load/capture records on required architectures |
| No target mutation or speculative profile kind | No target flags/agents or infrastructure changes | Approved qualification target and operator thresholds |

The exact blockers are IN-01 through IN-07 in the replacement contract,
including the runtime deployment matrix, accessible evidence destinations,
TH-STACK/CPU limits, and execution authorization. There is no live qualification
record from this change. Issue 52 stays open until every required cell meets
its approved criteria; this implementation must not auto-close it.
