# Boundaries

This document is the public source of truth for what E-Navigator does not claim.
It should be read before deploying the project or citing its benchmark/proof
results.

E-Navigator is a pre-release runtime signal plane. It is designed to collect,
attribute, derive, and export bounded runtime signals. It is not yet a complete
observability product.

## In Scope

E-Navigator is designed to provide:

- node-local Linux and Kubernetes runtime observations;
- versioned signal envelopes;
- bounded attribution to host, process, container, and Kubernetes context;
- optional operator-controlled capture filtering that scopes which workloads
  are probed by namespace and label rules, enforced in-kernel per cgroup id;
- low-cardinality metrics, dependency edges, request spans, profiling windows,
  and runtime security findings;
- JSON stdout by default;
- opt-in Prometheus HTTP and OTLP HTTP export surfaces;
- explicit evidence boundaries for synthetic, local, Docker, render, and
  privileged runtime proof.

## Explicit Non-Claims

E-Navigator does not currently claim:

- production observability backend behavior;
- trace storage, profile storage, flamegraph UI, dashboards, or query UI;
- production or homelab proof of direct profile delivery (the generic OTLP
  Profiles HTTP sink is locally proven against Pyroscope `1.20.3`; storage,
  retention, and query service behavior remain backend responsibilities);
- complete production HTTP/gRPC protocol coverage (bounded HTTP/1 and
  HTTP/2/HPACK request capture with request/response matching is implemented
  and locally proven for Redis and HTTP/2; HTTP/2 CONTINUATION reassembly is
  not covered);
- live Kafka protocol capture proof (capture, reassembly, and request/response
  matching are implemented and unit-tested; only Redis and HTTP/2 are live
  proven);
- live NATS, MongoDB, MySQL, or PostgreSQL protocol capture proof (implemented
  and unit-tested, not yet runtime-proven);
- on-the-wire TLS decryption (the claimed `source.aya_tls` surface is
  userspace library-boundary plaintext interception for dynamically linked
  OpenSSL 1.1.1/3 with the complete required read/write/fd-association export
  set and GnuTLS ABI 30 using the standard integer socket transport; candidate
  images are version-gated, architecture-checked, export-preflighted, and
  transactionally attached, with 15-second rescans and native coverage
  counters; BoringSSL, Go `crypto/tls`, rustls, custom BIO/custom transport,
  and statically bundled Node/JVM TLS fail closed and are not claimed);
- full per-connection TCP state-machine tracking or packet accounting (TCP
  retransmit, reset, and state-transition observation and counting are
  implemented, with resets and state transitions locally proven);
- universal stack unwinding (CPU profiles unwind natively via in-kernel
  DWARF/CFI rules parsed from `.eh_frame` for registered processes, with
  frame-pointer unwinding as the fallback, up to 128 configurable frames and
  the kernel `kernel.perf_event_max_stack` sysctl bound of 127 for the
  frame-pointer path; DWARF-expression CFI rules are not evaluated — they
  stop the unwind with accounting — coverage is bounded by row/module/process
  budgets with counters, terminal frames in modules that do not CFI-mark
  their outermost function classify conservatively as `no_mapping`, and
  stacks that fill the configured budget are flagged and counted, never
  silently truncated);
- interpreter unwinding beyond CPython 3.12 (the interpreter walk targets
  CPython 3.12 struct offsets measured from its headers; other versions are
  counted as unsupported; Node/V8 and JVM generated-code names resolve only
  when the target runtime or its tooling publishes a bounded
  `/tmp/perf-<pid>.map` in the target mount namespace, and that symbol map does
  not itself make every opaque JIT frame unwindable; thread matching uses
  `native_thread_id` and therefore degrades with accounting when the
  interpreter runs in a pid namespace whose CPython thread ids the agent
  cannot translate, and only co_qualname/co_name, co_filename, and
  co_firstlineno are ever read from interpreter memory; the interpreter's
  own pid namespace is translated when the kernel allows, which is the
  containerized-workload case proven on the homelab);
- native DWARF coverage of every process on a heavily loaded node (the
  in-kernel unwind-table row pool is finite; the agent prioritizes
  processes it observes on-CPU and re-allocates the pool each refresh, but
  on nodes running many processes with large system libraries some
  modules are skipped with row-budget accounting and fall back to
  frame-pointer unwinding);
- cross-pid-namespace symbolization beyond verified pids (pids are translated
  in-kernel into the symbolization procfs namespace where the kernel allows;
  untranslatable pids are symbolized only after a thread-comm identity check
  and otherwise carry raw addresses with accounting — an unrelated process
  sharing pid, tid, and thread comm would evade this check);
- instant capture-scope changes for newly started workloads (the optional
  `[capture_filter]` cgroup-id capture filter cannot decide a pod that
  userspace has not yet discovered; a new pod's cgroup id is absent from the
  eBPF membership map until the next controller refresh — pod identity arrives
  through a Kubernetes watch while the local cgroup tree is scanned every ~2s — so there is a bootstrap
  window of roughly a few seconds during which the pod follows the configured
  `unknown_cgroup` posture: under an allowlist posture that is a brief coverage
  gap for new included pods, and under a denylist posture a brief capture leak
  for new excluded pods, minimized by resolving the pod UID directly from the
  cgroup path but not eliminated);
- cgroup-based capture filtering of softirq TCP-stat observations (the
  `tcp_set_state`, `tcp_retransmit_skb`, and `tcp_send_reset`/`receive_reset`
  tracepoints run in softirq/interrupt context where `bpf_get_current_cgroup_id`
  reflects whatever task is on-CPU rather than the connection's workload; these
  observations are therefore treated as node-scoped and are always emitted, never
  cgroup-filtered);
- namespace or label capture filtering without the Kubernetes API (a namespace
  and labels are not present in the cgroup path — only the pod UID and container
  id are — so namespace/label rules hard-depend on the node pod list; when the
  API is unavailable the filter degrades loudly and applies the configured
  `unknown_cgroup` posture to every workload);
- glob or regular-expression label values (capture-filter namespace and
  process/container patterns support `*` and `?`; label rules support exact
  equality/inequality, existence/non-existence, set membership, and bounded OR
  groups);
- cgroup v1 capture filtering (the capture filter's join key is the cgroup v2
  container cgroup inode; it assumes the unified cgroup v2 hierarchy used by
  modern Kubernetes nodes, and host/non-pod processes — which have a cgroup but
  no namespace — always fall to the `unknown_cgroup` posture);
- capture filtering of a connection's network open/close lifecycle events after
  a mid-connection verdict flip (the capture decision for connection-lifecycle
  events is taken at connect/accept establishment; a workload whose verdict
  changes while a connection is open still emits that connection's open/close
  events, though its L7/payload events re-check the live per-cgroup verdict);
- lossless DNS or HTTP capture across every node and workload shape;
- live native `network.flow.bytes` export from traffic after the native metric
  migration, including flow-attribution warning proof;
- production collector/backend compatibility beyond recorded local or
  namespace-local Collector proof;
- reduced overhead versus another observability stack;
- reduced-privilege or non-root eBPF operation;
- complete attribution for every host process, packet, profile sample, or
  runtime security finding.

## Evidence Rules

Do not treat these as interchangeable:

- synthetic CLI output;
- Cargo/unit/golden tests;
- Docker smoke tests;
- Helm rendering or Kubernetes schema checks;
- guarded Linux/Kubernetes runtime proof.

A claim is runtime proven only when a capable Linux host or Kubernetes cluster
recorded the relevant E-Navigator output, pod state, workload output, and
cleanup/restore evidence.

## Security And Data Handling Boundaries

E-Navigator favors bounded data structures and explicit attribution warnings.
Sensitive values must not be added as high-cardinality labels or exported as
raw secrets. Signal schemas and exporters must keep secret-like label filtering
and bounded cardinality intact. Prometheus preserves the identity of bounded
metric series whose raw workload, process, endpoint, or DNS dimensions are
redacted by exporting deterministic fingerprints instead of the raw values.

## Operational Boundaries

The current Kubernetes posture still depends on privileged eBPF capabilities for
the live Aya sources. Do not present the chart as reduced-privilege or non-root
until that exact configuration has been implemented and proven on a capable
cluster.

## Benchmark Boundaries

Local Criterion benchmarks are hot-path hygiene and regression tools. They are
not live overhead proof. Runtime overhead claims require a controlled baseline,
resource samples, comparable workload shape, and recorded runtime evidence.
