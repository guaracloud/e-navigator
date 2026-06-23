# Engineering Invariants

These invariants keep E-Navigator's implementation and public claims aligned.

## Runtime And Modules

- Preserve the static `Source -> Processor -> Generator -> Sink` pipeline.
- Do not add runtime plugin loading without a deliberate architecture change.
- Module names are product-native E-Navigator names. Do not add vendor-specific
  compatibility layers or compatibility-named signal families.
- Config validation must keep every registered module explicit and bounded.

## Signals And Attribution

- Signal schemas are versioned contracts.
- Bounded cardinality is mandatory for labels, attributes, and exported metrics.
- Missing host, process, container, or Kubernetes context must be represented as
  missing context or structured warnings, not guessed identity.
- Secret-like labels and attributes must be filtered before export.

## Parsers And Decoders

- Parser and decoder limits must be explicit.
- Fuzz or fixture coverage should sit near protocol and raw-event boundaries.
- Synthetic or fixture proof must not be described as live runtime proof.

## Privileged Boundaries

- Aya/eBPF behavior is a privileged runtime boundary.
- Do not claim live Linux or Kubernetes behavior unless a capable host or
  cluster produced recorded evidence.
- Do not claim reduced privilege or non-root operation until the exact runtime
  posture is implemented and proven.

## Exporter Boundaries

- Registered sinks are not the same as production backend compatibility.
- Prometheus and OTLP claims must distinguish local formatter/fake-collector
  tests from live scrape or Collector acceptance.
- Storage, UI, pprof, trace backend, profile backend, and flamegraph behavior
  remain non-claims until implemented and proven.

## Public Documentation

- `README.md`, `capabilities.md`, `boundaries.md`, `proof-report.md`, and
  `benchmark.md` must agree.
- Historical proof details belong in raw ignored result directories, not in the
  public reader path.
- Public docs should state what is proven, partial, not proven, or blocked
  without exposing a chronological lab notebook.
