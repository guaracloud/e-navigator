# Module Authoring

E-Navigator modules are statically registered. New modules must fit the existing
pipeline and produce native E-Navigator signals.

## Sources

Sources observe raw input and emit versioned signal envelopes. A source must:

- define bounded event shapes;
- avoid secret or high-cardinality output by default;
- include local tests or fixtures;
- document any privileged runtime requirements.

## Processors

Processors enrich or normalize existing signals. A processor must:

- preserve original signal identity;
- attach attribution only when evidence exists;
- emit warnings or missing context rather than guessed identity.

## Generators

Generators derive metrics, dependency edges, request spans, profile windows, or
security findings. A generator must:

- bound memory and cardinality;
- implement `accepts` when its input signal set is closed, so unrelated signals
  do not allocate a future or output channel;
- implement `observe_immediate` when derivation is synchronous, while keeping
  `observe` behavior equivalent for direct trait callers;
- include tests for eviction and duplicate handling when relevant;
- emit native metric and signal names.

The runner rejects more than 64 outputs from one generator for one input, then
applies configured total breadth and depth budgets to the complete derivation
cascade. New generators must test their worst-case fanout.

## Sinks

Sinks export existing signal envelopes or derived records. A sink must:

- keep secret-like label filtering;
- implement `accepts` for a closed signal family and `write_immediate` only when
  the write performs no asynchronous I/O;
- distinguish formatting tests from live backend proof;
- expose bounded queue, retry, timeout, or drop behavior when applicable.

## Adding A Signal Family

Before adding a signal family, update:

- schema/golden tests;
- module registration and config validation;
- local generator/sink tests;
- [capabilities.md](capabilities.md) and [boundaries.md](boundaries.md) if the
  public surface changes;
- [proof-report.md](proof-report.md) only after evidence exists.
