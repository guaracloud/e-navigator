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
- include tests for eviction and duplicate handling when relevant;
- emit native metric and signal names.

## Sinks

Sinks export existing signal envelopes or derived records. A sink must:

- keep secret-like label filtering;
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
