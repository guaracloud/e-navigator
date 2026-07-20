## Summary

Describe the problem, the bounded change, and the user-visible result.

## Architecture And Safety

- [ ] The static `Source -> Processor -> Generator -> Sink` architecture is preserved, or an ADR is linked.
- [ ] Memory, cardinality, input, queue, retry, fanout, and shutdown bounds remain explicit.
- [ ] Signal schemas and public behavior are compatible, or the versioning impact is documented.
- [ ] Unsafe or privileged boundaries include focused invariants and tests.

## Evidence

List the exact checks and environments used. Keep these tiers separate:

- unit, integration, fixture, property, or fuzz-build evidence;
- Criterion or local hot-path evidence;
- Docker or local Linux runtime evidence;
- privileged Linux or Kubernetes evidence;
- backend acceptance or production evidence.

## Documentation

- [ ] README, website, capabilities, boundaries, proof, and benchmark claims still agree.
- [ ] New or changed operator behavior is documented.
- [ ] Public prose contains no em dashes.

## Validation

```text
scripts/quality.sh
```

List every skipped gate and the exact environment reason. Do not describe a
skipped privileged, backend, or runtime gate as proof.
