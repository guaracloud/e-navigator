# Standalone code and qualification audit

Audit date: 2026-10-14. Baseline: `caa74fc1139068851510f51a49bceb32a983b162`.

E-Navigator belongs to the GuaraCloud organization. Repository, registry,
security-reporting, and published artifact addresses remain distribution
metadata. Organization ownership does not select application behavior, customer
labels, account tiers, qualification namespaces, or reference collector products.

## Coverage and findings

The baseline tracked-file scan found 263 named-reference lines in 66 files.
A separate scan found 105 workload namespace references in 22 files, with 80
distinct files across the two inventories. Follow-up tracing also identified
the fixed consumer-query namespace in the campaign validator.

| Surface | Finding | Resolution |
| --- | --- | --- |
| Rust sources and integration tests | Customer label names and tier/catalog terminology in fixtures | Use reserved example-domain labels and generic environment/exclusion scenarios; production Rust logic and configuration defaults are unchanged |
| Qualification validators and examples | Workload namespace and CPU checks required a customer prefix | Parse a bounded operator-owned namespace and validated family; maintained examples use `WC` |
| Campaign consumer queries | A fixed customer query prefix was mandatory | Accept a bounded operator-owned query namespace; maintained examples use `CQ` |
| Reference comparison | The campaign required particular reference collector names | Require operator-named immutable collector digests plus a pinned configuration snapshot |
| Release and benchmark scripts | Organization/image identity embedded in executable code | Read the existing repository and image distribution metadata; keep benchmark identity/substitution reporting |
| Release signatures | Verification embedded one organization in a regular expression | Verify the exact executing repository, workflow, and tag identity from GitHub context |
| Quality and documentation contracts | A customer deployment inventory defined the product's qualification gate | Use the generic [acceptance contract](replacement-acceptance.md) and [workload ledger](workload-qualification.md); retain customer profiles as historical records |
| Published proof and distribution | Real artifact identities and historical observations | Preserve historical proof files, distribution addresses, and published tags |

The namespace changes broaden accepted identifiers without renaming historical
IDs or regenerating their artifact hashes. Existing valid workload and query IDs
remain accepted through the generic syntax, with no customer-specific branch.
Cell counts, family coverage, immutable identities, approvals, exact evidence
matching, privacy, losses, CPU thresholds, retention, and rollback remain gates.
Fixtures still cannot promote live qualification.

## Reproducible checks

The following scoped scan has no matches in executable source or test tooling:

```bash
rg -n -i 'guaracloud|guara[./]|\bguara\b|\bG[WQ]-' \
  crates scripts tests benchmarks/runner .github/workflows
```

The independence checks are part of `scripts/quality.sh`:

- `tests/standalone_qualification_test.py` checks multiple operator namespaces,
  maximum namespace length, malformed IDs, CPU sample quality, backend assertions,
  and absence of synthetic promotion.
- `tests/campaign_qualification_test.py` checks a complete alternate-namespace
  artifact graph, operator-named reference collectors, consumer-query bounds,
  and rejection when the CPU quality threshold is removed.
- `tests/release_identity_test.py` checks repository-driven notes and the public
  image-repository command against alternate distribution metadata.

Validation passed: the full quality gate with no optional skips, 1,660 Rust
tests with no failures or ignored tests, and GitHub Actions linting. After the
final query-namespace change, all 28 campaign tests passed again. Documentation,
release consistency, and diff checks were rerun after the final documentation edits.

Unchanged CPU evidence and the replacement fixture from the baseline revision
were replayed successfully. Exact-identity Cosign verification accepted the
published `v0.6.0` manifest bundle and rejected an identity for a different tag.
An independent read-only review found a residual named-reference requirement
in the new documentation; it was corrected and the follow-up review passed.

These checks do not execute a new hosted release or establish privileged Linux,
live Kubernetes workload, backend retention, or production cutover qualification.
