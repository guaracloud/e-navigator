# Capabilities

This document is the current public capability map for E-Navigator. It is
intentionally shorter than the internal proof trail and should be updated only
when implementation and evidence change together.

| Area | Current state | Evidence level | Still missing |
| --- | --- | --- | --- |
| Static pipeline runtime | Implemented `Source -> Processor -> Generator -> Sink` runtime with registered modules | Cargo tests, synthetic CLI, Docker smoke | runtime plugin loading is not planned |
| JSON signal envelopes | Implemented versioned newline-delimited JSON output | Cargo tests, golden signal coverage, Docker smoke | storage and UI |
| Process exec source | Implemented Aya exec/exit source | raw decode tests and guarded homelab observations | reduced-capability/non-root eBPF proof |
| TCP network source | Implemented TCP-oriented network observations | raw decode tests and guarded homelab observations | full TCP state, retransmit/reset accounting |
| Host resource source | Implemented procfs/sysfs/cgroup observation | parser tests, Docker fixtures, guarded homelab observations | independent host-accuracy baseline and warning-free/lossless enumeration proof |
| Kubernetes attribution | Implemented best-effort container/Kubernetes context enrichment | unit tests and guarded homelab attribution for selected signals | complete attribution for every host process or packet |
| DNS runtime capture | Partial opt-in source and generator | parser/raw decode tests and selected homelab DNS proof | symmetric all-node capture and lossless DNS proof |
| HTTP/request foundation | Partial opt-in cleartext client capture | fixture tests and selected homelab `writev`/bounded-iovec proof | TLS, gRPC, inbound server-side parsing, status codes, route templates, broad multi-iovec support |
| MongoDB parser foundation | Parser-only `OP_MSG` and command `OP_QUERY` extraction for bounded operation semantics without raw BSON value or namespace export | parser fixture, malformed-input, property, and fuzz-target coverage | runtime eBPF capture, request/response matching, status/error extraction, live MongoDB proof |
| MySQL parser foundation | Parser-only `COM_QUERY` and `COM_STMT_PREPARE` command extraction for bounded operation semantics without raw SQL export | parser fixture, malformed-input, property, and fuzz-target coverage | runtime eBPF capture, request/response matching, status/error extraction, live MySQL proof |
| NATS parser foundation | Parser-only text command extraction for bounded operation semantics without raw subject or payload export | parser fixture, malformed-input, property, and fuzz-target coverage | runtime eBPF capture, request/response matching, status/error extraction, live NATS proof |
| PostgreSQL parser foundation | Parser-only simple Query and Parse message extraction for bounded operation semantics without raw SQL export | parser fixture, malformed-input, property, and fuzz-target coverage | runtime eBPF capture, request/response matching, status/error extraction, live PostgreSQL proof |
| Redis parser foundation | Parser-only RESP command extraction for bounded command semantics without raw key/value export | parser fixture, malformed-input, property, and fuzz-target coverage | runtime eBPF capture, request/response matching, status/error extraction, live Redis proof |
| Dependency graph | Implemented generator for observed network relationships | generator tests and selected live output | persisted service map and complete topology |
| Resource metrics | Implemented bounded resource metric generation | parser/generator tests and selected live output | production overhead baselines |
| Runtime security findings | Implemented first generator scope | generator tests, golden coverage, selected live findings | broad policy engine and production alert routing |
| CPU profiling source | Partial opt-in CPU profile sampling | raw decode/profile tests and selected live workload attribution | pprof export, storage, symbolization, flamegraphs, deterministic all-workload capture |
| Native flow byte metrics | Implemented native `network.flow.bytes` signal and Prometheus rendering | generator/sink tests and golden schema coverage | positive live native metric export after migration |
| Prometheus HTTP sink | Implemented opt-in HTTP surface | local `/metrics`, `/healthz`, `/readyz` tests and selected live scrape proof | longer soak, cardinality baseline, production-load correctness |
| OTLP HTTP sink | Partial metric, trace, development-status profile protobuf support, and per-family endpoint routing | fake-collector tests and selected namespace-local Collector proof | broad production collector/backend compatibility |
| Kubernetes packaging | Implemented Helm chart and raw manifests | Helm lint/template, schema checks, guarded homelab rollouts | production rollout proof across environments |
| Supply chain | Implemented release signing/SBOM workflow and local checks | release workflow, `cargo deny`, `cargo audit`, `cargo machete`, secret-pattern guard | container vulnerability policy gates |

## Reading The Evidence Level

- **Implemented:** code path exists and is registered/configurable.
- **Local proven:** tests, fixtures, synthetic CLI, Docker smoke, or render checks
  prove the userspace behavior.
- **Runtime proven:** a guarded Linux/Kubernetes run recorded the claimed output.
- **Partial:** a useful slice is proven, but nearby production behavior remains
  outside the claim.

Detailed evidence lives in [proof-report.md](proof-report.md). Non-claims live
in [boundaries.md](boundaries.md).
