# Optimization Campaign Erratum

Date discovered: 2026-07-22

Status: comparative CPU, RSS, allocation, throughput, and latency claims in
this directory are invalidated.

The 33-run campaign correctly isolated the standing E-Navigator deployment,
but its workload opened one process-wide Redis backend connection before each
collector arm attached. E-Navigator observes the server node. The long-lived
proxy-to-Redis socket therefore predated eBPF attachment and none of the 9,600
successful Redis operations in each Redis, PostgreSQL, or profile arm reached
the protocol source.

The aggregate signal gate did not distinguish protocol families. It accepted
the Redis arms because the 6,000 HTTP and 4,800 gRPC observations made the
aggregate counter nonzero. All three E-Navigator Redis arms sent exactly
10,800 source signals, while the cumulative protocol-operation floor was
20,400. The PostgreSQL arms sent 22,874, 22,845, and 22,874 source signals
against a 23,400 floor. The profile arms sent 23,151, 23,323, and 23,008
against the same protocol floor, even before considering profile samples.

The immutable `report.md`, `summary.json`, and `SHA256SUMS` remain preserved
as historical provenance. They must not be cited as valid comparative proof.
The corrected workload creates a Redis backend connection per load connection,
after collector attachment, and the analyzer now rejects every E-Navigator arm
whose cumulative protocol signals fall below successful offered operations.

The replacement campaign is tracked in
[`../optimization-20260722-campaign2/report.md`](../optimization-20260722-campaign2/report.md).
