# Kubernetes Development

## Deployment Model

E-Navigator runs as one DaemonSet pod per node. Each pod runs one `e-navigator` process with statically registered internal modules.
The pod mounts the applied ConfigMap data at `/etc/e-navigator/e-navigator.toml`, and the process reads that file through `--config`.
Before applying the DaemonSet, build and publish or load an image that contains the `e-navigator` binary at `ghcr.io/victorbona/e-navigator:dev`, or edit the image reference for your development cluster.

```bash
docker build -f Containerfile -t ghcr.io/victorbona/e-navigator:dev .
```

The Phase 8 ConfigMap enables:

- bounded argv capture,
- procfs cgroup attribution,
- Kubernetes pod/node metadata attribution,
- Aya process exec and process exit visibility,
- Aya TCP connect/failure and fd-close duration visibility,
- bounded non-privileged node, process, and cgroup/container resource observations from host procfs, sysfs, and cgroup v2 files,
- bounded low-cardinality resource metric generation,
- bounded network metric generation for connection counters, failures, durations, active connections, traffic destinations, and protocol distribution,
- bounded DNS metric generation from DNS signals,
- bounded trace correlation from network observations, direct/upstream dependency-edge observations, and DNS observations,
- bounded request correlation from protocol request observations when such observations are supplied by synthetic fixtures or future bounded protocol sources,
- bounded profiling aggregation from explicit profile sample observations when such observations are supplied by synthetic fixtures or future bounded profiling sources,
- dependency edge generation from network observations,
- DNS domain dependency edge generation when DNS response signals are available,
- runtime security findings for shell-in-container, exact network-tool execution, external container egress, and Kubernetes API connections matched from configured endpoints or in-cluster Kubernetes service environment.

## Apply Manifests

```bash
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/rbac.yaml
kubectl apply -f deploy/kubernetes/configmap.yaml
kubectl apply -f deploy/kubernetes/daemonset.yaml
```

## Check Rollout

```bash
kubectl -n e-navigator-system rollout status daemonset/e-navigator
kubectl -n e-navigator-system get pods -o wide
```

Expected result: one ready `e-navigator` pod per schedulable node.
If pods enter `ImagePullBackOff`, verify the image reference and local cluster image-loading flow before debugging the agent.

## Generate Exec Events

```bash
kubectl run e-navigator-exec-smoke --rm -it --restart=Never --image=busybox:1.36 -- sh -c 'echo smoke'
```

## Generate Network Events

Run a workload that opens a TCP connection. For example, in a development cluster with outbound access:

```bash
kubectl run e-navigator-network-smoke --rm -it --restart=Never --image=busybox:1.36 -- sh -c 'wget -qO- https://example.com >/dev/null'
```

## Read Agent Logs

```bash
kubectl -n e-navigator-system logs -l app.kubernetes.io/name=e-navigator --tail=100
```

Expected exec result: JSON exec or process exit signals from `source.aya_exec` are visible in the DaemonSet logs.

Expected network result: JSON network connection signals from `source.aya_network` are visible, and network metric, dependency edge, or network runtime security finding signals appear when the observed connection matches generator inputs.

Expected resource result: JSON resource observation signals from `source.host_resource` and resource metric signals from `generator.resource_metrics` appear in the DaemonSet logs after the configured sampling interval. These signals require the configured read-only `/host/proc` and `/host/cgroup` mounts. Treat them as host-resource runtime proof only after running in a real Linux Kubernetes node environment.

Expected trace-foundation result: JSON `service_interaction_span_observation` signals may appear for observed network close or failure events, and `trace_service_path_observation` signals may appear when direct/upstream dependency-edge observations or DNS observations are available. Expected request-foundation result: JSON `request_span_observation` and `request_correlation_warning` signals appear only when `protocol_request_observation` signals are available. Expected profiling-foundation result: JSON `profiling_session_observation` signals appear only when `profile_sample_observation` signals are available. The current Aya sources do not emit live HTTP/gRPC protocol request observations or live eBPF/perf-event profile samples, so trace IDs, span IDs, routes, methods, status codes, retries, request errors, CPU flamegraphs, allocation profiles, lock profiles, and profile storage are not expected from real Kubernetes traffic unless a future source actually observes them.

## Privilege Boundary

Kubernetes manifest dry-run validation and Docker synthetic checks are non-privileged CI checks. They do not prove real Aya/eBPF load or tracepoint attachment.

The DaemonSet is configured for privileged eBPF testing with mounted host procfs/cgroup paths and one `e-navigator` container per pod. It does not join the host PID namespace. Treat the Kubernetes exec smoke test as passed only after running it in a real Linux cluster where the pod can access tracefs/eBPF facilities and the logs show real process exec or process exit signals from `source.aya_exec`. Treat the Kubernetes network smoke test as passed only when the logs show real network connection signals from `source.aya_network` after a workload opens a TCP connection.

The current network source attaches syscall tracepoints for TCP-oriented connect attempt/failure visibility and fd-close duration derived from connections observed by this agent. It does not implement DNS packet parsing, live HTTP or gRPC protocol parsing, runtime trace-context extraction from real payloads, full OTLP export, full distributed tracing, request-level tracing from real traffic, live eBPF/perf-event CPU profiling, memory allocation profiling, lock profiling, pprof export, OTLP profile export, profile storage, trace/profile correlation, capacity planning, cost attribution, continuous profiling backend behavior, Pyroscope replacement behavior, or UI storage. DNS metrics and DNS-derived service paths in Kubernetes require DNS signals; the included Aya sources do not yet produce real DNS query or response signals. Profiling sessions in Kubernetes require profile sample signals; the included Aya sources do not yet produce real profile sample signals.
