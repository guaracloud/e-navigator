# Kubernetes Development

## Deployment Model

E-Navigator runs as one DaemonSet pod per node. Each pod runs one `e-navigator` process with statically registered internal modules.
The pod mounts the applied ConfigMap data at `/etc/e-navigator/e-navigator.toml`, and the process reads that file through `--config`.
Before applying the DaemonSet, build and publish or load an image that contains the `e-navigator` binary at `ghcr.io/victorbona/e-navigator:dev`, or edit the image reference for your development cluster.

```bash
docker build -f Containerfile -t ghcr.io/victorbona/e-navigator:dev .
```

The Phase 4 ConfigMap enables:

- bounded argv capture,
- procfs cgroup attribution,
- Kubernetes pod/node metadata attribution,
- Aya process exec and process exit visibility,
- Aya TCP connect/failure and fd-close duration visibility,
- bounded network metric generation for connection counters, failures, durations, active connections, traffic destinations, and protocol distribution,
- bounded DNS metric generation from DNS signals,
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

## Privilege Boundary

Kubernetes manifest dry-run validation and Docker synthetic checks are non-privileged CI checks. They do not prove real Aya/eBPF load or tracepoint attachment.

The DaemonSet is configured for privileged eBPF testing with `hostPID: true` and one `e-navigator` container per pod. Treat the Kubernetes exec smoke test as passed only after running it in a real Linux cluster where the pod can access tracefs/eBPF facilities and the logs show real process exec or process exit signals from `source.aya_exec`. Treat the Kubernetes network smoke test as passed only when the logs show real network connection signals from `source.aya_network` after a workload opens a TCP connection.

The current network source attaches syscall tracepoints for TCP-oriented connect attempt/failure visibility and fd-close duration derived from connections observed by this agent. It does not implement DNS packet parsing, full OTLP export, or full distributed tracing. Phase 4 DNS metrics in Kubernetes require DNS signals; the included Aya sources do not yet produce real DNS query or response signals.
