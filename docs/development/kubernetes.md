# Kubernetes Development

## Deployment Model

E-Navigator runs as one DaemonSet pod per node. Each pod runs one `e-navigator` process with statically registered internal modules.
The pod mounts the applied ConfigMap data at `/etc/e-navigator/e-navigator.toml`, and the process reads that file through `--config`.
Before applying the DaemonSet, build and publish or load an image that contains the `e-navigator` binary at `ghcr.io/victorbona/e-navigator:dev`, or edit the image reference for your development cluster.

```bash
docker build -f Containerfile -t ghcr.io/victorbona/e-navigator:dev .
```

The Phase 2 ConfigMap enables:

- bounded argv capture,
- procfs cgroup attribution,
- Kubernetes pod/node metadata attribution,
- runtime security findings for shell-in-container and exact network-tool execution.

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

## Read Agent Logs

```bash
kubectl -n e-navigator-system logs -l app.kubernetes.io/name=e-navigator --tail=100
```

Expected result: JSON exec signals are visible in the DaemonSet logs.

## Privilege Boundary

Kubernetes manifest dry-run validation and Docker synthetic checks are non-privileged CI checks. They do not prove real Aya/eBPF load or tracepoint attachment.

The DaemonSet is configured for privileged eBPF testing with `hostPID: true` and one `e-navigator` container per pod. Treat the Kubernetes smoke test as passed only after running it in a real Linux cluster where the pod can access tracefs/eBPF facilities and the logs show real process exec or process exit signals from `source.aya_exec`.
