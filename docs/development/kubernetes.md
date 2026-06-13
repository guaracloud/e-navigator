# Kubernetes Development

## Deployment Model

E-Navigator runs as one DaemonSet pod per node. Each pod runs one `e-navigator` process with statically registered internal modules.
The pod mounts the applied ConfigMap data at `/etc/e-navigator/e-navigator.toml`, and the process reads that file through `--config`.
Before applying the DaemonSet, build and publish or load an image that contains the `e-navigator` binary at `ghcr.io/victorbona/e-navigator:dev`, or edit the image reference for your development cluster.

```bash
docker build -f Containerfile -t ghcr.io/victorbona/e-navigator:dev .
```

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
