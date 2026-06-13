# Kubernetes Development

## Deployment Model

E-Navigator runs as one DaemonSet pod per node. Each pod runs one `e-navigator` process with statically registered internal modules.

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

## Generate Exec Events

```bash
kubectl run e-navigator-exec-smoke --rm -it --restart=Never --image=busybox:1.36 -- sh -c 'echo smoke'
```

## Read Agent Logs

```bash
kubectl -n e-navigator-system logs -l app.kubernetes.io/name=e-navigator --tail=100
```

Expected result: JSON exec signals are visible in the DaemonSet logs.
