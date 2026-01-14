# Getting Started

## Prerequisites

- Kubernetes 1.19+
- An EdgeNEXUS ADC reachable from the controller Pod(s)

## Install with Helm

The Helm chart lives in `charts/edgenexus-ingress`.

```bash
helm install edgenexus-ingress ./charts/edgenexus-ingress
```

If you need to override values, create a `values.yaml` and pass `-f values.yaml`.

## Install with manifests

The `deployments/` folder contains example YAMLs and is useful for learning and quick manual installs.

## Verify

- Confirm the controller Pods are running: `kubectl get pods -n <namespace>`
- Confirm the controller is watching the expected namespaces/class
- Apply an example Ingress in `deployments/` and verify the ADC configuration updates

