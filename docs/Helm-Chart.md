# Helm Chart

The Helm chart is located at `charts/edgenexus-ingress`.

## Install

```bash
helm install edgenexus-ingress ./charts/edgenexus-ingress
```

## Upgrade

```bash
helm upgrade edgenexus-ingress ./charts/edgenexus-ingress
```

## Notes

- The chart includes CRDs under `charts/edgenexus-ingress/crds/` which Helm installs before templates.
- RBAC and `IngressClass` resources are templated under `charts/edgenexus-ingress/templates/`.

