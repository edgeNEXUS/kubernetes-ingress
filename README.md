<p align="center">
  <img src="https://github.com/edgeNEXUS.png" alt="EdgeNEXUS" width="240" />
</p>

# EdgeNEXUS Kubernetes Ingress Controller

This repository contains the EdgeNEXUS Kubernetes Ingress Controller, which watches Kubernetes resources (Ingress and EdgeNEXUS CRDs) and configures an EdgeNEXUS ADC via the bundled manager.

- **Wiki**: `https://github.com/edgeNEXUS/kubernetes-ingress/wiki`
- **Helm chart**: `charts/edgenexus-ingress`
- **Example manifests**: `deployments/`
- **In-repo docs**: `docs/`

## What it supports

- **Kubernetes Ingress (networking.k8s.io/v1)** with an `IngressClass` controller name of `k8s.edgenexus.io/ingress-controller`
- **EdgeNEXUS CRDs** (when enabled): `VirtualServer`, `VirtualServerRoute`, `TransportServer`, `Policy`, `GlobalConfiguration`
- **TLS termination** via Kubernetes Secrets (including a wildcard TLS secret option)
- **Leader election** (Lease-based) for status reporting
- **Prometheus metrics** (optional)
- **Kubernetes Gateway API** (experimental; behind a feature flag)

## Compatibility

- **Kubernetes**: 1.19+ (the controller enforces a minimum at startup)
- **Go**: this repo currently targets Go 1.16 in `go.mod` (newer Go toolchains can still build it)

## Install

### Helm (recommended)

```bash
helm install edgenexus-ingress ./charts/edgenexus-ingress
```

### Manifests

You can also apply the example YAMLs in `deployments/`. These are useful for learning, but Helm is recommended for repeatable installs.

## Configuration

Most runtime options are CLI flags. Common ones include:

- **Watching a namespace**: `-watch-namespace=<ns>` (default is all namespaces)
- **Ingress class**: `-ingress-class=edgenexus`
- **Controller ConfigMap**: `-edge-configmaps=<namespace>/<name>`
- **Status reporting**: `-report-ingress-status` plus `-external-service` or `-ingresslink`
- **Metrics**: `-enable-prometheus-metrics`
- **Gateway API**: `-enable-gateway-api` (experimental)

For EdgeNEXUS ADC connectivity and runtime behavior, see `internal/configs/` and the chart values in `charts/edgenexus-ingress/`.

## Useful scripts

- **Open a shell in the ingress container**: `scripts/ingress-bash.sh`
- **Collect diagnostics/logs**: `scripts/ingress-diag.sh`

## Development

Build the image (CentOS 8 based):

```bash
make centos8-image
```

Build inside a container:

```bash
make centos8-image TARGET=container
```

Push to a registry (uses `PREFIX`/`TAG`):

```bash
make push
```

## Troubleshooting

- **Why do I see an upstream of `127.0.0.1:8181`?** This is the default backend that returns HTTP 502 and is used when services have no endpoints.

## Roadmap

This project is actively evolving. Near-term goals include improving configuration reconciliation performance and continuing to harden Gateway API support.
