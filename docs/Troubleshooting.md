# Troubleshooting

## Controller starts but no configuration changes occur

- Confirm the `IngressClass` exists and matches `-ingress-class`
- Confirm watched namespaces match `-watch-namespace`
- Check controller logs for resource rejection/validation errors

## 502 from the default backend

If a Service has no endpoints, the controller can route traffic to a default backend that returns HTTP 502. Check that your Service selectors match running Pods and that Endpoints are being created.

## Leader election / status reporting issues

- Ensure RBAC allows access to `leases.coordination.k8s.io` in the controller namespace
- If running multiple replicas, keep leader election enabled so only one replica updates status

## Where to look

- Controller logs: `kubectl logs <pod>`
- Metrics (if enabled): Prometheus scrape target on the configured port
- Chart templates and values: `charts/edgenexus-ingress/`

