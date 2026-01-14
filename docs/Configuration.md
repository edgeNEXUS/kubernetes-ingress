# Configuration

The controller is configured primarily via CLI flags and (optionally) a ConfigMap referenced by `-edge-configmaps`.

## Common flags

- `-watch-namespace`: Namespace to watch (default: all)
- `-ingress-class`: IngressClass name that this controller should process
- `-edge-configmaps`: `<namespace>/<name>` config map for controller tuning and templating
- `-report-ingress-status`: Enable status updates on watched resources
- `-external-service`: LoadBalancer Service name used to publish status addresses
- `-enable-leader-election`: Enable leader election for status reporting (recommended for HA)
- `-enable-prometheus-metrics`: Expose Prometheus metrics (optional)

## EdgeNEXUS ADC connectivity

The controller connects to the EdgeNEXUS ADC using flags:

- `-edge-balancer-ip`
- `-edge-balancer-user`
- `-edge-balancer-pass`
- `-edge-external-ip`

Make sure to override defaults in production.

## ConfigMap

When `-edge-configmaps=<namespace>/<name>` is set, the controller loads configuration parameters from that ConfigMap at startup (and in some cases watches for changes depending on deployment settings).

See `internal/configs/configmaps.go` and `internal/configs/config_params.go` for available keys and their effects.

