# Gateway API (Experimental)

This repository includes an experimental Gateway API controller that can be enabled with the `-enable-gateway-api` flag.

## Scope

- Watches `Gateway`, `GatewayClass`, and `HTTPRoute`
- Converts supported Gateway API constructs into EdgeNEXUS configuration via the existing configurator pipeline

## Limitations

- The implementation is intentionally minimal and does not yet cover the full Gateway API attachment and hostname matching specifications.
- Status updates for Gateway API resources are currently placeholders.

## Enable

Run the controller with:

```bash
edgenexus-ingress -enable-gateway-api
```

