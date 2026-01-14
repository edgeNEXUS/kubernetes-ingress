package configs

import (
	"fmt"
	"strings"

	"github.com/edgeNEXUS/kubernetes-ingress/internal/configs/version1"
	api_v1 "k8s.io/api/core/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

// GatewayEx holds a Gateway and its related resources.
type GatewayEx struct {
	Gateway      *gatewayv1beta1.Gateway
	HTTPRoutes   []*gatewayv1beta1.HTTPRoute
	Services     map[string]*api_v1.Service
	Endpoints    map[string][]string // ServiceName -> Endpoints
	Valid        bool
	ErrorMessage string
}

func (g *GatewayEx) String() string {
	if g.Gateway == nil {
		return "GatewayEx has no Gateway"
	}
	return fmt.Sprintf("%v/%v", g.Gateway.Namespace, g.Gateway.Name)
}

// GenerateEdgeConfigForGateway converts a GatewayEx into IngressEdgeConfig.
func GenerateEdgeConfigForGateway(gEx *GatewayEx, cfgParams *ConfigParams) (version1.IngressEdgeConfig, Warnings) {
	warnings := newWarnings()
	upstreams := make(map[string]version1.Upstream)
	var servers []version1.Server

	// Create a Server for each Listener
	for _, listener := range gEx.Gateway.Spec.Listeners {
		serverName := string(*listener.Hostname)
		if serverName == "" {
			serverName = "*" // Default catch-all
		}

		server := version1.Server{
			Name:         serverName,
			ServerTokens: cfgParams.ServerTokens,
			HTTP2:        cfgParams.HTTP2,
			// Add other default params...
			StatusZone: serverName,
		}

		// Configure Ports
		port := int(listener.Port)
		if listener.Protocol == gatewayv1beta1.HTTPSProtocolType || listener.Protocol == gatewayv1beta1.TLSProtocolType {
			server.SSL = true
			server.SSLPorts = []int{port}
			// TODO: Handle TLS config from Listener.TLS
		} else {
			server.Ports = []int{port}
		}

		var locations []version1.Location

		// Process HTTPRoutes attached to this listener
		for _, route := range gEx.HTTPRoutes {
			// Basic filtering: check if route matches listener hostnames
			// This is a simplified check. Real implementation needs full hostname matching logic.
			if !routeMatchesListener(route, listener) {
				continue
			}

			for _, rule := range route.Spec.Rules {
				// Handle BackendRefs
				var upsName string
				if len(rule.BackendRefs) > 0 {
					ref := rule.BackendRefs[0]
					svcName := string(ref.Name)
					svcPort := int(*ref.Port)
					upsName = fmt.Sprintf("%s-%s-%d", route.Namespace, svcName, svcPort)

					// Create Upstream if not exists
					if _, exists := upstreams[upsName]; !exists {
						upstreams[upsName] = createUpstreamForGateway(svcName, svcPort, gEx.Endpoints[svcName], cfgParams)
					}
				}

				// Handle Matches (Paths)
				paths := []string{"/"}
				if len(rule.Matches) > 0 {
					paths = []string{}
					for _, match := range rule.Matches {
						if match.Path != nil && match.Path.Type != nil && *match.Path.Type == gatewayv1beta1.PathMatchPathPrefix {
							paths = append(paths, *match.Path.Value)
						} else if match.Path != nil && *match.Path.Type == gatewayv1beta1.PathMatchExact {
							paths = append(paths, "= "+*match.Path.Value)
						} else {
							paths = append(paths, "/")
						}
					}
				}

				for _, path := range paths {
					loc := version1.Location{
						Path:                path,
						Upstream:            upstreams[upsName],
						ProxyConnectTimeout: cfgParams.ProxyConnectTimeout,
						ProxyReadTimeout:    cfgParams.ProxyReadTimeout,
						ProxySendTimeout:    cfgParams.ProxySendTimeout,
						ClientMaxBodySize:   cfgParams.ClientMaxBodySize,
						// Add more params
					}
					locations = append(locations, loc)
				}
			}
		}

		server.Locations = locations
		servers = append(servers, server)
	}

	return version1.IngressEdgeConfig{
		Upstreams: upstreamMapToSlice(upstreams),
		Servers:   servers,
		Keepalive: fmt.Sprint(cfgParams.Keepalive),
		Ingress: version1.Ingress{ // Reuse Ingress struct for metadata
			Name:      gEx.Gateway.Name,
			Namespace: gEx.Gateway.Namespace,
		},
	}, warnings
}

func createUpstreamForGateway(svcName string, svcPort int, endpoints []string, cfg *ConfigParams) version1.Upstream {
	ups := version1.NewUpstreamWithDefaultServer(fmt.Sprintf("gw-%s-%d", svcName, svcPort))
	ups.Name = fmt.Sprintf("%s-%d", svcName, svcPort) // Simplified name

	if len(endpoints) > 0 {
		var upsServers []version1.UpstreamServer
		for _, endp := range endpoints {
			parts := strings.Split(endp, ":")
			if len(parts) == 2 {
				upsServers = append(upsServers, version1.UpstreamServer{
					Address:     parts[0],
					Port:        parts[1],
					MaxFails:    cfg.MaxFails,
					MaxConns:    cfg.MaxConns,
					FailTimeout: cfg.FailTimeout,
					SlowStart:   cfg.SlowStart,
				})
			}
		}
		ups.UpstreamServers = upsServers
	}
	return ups
}

func routeMatchesListener(route *gatewayv1beta1.HTTPRoute, listener gatewayv1beta1.Listener) bool {
	// Simplified matching logic
	// In production, implement full Gateway API matching spec (Section "Hostname Matching")

	// If listener has no hostname, it matches all (unless route specifies hostnames)
	if listener.Hostname == nil || *listener.Hostname == "" {
		return true
	}

	// If route has no hostnames, it matches if listener allows
	if len(route.Spec.Hostnames) == 0 {
		return true
	}

	listenerHost := string(*listener.Hostname)
	for _, routeHost := range route.Spec.Hostnames {
		if string(routeHost) == listenerHost {
			return true
		}
	}
	return false
}
