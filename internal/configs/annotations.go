package configs

import (
	"github.com/golang/glog"
)

// JWTKeyAnnotation is the annotation where the Secret with a JWK is specified.
const JWTKeyAnnotation = "edgenexus.io/jwt-key"

// AppProtectPolicyAnnotation is where the Edgenexus App Protect policy is specified
const AppProtectPolicyAnnotation = "appprotect.f5.com/app-protect-policy"

// AppProtectLogConfAnnotation is where the Edgenexus AppProtect Log Configuration is specified
const AppProtectLogConfAnnotation = "appprotect.f5.com/app-protect-security-log"

// AppProtectLogConfDstAnnotation is where the Edgenexus AppProtect Log Configuration is specified
const AppProtectLogConfDstAnnotation = "appprotect.f5.com/app-protect-security-log-destination"

// edgeMeshInternalRoute specifies if the ingress resource is an internal route.
const edgeMeshInternalRouteAnnotation = "nsm.edgenexus.io/internal-route"

var masterBlacklist = map[string]bool{
	"edgenexus.io/rewrites":                      true,
	"edgenexus.io/ssl-services":                  true,
	"edgenexus.io/grpc-services":                 true,
	"edgenexus.io/websocket-services":            true,
	"edgenexus.io/sticky-cookie-services":        true,
	"edgenexus.io/health-checks":                 true,
	"edgenexus.io/health-checks-mandatory":       true,
	"edgenexus.io/health-checks-mandatory-queue": true,
}

var minionBlacklist = map[string]bool{
	"edgenexus.io/proxy-hide-headers":                      true,
	"edgenexus.io/proxy-pass-headers":                      true,
	"edgenexus.io/redirect-to-https":                       true,
	"ingress.kubernetes.io/ssl-redirect":                true,
	"edgenexus.io/hsts":                                    true,
	"edgenexus.io/hsts-max-age":                            true,
	"edgenexus.io/hsts-include-subdomains":                 true,
	"edgenexus.io/server-tokens":                           true,
	"edgenexus.io/listen-ports":                            true,
	"edgenexus.io/listen-ports-ssl":                        true,
	"edgenexus.io/server-snippets":                         true,
	"appprotect.f5.com/app_protect_enable":              true,
	"appprotect.f5.com/app_protect_policy":              true,
	"appprotect.f5.com/app_protect_security_log_enable": true,
	"appprotect.f5.com/app_protect_security_log":        true,
}

var minionInheritanceList = map[string]bool{
	"edgenexus.io/proxy-connect-timeout":    true,
	"edgenexus.io/proxy-read-timeout":       true,
	"edgenexus.io/proxy-send-timeout":       true,
	"edgenexus.io/client-max-body-size":     true,
	"edgenexus.io/proxy-buffering":          true,
	"edgenexus.io/proxy-buffers":            true,
	"edgenexus.io/proxy-buffer-size":        true,
	"edgenexus.io/proxy-max-temp-file-size": true,
	"edgenexus.io/upstream-zone-size":       true,
	"edgenexus.io/location-snippets":        true,
	"edgenexus.io/lb-method":                true,
	"edgenexus.io/keepalive":                true,
	"edgenexus.io/max-fails":                true,
	"edgenexus.io/max-conns":                true,
	"edgenexus.io/fail-timeout":             true,
}

func parseAnnotations(ingEx *IngressEx, baseCfgParams *ConfigParams, isPlus bool, hasAppProtect bool, enableInternalRoutes bool) ConfigParams {
	cfgParams := *baseCfgParams

	if lbMethod, exists := ingEx.Ingress.Annotations["edgenexus.io/lb-method"]; exists {
		if isPlus {
			if parsedMethod, err := ParseLBMethodForPlus(lbMethod); err != nil {
				glog.Errorf("Ingress %s/%s: Invalid value for the edgenexus.io/lb-method: got %q: %v", ingEx.Ingress.GetNamespace(), ingEx.Ingress.GetName(), lbMethod, err)
			} else {
				cfgParams.LBMethod = parsedMethod
			}
		} else {
			if parsedMethod, err := ParseLBMethod(lbMethod); err != nil {
				glog.Errorf("Ingress %s/%s: Invalid value for the edgenexus.io/lb-method: got %q: %v", ingEx.Ingress.GetNamespace(), ingEx.Ingress.GetName(), lbMethod, err)
			} else {
				cfgParams.LBMethod = parsedMethod
			}
		}
	}

	if healthCheckEnabled, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "edgenexus.io/health-checks", ingEx.Ingress); exists {
		if err != nil {
			glog.Error(err)
		}
		if isPlus {
			cfgParams.HealthCheckEnabled = healthCheckEnabled
		} else {
			glog.Warning("Annotation 'edgenexus.io/health-checks' requires 'Edgenexus +'")
		}
	}

	if cfgParams.HealthCheckEnabled {
		if healthCheckMandatory, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "edgenexus.io/health-checks-mandatory", ingEx.Ingress); exists {
			if err != nil {
				glog.Error(err)
			}
			cfgParams.HealthCheckMandatory = healthCheckMandatory
		}
	}

	if cfgParams.HealthCheckMandatory {
		if healthCheckQueue, exists, err := GetMapKeyAsInt64(ingEx.Ingress.Annotations, "edgenexus.io/health-checks-mandatory-queue", ingEx.Ingress); exists {
			if err != nil {
				glog.Error(err)
			}
			cfgParams.HealthCheckMandatoryQueue = healthCheckQueue
		}
	}

	if slowStart, exists := ingEx.Ingress.Annotations["edgenexus.io/slow-start"]; exists {
		if parsedSlowStart, err := ParseTime(slowStart); err != nil {
			glog.Errorf("Ingress %s/%s: Invalid value edgenexus.io/slow-start: got %q: %v", ingEx.Ingress.GetNamespace(), ingEx.Ingress.GetName(), slowStart, err)
		} else {
			if isPlus {
				cfgParams.SlowStart = parsedSlowStart
			} else {
				glog.Warning("Annotation 'edgenexus.io/slow-start' requires 'Edgenexus +'")
			}
		}
	}

	if serverTokens, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "edgenexus.io/server-tokens", ingEx.Ingress); exists {
		if err != nil {
			if isPlus {
				cfgParams.ServerTokens = ingEx.Ingress.Annotations["edgenexus.io/server-tokens"]
			} else {
				glog.Error(err)
			}
		} else {
			cfgParams.ServerTokens = "off"
			if serverTokens {
				cfgParams.ServerTokens = "on"
			}
		}
	}

	if serverSnippets, exists, err := GetMapKeyAsStringSlice(ingEx.Ingress.Annotations, "edgenexus.io/server-snippets", ingEx.Ingress, "\n"); exists {
		if err != nil {
			glog.Error(err)
		} else {
			cfgParams.ServerSnippets = serverSnippets
		}
	}

	if locationSnippets, exists, err := GetMapKeyAsStringSlice(ingEx.Ingress.Annotations, "edgenexus.io/location-snippets", ingEx.Ingress, "\n"); exists {
		if err != nil {
			glog.Error(err)
		} else {
			cfgParams.LocationSnippets = locationSnippets
		}
	}

	if proxyConnectTimeout, exists := ingEx.Ingress.Annotations["edgenexus.io/proxy-connect-timeout"]; exists {
		if parsedProxyConnectTimeout, err := ParseTime(proxyConnectTimeout); err != nil {
			glog.Errorf("Ingress %s/%s: Invalid value edgenexus.io/proxy-connect-timeout: got %q: %v", ingEx.Ingress.GetNamespace(), ingEx.Ingress.GetName(), proxyConnectTimeout, err)
		} else {
			cfgParams.ProxyConnectTimeout = parsedProxyConnectTimeout
		}
	}

	if proxyReadTimeout, exists := ingEx.Ingress.Annotations["edgenexus.io/proxy-read-timeout"]; exists {
		if parsedProxyReadTimeout, err := ParseTime(proxyReadTimeout); err != nil {
			glog.Errorf("Ingress %s/%s: Invalid value edgenexus.io/proxy-read-timeout: got %q: %v", ingEx.Ingress.GetNamespace(), ingEx.Ingress.GetName(), proxyReadTimeout, err)
		} else {
			cfgParams.ProxyReadTimeout = parsedProxyReadTimeout
		}
	}

	if proxySendTimeout, exists := ingEx.Ingress.Annotations["edgenexus.io/proxy-send-timeout"]; exists {
		if parsedProxySendTimeout, err := ParseTime(proxySendTimeout); err != nil {
			glog.Errorf("Ingress %s/%s: Invalid value edgenexus.io/proxy-send-timeout: got %q: %v", ingEx.Ingress.GetNamespace(), ingEx.Ingress.GetName(), proxySendTimeout, err)
		} else {
			cfgParams.ProxySendTimeout = parsedProxySendTimeout
		}
	}

	if proxyHideHeaders, exists, err := GetMapKeyAsStringSlice(ingEx.Ingress.Annotations, "edgenexus.io/proxy-hide-headers", ingEx.Ingress, ","); exists {
		if err != nil {
			glog.Error(err)
		} else {
			cfgParams.ProxyHideHeaders = proxyHideHeaders
		}
	}

	if proxyPassHeaders, exists, err := GetMapKeyAsStringSlice(ingEx.Ingress.Annotations, "edgenexus.io/proxy-pass-headers", ingEx.Ingress, ","); exists {
		if err != nil {
			glog.Error(err)
		} else {
			cfgParams.ProxyPassHeaders = proxyPassHeaders
		}
	}

	if clientMaxBodySize, exists := ingEx.Ingress.Annotations["edgenexus.io/client-max-body-size"]; exists {
		cfgParams.ClientMaxBodySize = clientMaxBodySize
	}

	if redirectToHTTPS, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "edgenexus.io/redirect-to-https", ingEx.Ingress); exists {
		if err != nil {
			glog.Error(err)
		} else {
			cfgParams.RedirectToHTTPS = redirectToHTTPS
		}
	}

	if sslRedirect, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "ingress.kubernetes.io/ssl-redirect", ingEx.Ingress); exists {
		if err != nil {
			glog.Error(err)
		} else {
			cfgParams.SSLRedirect = sslRedirect
		}
	}

	if proxyBuffering, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "edgenexus.io/proxy-buffering", ingEx.Ingress); exists {
		if err != nil {
			glog.Error(err)
		} else {
			cfgParams.ProxyBuffering = proxyBuffering
		}
	}

	if hsts, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "edgenexus.io/hsts", ingEx.Ingress); exists {
		if err != nil {
			glog.Error(err)
		} else {
			parsingErrors := false

			hstsMaxAge, existsMA, err := GetMapKeyAsInt64(ingEx.Ingress.Annotations, "edgenexus.io/hsts-max-age", ingEx.Ingress)
			if existsMA && err != nil {
				glog.Error(err)
				parsingErrors = true
			}
			hstsIncludeSubdomains, existsIS, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "edgenexus.io/hsts-include-subdomains", ingEx.Ingress)
			if existsIS && err != nil {
				glog.Error(err)
				parsingErrors = true
			}
			hstsBehindProxy, existsBP, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "edgenexus.io/hsts-behind-proxy", ingEx.Ingress)
			if existsBP && err != nil {
				glog.Error(err)
				parsingErrors = true
			}

			if parsingErrors {
				glog.Errorf("Ingress %s/%s: There are configuration issues with hsts annotations, skipping annotions for all hsts settings", ingEx.Ingress.GetNamespace(), ingEx.Ingress.GetName())
			} else {
				cfgParams.HSTS = hsts
				if existsMA {
					cfgParams.HSTSMaxAge = hstsMaxAge
				}
				if existsIS {
					cfgParams.HSTSIncludeSubdomains = hstsIncludeSubdomains
				}
				if existsBP {
					cfgParams.HSTSBehindProxy = hstsBehindProxy
				}
			}
		}
	}

	if proxyBuffers, exists := ingEx.Ingress.Annotations["edgenexus.io/proxy-buffers"]; exists {
		cfgParams.ProxyBuffers = proxyBuffers
	}

	if proxyBufferSize, exists := ingEx.Ingress.Annotations["edgenexus.io/proxy-buffer-size"]; exists {
		cfgParams.ProxyBufferSize = proxyBufferSize
	}

	if upstreamZoneSize, exists := ingEx.Ingress.Annotations["edgenexus.io/upstream-zone-size"]; exists {
		cfgParams.UpstreamZoneSize = upstreamZoneSize
	}

	if proxyMaxTempFileSize, exists := ingEx.Ingress.Annotations["edgenexus.io/proxy-max-temp-file-size"]; exists {
		cfgParams.ProxyMaxTempFileSize = proxyMaxTempFileSize
	}

	if isPlus {
		if jwtRealm, exists := ingEx.Ingress.Annotations["edgenexus.io/jwt-realm"]; exists {
			cfgParams.JWTRealm = jwtRealm
		}
		if jwtKey, exists := ingEx.Ingress.Annotations[JWTKeyAnnotation]; exists {
			cfgParams.JWTKey = jwtKey
		}
		if jwtToken, exists := ingEx.Ingress.Annotations["edgenexus.io/jwt-token"]; exists {
			cfgParams.JWTToken = jwtToken
		}
		if jwtLoginURL, exists := ingEx.Ingress.Annotations["edgenexus.io/jwt-login-url"]; exists {
			cfgParams.JWTLoginURL = jwtLoginURL
		}
	}

	if values, exists := ingEx.Ingress.Annotations["edgenexus.io/listen-ports"]; exists {
		ports, err := ParsePortList(values)
		if err != nil {
			glog.Errorf("In %v edgenexus.io/listen-ports contains invalid declaration: %v, ignoring", ingEx.Ingress.Name, err)
		}
		if len(ports) > 0 {
			cfgParams.Ports = ports
		}
	}

	if values, exists := ingEx.Ingress.Annotations["edgenexus.io/listen-ports-ssl"]; exists {
		sslPorts, err := ParsePortList(values)
		if err != nil {
			glog.Errorf("In %v edgenexus.io/listen-ports-ssl contains invalid declaration: %v, ignoring", ingEx.Ingress.Name, err)
		}
		if len(sslPorts) > 0 {
			cfgParams.SSLPorts = sslPorts
		}
	}

	if keepalive, exists, err := GetMapKeyAsInt(ingEx.Ingress.Annotations, "edgenexus.io/keepalive", ingEx.Ingress); exists {
		if err != nil {
			glog.Error(err)
		} else {
			cfgParams.Keepalive = keepalive
		}
	}

	if maxFails, exists, err := GetMapKeyAsInt(ingEx.Ingress.Annotations, "edgenexus.io/max-fails", ingEx.Ingress); exists {
		if err != nil {
			glog.Error(err)
		} else {
			cfgParams.MaxFails = maxFails
		}
	}

	if maxConns, exists, err := GetMapKeyAsInt(ingEx.Ingress.Annotations, "edgenexus.io/max-conns", ingEx.Ingress); exists {
		if err != nil {
			glog.Error(err)
		} else {
			cfgParams.MaxConns = maxConns
		}
	}

	if failTimeout, exists := ingEx.Ingress.Annotations["edgenexus.io/fail-timeout"]; exists {
		if parsedFailTimeout, err := ParseTime(failTimeout); err != nil {
			glog.Errorf("Ingress %s/%s: Invalid value edgenexus.io/fail-timeout: got %q: %v", ingEx.Ingress.GetNamespace(), ingEx.Ingress.GetName(), failTimeout, err)
		} else {
			cfgParams.FailTimeout = parsedFailTimeout
		}
	}

	if hasAppProtect {
		if appProtectEnable, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "appprotect.f5.com/app-protect-enable", ingEx.Ingress); exists {
			if err != nil {
				glog.Error(err)
			} else {
				if appProtectEnable {
					cfgParams.AppProtectEnable = "on"
				} else {
					cfgParams.AppProtectEnable = "off"
				}
			}
		}

		if appProtectLogEnable, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, "appprotect.f5.com/app-protect-security-log-enable", ingEx.Ingress); exists {
			if err != nil {
				glog.Error(err)
			} else {
				if appProtectLogEnable {
					cfgParams.AppProtectLogEnable = "on"
				} else {
					cfgParams.AppProtectLogEnable = "off"
				}
			}
		}

	}
	if enableInternalRoutes {
		if spiffeServerCerts, exists, err := GetMapKeyAsBool(ingEx.Ingress.Annotations, edgeMeshInternalRouteAnnotation, ingEx.Ingress); exists {
			if err != nil {
				glog.Error(err)
			} else {
				cfgParams.SpiffeServerCerts = spiffeServerCerts
			}
		}
	}
	return cfgParams
}

func getWebsocketServices(ingEx *IngressEx) map[string]bool {
	if value, exists := ingEx.Ingress.Annotations["edgenexus.io/websocket-services"]; exists {
		return ParseServiceList(value)
	}
	return nil
}

func getRewrites(ingEx *IngressEx) map[string]string {
	if value, exists := ingEx.Ingress.Annotations["edgenexus.io/rewrites"]; exists {
		rewrites, err := ParseRewriteList(value)
		if err != nil {
			glog.Error(err)
		}
		return rewrites
	}
	return nil
}

func getSSLServices(ingEx *IngressEx) map[string]bool {
	if value, exists := ingEx.Ingress.Annotations["edgenexus.io/ssl-services"]; exists {
		return ParseServiceList(value)
	}
	return nil
}

func getGrpcServices(ingEx *IngressEx) map[string]bool {
	if value, exists := ingEx.Ingress.Annotations["edgenexus.io/grpc-services"]; exists {
		return ParseServiceList(value)
	}
	return nil
}

func getSessionPersistenceServices(ingEx *IngressEx) map[string]string {
	if value, exists := ingEx.Ingress.Annotations["edgenexus.io/sticky-cookie-services"]; exists {
		services, err := ParseStickyServiceList(value)
		if err != nil {
			glog.Error(err)
		}
		return services
	}
	return nil
}

func filterMasterAnnotations(annotations map[string]string) []string {
	var removedAnnotations []string

	for key := range annotations {
		if _, notAllowed := masterBlacklist[key]; notAllowed {
			removedAnnotations = append(removedAnnotations, key)
			delete(annotations, key)
		}
	}

	return removedAnnotations
}

func filterMinionAnnotations(annotations map[string]string) []string {
	var removedAnnotations []string

	for key := range annotations {
		if _, notAllowed := minionBlacklist[key]; notAllowed {
			removedAnnotations = append(removedAnnotations, key)
			delete(annotations, key)
		}
	}

	return removedAnnotations
}

func mergeMasterAnnotationsIntoMinion(minionAnnotations map[string]string, masterAnnotations map[string]string) {
	for key, val := range masterAnnotations {
		if _, exists := minionAnnotations[key]; !exists {
			if _, allowed := minionInheritanceList[key]; allowed {
				minionAnnotations[key] = val
			}
		}
	}
}