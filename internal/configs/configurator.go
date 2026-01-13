package configs

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/edgeNEXUS/kubernetes-ingress/internal/k8s/secrets"
	"github.com/spiffe/go-spiffe/workload"

	"github.com/edgeNEXUS/kubernetes-ingress/internal/configs/version2"
	conf_v1alpha1 "github.com/edgeNEXUS/kubernetes-ingress/pkg/apis/configuration/v1alpha1"

	"github.com/golang/glog"
	api_v1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/edgeNEXUS/kubernetes-ingress/internal/configs/version1"
	"github.com/edgeNEXUS/kubernetes-ingress/internal/edge"
	conf_v1 "github.com/edgeNEXUS/kubernetes-ingress/pkg/apis/configuration/v1"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	latCollector "github.com/edgeNEXUS/kubernetes-ingress/internal/metrics/collectors"
)

const (
	pemFileNameForWildcardTLSSecret = "/etc/edgenexus-manager/secrets/wildcard" // #nosec G101
	appProtectPolicyFolder          = "/etc/edgenexus-manager/waf/nac-policies/"
	appProtectLogConfFolder         = "/etc/edgenexus-manager/waf/nac-logconfs/"
	appProtectUserSigFolder         = "/etc/edgenexus-manager/waf/nac-usersigs/"
	appProtectUserSigIndex          = "/etc/edgenexus-manager/waf/nac-usersigs/index.conf"
)

// DefaultServerSecretPath is the full path to the Secret with a TLS cert and a key for the default server. #nosec G101
const DefaultServerSecretPath = "/etc/edgenexus-manager/secrets/default"

// DefaultServerSecretName is the filename of the Secret with a TLS cert and a key for the default server.
const DefaultServerSecretName = "default"

// WildcardSecretName is the filename of the Secret with a TLS cert and a key for the ingress resources with TLS termination enabled but not secret defined.
const WildcardSecretName = "wildcard"

// JWTKeyKey is the key of the data field of a Secret where the JWK must be stored.
const JWTKeyKey = "jwk"

// CAKey is the key of the data field of a Secret where the cert must be stored.
const CAKey = "ca.crt"

// ClientSecretKey is the key of the data field of a Secret where the OIDC client secret must be stored.
const ClientSecretKey = "client-secret"

// SPIFFE filenames and modes
const (
	spiffeCertFileName   = "spiffe_cert.pem"
	spiffeKeyFileName    = "spiffe_key.pem"
	spiffeBundleFileName = "spiffe_rootca.pem"
	spiffeCertsFileMode  = os.FileMode(0o644)
	spiffeKeyFileMode    = os.FileMode(0o600)
)

// ExtendedResources holds all extended configuration resources, for which Configurator configures Edgenexus.
type ExtendedResources struct {
	IngressExes         []*IngressEx
	MergeableIngresses  []*MergeableIngresses
	VirtualServerExes   []*VirtualServerEx
	TransportServerExes []*TransportServerEx
}

type tlsPassthroughPair struct {
	Host       string
	UnixSocket string
}

// metricLabelsIndex keeps the relations between Ingress Controller resources and Edgenexus configuration.
// Used to be able to add Prometheus Metrics variable labels grouped by resource key.
type metricLabelsIndex struct {
	ingressUpstreams             map[string][]string
	virtualServerUpstreams       map[string][]string
	transportServerUpstreams     map[string][]string
	ingressServerZones           map[string][]string
	virtualServerServerZones     map[string][]string
	transportServerServerZones   map[string][]string
	ingressUpstreamPeers         map[string][]string
	virtualServerUpstreamPeers   map[string][]string
	transportServerUpstreamPeers map[string][]string
}

// Configurator configures Edgenexus.
// Until reloads are enabled via EnableReloads(), the Configurator will not reload Edgenexus and update 'Edgenexus +'
// upstream servers via 'Edgenexus +' API for configuration changes.
// This allows the Ingress Controller to incrementally build the Edgenexus configuration during the IC start and
// then apply it at the end of the start.
type Configurator struct {
	edgeManager            edge.Manager
	staticCfgParams         *StaticConfigParams
	cfgParams               *ConfigParams
	templateExecutor        *version1.TemplateExecutor
	templateExecutorV2      *version2.TemplateExecutor
	ingresses               map[string]*IngressEx
	gateways                map[string]*GatewayEx
	minions                 map[string]map[string]bool
	virtualServers          map[string]*VirtualServerEx
	tlsPassthroughPairs     map[string]tlsPassthroughPair
	isWildcardEnabled       bool
	isPlus                  bool
//	labelUpdater            collector.LabelUpdater
	metricLabelsIndex       *metricLabelsIndex
	isPrometheusEnabled     bool
	latencyCollector        latCollector.LatencyCollector
	isLatencyMetricsEnabled bool
	isReloadsEnabled        bool
}

// NewConfigurator creates a new Configurator.
func NewConfigurator(edgeManager edge.Manager, staticCfgParams *StaticConfigParams, config *ConfigParams,
	templateExecutor *version1.TemplateExecutor, templateExecutorV2 *version2.TemplateExecutor, isPlus bool, isWildcardEnabled bool,
	//labelUpdater collector.LabelUpdater,
    isPrometheusEnabled bool, latencyCollector latCollector.LatencyCollector, isLatencyMetricsEnabled bool) *Configurator {
	metricLabelsIndex := &metricLabelsIndex{
		ingressUpstreams:             make(map[string][]string),
		virtualServerUpstreams:       make(map[string][]string),
		transportServerUpstreams:     make(map[string][]string),
		ingressServerZones:           make(map[string][]string),
		virtualServerServerZones:     make(map[string][]string),
		transportServerServerZones:   make(map[string][]string),
		ingressUpstreamPeers:         make(map[string][]string),
		virtualServerUpstreamPeers:   make(map[string][]string),
		transportServerUpstreamPeers: make(map[string][]string),
	}

	cnf := Configurator{
		edgeManager:            edgeManager,
		staticCfgParams:         staticCfgParams,
		cfgParams:               config,
		ingresses:               make(map[string]*IngressEx),
		gateways:                make(map[string]*GatewayEx),
		virtualServers:          make(map[string]*VirtualServerEx),
		templateExecutor:        templateExecutor,
		templateExecutorV2:      templateExecutorV2,
		minions:                 make(map[string]map[string]bool),
		tlsPassthroughPairs:     make(map[string]tlsPassthroughPair),
		isPlus:                  isPlus,
		isWildcardEnabled:       isWildcardEnabled,
		//labelUpdater:            labelUpdater,
		metricLabelsIndex:       metricLabelsIndex,
		isPrometheusEnabled:     isPrometheusEnabled,
		latencyCollector:        latencyCollector,
		isLatencyMetricsEnabled: isLatencyMetricsEnabled,
		isReloadsEnabled:        false,
	}
	return &cnf
}

// AddOrUpdateDHParam creates a dhparam file with the content of the string.
func (cnf *Configurator) AddOrUpdateDHParam(content string) (string, error) {
	return cnf.edgeManager.CreateDHParam(content)
}

func findRemovedKeys(currentKeys []string, newKeys map[string]bool) []string {
	var removedKeys []string
	for _, name := range currentKeys {
		if _, exists := newKeys[name]; !exists {
			removedKeys = append(removedKeys, name)
		}
	}
	return removedKeys
}

func (cnf *Configurator) updateIngressMetricsLabels(ingEx *IngressEx, upstreams []version1.Upstream) {
	upstreamServerLabels := make(map[string][]string)
	newUpstreams := make(map[string]bool)
	var newUpstreamsNames []string

	upstreamServerPeerLabels := make(map[string][]string)
	newPeers := make(map[string]bool)
	var newPeersIPs []string

	for _, u := range upstreams {
		upstreamServerLabels[u.Name] = []string{u.UpstreamLabels.Service, u.UpstreamLabels.ResourceType, u.UpstreamLabels.ResourceName, u.UpstreamLabels.ResourceNamespace}
		newUpstreams[u.Name] = true
		newUpstreamsNames = append(newUpstreamsNames, u.Name)
		for _, server := range u.UpstreamServers {
			s := fmt.Sprintf("%v:%v", server.Address, server.Port)
			podInfo := ingEx.PodsByIP[s]
			labelKey := fmt.Sprintf("%v/%v", u.Name, s)
			upstreamServerPeerLabels[labelKey] = []string{podInfo.Name}
			if cnf.staticCfgParams.EdgeServiceMesh {
				ownerLabelVal := fmt.Sprintf("%s/%s", podInfo.OwnerType, podInfo.OwnerName)
				upstreamServerPeerLabels[labelKey] = append(upstreamServerPeerLabels[labelKey], ownerLabelVal)
			}
			newPeers[labelKey] = true
			newPeersIPs = append(newPeersIPs, labelKey)
		}
	}

	key := fmt.Sprintf("%v/%v", ingEx.Ingress.Namespace, ingEx.Ingress.Name)
	removedUpstreams := findRemovedKeys(cnf.metricLabelsIndex.ingressUpstreams[key], newUpstreams)
	cnf.metricLabelsIndex.ingressUpstreams[key] = newUpstreamsNames
	cnf.latencyCollector.UpdateUpstreamServerLabels(upstreamServerLabels)
	cnf.latencyCollector.DeleteUpstreamServerLabels(removedUpstreams)

	removedPeers := findRemovedKeys(cnf.metricLabelsIndex.ingressUpstreamPeers[key], newPeers)
	cnf.metricLabelsIndex.ingressUpstreamPeers[key] = newPeersIPs
	cnf.latencyCollector.UpdateUpstreamServerPeerLabels(upstreamServerPeerLabels)
	cnf.latencyCollector.DeleteUpstreamServerPeerLabels(removedPeers)
	cnf.latencyCollector.DeleteMetrics(removedPeers)

}

func (cnf *Configurator) deleteIngressMetricsLabels(key string) {
	cnf.latencyCollector.DeleteUpstreamServerLabels(cnf.metricLabelsIndex.ingressUpstreams[key])
	cnf.latencyCollector.DeleteUpstreamServerPeerLabels(cnf.metricLabelsIndex.ingressUpstreamPeers[key])
	cnf.latencyCollector.DeleteMetrics(cnf.metricLabelsIndex.ingressUpstreamPeers[key])

	delete(cnf.metricLabelsIndex.ingressUpstreams, key)
	delete(cnf.metricLabelsIndex.ingressServerZones, key)
	delete(cnf.metricLabelsIndex.ingressUpstreamPeers, key)
}

// AddOrUpdateIngress adds or updates Edgenexus configuration for the Ingress resource.
func (cnf *Configurator) AddOrUpdateIngress(ingEx *IngressEx) (Warnings, error) {
	warnings, err := cnf.addOrUpdateIngress(ingEx)
	if err != nil {
		return warnings, fmt.Errorf("Error adding or updating ingress %v/%v: %w", ingEx.Ingress.Namespace, ingEx.Ingress.Name, err)
	}

	if err := cnf.reload(edge.ReloadForOtherUpdate); err != nil {
		return warnings, fmt.Errorf("Error reloading EdgeNEXUS Manager for %v/%v: %w", ingEx.Ingress.Namespace, ingEx.Ingress.Name, err)
	}

	return warnings, nil
}

func (cnf *Configurator) addOrUpdateIngress(ingEx *IngressEx) (Warnings, error) {
	apResources := cnf.updateApResources(ingEx)

	if jwtKey, exists := ingEx.Ingress.Annotations[JWTKeyAnnotation]; exists {
		// LocalSecretStore will not set Path if the secret is not on the filesystem.
		// However, Edgenexus configuration for an Ingress resource, to handle the case of a missing secret,
		// relies on the path to be always configured.
		ingEx.SecretRefs[jwtKey].Path = cnf.edgeManager.GetFilenameForSecret(ingEx.Ingress.Namespace + "-" + jwtKey)
	}

	isMinion := false
	edgeCfg, warnings := generateEdgeCfg(ingEx, apResources, isMinion, cnf.cfgParams, cnf.isPlus, cnf.IsResolverConfigured(),
		cnf.staticCfgParams, cnf.isWildcardEnabled)
	name := objectMetaToFileName(&ingEx.Ingress.ObjectMeta)
	content, err := cnf.templateExecutor.ExecuteIngressConfigTemplate(&edgeCfg)
	if err != nil {
		return warnings, fmt.Errorf("Error generating Ingress Config %v: %w", name, err)
	}
	cnf.edgeManager.CreateConfig(name, content)

	cnf.ingresses[name] = ingEx
	if (cnf.isPlus && cnf.isPrometheusEnabled) || cnf.isLatencyMetricsEnabled {
		cnf.updateIngressMetricsLabels(ingEx, edgeCfg.Upstreams)
	}
	return warnings, nil
}

// AddOrUpdateMergeableIngress adds or updates Edgenexus configuration for the Ingress resources with Mergeable Types.
func (cnf *Configurator) AddOrUpdateMergeableIngress(mergeableIngs *MergeableIngresses) (Warnings, error) {
	warnings, err := cnf.addOrUpdateMergeableIngress(mergeableIngs)
	if err != nil {
		return warnings, fmt.Errorf("Error when adding or updating ingress %v/%v: %w", mergeableIngs.Master.Ingress.Namespace, mergeableIngs.Master.Ingress.Name, err)
	}

	if err := cnf.reload(edge.ReloadForOtherUpdate); err != nil {
		return warnings, fmt.Errorf("Error reloading EdgeNEXUS Manager for %v/%v: %w", mergeableIngs.Master.Ingress.Namespace, mergeableIngs.Master.Ingress.Name, err)
	}

	return warnings, nil
}

func (cnf *Configurator) addOrUpdateMergeableIngress(mergeableIngs *MergeableIngresses) (Warnings, error) {
	masterApResources := cnf.updateApResources(mergeableIngs.Master)

	// LocalSecretStore will not set Path if the secret is not on the filesystem.
	// However, Edgenexus configuration for an Ingress resource, to handle the case of a missing secret,
	// relies on the path to be always configured.
	if jwtKey, exists := mergeableIngs.Master.Ingress.Annotations[JWTKeyAnnotation]; exists {
		mergeableIngs.Master.SecretRefs[jwtKey].Path = cnf.edgeManager.GetFilenameForSecret(mergeableIngs.Master.Ingress.Namespace + "-" + jwtKey)
	}
	for _, minion := range mergeableIngs.Minions {
		if jwtKey, exists := minion.Ingress.Annotations[JWTKeyAnnotation]; exists {
			minion.SecretRefs[jwtKey].Path = cnf.edgeManager.GetFilenameForSecret(minion.Ingress.Namespace + "-" + jwtKey)
		}
	}

	edgeCfg, warnings := generateEdgeCfgForMergeableIngresses(mergeableIngs, masterApResources, cnf.cfgParams, cnf.isPlus,
		cnf.IsResolverConfigured(), cnf.staticCfgParams, cnf.isWildcardEnabled)

	name := objectMetaToFileName(&mergeableIngs.Master.Ingress.ObjectMeta)
	content, err := cnf.templateExecutor.ExecuteIngressConfigTemplate(&edgeCfg)
	if err != nil {
		return warnings, fmt.Errorf("Error generating Ingress Config %v: %w", name, err)
	}
	cnf.edgeManager.CreateConfig(name, content)

	cnf.ingresses[name] = mergeableIngs.Master
	cnf.minions[name] = make(map[string]bool)
	for _, minion := range mergeableIngs.Minions {
		minionName := objectMetaToFileName(&minion.Ingress.ObjectMeta)
		cnf.minions[name][minionName] = true
	}
	if (cnf.isPlus && cnf.isPrometheusEnabled) || cnf.isLatencyMetricsEnabled {
		cnf.updateIngressMetricsLabels(mergeableIngs.Master, edgeCfg.Upstreams)
	}

	return warnings, nil
}

func (cnf *Configurator) updateVirtualServerMetricsLabels(virtualServerEx *VirtualServerEx, upstreams []version2.Upstream) {
	labels := make(map[string][]string)
	newUpstreams := make(map[string]bool)
	var newUpstreamsNames []string

	upstreamServerPeerLabels := make(map[string][]string)
	newPeers := make(map[string]bool)
	var newPeersIPs []string

	for _, u := range upstreams {
		labels[u.Name] = []string{u.UpstreamLabels.Service, u.UpstreamLabels.ResourceType, u.UpstreamLabels.ResourceName, u.UpstreamLabels.ResourceNamespace}
		newUpstreams[u.Name] = true
		newUpstreamsNames = append(newUpstreamsNames, u.Name)
		for _, server := range u.Servers {
			podInfo := virtualServerEx.PodsByIP[server.Address]
			labelKey := fmt.Sprintf("%v/%v", u.Name, server.Address)
			upstreamServerPeerLabels[labelKey] = []string{podInfo.Name}
			if cnf.staticCfgParams.EdgeServiceMesh {
				ownerLabelVal := fmt.Sprintf("%s/%s", podInfo.OwnerType, podInfo.OwnerName)
				upstreamServerPeerLabels[labelKey] = append(upstreamServerPeerLabels[labelKey], ownerLabelVal)
			}
			newPeers[labelKey] = true
			newPeersIPs = append(newPeersIPs, labelKey)
		}
	}

	key := fmt.Sprintf("%v/%v", virtualServerEx.VirtualServer.Namespace, virtualServerEx.VirtualServer.Name)

	removedPeers := findRemovedKeys(cnf.metricLabelsIndex.virtualServerUpstreamPeers[key], newPeers)
	cnf.metricLabelsIndex.virtualServerUpstreamPeers[key] = newPeersIPs
	cnf.latencyCollector.UpdateUpstreamServerPeerLabels(upstreamServerPeerLabels)
	cnf.latencyCollector.DeleteUpstreamServerPeerLabels(removedPeers)

	removedUpstreams := findRemovedKeys(cnf.metricLabelsIndex.virtualServerUpstreams[key], newUpstreams)
	cnf.latencyCollector.UpdateUpstreamServerLabels(labels)
	cnf.metricLabelsIndex.virtualServerUpstreams[key] = newUpstreamsNames

	cnf.latencyCollector.DeleteUpstreamServerLabels(removedUpstreams)
	cnf.latencyCollector.DeleteMetrics(removedPeers)

}

func (cnf *Configurator) deleteVirtualServerMetricsLabels(key string) {
	cnf.latencyCollector.DeleteUpstreamServerLabels(cnf.metricLabelsIndex.virtualServerUpstreams[key])
	cnf.latencyCollector.DeleteUpstreamServerPeerLabels(cnf.metricLabelsIndex.virtualServerUpstreamPeers[key])
	cnf.latencyCollector.DeleteMetrics(cnf.metricLabelsIndex.virtualServerUpstreamPeers[key])

	delete(cnf.metricLabelsIndex.virtualServerUpstreams, key)
	delete(cnf.metricLabelsIndex.virtualServerServerZones, key)
	delete(cnf.metricLabelsIndex.virtualServerUpstreamPeers, key)
}

// AddOrUpdateVirtualServer adds or updates Edgenexus configuration for the VirtualServer resource.
func (cnf *Configurator) AddOrUpdateVirtualServer(virtualServerEx *VirtualServerEx) (Warnings, error) {
	warnings, err := cnf.addOrUpdateVirtualServer(virtualServerEx)
	if err != nil {
		return warnings, fmt.Errorf("Error adding or updating VirtualServer %v/%v: %w", virtualServerEx.VirtualServer.Namespace, virtualServerEx.VirtualServer.Name, err)
	}

	if err := cnf.reload(edge.ReloadForOtherUpdate); err != nil {
		return warnings, fmt.Errorf("Error reloading EdgeNEXUS Manager for VirtualServer %v/%v: %w", virtualServerEx.VirtualServer.Namespace, virtualServerEx.VirtualServer.Name, err)
	}

	return warnings, nil
}

func (cnf *Configurator) addOrUpdateOpenTracingTracerConfig(content string) error {
	err := cnf.edgeManager.CreateOpenTracingTracerConfig(content)
	return err
}

func (cnf *Configurator) addOrUpdateVirtualServer(virtualServerEx *VirtualServerEx) (Warnings, error) {
	apResources := cnf.updateApResourcesForVs(virtualServerEx)

	name := getFileNameForVirtualServer(virtualServerEx.VirtualServer)

	vsc := newVirtualServerConfigurator(cnf.cfgParams, cnf.isPlus, cnf.IsResolverConfigured(), cnf.staticCfgParams)
	vsCfg, warnings := vsc.GenerateVirtualServerConfig(virtualServerEx, apResources)
	content, err := cnf.templateExecutorV2.ExecuteVirtualServerTemplate(&vsCfg)
	if err != nil {
		return warnings, fmt.Errorf("Error generating VirtualServer config: %v: %w", name, err)
	}
	cnf.edgeManager.CreateConfig(name, content)

	cnf.virtualServers[name] = virtualServerEx

	if (cnf.isPlus && cnf.isPrometheusEnabled) || cnf.isLatencyMetricsEnabled {
		cnf.updateVirtualServerMetricsLabels(virtualServerEx, vsCfg.Upstreams)
	}
	return warnings, nil
}

// AddOrUpdateVirtualServers adds or updates Edgenexus configuration for multiple VirtualServer resources.
func (cnf *Configurator) AddOrUpdateVirtualServers(virtualServerExes []*VirtualServerEx) (Warnings, error) {
	allWarnings := newWarnings()

	for _, vsEx := range virtualServerExes {
		warnings, err := cnf.addOrUpdateVirtualServer(vsEx)
		if err != nil {
			return allWarnings, err
		}
		allWarnings.Add(warnings)
	}

	if err := cnf.reload(edge.ReloadForOtherUpdate); err != nil {
		return allWarnings, fmt.Errorf("Error when reloading EdgeNEXUS Manager when updating Policy: %w", err)
	}

	return allWarnings, nil
}

// AddOrUpdateTransportServer adds or updates Edgenexus configuration for the TransportServer resource.
// It is a responsibility of the caller to check that the TransportServer references an existing listener.
func (cnf *Configurator) AddOrUpdateTransportServer(transportServerEx *TransportServerEx) error {
	err := cnf.addOrUpdateTransportServer(transportServerEx)
	if err != nil {
		return fmt.Errorf("Error adding or updating TransportServer %v/%v: %w", transportServerEx.TransportServer.Namespace, transportServerEx.TransportServer.Name, err)
	}

	if err := cnf.reload(edge.ReloadForOtherUpdate); err != nil {
		return fmt.Errorf("Error reloading EdgeNEXUS Manager for TransportServer %v/%v: %w", transportServerEx.TransportServer.Namespace, transportServerEx.TransportServer.Name, err)
	}

	return nil
}

func (cnf *Configurator) addOrUpdateTransportServer(transportServerEx *TransportServerEx) error {
	name := getFileNameForTransportServer(transportServerEx.TransportServer)

	tsCfg := generateTransportServerConfig(transportServerEx, transportServerEx.ListenerPort, cnf.isPlus)

	content, err := cnf.templateExecutorV2.ExecuteTransportServerTemplate(tsCfg)
	if err != nil {
		return fmt.Errorf("Error generating TransportServer config %v: %w", name, err)
	}

	cnf.edgeManager.CreateStreamConfig(name, content)

	// update TLS Passthrough Hosts config in case we have a TLS Passthrough TransportServer
	// only TLS Passthrough TransportServers have non-empty hosts
	if transportServerEx.TransportServer.Spec.Host != "" {
		key := generateNamespaceNameKey(&transportServerEx.TransportServer.ObjectMeta)
		cnf.tlsPassthroughPairs[key] = tlsPassthroughPair{
			Host:       transportServerEx.TransportServer.Spec.Host,
			UnixSocket: generateUnixSocket(transportServerEx),
		}

		return cnf.updateTLSPassthroughHostsConfig()
	}

	return nil
}

// GetVirtualServerRoutesForVirtualServer returns the virtualServerRoutes that a virtualServer
// references, if that virtualServer exists
func (cnf *Configurator) GetVirtualServerRoutesForVirtualServer(key string) []*conf_v1.VirtualServerRoute {
	vsFileName := getFileNameForVirtualServerFromKey(key)
	if cnf.virtualServers[vsFileName] != nil {
		return cnf.virtualServers[vsFileName].VirtualServerRoutes
	}
	return nil
}

func (cnf *Configurator) updateTLSPassthroughHostsConfig() error {
	cfg := generateTLSPassthroughHostsConfig(cnf.tlsPassthroughPairs)

	content, err := cnf.templateExecutorV2.ExecuteTLSPassthroughHostsTemplate(cfg)
	if err != nil {
		return fmt.Errorf("Error generating config for TLS Passthrough Unix Sockets map: %w", err)
	}

	cnf.edgeManager.CreateTLSPassthroughHostsConfig(content)

	return nil
}

func generateTLSPassthroughHostsConfig(tlsPassthroughPairs map[string]tlsPassthroughPair) *version2.TLSPassthroughHostsConfig {
	cfg := version2.TLSPassthroughHostsConfig{}

	for _, pair := range tlsPassthroughPairs {
		cfg[pair.Host] = pair.UnixSocket
	}

	return &cfg
}

func (cnf *Configurator) addOrUpdateCASecret(secret *api_v1.Secret) string {
	name := objectMetaToFileName(&secret.ObjectMeta)
	data := GenerateCAFileContent(secret)
	return cnf.edgeManager.CreateSecret(name, data, edge.TLSSecretFileMode)
}

func (cnf *Configurator) addOrUpdateJWKSecret(secret *api_v1.Secret) string {
	name := objectMetaToFileName(&secret.ObjectMeta)
	data := secret.Data[JWTKeyKey]
	return cnf.edgeManager.CreateSecret(name, data, edge.JWKSecretFileMode)
}

// AddOrUpdateResources adds or updates configuration for resources.
func (cnf *Configurator) AddOrUpdateResources(resources ExtendedResources) (Warnings, error) {
	allWarnings := newWarnings()

	for _, ingEx := range resources.IngressExes {
		warnings, err := cnf.addOrUpdateIngress(ingEx)
		if err != nil {
			return allWarnings, fmt.Errorf("Error adding or updating ingress %v/%v: %w", ingEx.Ingress.Namespace, ingEx.Ingress.Name, err)
		}
		allWarnings.Add(warnings)
	}

	for _, m := range resources.MergeableIngresses {
		warnings, err := cnf.addOrUpdateMergeableIngress(m)
		if err != nil {
			return allWarnings, fmt.Errorf("Error adding or updating mergeableIngress %v/%v: %w", m.Master.Ingress.Namespace, m.Master.Ingress.Name, err)
		}
		allWarnings.Add(warnings)
	}

	for _, vsEx := range resources.VirtualServerExes {
		warnings, err := cnf.addOrUpdateVirtualServer(vsEx)
		if err != nil {
			return allWarnings, fmt.Errorf("Error adding or updating VirtualServer %v/%v: %w", vsEx.VirtualServer.Namespace, vsEx.VirtualServer.Name, err)
		}
		allWarnings.Add(warnings)
	}

	for _, tsEx := range resources.TransportServerExes {
		err := cnf.addOrUpdateTransportServer(tsEx)
		if err != nil {
			return allWarnings, fmt.Errorf("Error adding or updating TransportServer %v/%v: %w", tsEx.TransportServer.Namespace, tsEx.TransportServer.Name, err)
		}
	}

	if err := cnf.reload(edge.ReloadForOtherUpdate); err != nil {
		return allWarnings, fmt.Errorf("Error when reloading EdgeNEXUS Manager when updating resources: %w", err)
	}

	return allWarnings, nil
}

func (cnf *Configurator) addOrUpdateTLSSecret(secret *api_v1.Secret) string {
	name := objectMetaToFileName(&secret.ObjectMeta)
	data := GenerateCertAndKeyFileContent(secret)
	return cnf.edgeManager.CreateSecret(name, data, edge.TLSSecretFileMode)
}

// AddOrUpdateSpecialTLSSecrets adds or updates a file with a TLS cert and a key from a Special TLS Secret (eg. DefaultServerSecret, WildcardTLSSecret).
func (cnf *Configurator) AddOrUpdateSpecialTLSSecrets(secret *api_v1.Secret, secretNames []string) error {
	data := GenerateCertAndKeyFileContent(secret)

	for _, secretName := range secretNames {
		cnf.edgeManager.CreateSecret(secretName, data, edge.TLSSecretFileMode)
	}

	if err := cnf.reload(edge.ReloadForOtherUpdate); err != nil {
		return fmt.Errorf("Error when reloading EdgeNEXUS Manager when updating the special Secrets: %w", err)
	}

	return nil
}

// GenerateCertAndKeyFileContent generates a pem file content from the TLS secret.
func GenerateCertAndKeyFileContent(secret *api_v1.Secret) []byte {
	var res bytes.Buffer

	res.Write(secret.Data[api_v1.TLSCertKey])
	res.WriteString("\n")
	res.Write(secret.Data[api_v1.TLSPrivateKeyKey])

	return res.Bytes()
}

// GenerateCAFileContent generates a pem file content from the TLS secret.
func GenerateCAFileContent(secret *api_v1.Secret) []byte {
	var res bytes.Buffer

	res.Write(secret.Data[CAKey])

	return res.Bytes()
}

// DeleteIngress deletes Edgenexus configuration for the Ingress resource.
func (cnf *Configurator) DeleteIngress(key string) error {
	name := keyToFileName(key)
	cnf.edgeManager.DeleteConfig(name)

	delete(cnf.ingresses, name)
	delete(cnf.minions, name)

	if (cnf.isPlus && cnf.isPrometheusEnabled) || cnf.isLatencyMetricsEnabled {
		cnf.deleteIngressMetricsLabels(key)
	}

	if err := cnf.reload(edge.ReloadForOtherUpdate); err != nil {
		return fmt.Errorf("Error when removing ingress %v: %w", key, err)
	}

	return nil
}

// DeleteVirtualServer deletes Edgenexus configuration for the VirtualServer resource.
func (cnf *Configurator) DeleteVirtualServer(key string) error {
	name := getFileNameForVirtualServerFromKey(key)
	cnf.edgeManager.DeleteConfig(name)

	delete(cnf.virtualServers, name)
	if (cnf.isPlus && cnf.isPrometheusEnabled) || cnf.isLatencyMetricsEnabled {
		cnf.deleteVirtualServerMetricsLabels(key)
	}

	if err := cnf.reload(edge.ReloadForOtherUpdate); err != nil {
		return fmt.Errorf("Error when removing VirtualServer %v: %w", key, err)
	}

	return nil
}

// DeleteTransportServer deletes Edgenexus configuration for the TransportServer resource.
func (cnf *Configurator) DeleteTransportServer(key string) error {
	//if cnf.isPlus && cnf.isPrometheusEnabled {
	//	cnf.deleteTransportServerMetricsLabels(key)
	//}

	err := cnf.deleteTransportServer(key)
	if err != nil {
		return fmt.Errorf("Error when removing TransportServer %v: %w", key, err)
	}

	err = cnf.reload(edge.ReloadForOtherUpdate)
	if err != nil {
		return fmt.Errorf("Error when removing TransportServer %v: %w", key, err)
	}

	return nil
}

func (cnf *Configurator) deleteTransportServer(key string) error {
	name := getFileNameForTransportServerFromKey(key)
	cnf.edgeManager.DeleteStreamConfig(name)

	// update TLS Passthrough Hosts config in case we have a TLS Passthrough TransportServer
	if _, exists := cnf.tlsPassthroughPairs[key]; exists {
		delete(cnf.tlsPassthroughPairs, key)

		return cnf.updateTLSPassthroughHostsConfig()
	}

	return nil
}

// UpdateEndpoints updates endpoints in Edgenexus configuration for the Ingress resources.
func (cnf *Configurator) UpdateEndpoints(ingExes []*IngressEx) error {
	reloadPlus := false

	for _, ingEx := range ingExes {
		// It is safe to ignore warnings here as no new warnings should appear when updating Endpoints for Ingresses
		_, err := cnf.addOrUpdateIngress(ingEx)
		if err != nil {
			return fmt.Errorf("Error adding or updating ingress %v/%v: %w", ingEx.Ingress.Namespace, ingEx.Ingress.Name, err)
		}

	}

	if cnf.isPlus && !reloadPlus {
		glog.V(3).Info("No need to reload EdgeNEXUS Manager")
		return nil
	}

	if err := cnf.reload(edge.ReloadForEndpointsUpdate); err != nil {
		return fmt.Errorf("Error reloading EdgeNEXUS Manager when updating endpoints: %w", err)
	}

	return nil
}

// UpdateEndpointsMergeableIngress updates endpoints in Edgenexus configuration for a mergeable Ingress resource.
func (cnf *Configurator) UpdateEndpointsMergeableIngress(mergeableIngresses []*MergeableIngresses) error {
	reloadPlus := false

	for i := range mergeableIngresses {
		// It is safe to ignore warnings here as no new warnings should appear when updating Endpoints for Ingresses
		_, err := cnf.addOrUpdateMergeableIngress(mergeableIngresses[i])
		if err != nil {
			return fmt.Errorf("Error adding or updating mergeableIngress %v/%v: %w", mergeableIngresses[i].Master.Ingress.Namespace, mergeableIngresses[i].Master.Ingress.Name, err)
		}

	}

	if cnf.isPlus && !reloadPlus {
		glog.V(3).Info("No need to reload EdgeNEXUS Manager")
		return nil
	}

	if err := cnf.reload(edge.ReloadForEndpointsUpdate); err != nil {
		return fmt.Errorf("Error reloading EdgeNEXUS Manager when updating endpoints for %v: %w", mergeableIngresses, err)
	}

	return nil
}

// UpdateEndpointsForVirtualServers updates endpoints in Edgenexus configuration for the VirtualServer resources.
func (cnf *Configurator) UpdateEndpointsForVirtualServers(virtualServerExes []*VirtualServerEx) error {
	reloadPlus := false

	for _, vs := range virtualServerExes {
		// It is safe to ignore warnings here as no new warnings should appear when updating Endpoints for VirtualServers
		_, err := cnf.addOrUpdateVirtualServer(vs)
		if err != nil {
			return fmt.Errorf("Error adding or updating VirtualServer %v/%v: %w", vs.VirtualServer.Namespace, vs.VirtualServer.Name, err)
		}

	}

	if cnf.isPlus && !reloadPlus {
		glog.V(3).Info("No need to reload EdgeNEXUS Manager")
		return nil
	}

	if err := cnf.reload(edge.ReloadForEndpointsUpdate); err != nil {
		return fmt.Errorf("Error reloading EdgeNEXUS Manager when updating endpoints: %w", err)
	}

	return nil
}


// UpdateEndpointsForTransportServers updates endpoints in Edgenexus configuration for the TransportServer resources.
func (cnf *Configurator) UpdateEndpointsForTransportServers(transportServerExes []*TransportServerEx) error {
	reloadPlus := false

	for _, tsEx := range transportServerExes {
		err := cnf.addOrUpdateTransportServer(tsEx)
		if err != nil {
			return fmt.Errorf("Error adding or updating TransportServer %v/%v: %w", tsEx.TransportServer.Namespace, tsEx.TransportServer.Name, err)
		}

	}

	if cnf.isPlus && !reloadPlus {
		glog.V(3).Info("No need to reload EdgeNEXUS Manager")
		return nil
	}

	if err := cnf.reload(edge.ReloadForEndpointsUpdate); err != nil {
		return fmt.Errorf("Error reloading EdgeNEXUS Manager when updating endpoints: %w", err)
	}

	return nil
}


// EnableReloads enables Edgenexus reloads meaning that configuration changes will be followed by a reload.
func (cnf *Configurator) EnableReloads() {
	cnf.isReloadsEnabled = true
}

func (cnf *Configurator) reload(isEndpointsUpdate bool) error {
	if !cnf.isReloadsEnabled {
		return nil
	}

	return cnf.edgeManager.Reload(isEndpointsUpdate)
}


// UpdateConfig updates Edgenexus configuration parameters.
//gocyclo:ignore
func (cnf *Configurator) UpdateConfig(cfgParams *ConfigParams, resources ExtendedResources) (Warnings, error) {
	cnf.cfgParams = cfgParams
	allWarnings := newWarnings()

	if cnf.cfgParams.MainServerSSLDHParamFileContent != nil {
		fileName, err := cnf.edgeManager.CreateDHParam(*cnf.cfgParams.MainServerSSLDHParamFileContent)
		if err != nil {
			return allWarnings, fmt.Errorf("Error when updating dhparams: %w", err)
		}
		cfgParams.MainServerSSLDHParam = fileName
	}

	if cfgParams.MainTemplate != nil {
		err := cnf.templateExecutor.UpdateMainTemplate(cfgParams.MainTemplate)
		if err != nil {
			return allWarnings, fmt.Errorf("Error when parsing the main template: %w", err)
		}
	}

	if cfgParams.IngressTemplate != nil {
		err := cnf.templateExecutor.UpdateIngressTemplate(cfgParams.IngressTemplate)
		if err != nil {
			return allWarnings, fmt.Errorf("Error when parsing the ingress template: %w", err)
		}
	}

	if cfgParams.VirtualServerTemplate != nil {
		err := cnf.templateExecutorV2.UpdateVirtualServerTemplate(cfgParams.VirtualServerTemplate)
		if err != nil {
			return allWarnings, fmt.Errorf("Error when parsing the VirtualServer template: %w", err)
		}
	}

	mainCfg := GenerateEdgeMainConfig(cnf.staticCfgParams, cfgParams)
	mainCfgContent, err := cnf.templateExecutor.ExecuteMainConfigTemplate(mainCfg)
	if err != nil {
		return allWarnings, fmt.Errorf("Error when writing main Config")
	}
	cnf.edgeManager.CreateMainConfig(mainCfgContent)

	for _, ingEx := range resources.IngressExes {
		warnings, err := cnf.addOrUpdateIngress(ingEx)
		if err != nil {
			return allWarnings, err
		}
		allWarnings.Add(warnings)
	}
	for _, mergeableIng := range resources.MergeableIngresses {
		warnings, err := cnf.addOrUpdateMergeableIngress(mergeableIng)
		if err != nil {
			return allWarnings, err
		}
		allWarnings.Add(warnings)
	}
	for _, vsEx := range resources.VirtualServerExes {
		warnings, err := cnf.addOrUpdateVirtualServer(vsEx)
		if err != nil {
			return allWarnings, err
		}
		allWarnings.Add(warnings)
	}

	// we don't need to regenerate config for TransportServers, because:
	// (1) Changes to the ConfigMap don't affect TransportServer configs directly
	// (2) addOrUpdateTransportServer doesn't return any warnings that we need to propagate to the caller.
	// if (1) and (2) is no longer the case, we need to generate the config for TransportServers

	if mainCfg.OpenTracingLoadModule {
		if err := cnf.addOrUpdateOpenTracingTracerConfig(mainCfg.OpenTracingTracerConfig); err != nil {
			return allWarnings, fmt.Errorf("Error when updating OpenTracing tracer config: %w", err)
		}
	}

	cnf.edgeManager.SetOpenTracing(mainCfg.OpenTracingLoadModule)
	if err := cnf.reload(edge.ReloadForOtherUpdate); err != nil {
		return allWarnings, fmt.Errorf("Error when updating config from ConfigMap: %w", err)
	}

	return allWarnings, nil
}

// UpdateTransportServers updates TransportServers.
func (cnf *Configurator) UpdateTransportServers(updatedTSExes []*TransportServerEx, deletedKeys []string) error {
	for _, tsEx := range updatedTSExes {
		err := cnf.addOrUpdateTransportServer(tsEx)
		if err != nil {
			return fmt.Errorf("Error adding or updating TransportServer %v/%v: %w", tsEx.TransportServer.Namespace, tsEx.TransportServer.Name, err)
		}
	}

	for _, key := range deletedKeys {
		err := cnf.deleteTransportServer(key)
		if err != nil {
			return fmt.Errorf("Error when removing TransportServer %v: %w", key, err)
		}
	}

	if err := cnf.reload(edge.ReloadForOtherUpdate); err != nil {
		return fmt.Errorf("Error when updating TransportServers: %w", err)
	}

	return nil
}

func keyToFileName(key string) string {
	return strings.Replace(key, "/", "-", -1)
}

func objectMetaToFileName(meta *meta_v1.ObjectMeta) string {
	return meta.Namespace + "-" + meta.Name
}

func generateNamespaceNameKey(objectMeta *meta_v1.ObjectMeta) string {
	return fmt.Sprintf("%s/%s", objectMeta.Namespace, objectMeta.Name)
}

func getFileNameForVirtualServer(virtualServer *conf_v1.VirtualServer) string {
	return fmt.Sprintf("vs_%s_%s", virtualServer.Namespace, virtualServer.Name)
}

func getFileNameForTransportServer(transportServer *conf_v1alpha1.TransportServer) string {
	return fmt.Sprintf("ts_%s_%s", transportServer.Namespace, transportServer.Name)
}

func getFileNameForVirtualServerFromKey(key string) string {
	replaced := strings.Replace(key, "/", "_", -1)
	return fmt.Sprintf("vs_%s", replaced)
}

func getFileNameForTransportServerFromKey(key string) string {
	replaced := strings.Replace(key, "/", "_", -1)
	return fmt.Sprintf("ts_%s", replaced)
}

// HasIngress checks if the Ingress resource is present in Edgenexus configuration.
func (cnf *Configurator) HasIngress(ing *networking.Ingress) bool {
	name := objectMetaToFileName(&ing.ObjectMeta)
	_, exists := cnf.ingresses[name]
	return exists
}

// HasMinion checks if the minion Ingress resource of the master is present in Edgenexus configuration.
func (cnf *Configurator) HasMinion(master *networking.Ingress, minion *networking.Ingress) bool {
	masterName := objectMetaToFileName(&master.ObjectMeta)

	if _, exists := cnf.minions[masterName]; !exists {
		return false
	}

	return cnf.minions[masterName][objectMetaToFileName(&minion.ObjectMeta)]
}

// IsResolverConfigured checks if a DNS resolver is present in Edgenexus configuration.
func (cnf *Configurator) IsResolverConfigured() bool {
	return len(cnf.cfgParams.ResolverAddresses) != 0
}

// GetIngressCounts returns the total count of Ingress resources that are handled by the Ingress Controller grouped by their type
func (cnf *Configurator) GetIngressCounts() map[string]int {
	counters := map[string]int{
		"master":  0,
		"regular": 0,
		"minion":  0,
	}

	// cnf.ingresses contains only master and regular Ingress Resources
	for _, ing := range cnf.ingresses {
		if ing.Ingress.Annotations["edgenexus.io/mergeable-ingress-type"] == "master" {
			counters["master"]++
		} else {
			counters["regular"]++
		}
	}

	for _, min := range cnf.minions {
		counters["minion"] += len(min)
	}

	return counters
}

// GetVirtualServerCounts returns the total count of VS/VSR resources that are handled by the Ingress Controller
func (cnf *Configurator) GetVirtualServerCounts() (vsCount int, vsrCount int) {
	vsCount = len(cnf.virtualServers)
	for _, vs := range cnf.virtualServers {
		vsrCount += len(vs.VirtualServerRoutes)
	}

	return vsCount, vsrCount
}

// AddOrUpdateSpiffeCerts writes Spiffe certs and keys to disk and reloads Edgenexus
func (cnf *Configurator) AddOrUpdateSpiffeCerts(svidResponse *workload.X509SVIDs) error {
	svid := svidResponse.Default()
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(svid.PrivateKey.(crypto.PrivateKey))
	if err != nil {
		return fmt.Errorf("error when marshaling private key: %w", err)
	}

	cnf.edgeManager.CreateSecret(spiffeKeyFileName, createSpiffeKey(privateKeyBytes), spiffeKeyFileMode)
	cnf.edgeManager.CreateSecret(spiffeCertFileName, createSpiffeCert(svid.Certificates), spiffeCertsFileMode)
	cnf.edgeManager.CreateSecret(spiffeBundleFileName, createSpiffeCert(svid.TrustBundle), spiffeCertsFileMode)

	err = cnf.reload(edge.ReloadForOtherUpdate)
	if err != nil {
		return fmt.Errorf("error when reloading EdgeNEXUS Manager when updating the SPIFFE Certs: %w", err)
	}
	return nil
}

func createSpiffeKey(content []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: content,
	})
}

func createSpiffeCert(certs []*x509.Certificate) []byte {
	pemData := make([]byte, 0, len(certs))
	for _, c := range certs {
		b := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		}
		pemData = append(pemData, pem.EncodeToMemory(b)...)
	}
	return pemData
}

func (cnf *Configurator) updateApResources(ingEx *IngressEx) (apRes AppProtectResources) {
	if ingEx.AppProtectPolicy != nil {
		policyFileName := appProtectPolicyFileNameFromUnstruct(ingEx.AppProtectPolicy)
		policyContent := generateApResourceFileContent(ingEx.AppProtectPolicy)
		cnf.edgeManager.CreateAppProtectResourceFile(policyFileName, policyContent)
		apRes.AppProtectPolicy = policyFileName
	}

	for _, logConf := range ingEx.AppProtectLogs {
		logConfFileName := appProtectLogConfFileNameFromUnstruct(logConf.LogConf)
		logConfContent := generateApResourceFileContent(logConf.LogConf)
		cnf.edgeManager.CreateAppProtectResourceFile(logConfFileName, logConfContent)
		apRes.AppProtectLogconfs = append(apRes.AppProtectLogconfs, logConfFileName+" "+logConf.Dest)
	}

	return apRes
}

func (cnf *Configurator) updateApResourcesForVs(vsEx *VirtualServerEx) map[string]string {
	apRes := make(map[string]string)

	if vsEx.ApPolRefs != nil {
		for apPolKey, apPol := range vsEx.ApPolRefs {
			policyFileName := appProtectPolicyFileNameFromUnstruct(apPol)
			policyContent := generateApResourceFileContent(apPol)
			cnf.edgeManager.CreateAppProtectResourceFile(policyFileName, policyContent)
			apRes[apPolKey] = policyFileName
		}
	}

	if vsEx.LogConfRefs != nil {
		for logConfKey, logConf := range vsEx.LogConfRefs {
			logConfFileName := appProtectLogConfFileNameFromUnstruct(logConf)
			logConfContent := generateApResourceFileContent(logConf)
			cnf.edgeManager.CreateAppProtectResourceFile(logConfFileName, logConfContent)
			apRes[logConfKey] = logConfFileName
		}
	}

	return apRes
}

func appProtectPolicyFileNameFromUnstruct(unst *unstructured.Unstructured) string {
	return fmt.Sprintf("%s%s_%s", appProtectPolicyFolder, unst.GetNamespace(), unst.GetName())
}

func appProtectLogConfFileNameFromUnstruct(unst *unstructured.Unstructured) string {
	return fmt.Sprintf("%s%s_%s", appProtectLogConfFolder, unst.GetNamespace(), unst.GetName())
}

func appProtectUserSigFileNameFromUnstruct(unst *unstructured.Unstructured) string {
	return fmt.Sprintf("%s%s_%s", appProtectUserSigFolder, unst.GetNamespace(), unst.GetName())
}

func generateApResourceFileContent(apResource *unstructured.Unstructured) []byte {
	// Safe to ignore errors since validation already checked those
	spec, _, _ := unstructured.NestedMap(apResource.Object, "spec")
	data, _ := json.Marshal(spec)
	return data
}

// AddOrUpdateAppProtectResource updates Ingresses and VirtualServers that use App Protect Resources
func (cnf *Configurator) AddOrUpdateAppProtectResource(resource *unstructured.Unstructured, ingExes []*IngressEx, mergeableIngresses []*MergeableIngresses, vsExes []*VirtualServerEx) (Warnings, error) {
	allWarnings := newWarnings()

	for _, ingEx := range ingExes {
		warnings, err := cnf.addOrUpdateIngress(ingEx)
		if err != nil {
			return allWarnings, fmt.Errorf("Error adding or updating ingress %v/%v: %w", ingEx.Ingress.Namespace, ingEx.Ingress.Name, err)
		}
		allWarnings.Add(warnings)
	}

	for _, m := range mergeableIngresses {
		warnings, err := cnf.addOrUpdateMergeableIngress(m)
		if err != nil {
			return allWarnings, fmt.Errorf("Error adding or updating mergeableIngress %v/%v: %w", m.Master.Ingress.Namespace, m.Master.Ingress.Name, err)
		}
		allWarnings.Add(warnings)
	}

	for _, vs := range vsExes {
		warnings, err := cnf.addOrUpdateVirtualServer(vs)
		if err != nil {
			return allWarnings, fmt.Errorf("Error adding or updating VirtualServer %v/%v: %w", vs.VirtualServer.Namespace, vs.VirtualServer.Name, err)
		}
		allWarnings.Add(warnings)
	}

	if err := cnf.reload(edge.ReloadForOtherUpdate); err != nil {
		return allWarnings, fmt.Errorf("Error when reloading EdgeNEXUS Manager when updating %v: %w", resource.GetKind(), err)
	}

	return allWarnings, nil
}

// DeleteAppProtectPolicy updates Ingresses and VirtualServers that use AP Policy after that policy is deleted
func (cnf *Configurator) DeleteAppProtectPolicy(polNamespaceName string, ingExes []*IngressEx, mergeableIngresses []*MergeableIngresses, vsExes []*VirtualServerEx) (Warnings, error) {
	if len(ingExes)+len(mergeableIngresses)+len(vsExes) > 0 {
		fName := strings.Replace(polNamespaceName, "/", "_", 1)
		polFileName := appProtectPolicyFolder + fName
		cnf.edgeManager.DeleteAppProtectResourceFile(polFileName)
	}

	allWarnings := newWarnings()

	for _, ingEx := range ingExes {
		warnings, err := cnf.addOrUpdateIngress(ingEx)
		if err != nil {
			return allWarnings, fmt.Errorf("Error adding or updating ingress %v/%v: %w", ingEx.Ingress.Namespace, ingEx.Ingress.Name, err)
		}
		allWarnings.Add(warnings)
	}

	for _, m := range mergeableIngresses {
		warnings, err := cnf.addOrUpdateMergeableIngress(m)
		if err != nil {
			return allWarnings, fmt.Errorf("Error adding or updating mergeableIngress %v/%v: %w", m.Master.Ingress.Namespace, m.Master.Ingress.Name, err)
		}
		allWarnings.Add(warnings)
	}

	for _, v := range vsExes {
		warnings, err := cnf.addOrUpdateVirtualServer(v)
		if err != nil {
			return allWarnings, fmt.Errorf("Error adding or updating VirtualServer %v/%v: %w", v.VirtualServer.Namespace, v.VirtualServer.Name, err)
		}
		allWarnings.Add(warnings)
	}

	if err := cnf.reload(edge.ReloadForOtherUpdate); err != nil {
		return allWarnings, fmt.Errorf("Error when reloading EdgeNEXUS Manager when removing App Protect Policy: %w", err)
	}

	return allWarnings, nil
}

// DeleteAppProtectLogConf updates Ingresses and VirtualServers that use AP Log Configuration after that policy is deleted
func (cnf *Configurator) DeleteAppProtectLogConf(logConfNamespaceName string, ingExes []*IngressEx, mergeableIngresses []*MergeableIngresses, vsExes []*VirtualServerEx) (Warnings, error) {
	if len(ingExes)+len(mergeableIngresses)+len(vsExes) > 0 {
		fName := strings.Replace(logConfNamespaceName, "/", "_", 1)
		logConfFileName := appProtectLogConfFolder + fName
		cnf.edgeManager.DeleteAppProtectResourceFile(logConfFileName)
	}
	allWarnings := newWarnings()

	for _, ingEx := range ingExes {
		warnings, err := cnf.addOrUpdateIngress(ingEx)
		if err != nil {
			return allWarnings, fmt.Errorf("Error adding or updating ingress %v/%v: %w", ingEx.Ingress.Namespace, ingEx.Ingress.Name, err)
		}
		allWarnings.Add(warnings)
	}

	for _, m := range mergeableIngresses {
		warnings, err := cnf.addOrUpdateMergeableIngress(m)
		if err != nil {
			return allWarnings, fmt.Errorf("Error adding or updating mergeableIngress %v/%v: %w", m.Master.Ingress.Namespace, m.Master.Ingress.Name, err)
		}
		allWarnings.Add(warnings)
	}

	for _, v := range vsExes {
		warnings, err := cnf.addOrUpdateVirtualServer(v)
		if err != nil {
			return allWarnings, fmt.Errorf("Error adding or updating VirtualServer %v/%v: %w", v.VirtualServer.Namespace, v.VirtualServer.Name, err)
		}
		allWarnings.Add(warnings)
	}

	if err := cnf.reload(edge.ReloadForOtherUpdate); err != nil {
		return allWarnings, fmt.Errorf("Error when reloading EdgeNEXUS Manager when removing App Protect Log Configuration: %w", err)
	}

	return allWarnings, nil
}

// RefreshAppProtectUserSigs writes all valid UDS files to fs and reloads Edgenexus
func (cnf *Configurator) RefreshAppProtectUserSigs(
	userSigs []*unstructured.Unstructured, delPols []string, ingExes []*IngressEx, mergeableIngresses []*MergeableIngresses, vsExes []*VirtualServerEx,
) (Warnings, error) {
	allWarnings := newWarnings()
	for _, ingEx := range ingExes {
		warnings, err := cnf.addOrUpdateIngress(ingEx)
		if err != nil {
			return allWarnings, fmt.Errorf("Error adding or updating ingress %v/%v: %w", ingEx.Ingress.Namespace, ingEx.Ingress.Name, err)
		}
		allWarnings.Add(warnings)
	}

	for _, m := range mergeableIngresses {
		warnings, err := cnf.addOrUpdateMergeableIngress(m)
		if err != nil {
			return allWarnings, fmt.Errorf("Error adding or updating mergeableIngress %v/%v: %w", m.Master.Ingress.Namespace, m.Master.Ingress.Name, err)
		}
		allWarnings.Add(warnings)
	}

	for _, v := range vsExes {
		warnings, err := cnf.addOrUpdateVirtualServer(v)
		if err != nil {
			return allWarnings, fmt.Errorf("Error adding or updating VirtualServer %v/%v: %w", v.VirtualServer.Namespace, v.VirtualServer.Name, err)
		}
		allWarnings.Add(warnings)
	}

	for _, file := range delPols {
		cnf.edgeManager.DeleteAppProtectResourceFile(file)
	}

	var builder strings.Builder
	cnf.edgeManager.ClearAppProtectFolder(appProtectUserSigFolder)
	for _, sig := range userSigs {
		fName := appProtectUserSigFileNameFromUnstruct(sig)
		data := generateApResourceFileContent(sig)
		cnf.edgeManager.CreateAppProtectResourceFile(fName, data)
		fmt.Fprintf(&builder, "app_protect_user_defined_signatures %s;\n", fName)
	}
	cnf.edgeManager.CreateAppProtectResourceFile(appProtectUserSigIndex, []byte(builder.String()))
	return allWarnings, cnf.reload(edge.ReloadForOtherUpdate)
}

// AddInternalRouteConfig adds internal route server to Edgenexus Configuration and reloads Edgenexus
func (cnf *Configurator) AddInternalRouteConfig() error {
	cnf.staticCfgParams.EnableInternalRoutes = true
	cnf.staticCfgParams.PodName = os.Getenv("POD_NAME")
	mainCfg := GenerateEdgeMainConfig(cnf.staticCfgParams, cnf.cfgParams)
	mainCfgContent, err := cnf.templateExecutor.ExecuteMainConfigTemplate(mainCfg)
	if err != nil {
		return fmt.Errorf("Error when writing main Config: %w", err)
	}
	cnf.edgeManager.CreateMainConfig(mainCfgContent)
	if err := cnf.reload(edge.ReloadForOtherUpdate); err != nil {
		return fmt.Errorf("Error when reloading EdgeNEXUS manager: %w", err)
	}
	return nil
}

// AddOrUpdateSecret adds or updates a secret.
func (cnf *Configurator) AddOrUpdateSecret(secret *api_v1.Secret) string {
	switch secret.Type {
	case secrets.SecretTypeCA:
		return cnf.addOrUpdateCASecret(secret)
	case secrets.SecretTypeJWK:
		return cnf.addOrUpdateJWKSecret(secret)
	case secrets.SecretTypeOIDC:
		// OIDC ClientSecret is not required on the filesystem, it is written directly to the config file.
		return ""
	default:
		return cnf.addOrUpdateTLSSecret(secret)
	}
}

// DeleteSecret deletes a secret.
func (cnf *Configurator) DeleteSecret(key string) {
	cnf.edgeManager.DeleteSecret(keyToFileName(key))
}

// AddOrUpdateGateway adds or updates EdgeNexus configuration for the Gateway resource.
func (cnf *Configurator) AddOrUpdateGateway(gEx *GatewayEx) (Warnings, error) {
	warnings, err := cnf.addOrUpdateGateway(gEx)
	if err != nil {
		return warnings, fmt.Errorf("Error adding or updating gateway %v/%v: %w", gEx.Gateway.Namespace, gEx.Gateway.Name, err)
	}

	if err := cnf.reload(edge.ReloadForOtherUpdate); err != nil {
		return warnings, fmt.Errorf("Error reloading EdgeNEXUS Manager for gateway %v/%v: %w", gEx.Gateway.Namespace, gEx.Gateway.Name, err)
	}

	return warnings, nil
}

func (cnf *Configurator) addOrUpdateGateway(gEx *GatewayEx) (Warnings, error) {
	edgeCfg, warnings := GenerateEdgeConfigForGateway(gEx, cnf.cfgParams)
	name := fmt.Sprintf("gw_%s_%s", gEx.Gateway.Namespace, gEx.Gateway.Name)

	// We reuse the Ingress template for now as the structure is compatible (IngressEdgeConfig)
	content, err := cnf.templateExecutor.ExecuteIngressConfigTemplate(&edgeCfg)
	if err != nil {
		return warnings, fmt.Errorf("Error generating Gateway Config %v: %w", name, err)
	}
	cnf.edgeManager.CreateConfig(name, content)

	cnf.gateways[name] = gEx
	return warnings, nil
}

// DeleteGateway deletes EdgeNexus configuration for the Gateway resource.
func (cnf *Configurator) DeleteGateway(key string) error {
	name := fmt.Sprintf("gw_%s", strings.Replace(key, "/", "_", -1))
	cnf.edgeManager.DeleteConfig(name)

	delete(cnf.gateways, name)

	if err := cnf.reload(edge.ReloadForOtherUpdate); err != nil {
		return fmt.Errorf("Error when removing gateway %v: %w", key, err)
	}

	return nil
}
