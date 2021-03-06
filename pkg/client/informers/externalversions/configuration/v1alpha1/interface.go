// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	internalinterfaces "github.com/edgeNEXUS/kubernetes-ingress/pkg/client/informers/externalversions/internalinterfaces"
)

// Interface provides access to all the informers in this group version.
type Interface interface {
	// GlobalConfigurations returns a GlobalConfigurationInformer.
	GlobalConfigurations() GlobalConfigurationInformer
	// TransportServers returns a TransportServerInformer.
	TransportServers() TransportServerInformer
}

type version struct {
	factory          internalinterfaces.SharedInformerFactory
	namespace        string
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// New returns a new Interface.
func New(f internalinterfaces.SharedInformerFactory, namespace string, tweakListOptions internalinterfaces.TweakListOptionsFunc) Interface {
	return &version{factory: f, namespace: namespace, tweakListOptions: tweakListOptions}
}

// GlobalConfigurations returns a GlobalConfigurationInformer.
func (v *version) GlobalConfigurations() GlobalConfigurationInformer {
	return &globalConfigurationInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// TransportServers returns a TransportServerInformer.
func (v *version) TransportServers() TransportServerInformer {
	return &transportServerInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}