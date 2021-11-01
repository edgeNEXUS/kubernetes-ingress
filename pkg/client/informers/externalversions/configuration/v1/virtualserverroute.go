// Code generated by informer-gen. DO NOT EDIT.

package v1

import (
	"context"
	time "time"

	configurationv1 "github.com/edgeNEXUS/kubernetes-ingress/pkg/apis/configuration/v1"
	versioned "github.com/edgeNEXUS/kubernetes-ingress/pkg/client/clientset/versioned"
	internalinterfaces "github.com/edgeNEXUS/kubernetes-ingress/pkg/client/informers/externalversions/internalinterfaces"
	v1 "github.com/edgeNEXUS/kubernetes-ingress/pkg/client/listers/configuration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// VirtualServerRouteInformer provides access to a shared informer and lister for
// VirtualServerRoutes.
type VirtualServerRouteInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1.VirtualServerRouteLister
}

type virtualServerRouteInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
	namespace        string
}

// NewVirtualServerRouteInformer constructs a new informer for VirtualServerRoute type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewVirtualServerRouteInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredVirtualServerRouteInformer(client, namespace, resyncPeriod, indexers, nil)
}

// NewFilteredVirtualServerRouteInformer constructs a new informer for VirtualServerRoute type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredVirtualServerRouteInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.K8sV1().VirtualServerRoutes(namespace).List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.K8sV1().VirtualServerRoutes(namespace).Watch(context.TODO(), options)
			},
		},
		&configurationv1.VirtualServerRoute{},
		resyncPeriod,
		indexers,
	)
}

func (f *virtualServerRouteInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredVirtualServerRouteInformer(client, f.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *virtualServerRouteInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&configurationv1.VirtualServerRoute{}, f.defaultInformer)
}

func (f *virtualServerRouteInformer) Lister() v1.VirtualServerRouteLister {
	return v1.NewVirtualServerRouteLister(f.Informer().GetIndexer())
}