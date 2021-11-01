// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	"time"

	v1alpha1 "github.com/edgeNEXUS/kubernetes-ingress/pkg/apis/configuration/v1alpha1"
	scheme "github.com/edgeNEXUS/kubernetes-ingress/pkg/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// TransportServersGetter has a method to return a TransportServerInterface.
// A group's client should implement this interface.
type TransportServersGetter interface {
	TransportServers(namespace string) TransportServerInterface
}

// TransportServerInterface has methods to work with TransportServer resources.
type TransportServerInterface interface {
	Create(ctx context.Context, transportServer *v1alpha1.TransportServer, opts v1.CreateOptions) (*v1alpha1.TransportServer, error)
	Update(ctx context.Context, transportServer *v1alpha1.TransportServer, opts v1.UpdateOptions) (*v1alpha1.TransportServer, error)
	UpdateStatus(ctx context.Context, transportServer *v1alpha1.TransportServer, opts v1.UpdateOptions) (*v1alpha1.TransportServer, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.TransportServer, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.TransportServerList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.TransportServer, err error)
	TransportServerExpansion
}

// transportServers implements TransportServerInterface
type transportServers struct {
	client rest.Interface
	ns     string
}

// newTransportServers returns a TransportServers
func newTransportServers(c *K8sV1alpha1Client, namespace string) *transportServers {
	return &transportServers{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the transportServer, and returns the corresponding transportServer object, and an error if there is any.
func (c *transportServers) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.TransportServer, err error) {
	result = &v1alpha1.TransportServer{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("transportservers").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of TransportServers that match those selectors.
func (c *transportServers) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.TransportServerList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.TransportServerList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("transportservers").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested transportServers.
func (c *transportServers) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("transportservers").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a transportServer and creates it.  Returns the server's representation of the transportServer, and an error, if there is any.
func (c *transportServers) Create(ctx context.Context, transportServer *v1alpha1.TransportServer, opts v1.CreateOptions) (result *v1alpha1.TransportServer, err error) {
	result = &v1alpha1.TransportServer{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("transportservers").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(transportServer).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a transportServer and updates it. Returns the server's representation of the transportServer, and an error, if there is any.
func (c *transportServers) Update(ctx context.Context, transportServer *v1alpha1.TransportServer, opts v1.UpdateOptions) (result *v1alpha1.TransportServer, err error) {
	result = &v1alpha1.TransportServer{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("transportservers").
		Name(transportServer.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(transportServer).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *transportServers) UpdateStatus(ctx context.Context, transportServer *v1alpha1.TransportServer, opts v1.UpdateOptions) (result *v1alpha1.TransportServer, err error) {
	result = &v1alpha1.TransportServer{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("transportservers").
		Name(transportServer.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(transportServer).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the transportServer and deletes it. Returns an error if one occurs.
func (c *transportServers) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("transportservers").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *transportServers) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("transportservers").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched transportServer.
func (c *transportServers) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.TransportServer, err error) {
	result = &v1alpha1.TransportServer{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("transportservers").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}