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

// GlobalConfigurationsGetter has a method to return a GlobalConfigurationInterface.
// A group's client should implement this interface.
type GlobalConfigurationsGetter interface {
	GlobalConfigurations(namespace string) GlobalConfigurationInterface
}

// GlobalConfigurationInterface has methods to work with GlobalConfiguration resources.
type GlobalConfigurationInterface interface {
	Create(ctx context.Context, globalConfiguration *v1alpha1.GlobalConfiguration, opts v1.CreateOptions) (*v1alpha1.GlobalConfiguration, error)
	Update(ctx context.Context, globalConfiguration *v1alpha1.GlobalConfiguration, opts v1.UpdateOptions) (*v1alpha1.GlobalConfiguration, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.GlobalConfiguration, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.GlobalConfigurationList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.GlobalConfiguration, err error)
	GlobalConfigurationExpansion
}

// globalConfigurations implements GlobalConfigurationInterface
type globalConfigurations struct {
	client rest.Interface
	ns     string
}

// newGlobalConfigurations returns a GlobalConfigurations
func newGlobalConfigurations(c *K8sV1alpha1Client, namespace string) *globalConfigurations {
	return &globalConfigurations{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the globalConfiguration, and returns the corresponding globalConfiguration object, and an error if there is any.
func (c *globalConfigurations) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.GlobalConfiguration, err error) {
	result = &v1alpha1.GlobalConfiguration{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("globalconfigurations").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of GlobalConfigurations that match those selectors.
func (c *globalConfigurations) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.GlobalConfigurationList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.GlobalConfigurationList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("globalconfigurations").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested globalConfigurations.
func (c *globalConfigurations) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("globalconfigurations").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a globalConfiguration and creates it.  Returns the server's representation of the globalConfiguration, and an error, if there is any.
func (c *globalConfigurations) Create(ctx context.Context, globalConfiguration *v1alpha1.GlobalConfiguration, opts v1.CreateOptions) (result *v1alpha1.GlobalConfiguration, err error) {
	result = &v1alpha1.GlobalConfiguration{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("globalconfigurations").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(globalConfiguration).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a globalConfiguration and updates it. Returns the server's representation of the globalConfiguration, and an error, if there is any.
func (c *globalConfigurations) Update(ctx context.Context, globalConfiguration *v1alpha1.GlobalConfiguration, opts v1.UpdateOptions) (result *v1alpha1.GlobalConfiguration, err error) {
	result = &v1alpha1.GlobalConfiguration{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("globalconfigurations").
		Name(globalConfiguration.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(globalConfiguration).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the globalConfiguration and deletes it. Returns an error if one occurs.
func (c *globalConfigurations) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("globalconfigurations").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *globalConfigurations) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("globalconfigurations").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched globalConfiguration.
func (c *globalConfigurations) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.GlobalConfiguration, err error) {
	result = &v1alpha1.GlobalConfiguration{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("globalconfigurations").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}