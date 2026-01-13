package k8s

import (
	"context"
	"time"

	"github.com/golang/glog"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	
	// Gateway API imports
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	gatewayclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
	gatewayinformers "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions"
)

// GatewayController watches Gateway API resources and configures EdgeNexus.
type GatewayController struct {
	client        gatewayclient.Interface
	informerFactory gatewayinformers.SharedInformerFactory
	queue         *TaskQueue
}

// NewGatewayController creates a new GatewayController.
func NewGatewayController(config *rest.Config) (*GatewayController, error) {
	client, err := gatewayclient.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	informerFactory := gatewayinformers.NewSharedInformerFactory(client, 10*time.Minute)
	
	gc := &GatewayController{
		client:        client,
		informerFactory: informerFactory,
		queue:         NewTaskQueue(func(key interface{}) error {
			glog.Infof("Syncing Gateway resource: %v", key)
			return nil
		}),
	}

	// Register handlers for GatewayClass
	informerFactory.Gateway().V1beta1().GatewayClasses().Informer().AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				gc.queue.Enqueue(obj)
			},
			UpdateFunc: func(old, cur interface{}) {
				gc.queue.Enqueue(cur)
			},
			DeleteFunc: func(obj interface{}) {
				gc.queue.Enqueue(obj)
			},
		},
	)

	// Register handlers for Gateway
	informerFactory.Gateway().V1beta1().Gateways().Informer().AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				gc.queue.Enqueue(obj)
			},
			UpdateFunc: func(old, cur interface{}) {
				gc.queue.Enqueue(cur)
			},
			DeleteFunc: func(obj interface{}) {
				gc.queue.Enqueue(obj)
			},
		},
	)

	// Register handlers for HTTPRoute
	informerFactory.Gateway().V1beta1().HTTPRoutes().Informer().AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				gc.queue.Enqueue(obj)
			},
			UpdateFunc: func(old, cur interface{}) {
				gc.queue.Enqueue(cur)
			},
			DeleteFunc: func(obj interface{}) {
				gc.queue.Enqueue(obj)
			},
		},
	)

	return gc, nil
}

// Run starts the Gateway controller.
func (gc *GatewayController) Run(stopCh <-chan struct{}) {
	glog.Info("Starting Gateway Controller")

	gc.informerFactory.Start(stopCh)
	gc.informerFactory.WaitForCacheSync(stopCh)

	go gc.queue.Run(time.Second, stopCh)

	<-stopCh
	glog.Info("Stopping Gateway Controller")
	gc.queue.Shutdown()
}
