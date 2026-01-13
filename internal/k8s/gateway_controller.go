package k8s

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/glog"
	"github.com/edgeNEXUS/kubernetes-ingress/internal/configs"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	listersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	// Gateway API imports
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	gatewayclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
	gatewayinformers "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions"
	gatewaylisters "sigs.k8s.io/gateway-api/pkg/client/listers/apis/v1beta1"
)

const (
	// ControllerName is the name of the EdgeNexus Gateway Controller
	GatewayControllerName = "edgenexus.io/gateway-controller"
)

// GatewayController watches Gateway API resources and configures EdgeNexus.
type GatewayController struct {
	client             gatewayclient.Interface
	kubeClient         kubernetes.Interface
	gatewayLister      gatewaylisters.GatewayLister
	gatewayClassLister gatewaylisters.GatewayClassLister
	httpRouteLister    gatewaylisters.HTTPRouteLister
	serviceLister      listersv1.ServiceLister
	endpointLister     listersv1.EndpointsLister
	queue              *taskQueue
	configurator       *configs.Configurator
	syncQueue          workqueue.RateLimitingInterface
	
	// HasSynced functions
	gatewaySynced      cache.InformerSynced
	gatewayClassSynced cache.InformerSynced
	httpRouteSynced    cache.InformerSynced
	serviceSynced      cache.InformerSynced
	endpointSynced     cache.InformerSynced
}

// NewGatewayController creates a new GatewayController.
func NewGatewayController(
	kubeClient kubernetes.Interface,
	gatewayClient gatewayclient.Interface,
	configurator *configs.Configurator,
	resyncPeriod time.Duration,
) *GatewayController {

	// Initialize informers
	gatewayInformerFactory := gatewayinformers.NewSharedInformerFactory(gatewayClient, resyncPeriod)
	kubeInformerFactory := informers.NewSharedInformerFactory(kubeClient, resyncPeriod)

	gatewayInformer := gatewayInformerFactory.Gateway().V1beta1().Gateways()
	gatewayClassInformer := gatewayInformerFactory.Gateway().V1beta1().GatewayClasses()
	httpRouteInformer := gatewayInformerFactory.Gateway().V1beta1().HTTPRoutes()
	serviceInformer := kubeInformerFactory.Core().V1().Services()
	endpointInformer := kubeInformerFactory.Core().V1().Endpoints()

	gc := &GatewayController{
		client:             gatewayClient,
		kubeClient:         kubeClient,
		gatewayLister:      gatewayInformer.Lister(),
		gatewayClassLister: gatewayClassInformer.Lister(),
		httpRouteLister:    httpRouteInformer.Lister(),
		serviceLister:      serviceInformer.Lister(),
		endpointLister:     endpointInformer.Lister(),
		configurator:       configurator,
		gatewaySynced:      gatewayInformer.Informer().HasSynced,
		gatewayClassSynced: gatewayClassInformer.Informer().HasSynced,
		httpRouteSynced:    httpRouteInformer.Informer().HasSynced,
		serviceSynced:      serviceInformer.Informer().HasSynced,
		endpointSynced:     endpointInformer.Informer().HasSynced,
	}

	gc.queue = newTaskQueue(gc.sync)

	// Register event handlers
	gatewayInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { gc.queue.Enqueue(obj) },
		UpdateFunc: func(old, cur interface{}) { gc.queue.Enqueue(cur) },
		DeleteFunc: func(obj interface{}) { gc.queue.Enqueue(obj) },
	})

	httpRouteInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { gc.queue.Enqueue(obj) },
		UpdateFunc: func(old, cur interface{}) { gc.queue.Enqueue(cur) },
		DeleteFunc: func(obj interface{}) { gc.queue.Enqueue(obj) },
	})

	// Start informers
	stopCh := make(chan struct{}) // TODO: Manage stopCh properly in Run. 
	// Ideally informer factories should be started in Run, but for simplicity here we start them.
	// But note: NewGatewayController usually shouldn't start informers. 
	// We'll keep them here but move Start() to Run() if factories were passed in.
	// Since factories are created here, we must start them here or store them.
	// Storing them is better.
	
	// Re-design: Store factories
	go gatewayInformerFactory.Start(stopCh)
	go kubeInformerFactory.Start(stopCh)

	return gc
}

// Run starts the Gateway controller.
func (gc *GatewayController) Run(stopCh <-chan struct{}) {
	defer runtime.HandleCrash()
	defer gc.queue.Shutdown()

	glog.Info("Starting Gateway Controller")

	// Wait for caches
	if !cache.WaitForCacheSync(stopCh, 
		gc.gatewaySynced, 
		gc.gatewayClassSynced,
		gc.httpRouteSynced,
		gc.serviceSynced,
		gc.endpointSynced,
	) {
		glog.Error("Timed out waiting for caches to sync")
		return
	}

	go gc.queue.Run(time.Second, stopCh)

	<-stopCh
	glog.Info("Stopping Gateway Controller")
}

// sync reconciles the state of Gateway resources.
func (gc *GatewayController) sync(t task) {
	glog.V(3).Infof("Syncing %v %v", t.Kind, t.Key)

	switch t.Kind {
	case gateway:
		gc.processGateway(t.Key)
	case httpRoute:
		// When a route changes, we need to find which Gateway it belongs to and re-process that Gateway.
		// For simplicity, we process the route here to find its parent Gateway.
		gc.processHTTPRoute(t.Key)
	}
}

func (gc *GatewayController) processGateway(key string) {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		glog.Errorf("Invalid key %s: %v", key, err)
		return
	}

	gw, err := gc.gatewayLister.Gateways(namespace).Get(name)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Gateway deleted
			glog.Infof("Gateway %s deleted", key)
			gc.configurator.DeleteGateway(key)
			return
		}
		glog.Errorf("Error fetching Gateway %s: %v", key, err)
		return
	}

	// Verify GatewayClass
	gwClass, err := gc.gatewayClassLister.Get(string(gw.Spec.GatewayClassName))
	if err != nil {
		glog.Errorf("Error fetching GatewayClass %s: %v", gw.Spec.GatewayClassName, err)
		return
	}
	if gwClass.Spec.ControllerName != GatewayControllerName {
		glog.V(3).Infof("GatewayClass %s not managed by this controller", gwClass.Name)
		return
	}

	// Find HTTPRoutes attached to this Gateway
	routes, err := gc.findHTTPRoutesForGateway(gw)
	if err != nil {
		glog.Errorf("Error finding routes for Gateway %s: %v", key, err)
		return
	}

	// Build GatewayEx
	gEx := &configs.GatewayEx{
		Gateway:    gw.DeepCopy(),
		HTTPRoutes: routes,
		Services:   make(map[string]*v1.Service),
		Endpoints:  make(map[string][]string),
		Valid:      true,
	}

	// Resolve Services and Endpoints referenced in Routes
	for _, route := range routes {
		for _, rule := range route.Spec.Rules {
			for _, ref := range rule.BackendRefs {
				svcName := string(ref.Name)
				svcNamespace := route.Namespace
				if ref.Namespace != nil {
					svcNamespace = string(*ref.Namespace)
				}

				svc, err := gc.serviceLister.Services(svcNamespace).Get(svcName)
				if err != nil {
					glog.Errorf("Error getting service %s/%s: %v", svcNamespace, svcName, err)
					continue
				}
				gEx.Services[svcName] = svc

				endpoints, err := gc.endpointLister.Endpoints(svcNamespace).Get(svcName)
				if err != nil {
					glog.Errorf("Error getting endpoints %s/%s: %v", svcNamespace, svcName, err)
					continue
				}

				var eps []string
				for _, subset := range endpoints.Subsets {
					for _, addr := range subset.Addresses {
						for _, port := range subset.Ports {
							eps = append(eps, fmt.Sprintf("%s:%d", addr.IP, port.Port))
						}
					}
				}
				gEx.Endpoints[svcName] = eps
			}
		}
	}

	// Update Configurator
	warnings, err := gc.configurator.AddOrUpdateGateway(gEx)
	if err != nil {
		glog.Errorf("Error updating configuration for Gateway %s: %v", key, err)
		// Update status to reflect failure?
	} else {
		glog.Infof("Successfully updated configuration for Gateway %s", key)
		// Update status to Ready
		gc.updateGatewayStatus(gw)
	}
	
	if len(warnings) > 0 {
		glog.Warningf("Warnings for Gateway %s: %v", key, warnings)
	}
}

func (gc *GatewayController) processHTTPRoute(key string) {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return
	}
	
	route, err := gc.httpRouteLister.HTTPRoutes(namespace).Get(name)
	if err != nil {
		return
	}

	// Find parent Gateways and enqueue them
	for _, parentRef := range route.Spec.ParentRefs {
		gwNamespace := route.Namespace
		if parentRef.Namespace != nil {
			gwNamespace = string(*parentRef.Namespace)
		}
		gc.queue.Enqueue(&gatewayv1beta1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      string(parentRef.Name),
				Namespace: gwNamespace,
			},
		})
	}
}

func (gc *GatewayController) findHTTPRoutesForGateway(gw *gatewayv1beta1.Gateway) ([]*gatewayv1beta1.HTTPRoute, error) {
	// In a real implementation, we should use an index. For now, iterate all routes.
	allRoutes, err := gc.httpRouteLister.List(cache.Everything)
	if err != nil {
		return nil, err
	}

	var attachedRoutes []*gatewayv1beta1.HTTPRoute
	for _, route := range allRoutes {
		for _, parentRef := range route.Spec.ParentRefs {
			// Check if this route references our Gateway
			if string(parentRef.Name) == gw.Name {
				ns := route.Namespace
				if parentRef.Namespace != nil {
					ns = string(*parentRef.Namespace)
				}
				if ns == gw.Namespace {
					attachedRoutes = append(attachedRoutes, route)
					break
				}
			}
		}
	}
	return attachedRoutes, nil
}

func (gc *GatewayController) updateGatewayStatus(gw *gatewayv1beta1.Gateway) {
	// Update status logic here (set Ready condition, Assiged addresses)
	// For now, this is a placeholder.
}
