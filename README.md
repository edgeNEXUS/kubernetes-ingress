Edgenexus Ingress Controller
============================

Overview
--------

edgenexus-ingress is an Ingress Controller (IC) for Kubernetes using Edgenexus
as a reverse proxy and load balancer.

Get Started
-----------

In the directory `deployments`, you can find useful deployment scripts to run
IC.

### Deploy two simple HTTP services ###

There are two sample services that we are going to test from IC. Deploy them:

    kubectl apply -f 010-deploy-echo.yaml
    kubectl apply -f 011-deploy-httpbin.yaml

To check deployed services:

    kubectl get services -n echo

    # NAME           TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)   AGE
    # echo-service   ClusterIP   10.101.119.221   <none>        80/TCP    39h

    kubectl get events --namespace=echo

    # LAST SEEN   TYPE     REASON           OBJECT                                MESSAGE
    # 15s         Normal   SandboxChanged   pod/echo-deployment-b97d6c86f-pphwv   Pod sandbox changed, it will be killed and re-created.
    # 14s         Normal   Pulling          pod/echo-deployment-b97d6c86f-pphwv   Pulling image "mendhak/http-https-echo"
    # 13s         Normal   Pulled           pod/echo-deployment-b97d6c86f-pphwv   Successfully pulled image "mendhak/http-https-echo" in 1.026127723s
    # 13s         Normal   Created          pod/echo-deployment-b97d6c86f-pphwv   Created container echo
    # 13s         Normal   Started          pod/echo-deployment-b97d6c86f-pphwv   Started container echo
    # 42s         Normal   AddedOrUpdated   ingress/echo-ingress                  Configuration for echo/echo-ingress was added or updated

    kubectl get services -n httpbin

    # NAME      TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)   AGE
    # httpbin   ClusterIP   10.110.41.17   <none>        80/TCP    39h

### Deploy IC ###

1. Run below commands to make Edgenexus IC able to use custom RESTful resource
paths on Kubernetes API Server:

       kubectl apply -f common/crds/k8s.edgenexus.io_globalconfigurations.yaml
       kubectl apply -f common/crds/k8s.edgenexus.io_policies.yaml
       kubectl apply -f common/crds/k8s.edgenexus.io_transportservers.yaml
       kubectl apply -f common/crds/k8s.edgenexus.io_virtualserverroutes.yaml
       kubectl apply -f common/crds/k8s.edgenexus.io_virtualservers.yaml

2. If you need to remove previous Edgenexus IC deployment:

       kubectl delete namespace edgenexus-ingress
       kubectl delete clusterrole edgenexus-ingress
       kubectl delete clusterrolebinding edgenexus-ingress
       # AND for k8s 1.18+ (<https://kubernetes.io/blog/2020/04/02/improvements-to-the-ingress-api-in-kubernetes-1.18/>):
       kubectl delete IngressClass edgenexus

3. Deploy Edgenexus IC using `deploy-edgenexus-cloud.yaml`. Since Edgenexus
is currently working as an external load balancer, please change the following
IP addresses to your own:

   - `loadBalancerIP: 192.168.2.132`
   - `-edge-balancer-ip=192.168.2.132`
   - `-edge-external-ip=192.168.2.135`

   You can set Edgenexus ADC username and password:

   - `-edge-balancer-user=admin`
   - `-edge-balancer-pass=jetnexus`

   IC image is `docker.io/edgenexus/edgenexus-ingress:latest` and that is set
the yaml file.

   So the command to deploy IC is as follows:

       kubectl apply -f deploy-edgenexus-ic-cloud.yaml

       # namespace/edgenexus-ingress created
       # serviceaccount/edgenexus-ingress created
       # serviceaccount/edgenexus-ingress configured
       # secret/edgenexus-ingress-default-server-tls created
       # configmap/edgenexus-ingress created
       # configmap/edgenexus-ingress-leader-election created
       # clusterrole.rbac.authorization.k8s.io/edgenexus-ingress created
       # clusterrolebinding.rbac.authorization.k8s.io/edgenexus-ingress created
       # service/edgenexus-ingress created
       # deployment.apps/edgenexus-ingress created
       # ingressclass.networking.k8s.io/edgenexus created

4. Get IC deployment details:

       kubectl describe svc edgenexus-ingress --namespace=edgenexus-ingress
       kubectl get pods --all-namespaces
       # ...
       kubectl get events --namespace=edgenexus-ingress

### Enable IC for two sample services ###

You can test it one by one to see changes on Edgenexus ADC:

    kubectl apply -f 020-ingress-echo.yaml
    kubectl apply -f 021-ingress-httpbin.yaml

Please note that file `020-ingress-echo.yaml` has SSL certificate for HTTPS
defined as:

```
apiVersion: v1
kind: Secret
metadata:
  name: echo-secret
  namespace: echo
type: kubernetes.io/tls
data:
  tls.crt: LS0tLS...
  tls.key: LS0tLS...
```

In current configuration, ADC API server is `192.168.2.132` and VS
for Kubernetes service endpoints is `192.168.2.135` (if you didn't change
addresses to your own). IC adds VS, RS and set flightPATHs to created VS.

After applying ingress for two sample services, you can see how IC works from
Log Output. For example, this is how IC is finished with last changes (run
`scripts/ingress-diag.sh` to see such logs):

```
2021-10-04 18:29:53 +0000 [14] [info ] edge/manager/web: Received request to return version of applied YAML config
2021-10-04 18:29:53 +0000 [14] [info ] edge/manager/web: Return config version: 0
2021-10-04 18:29:54 +0000 [275] [warn ] edge/clientapi/request/flightpath: ALB API request to drag-n-drop FPs raised a warning in manage_vs_fps(): 'Terminal flightPATH rule Kubernetes Ingress 1633372143.20388 can prevent later rules from running.'
2021-10-04 18:29:54 +0000 [14] [info ] edge/clientapi/feed: Created and enabled flightPATH 'Kubernetes Ingress 1633372143.20388' for 192.168.2.135/255.255.255.255:80
2021-10-04 18:29:54 +0000 [14] [info ] edge/clientapi/feed: VS 192.168.2.135/255.255.255.255:80 is completely configured
2021-10-04 18:29:54 +0000 [14] [info ] edge/clientapi/feed: Determine and configure VSs that are not created...
2021-10-04 18:29:54 +0000 [14] [info ] edge/clientapi/feed: No new VSs to add
2021-10-04 18:29:54 +0000 [14] [info ] edge/clientapi/feed: Provide applied config version: 1
2021-10-04 18:29:54 +0000 [14] [info ] edge/clientapi/feed: 
2021-10-04 18:29:54 +0000 + -------------------------------------------------------
2021-10-04 18:29:54 +0000 + Congrats! Feeding done. Config version in use is 1.
2021-10-04 18:29:54 +0000 + -------------------------------------------------------
2021-10-04 18:29:57 +0000 [14] [info ] edge/manager/web: Received request to return version of applied YAML config
2021-10-04 18:29:57 +0000 [14] [info ] edge/manager/web: Return config version: 1
```

### Scale two sample services ###

When you scale Kubernetes services, appropriate RS/flightPATH are created on
Edgenexus ADC by IC:

    kubectl scale --replicas=2 deployment/echo-deployment -n echo
    kubectl scale --replicas=2 deployment/httpbin -n httpbin

### Remove two sample services ###

When you remove Kubernetes services, appropriate RS/flightPATH are removed
from Edgenexus ADC by IC:

    kubectl delete ingress echo-ingress -n echo
    kubectl delete deployments echo-deployment -n echo

    kubectl delete ingress httpbin-ingress -n httpbin
    kubectl delete deployments httpbin -n httpbin

### Misc ###

If you need to open `bash` in IC container, run `scripts/ingress-bash.sh` or
similar command if you are not using `kubelet`.

The script `scripts/ingress-diag.sh` is to see IC logs.

Container
---------

Run `make image` to create docker image with IC from CentOS 6.10 amd64 base
image. `build/Dockerfile` is used for that.

Binaries `edgenexus-ingress` and `edgenexus-manager` are working on this OS.

Run `make push` to push docker image to `edgenexus/edgenexus-ingress`.

Questions
---------

**Q:** What is RS `127.0.0.1:8181` on the ADC?

**A:** This is the default server which should always return HTTP 502. It is
used for services that have no endpoints.

Development
-----------

To build project in container and push image to
`edgenexus/edgenexus-ingress:latest-centos8`:

    make centos8-image-push TARGET=container

Or to build project locally (Go 1.17 must be installed on your machine):

    make centos8-image

When local build is done, make Docker push to `$PREFIX` and `$TAG`:

    make push

TODO
----

1. Optimize API requests to the ADC; increase configuration speed.
2. Apply SSL certificates and test HTTPS.
3. Prepare IC image with the ADC with VS address(es) determined correctly.
4. Are RS balanced if they specified by `Use Server` action?
5. Clean source code after finalization.
6. Use helm templates (can be copied from NGINX IC -- Apache License,
Version 2.0).
