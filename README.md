EdgeNEXUS Ingress Controller
============================

Overview
--------

edgenexus-ingress is an Ingress Controller (IC) for Kubernetes using EdgeNEXUS
as a reverse proxy and load balancer.

Preview
-------

In the directory `deployments`, you can find useful deployment scripts to run
IC.

1. Run `000-common.sh` to IC able to use custom RESTful resource paths on
Kubernetes API Server. It must run just once.

2. Run `001-remove-edgenexus-cloud.sh` to remove IC, if you had it installed
previously.

3. Run `005-deploy-edgenexus-cloud.sh` to deploy and install IC. After
installation, you scan run the script `scripts/ingress-diag.sh` to see Log
Output of IC.

This script uses template `005-deploy-edgenexus-cloud.yaml` for EdgeNEXUS
working as external load balancer. Please change the following IP addresses to
your own:

  - `loadBalancerIP: 192.168.2.132` and `-edge-balancer-ip=192.168.2.132`
  - `-edge-external-ip=192.168.2.135`

In current configuration ADC API server is `192.168.2.132` and VS
for Kubernetes service endpoints is `192.168.2.135`. To this VS, IC adds RS
and set flightPATHs.

IC image is `docker.io/edgenexus/edgenexus-ingress:latest` (follow
`005-deploy-edgenexus-cloud.yaml`).

4. Run `050-deploy-echo.sh` to deploy and launch first service.

5. Run `051-ingress-echo.sh`. After that you can see in Log Output how IC works.
For example, this is how IC finished with that change (run
`scripts/ingress-diag.sh`):

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

6. Run `060-deploy-httpbin.sh` to deploy and launch another service in similar
way.

7. Run `061-ingress-httpbin.sh`. After that you may see in Log Output how IC
works.

8. Run `150-scale-echo.sh` to scale the first service to 2 replicas.

9. Run `160-scale-httpbin.sh` to scale the second service to 2 replicas.

10. Run `550-remove-echo.sh` to remove first POD.

11. Run `560-remove-httpbin.sh` to remove second POD.

All corresponding changes are applied on the ADC.

If you need to open `bash` in IC container, run `scripts/ingress-bash.sh` or
similar command if you are not on `kubelet`.

The script `scripts/ingress-diag.sh` is to see IC logs.

Container
---------

Run `make image` to create docker image with
IC from CentOS 6.10 amd64 base image. `build/Dockerfile` is used for that.

Binaries `edgenexus-ingress` and `edgenexus-manager` are working on this OS.

Run `make push` to push docker image to `edgenexus/edgenexus-ingress`.

Questions
---------

**Q:** What is RS `127.0.0.1:8181` on the ADC?

**A:** This is the default server which should always return HTTP 502. It is
used for services that have no endpoints. We need to use another solution after
discussing what it should be.

TODO
----

1. Optimize API requests to the ADC; increase configuration speed.
2. Apply SSL certificates and test HTTPS.
3. Prepare IC image with the ADC with VS address(es) determined correctly.
4. Are RS balanced if they specified by `Use Server` action?
5. Clean source code after finalization.
6. Use helm templates (can be copied from NGINX IC -- Apache License,
Version 2.0).
7. Do we need Prometheus metrics? If so, solve error: `Failed to get
http://config-status/stub_status: Get "http://config-status/stub_status": dial
unix /var/lib/edgenexus-manager/edge-status.sock: connect: no such file or
directory`
