# How to use the Kub-IC Ingress Controller for EdgeADC #

### You can find a fully informative guide to installing and using the Kub-IC ingress controller for Kubernetes by selecting the Wiki option on the menu bar. Or, click here <https://github.com/edgeNEXUS/kubernetes-ingress/wiki> ###

___

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

To build project in container:

    make centos8-image TARGET=container

Or build project in container and push image to
`edgenexus/edgenexus-ingress:latest-centos8`:

    make centos8-image-push TARGET=container

Or to build project locally (Go 1.17 must be installed on your machine):

    make centos8-image

When local build is done, make Docker push to `$PREFIX` and `$TAG`:

    make push

Helm Chart
----------

A Helm chart is available in `charts/edgenexus-ingress`.

To install:

    helm install my-release ./charts/edgenexus-ingress

TODO
----

1. Optimize API requests to the ADC; increase configuration speed.
2. [x] Apply SSL certificates and test HTTPS. (Verified in code)
3. Prepare IC image with the ADC with VS address(es) determined correctly.
4. Are RS balanced if they specified by `Use Server` action?
5. Clean source code after finalization.
6. [x] Use helm templates (See `charts/edgenexus-ingress`)
7. [ ] Implement Kubernetes Gateway API support
Version 2.0).
