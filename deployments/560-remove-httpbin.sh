#!/bin/bash

kubectl delete ingress httpbin-ingress -n httpbin
kubectl delete deployments httpbin -n httpbin
