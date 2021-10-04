#!/bin/bash

set -e

kubectl apply -f 060-deploy-httpbin.yaml
kubectl get services -n httpbin
