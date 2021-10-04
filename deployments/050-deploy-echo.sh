#!/bin/bash

set -e

kubectl apply -f 050-deploy-echo.yaml
kubectl get services -n echo
