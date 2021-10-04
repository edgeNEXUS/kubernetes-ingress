#!/bin/sh

set -e

# Run it make EdgeNEXUS Ingress Controller able to use custom RESTful resource
# paths on Kubernetes API Server.
kubectl apply -f common/k8s.edgenexus.io_globalconfigurations.yaml
kubectl apply -f common/k8s.edgenexus.io_policies.yaml
kubectl apply -f common/k8s.edgenexus.io_transportservers.yaml
kubectl apply -f common/k8s.edgenexus.io_virtualserverroutes.yaml
kubectl apply -f common/k8s.edgenexus.io_virtualservers.yaml
