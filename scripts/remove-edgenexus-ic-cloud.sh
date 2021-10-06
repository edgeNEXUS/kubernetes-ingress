#!/usr/bin/bash

echo "Remove existing EdgeNEXUS Ingress Controller..."
kubectl delete namespace edgenexus-ingress
kubectl delete clusterrole edgenexus-ingress
kubectl delete clusterrolebinding edgenexus-ingress
# AND for Kuber 1.18+ (<https://kubernetes.io/blog/2020/04/02/improvements-to-the-ingress-api-in-kubernetes-1.18/>):
kubectl delete IngressClass edgenexus

echo "Removed."
