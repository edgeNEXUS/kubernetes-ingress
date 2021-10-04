#!/usr/bin/bash

./001-remove-edgenexus-cloud.sh

set -e

echo "Apply EdgeNEXUS Ingress Controller..."
kubectl apply -f 005-deploy-edgenexus-cloud.yaml
echo "Applied."

echo
echo "Show info..."
kubectl describe svc edgenexus-ingress --namespace=edgenexus-ingress
kubectl get pods --all-namespaces
kubectl get events --namespace=edgenexus-ingress

# Diag. (https://stackoverflow.com/questions/62740869/nginx-ingress-controller-crashloopbackoff-kubernetes-on-proxmox-kvm)
echo
echo "Diag..."
POD_NAMESPACE=edgenexus-ingress
POD_NAME=
while [ "$POD_NAME" == "" ]
do
    echo "Try to get POD name (wait for container running)..."
    sleep 1
    set +e
    POD_NAME=$(kubectl get pods -n $POD_NAMESPACE --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
done
set -e
echo "Found POD $POD_NAME"
kubectl describe pod ${POD_NAME} -n edgenexus-ingress
kubectl logs ${POD_NAME} -n edgenexus-ingress -v10
