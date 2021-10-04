#!/bin/bash

POD_NAMESPACE=edgenexus-ingress
POD_NAME=$(kubectl get pods -n edgenexus-ingress --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
kubectl exec -it -n "$POD_NAMESPACE" "$POD_NAME" -- uname -a
kubectl exec -it -n "$POD_NAMESPACE" "$POD_NAME" -- cat /etc/issue
kubectl exec -it -n "$POD_NAMESPACE" "$POD_NAME" -- bash
