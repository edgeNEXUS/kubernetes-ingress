#!/bin/bash

kubectl delete ingress echo-ingress -n echo
kubectl delete deployments echo-deployment -n echo
