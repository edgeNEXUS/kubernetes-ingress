#!/bin/bash

kubectl scale --replicas=2 deployment/echo-deployment -n echo
