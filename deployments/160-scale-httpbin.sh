#!/bin/bash

kubectl scale --replicas=2 deployment/httpbin -n httpbin
