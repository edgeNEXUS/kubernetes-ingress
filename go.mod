module github.com/edgeNEXUS/kubernetes-ingress

go 1.16

require (
	github.com/aws/aws-sdk-go-v2/config v1.8.2
	github.com/aws/aws-sdk-go-v2/service/marketplacemetering v1.5.1
	github.com/dgrijalva/jwt-go/v4 v4.0.0-preview1
	github.com/golang/glog v1.0.0
	github.com/google/go-cmp v0.5.6
	github.com/imdario/mergo v0.3.12
	github.com/prometheus/client_golang v1.12.1
	github.com/spiffe/go-spiffe v1.1.0
	k8s.io/api v0.24.1
	k8s.io/apimachinery v0.24.1
	k8s.io/client-go v0.24.1
	k8s.io/code-generator v0.24.1
	sigs.k8s.io/controller-tools v0.7.0
	sigs.k8s.io/gateway-api v0.5.0 // indirect
)
