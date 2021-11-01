PREFIX = edgenexus/edgenexus-ingress
GIT_COMMIT = $(shell git rev-parse HEAD || echo unknown)
GIT_COMMIT_SHORT = $(shell echo ${GIT_COMMIT} | cut -c1-7)
GIT_TAG = $(shell git describe --tags --abbrev=0 || echo untagged)
DATE = $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
VERSION = $(GIT_TAG)-SNAPSHOT-$(GIT_COMMIT_SHORT)
TAG = $(VERSION:v%=%)
TARGET ?= local

override DOCKER_BUILD_OPTIONS += --build-arg IC_VERSION=$(VERSION) --build-arg GIT_COMMIT=$(GIT_COMMIT) --build-arg DATE=$(DATE)
DOCKER_CMD = docker build $(DOCKER_BUILD_OPTIONS) --target $(TARGET) -f build/Dockerfile -t $(PREFIX):$(TAG) .

export DOCKER_BUILDKIT = 1

.DEFAULT_GOAL:=help

.PHONY: help
help: ## Display this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "; printf "Usage:\n\n    make \033[36m<target>\033[0m [VARIABLE=value...]\n\nTargets:\n\n"}; {printf "    \033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: all
all: update-crds centos8-image

#.PHONY: lint
#lint: ## Run linter
#	docker run --pull always --rm -v $(shell pwd):/kubernetes-ingress -w /kubernetes-ingress -v $(shell go env GOCACHE):/cache/go -e GOCACHE=/cache/go -e GOLANGCI_LINT_CACHE=/cache/go -v $(shell go env GOPATH)/pkg:/go/pkg golangci/golangci-lint:latest golangci-lint --color always run -v

.PHONY: update-crds
update-crds: ## Update CRDs
	go run sigs.k8s.io/controller-tools/cmd/controller-gen crd:crdVersions=v1 schemapatch:manifests=./deployments/common/crds/ paths=./pkg/apis/configuration/... output:dir=./deployments/common/crds

.PHONY: build
build: ## Build Edgenexus Ingress Controller binary
	@docker -v || (code=$$?; printf "\033[0;31mError\033[0m: there was a problem with Docker\n"; exit $$code)
ifeq (${TARGET},local)
	@go version || (code=$$?; printf "\033[0;31mError\033[0m: unable to build locally, try using the parameter TARGET=container\n"; exit $$code)
	CGO_ENABLED=0 GO111MODULE=on GOOS=linux go build -trimpath -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${GIT_COMMIT} -X main.date=$(DATE)" -o edgenexus-ingress github.com/edgeNEXUS/kubernetes-ingress/cmd/edgenexus-ingress
endif

.PHONY: build-goreleaser
build-goreleaser: ## Build Edgenexus Ingress Controller binary using GoReleaser
	@goreleaser -v || (code=$$?; printf "\033[0;31mError\033[0m: there was a problem with GoReleaser. Follow the docs to install it https://goreleaser.com/install\n"; exit $$code)
	GOPATH=$(shell go env GOPATH) goreleaser build --rm-dist --debug --snapshot --id kubernetes-ingress

.PHONY: centos8-image
centos8-image: build ## Create Docker image for Ingress Controller (centos8)
	$(DOCKER_CMD) --build-arg BUILD_OS=centos8

.PHONY: centos6-image
centos6-image: build ## Create Docker image for Ingress Controller (centos6)
	$(DOCKER_CMD) --build-arg BUILD_OS=centos6

.PHONY: centos8-image-push
centos8-image-push: centos8-image ## Docker push to $PREFIX:$TAG-centos8 and $PREFIX:latest-centos8
	docker tag $(PREFIX):$(TAG) $(PREFIX):$(TAG)-centos8
	docker tag $(PREFIX):$(TAG) $(PREFIX):latest-centos8
	docker push $(PREFIX):latest-centos8

.PHONY: centos6-image-push
centos6-image-push: centos6-image ## Docker push to $PREFIX:$TAG-centos6 and $PREFIX:latest-centos6
	docker tag $(PREFIX):$(TAG) $(PREFIX):$(TAG)-centos6
	docker tag $(PREFIX):$(TAG) $(PREFIX):latest-centos6
	docker push $(PREFIX):latest-centos6

.PHONY: all-images ## Create all the Docker images for Ingress Controller
all-images: centos8-image centos6-image

#.PHONY: push
#push: ## Docker push to $PREFIX and $TAG
#	docker push $(PREFIX):$(TAG)

.PHONY: clean
clean:  ## Remove edgenexus-ingress and edgenexus-manager binaries
	-rm edgenexus-ingress
	-rm edgenexus-manager

.PHONY: deps
deps: ## Add missing and remove unused modules, verify deps and dowload them to local cache
	@go mod tidy && go mod verify && go mod download

.PHONY: clean-cache
clean-cache: ## Clean go cache
	@go clean -modcache
