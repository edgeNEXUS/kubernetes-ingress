PREFIX = edgenexus/edgenexus-ingress
GIT_COMMIT = $(shell git rev-parse HEAD || echo unknown)
GIT_COMMIT_SHORT = $(shell echo ${GIT_COMMIT} | cut -c1-7)
GIT_TAG = $(shell git describe --tags --abbrev=0 || echo untagged)
DATE = $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
VERSION = $(GIT_TAG)-SNAPSHOT-$(GIT_COMMIT_SHORT)
TAG = $(VERSION:v%=%)
TARGET ?= local

override DOCKER_BUILD_OPTIONS += --build-arg IC_VERSION=$(VERSION) --build-arg GIT_COMMIT=$(GIT_COMMIT) --build-arg DATE=$(DATE)
DOCKER_CMD = docker build $(DOCKER_BUILD_OPTIONS) --target $(TARGET) -f build/Dockerfile -t $(PREFIX):$(TAG) -t $(PREFIX):latest .

export DOCKER_BUILDKIT = 1

.DEFAULT_GOAL:=help

.PHONY: help
help: ## Display this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "; printf "Usage:\n\n    make \033[36m<target>\033[0m [VARIABLE=value...]\n\nTargets:\n\n"}; {printf "    \033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: all
all: image push

.PHONY: image
image: ## Create Docker image for Ingress Controller (centos)
	$(DOCKER_CMD) --build-arg BUILD_OS=centos

.PHONY: push
push: ## Docker push to $PREFIX and $TAG
	docker push $(PREFIX):$(TAG)

.PHONY: clean
clean:  ## Remove edgenexus-ingress and edgenexus-manager binaries
	-rm edgenexus-ingress
	-rm edgenexus-manager
	-rm -r dist
