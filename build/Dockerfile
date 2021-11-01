# syntax=docker/dockerfile:1.3
ARG BUILD_OS=centos
ARG FILES=
ARG EDGENEXUS_VERSION=4.2.8

############################# Base image for CentOS 6 ##########################
FROM centos:6 AS centos6

RUN groupadd --system --gid 101 edgenexus \
    && useradd --system --gid edgenexus --no-create-home \
               --home-dir /nonexistent --comment "edgenexus user" \
               --shell /bin/false --uid 101 edgenexus


############################# Base image for CentOS 8 ##########################
FROM centos:8 AS centos8

RUN groupadd --system --gid 101 edgenexus \
    && useradd --system --gid edgenexus --no-create-home \
               --home-dir /nonexistent --comment "edgenexus user" \
               --shell /bin/false --uid 101 edgenexus


##################### Create common files and permissions ######################
FROM ${FILES:-$BUILD_OS} as common

ARG BUILD_OS
ARG IC_VERSION
ARG GIT_COMMIT
ARG DATE
ARG TARGETPLATFORM
ARG EDGENEXUS_VERSION

RUN mkdir -p /etc/edgenexus-manager \
             /etc/edgenexus-manager/conf.d \
             /var/lib/edgenexus-manager \
             /var/log/edgenexus-manager \
             /var/cache/edgenexus-manager \
             /etc/edgenexus-manager/secrets \
             /etc/edgenexus-manager/stream-conf.d \
    && chown -R edgenexus:0 \
             /etc/edgenexus-manager \
             /etc/edgenexus-manager/conf.d \
             /var/lib/edgenexus-manager \
             /var/log/edgenexus-manager \
             /var/cache/edgenexus-manager \
             /etc/edgenexus-manager/secrets \
             /etc/edgenexus-manager/stream-conf.d

COPY --chown=edgenexus:0 \
    internal/configs/version1/edgenexus.ingress.tmpl \
    internal/configs/version1/edgenexus.tmpl \
    internal/configs/version2/edgenexus.virtualserver.tmpl \
    internal/configs/version2/edgenexus.transportserver.tmpl \
    /

EXPOSE 80 443

STOPSIGNAL SIGTERM
ENTRYPOINT ["/edgenexus-ingress" ]
USER edgenexus

LABEL org.opencontainers.image.version="${IC_VERSION}"
LABEL org.opencontainers.image.revision="${GIT_COMMIT}"
LABEL org.opencontainers.image.created="${DATE}"
LABEL org.edgenexus.kic.image.build.target="${TARGETPLATFORM}"
LABEL org.edgenexus.kic.image.build.os="${BUILD_OS}"
LABEL org.edgenexus.kic.image.build.edgenexus.vesion="${EDGENEXUS_VERSION}"


################## Build edgenexus-ingress in golang container #################
FROM golang:1.17-alpine AS golang_builder
ARG IC_VERSION
ARG GIT_COMMIT
ARG DATE
ARG TARGETARCH

WORKDIR /go/src/github.com/edgeNEXUS/kubernetes-ingress/edgenexus-ingress/cmd/edgenexus-ingress
COPY go.mod go.sum /go/src/github.com/edgeNEXUS/kubernetes-ingress/edgenexus-ingress/
RUN go mod download
COPY . /go/src/github.com/edgeNEXUS/kubernetes-ingress/edgenexus-ingress/
RUN CGO_ENABLED=0 GO111MODULE=on GOOS=linux GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${IC_VERSION} \
    -X main.commit=${GIT_COMMIT} -X main.date=${DATE}" -o /edgenexus-ingress


############### Build edgenexus-manager in static Perl container ###############
FROM smartcodemaker/staticperl:latest-$BUILD_OS AS perl_builder
ARG BUILD_OS
ARG IC_VERSION
ARG GIT_COMMIT
ARG DATE
ARG TARGETARCH

WORKDIR /staticperl/src/github.com/edgeNEXUS/kubernetes-ingress/edgenexus-manager
ADD ./manager /staticperl/src/github.com/edgeNEXUS/kubernetes-ingress/edgenexus-manager/manager
RUN cp /staticperl/.staticperlrc /staticperl/src/github.com/edgeNEXUS/kubernetes-ingress/edgenexus-manager/manager/build/
WORKDIR /staticperl/src/github.com/edgeNEXUS/kubernetes-ingress/edgenexus-manager/manager/build
RUN make


########### Create image with edgenexus-ingress built in container #############
FROM common AS container

LABEL org.edgenexus.kic.image.build.version="container"

COPY --chown=edgenexus:0 --from=perl_builder   /staticperl/src/github.com/edgeNEXUS/kubernetes-ingress/edgenexus-manager/manager/build/bin/edgenexus-manager /
COPY --chown=edgenexus:0 --from=golang_builder /edgenexus-ingress /


############# Create image with edgenexus-ingress built locally ################
FROM common AS local

LABEL org.edgenexus.kic.image.build.version="local"

COPY --chown=edgenexus:0 ./edgenexus-ingress /
COPY --chown=edgenexus:0 ./edgenexus-manager /
