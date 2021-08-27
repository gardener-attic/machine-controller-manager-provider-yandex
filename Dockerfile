# SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
# SPDX-License-Identifier: Apache-2.0

#############      builder                                  #############
FROM golang:1.15.13 AS builder

WORKDIR /go/src/github.com/flant/machine-controller-manager-provider-yandex
COPY go.mod go.sum ./
RUN go mod download -x
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -o bin/rel/machine-controller cmd/machine-controller/main.go

#############      base                                     #############
FROM alpine:3.11.2 as base

RUN apk add --update bash curl tzdata
WORKDIR /

#############      machine-controller               #############
FROM base AS machine-controller

COPY --from=builder /go/src/github.com/flant/machine-controller-manager-provider-yandex/bin/rel/machine-controller /machine-controller
ENTRYPOINT ["/machine-controller"]
