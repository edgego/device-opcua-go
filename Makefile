.PHONY: build test clean prepare update docker

GO=CGO_ENABLED=0 GO111MODULE=on go
GOCGO=GCO_ENABLED=1 GO111MODULE=on go

MICROSERVICES=cmd/device-opcua

.PHONY: $(MICROSERVICES)

DOCKERS=docker_device_opcua_go

.PHONY: $(DOCKERS)

VERSION=$(shell cat ./VERSION 2>/dev/null || echo 0.0.0)
GIT_SHA=$(shell git rev-parse HEAD)

GOFLAGS=-ldflags "-X github.com/edgego/device-opcua-go.Version=$(VERSION)"

tidy:
	go mod tidy

build: $(MICROSERVICES)

cmd/device-mqtt:
	$(GOCGO) build $(GOFLAGS) -o $@ ./cmd

test:
	$(GOCGO) test ./... -coverprofile=coverage.out
	$(GOCGO) vet ./...
	gofmt -l $$(find . -type f -name '*.go'| grep -v "/vendor/")
	[ "`gofmt -l $$(find . -type f -name '*.go'| grep -v "/vendor/")`" = "" ]
	./bin/test-attribution-txt.sh

clean:
	rm -f $(MICROSERVICES)

run:
	cd bin && ./edgex-launch.sh

docker: $(DOCKERS)

docker_device_opcua_go:
	docker build \
		--label "git_sha=$(GIT_SHA)" \
		-t edgego/device-opcua:$(GIT_SHA) \
		-t edgego/device-opcua:$(VERSION) \
		.

vendor:
	$(GO) mod vendor
