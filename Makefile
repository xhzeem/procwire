VERSION ?= dev
GOFLAGS := -trimpath -tags netgo,osusergo
LDFLAGS := -s -w -buildid= -X main.version=$(VERSION)

.PHONY: test vet build-linux-amd64 build-linux-arm64 integration-ubuntu

test:
	go test ./...

vet:
	go vet ./...

build-linux-amd64:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/procwire-linux-amd64 ./cmd/procwire

build-linux-arm64:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/procwire-linux-arm64 ./cmd/procwire

integration-ubuntu:
	sh scripts/integration-ubuntu.sh ubuntu:22.04
