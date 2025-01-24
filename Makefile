# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOMOD=$(GOCMD) mod
GOTEST=$(GOCMD) test
GOFLAGS := -v 
LDFLAGS := -s -w
CGO_ENABLED=1

# 非macOS环境下设置LDFLAGS
ifneq ($(shell go env GOOS),darwin)
	LDFLAGS=-extldflags "-static"
endif

all: build

build:
	CGO_ENABLED=$(CGO_ENABLED) CGO_LDFLAGS="$(CGO_LDFLAGS)" CGO_CFLAGS="$(CGO_CFLAGS)" $(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -o "naabu" cmd/naabu/main.go

goreleaser:
	goreleaser build -f ./.goreleaser/mac.yml --skip=validate --clean

test:
	$(GOTEST) $(GOFLAGS) ./...

tidy:
	$(GOMOD) tidy