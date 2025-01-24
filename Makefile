# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOMOD=$(GOCMD) mod
GOTEST=$(GOCMD) test
GOFLAGS := -v 
LDFLAGS := -s -w
CGO_ENABLED=1

# Git
GITCMD=git

# 非macOS环境下设置LDFLAGS
ifneq ($(shell go env GOOS),darwin)
	LDFLAGS=-extldflags "-static"
endif

all: build

tag:
	$(GITCMD) tag -d v1.0.0
	$(GITCMD) push origin -d v1.0.0
	$(GITCMD) tag v1.0.0
	$(GITCMD) push origin v1.0.0

build:
	CGO_ENABLED=$(CGO_ENABLED) CGO_LDFLAGS="$(CGO_LDFLAGS)" CGO_CFLAGS="$(CGO_CFLAGS)" $(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -o "naabu" cmd/naabu/main.go

goreleaser:
	goreleaser build -f ./.goreleaser/mac.yml --skip=validate --clean

test:
	$(GOTEST) $(GOFLAGS) ./...

tidy:
	$(GOMOD) tidy