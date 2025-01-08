# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOMOD=$(GOCMD) mod
GOTEST=$(GOCMD) test
GOFLAGS := -v 
LDFLAGS := -s -w

ifeq ($(shell go env GOOS),darwin)
    CGO_LDFLAGS := -L/opt/homebrew/Cellar/libpcap/1.10.4/lib
    CGO_CFLAGS := -I/opt/homebrew/Cellar/libpcap/1.10.4/include
else
    LDFLAGS := -extldflags "-static"
endif

all: build
build:
	CGO_LDFLAGS="$(CGO_LDFLAGS)" CGO_CFLAGS="$(CGO_CFLAGS)" $(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -o "naabu" cmd/naabu/main.go
goreleaser:
	goreleaser build -f ./.goreleaser/mac.yml --skip=validate --clean
test:
	$(GOTEST) $(GOFLAGS) ./...
tidy:
	$(GOMOD) tidy