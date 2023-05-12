PROJECT_NAME         := homecert

BIN_NAME             := $(PROJECT_NAME)
MODULE               := $(shell awk 'NR==1{print $$2}' go.mod)
VERSION              := $(shell echo $$(ver=$$(git tag -l --points-at HEAD) && [ -z $$ver ] && ver=$$(git describe --always --dirty); printf $$ver))

LDFLAGS              := -s -w -X $(MODULE)/meta.Version=$(VERSION) -X $(MODULE)/meta.ModuleName=$(MODULE)
FLAGS                := -trimpath

DIST                 := dist
SOURCE               := $(shell find . -name '*.go')
SOURCE_NO_TEST       := $(shell find . -name '*.go' ! -name '*_test.go')

PLATFORMS            ?= darwin-amd64 darwin-arm64 \
						dragonfly-amd64 \
						freebsd-amd64 freebsd-arm freebsd-arm64 \
						linux-amd64 linux-arm linux-arm64 \
						netbsd-amd64 netbsd-arm netbsd-arm64 \
						openbsd-amd64 openbsd-arm openbsd-arm64 \
						windows-amd64 windows-arm

default: clean check-version test all shasums readme

check-version:
	@if [ -z "$(VERSION)" ]; then echo "VERSION variable must be set"; exit 1; fi

build: $(DIST)/$(BIN_NAME)
$(DIST)/$(BIN_NAME): $(SOURCE)
	go build $(ARGS) $(FLAGS) -ldflags="$(LDFLAGS)" -o $@

all: $(addprefix $(DIST)/$(BIN_NAME)-,$(PLATFORMS))

clean:
	rm -rf dist && mkdir dist

$(DIST)/$(BIN_NAME)-%: GOOS   = $(word 1,$(subst -, ,$*))
$(DIST)/$(BIN_NAME)-%: GOARCH = $(word 2,$(subst -, ,$*))
$(DIST)/$(BIN_NAME)-%: $(SOURCE)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(ARGS) $(FLAGS) -ldflags="$(LDFLAGS)" -o $@

shasums: $(DIST)/$(BIN_NAME)-shasums
$(DIST)/$(BIN_NAME)-shasums: all
	cd $(DIST) && shasum -a 256 $(BIN_NAME)-* > $(BIN_NAME)-shasums

install:
	go install -ldflags=$(LDFLAGS)

readme: README.md
README.md: README.tpl.md
	go run tools/readmegen/main.go README.tpl.md > README.md

test:
	go test -v ./...

install-git-hooks:
	cp -f hooks/* .git/hooks/

