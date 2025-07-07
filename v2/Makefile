.DEFAULT_GOAL := help

MAKEFLAGS += --no-print-directory

VERSION=$(shell bin/linuxamd64/glauth --version)

GIT_COMMIT=$(shell git rev-list -1 HEAD )
BUILD_TIME=$(shell date -u +%Y%m%d_%H%M%SZ)
GIT_CLEAN=$(shell git status | grep -E "working (tree|directory) clean" | wc -l | sed 's/^[ ]*//')

# Last git tag
LAST_GIT_TAG=$(shell git describe --abbrev=0 --tags 2> /dev/null)

# this=1 if the current commit is the tagged commit (ie, if this is a release build)
GIT_IS_TAG_COMMIT=$(shell git describe --abbrev=0 --tags > /dev/null 2> /dev/null && echo "1" || echo "0")

# Used when a tag isn't available
GIT_BRANCH=$(shell git rev-parse --abbrev-ref HEAD)

# Build variables
BUILD_VARS?=-s -w
BUILD_FILES=.
TRIM_FLAGS>?=-trimpath
BUILD_TAGS?=noembed

# Targets
MAIN_TARGETS?=linux/amd64,linux/386,linux/arm64,linux/arm-7,darwin/amd64,darwin/arm64,windows/amd64,windows/386
# Database support is now embedded, no need for plugin targets
EMBED_TARGETS?=windows/amd64

# For release process
GO_RELEASE_V=$(shell go version | { read _ _ v _; echo $${v#go}; })

# Build
GOOS?=linux
GOARCH?=amd64

# Database support is now embedded

#####################
# High level commands
#####################

#help: @ List available tasks on this project
help: 
	@grep -E '[a-zA-Z\.\-]+:.*?@ .*$$' $(MAKEFILE_LIST)| tr -d '#' | sed -E 's/Makefile.//' | awk 'BEGIN {FS = ":.*?@ "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

#run: @ build and run - used for development
run: setup devrun

mocks:
	go install go.uber.org/mock/mockgen@v0.3.0
	# generate gomocks
	go generate ./...
.PHONY: mocks

vet:
	-go vet ./...
.PHONY: vet
#test: @ runs the integration test on linuxamd64 (eventually allow the binary to be set)
test: mocks vet
	# also run unit tests for packages, skip glauth_test.go for now
	go test -v -cover -coverprofile coverage.out ./pkg/... ./internal/...
	$(MAKE) runtest
#all: @ run build process for all binaries
all: setup binaries verify

#fast: @ run build process for only linuxamd64
fast: setup linuxamd64

#binaries: @ list of binary formats to build
binaries: linux386 linuxamd64 linuxarm linuxarm64 darwinamd64 darwinarm64 win386 winamd64

#setup: @ setup commands to always run
setup: getdeps format

#####################
# Subcommands
#####################
#	@echo \- removing any changes and pulling latest master && \
#	git reset --hard HEAD >/dev/null 2>&1 && \
#	git checkout master >/dev/null 2>&1 && \
#	git pull >/dev/null 2>&1 && \

prepbuild:
	echo \- taking care of ignore files && \
	sudo rm -rf bin/* >/dev/null && \
	echo \- plugins are now embedded

# Legacy embed functions removed - database handlers are now permanently embedded

# Run integration test
runtest:
	./scripts/ci/integration-test.sh cleanup

# Get all dependencies
getdeps:
	go get -d ./...

updatetest:
	./scripts/ci/integration-test.sh

format:
	go fmt ./...

devrun:
	go run ${BUILD_FILES} -c sample-simple.cfg

mkbindir:
	@echo "create directory bin/$(GOOS)$(GOARCH)"
	@mkdir -p bin/$(GOOS)$(GOARCH)
.PHONY: mkbindir

build: mkbindir
	@go build ${TRIM_FLAGS} -tags ${BUILD_TAGS} -ldflags "${BUILD_VARS}" -o bin/$(GOOS)$(GOARCH)/glauth -buildvcs .
	$(MAKE) sha256
.PHONY: build

sha256:
	@sha256sum bin/$(GOOS)$(GOARCH)/glauth > bin/$(GOOS)$(GOARCH)/glauth.sha256
.PHONY: sha256

linux386:
	GOOS=linux GOARCH=386 $(MAKE) build

linuxamd64:
	GOOS=linux GOARCH=amd64 $(MAKE) build

linuxarm:
	GOOS=linux GOARCH=arm $(MAKE) build

linuxarm64:
	GOOS=linux GOARCH=arm64 $(MAKE) build

# Testing target removed - plugin functionality is now embedded in main binary

darwinamd64:
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 $(MAKE) build

darwinarm64:
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 $(MAKE) build

win386:
	GOOS=windows GOARCH=386 $(MAKE) build

winamd64:
	GOOS=windows GOARCH=amd64 $(MAKE) build

verify:
	@for binary in linux386 linuxamd64 linuxarm linuxarm64 darwinamd64 darwinarm64 win386 winamd64; do cd bin/$$binary && sha256sum glauth.sha256 -c && cd ../..; done

# Plugin functionality has been replaced with embedded database handlers

_buildmain:
	@xgo -v -ldflags="${BUILD_VARS}" -trimpath -go ${GO_RELEASE_V} -out glauth -dest bin -buildvcs=false --targets="${MAIN_TARGETS}" .

#buildmain: @ build main binaries for distribution
buildmain: prepbuild _buildmain

# Legacy embed build targets removed - database handlers are now permanently embedded

# Plugin builds are no longer needed - database support is embedded

_checkdockerauth:
	@if ! grep -q "index.docker.io" $(HOME)/.docker/config.json; then \
		echo "❌ Not logged in to Docker Hub (index.docker.io not found in config)."; \
		exit 1; \
	fi; \
	if ! grep -q "ghcr.io" $(HOME)/.docker/config.json; then \
		echo "❌ Not logged in to GitHub Hub (ghcr.io not found in config)."; \
		exit 1; \
	fi

builddockermain:
	$(if $(TAG),,$(error ❌ Must set TAG))
	$(if $(REPO),,$(error ❌ Must set REPO - glauth or other))
	@mkdir -p docker/assets/linux/amd64 docker/assets/linux/arm64 docker/assets/linux/arm/v7 && \
	cp -f bin/glauth-linux-amd64 docker/assets/linux/amd64/glauth && \
	cp -f bin/glauth-linux-arm64 docker/assets/linux/arm64/glauth && \
	cp -f bin/glauth-linux-arm-7 docker/assets/linux/arm/v7/glauth && \
	docker buildx build --tag ghcr.io/$$REPO/glauth:$$TAG -t ghcr.io/$$REPO/glauth:latest -f docker/Dockerfile --platform linux/amd64,linux/arm64,linux/arm/v7 --push docker && \
	docker buildx build --tag $$REPO/glauth:$$TAG -t $$REPO/glauth:latest -f docker/Dockerfile --platform linux/amd64,linux/arm64,linux/arm/v7 --push docker

builddocker: _checkdockerauth builddockermain

buildeverything: prepbuild _buildmain builddocker

#testdocker: @ run integration test using docker
testdocker:
	$(if $(REPO),,$(error Must set REPO - glauth or other))
	@echo "==> Cleaning up any existing image to be on the safe side..." && \
	(for image in $$(docker image ls -q "$$REPO/glauth*"); do \
		for container in $$(docker container ls -a -q -f ancestor=$$image); do \
			docker stop $$container; \
			while [ "$$(docker container ls -q -f ancestor=$$image)" != "" ]; do sleep 1; done; \
			docker rm $$container; \
		done; \
		docker rmi $$image; \
	done) && \
	echo "==> Running glauth main container..." && \
	docker run -d --name glauth-test -p 3893:3893 $$REPO/glauth:latest && \
	sleep 5 && \
	if [ "$$(ldapsearch -LLL -H ldap://localhost:3893 -D cn=serviceuser,ou=svcaccts,dc=glauth,dc=com -w mysecret -x -bdc=glauth,dc=com cn=hackers | grep posixAccount)" != "" ]; then \
		echo "Checked: Glauth is responding properly to ldapsearch query."; \
	else \
		echo "glauth check did not pass. Aborting."; \
		exit 1; \
	fi && \
	echo "==> Stopping glauth main container..." && \
	docker stop glauth-test && \
	while [ "$$(docker ps -q -f name=glauth-test)" != "" ]; do sleep 1; done; \
	docker rm glauth-test && \
	echo "==> Testing complete."

.PHONY: all \
	prepbuild run test fast binaries setup getdeps runtest updatetest format devrun \
	linux386 linuxamd64 linuxarm linuxarm64 darwinamd64 darwinarm64 win386 winamd64 verify \
	buildmain build builddockermain builddocker testdocker buildeverything
