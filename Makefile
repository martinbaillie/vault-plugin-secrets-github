SHELL 		:=$(shell which bash)
.SHELLFLAGS =-c

ifndef DEBUG
.SILENT: ;
endif
.EXPORT_ALL_VARIABLES: ;

WORKDIR :=$(patsubst %/,%,$(dir $(realpath $(lastword $(MAKEFILE_LIST)))))
TIME 	:=$(shell date '+%a %b %d %H:%m:%S %Z %Y')

PROJECT =$(notdir $(WORKDIR))
PACKAGE =$(shell awk 'NR==1{print $$2}' go.mod)
BRANCH 	=$(shell git rev-parse --abbrev-ref HEAD)
COMMIT 	=$(shell git rev-parse --verify --short HEAD)
VERSION =$(shell git describe --always --tags --exact-match 2>/dev/null \
		|| echo $(COMMIT) \
)

LDFLAGS ?=-s -w -extld ld -extldflags -static \
		  -X '$(PACKAGE)/github.buildTime=$(TIME)' \
		  -X '$(PACKAGE)/github.buildCommit=$(COMMIT)' \
		  -X '$(PACKAGE)/github.buildLink=https://$(PACKAGE)/releases/download/$(VERSION)' \
		  -X '$(PACKAGE)/github.projectName=$(PROJECT)' \
		  -X '$(PACKAGE)/github.projectVersion=$(VERSION)' \
		  -X '$(PACKAGE)/github.projectDocs=https://$(PACKAGE)'
FLAGS	?=-trimpath -a -installsuffix cgo -ldflags "$(LDFLAGS)"

GOVERS 		=$(shell go version)
GOOS		=$(word 1,$(subst /, ,$(lastword $(GOVERS))))
GOARCH		=$(word 2,$(subst /, ,$(lastword $(GOVERS))))
GOOSES		?=darwin freebsd linux netbsd openbsd solaris windows
GOARCHES 	?=386 amd64 arm
NOARCHES 	?=darwin-arm solaris-386 solaris-arm windows-arm

help: ## This help target
	awk 'BEGIN {FS = ":.*?## "} /^[%a-zA-Z_-]+:.*?## / \
		{printf "\033[36m%-30s\033[0m	%s\n", $$1, $$2}' $(MAKEFILE_LIST)
.PHONY: help

default: help
.PHONY: default

todo: ## Shows TODO items per file
	grep --exclude=Makefile --text -InRo -E ' TODO.*' .
.PHONY: todo

# Create a cross-compile target for every os/arch pairing. This will generate a
# non-phony make target for each os/arch pair as well as a phony meta target
# (build) for compiling everything. Individual targets are available at:
# $ make vault-plugin-secrets-github-<os>-<arch>
_build:
	echo >&2 "> building"
.PHONY: _build
define build-target
  $(PROJECT)-$(1)-$(2)$(3):
  ifeq (,$(findstring $(1)-$(2),$(NOARCHES)))
		echo >&2 ">> $$@"
		env GOOS=$(1) GOARCH=$(2) CGO_ENABLED=0 go build $(FLAGS) -o $$@
  endif

  build: _build $(PROJECT)-$(1)-$(2)$(3)
  .PHONY: build
endef
$(foreach goarch,$(GOARCHES), \
	$(foreach goos,$(GOOSES), \
		$(eval \
			$(call build-target,$(goos),$(goarch),$(if \
				$(findstring windows,$(goos)),.exe,)\
			) \
		) \
	) \
)

vault-plugin-secrets-github: ## Build for every supported OS and arch combination
.PHONY: vault-plugin-secrets-github
vault-plugin-secrets-github-%-%: ## Build for a specific OS and arch (where '%-%' = os-arch)
.PHONY: vault-plugin-secrets-github-%-%

build: ## Build for the current OS and arch
.PHONY: build

lint: ## Linting (heavyweight when `CI=true`)
	echo >&2 "> linting"
ifdef CI
	mkdir -p test && \
		golangci-lint run --enable-all --out-format=checkstyle | \
		tee test/checkstyle.xml
	! grep "error" test/checkstyle.xml &>/dev/null
else
	golangci-lint run --enable-all --fast
endif
.PHONY: lint

test:
	if [ ! "$(SKIP_LINT)" = "true" ]; then $(MAKE) lint; lint_exit=$$?; fi; \
	echo >&2 "> testing"; \
	mkdir -p test; \
	if [ "$(CI)" = true ]; then \
		gotestsum --format short-verbose --junitfile test/junit.xml -- -race \
		$(GOTAGS) -coverprofile=test/coverage.out -covermode=atomic ./...; \
	else \
		gotestsum --format short-verbose --junitfile test/junit.xml -- \
		$(GOTAGS) ./...; \
	fi; \
	! grep "FAIL" test/junit.xml &>/dev/null && \
	exit $$lint_exit # Ensure we exit failure if linting failed
.PHONY: test

docker-%: ## Run any other target in Docker (where '%' = target name)
ifdef MAKEFLAGS
	docker-compose run make $* $(MAKEFLAGS)
else
	docker-compose run make $*
endif
.PHONY: docker-%
