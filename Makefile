SHELL 		:=$(shell which bash)
.SHELLFLAGS =-c

ifndef DEBUG
.SILENT: ;
endif
.EXPORT_ALL_VARIABLES: ;

WORKDIR =$(patsubst %/,%,$(dir $(realpath $(lastword $(MAKEFILE_LIST)))))
PROJECT =$(notdir $(WORKDIR))
TIME 	=$(shell date '+%a %b %d %H:%m:%S %Z %Y')
PACKAGE =$(shell awk 'NR==1{print $$2}' go.mod)
BRANCH 	=$(shell git rev-parse --abbrev-ref HEAD)
COMMIT 	=$(shell git rev-parse --verify --short HEAD)
VERSION =$(shell git describe --always --tags --exact-match 2>/dev/null || \
			echo $(COMMIT))

LDFLAGS =-s -w -extld ld -extldflags -static \
		  -X '$(PACKAGE)/github.buildTime=$(TIME)' \
		  -X '$(PACKAGE)/github.buildCommit=$(COMMIT)' \
		  -X '$(PACKAGE)/github.buildLink=https://$(PACKAGE)/releases/download/$(VERSION)' \
		  -X '$(PACKAGE)/github.projectName=$(PROJECT)' \
		  -X '$(PACKAGE)/github.projectVersion=$(VERSION)' \
		  -X '$(PACKAGE)/github.projectDocs=https://$(PACKAGE)'
FLAGS	=-trimpath -a -installsuffix cgo -ldflags "$(LDFLAGS)"

GOPATH		=$(shell go env GOPATH)
GOVERS 		=$(shell go version)
GOOS		=$(word 1,$(subst /, ,$(lastword $(GOVERS))))
GOARCH		=$(word 2,$(subst /, ,$(lastword $(GOVERS))))
GOOSES		=darwin freebsd linux netbsd openbsd solaris windows
GOARCHES 	=386 amd64 arm
NOARCHES 	=darwin-arm solaris-386 solaris-arm windows-arm

UNZIP		=$(shell command -v unzip || (apt-get -qq update &>/dev/null && \
				apt-get -yqq install unzip &>/dev/null && \
				command -v unzip))

GOCILINT_VER	?=v1.21.0
GOCILINT_URL 	=raw.githubusercontent.com/golangci/golangci-lint/master/install.sh
GOCILINT		=$(shell command -v golangci-lint || \
					(curl -sfL "https://$(GOCILINT_URL)" | \
					sh -s -- -b $(GOPATH)/bin $(GOCILINT_VER) && \
					command -v golangci-lint))

GOTESTSUM_VER	?=v0.4.0
GOTESTSUM_URL 	=gotest.tools/gotestsum
GOTESTSUM		=$(shell command -v gotestsum || \
					(go get $(GOTESTSUM_URL)@$(GOTESTSUM_VER) && \
					command -v gotestsum))

VAULT_TOKEN 	?=root
VAULT_ADDR		?=http://127.0.0.1:8200
VAULT_API_ADDR	?=$(VAULT_ADDR)
VAULT_VER		?=1.3.0
VAULT_ZIP 		=vault_$(VAULT_VER)_$(GOOS)_$(GOARCH).zip
VAULT_URL 		=releases.hashicorp.com/vault/$(VAULT_VER)/$(VAULT_ZIP)
VAULT			=$(shell command -v vault || \
					(curl -sfLO "https://$(VAULT_URL)" && \
					$(UNZIP) -od $(GOPATH)/bin $(VAULT_ZIP) 1>/dev/null && \
					rm vault_$(VAULT_VER)_$(GOOS)_$(GOARCH).zip && \
					command -v vault))

ifeq ($(GITHUB_ACTIONS),true)
CI 	?= true
endif

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
# (build) for compiling everything.
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

$(PROJECT): ## Build for every supported OS and arch combination
.PHONY: $(PROJECT)
$(PROJECT)-%-%: ## Build for a specific OS and arch (where '%-%' = os-arch)
.PHONY: $(PROJECT)-%-%

build: ## Build for the current OS and arch
.PHONY: build

lint: ## Linting (heavyweight when `CI=true`)
	echo >&2 "> linting"
ifdef CI
	mkdir -p test && \
		$(GOCILINT) run --enable-all --out-format=checkstyle | \
		tee test/checkstyle.xml
	! grep "error" test/checkstyle.xml &>/dev/null
else
	$(GOCILINT) run --enable-all --fast
endif
.PHONY: lint

test: ## Testing (also see the 'integration' targets)
	if [ ! "$(SKIP_LINT)" = "true" ]; then $(MAKE) lint; lint_exit=$$?; fi; \
	echo >&2 "> testing"; \
	mkdir -p test; \
	if [ "$(CI)" = true ]; then \
		$(GOTESTSUM) --format short-verbose --junitfile test/junit.xml -- -race \
		$(GOTAGS) -coverprofile=test/coverage.out -covermode=atomic ./...; \
	else \
		$(GOTESTSUM) --format short-verbose --junitfile test/junit.xml -- \
		$(GOTAGS) ./...; \
	fi; \
	! grep "FAIL" test/junit.xml &>/dev/null && \
	exit $$lint_exit # Ensure we exit failure if linting failed
.PHONY: test

integration: LOG_LEVEL=$(if $(DEBUG:-=),trace,error)
integration: $(PROJECT)-$(GOOS)-$(GOARCH) ## Run a local development Vault
	echo >&2 "> integration"
	rm -rf test/plugins && mkdir -p test/plugins
	cp $(PROJECT)-$(GOOS)-$(GOARCH) \
		test/plugins/$(PROJECT)
	pkill vault && sleep 2 || true
	$(VAULT) server \
		-dev \
		-dev-plugin-dir=$(WORKDIR)/test/plugins \
		-dev-root-token-id=root \
		-log-level=$(LOG_LEVEL) &
	sleep 2
	$(VAULT) secrets enable \
		-path=github \
		-plugin-name=$(PROJECT) \
		plugin
	$(eval GOTAGS+=-count 1 -tags integration)
.PHONY: integration

integration-test: integration test ## Run a local development Vault and the integration tests
.PHONY: integration-test

docker-%: ## Run any other target in Docker (where '%' = target name)
ifdef MAKEFLAGS
	docker-compose run make $* $(MAKEFLAGS)
else
	docker-compose run make $*
endif
.PHONY: docker-%
