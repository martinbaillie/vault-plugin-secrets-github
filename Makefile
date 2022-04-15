SHELL 		:=$(shell which bash)
.SHELLFLAGS =-c

ifndef DEBUG
.SILENT: ;
endif
.EXPORT_ALL_VARIABLES: ;

WORKDIR 	=$(patsubst %/,%,$(dir $(realpath $(lastword $(MAKEFILE_LIST)))))
PROJECT 	=$(notdir $(WORKDIR))
USER 		=$(if $(GITHUB_ACTOR),$(GITHUB_ACTOR),$(shell git config user.name))
DATE 		=$(shell date '+%a %b %d %H:%m:%S %Z %Y')
PACKAGE 	=$(shell awk 'NR==1{print $$2}' go.mod)
BRANCH 		=$(shell git rev-parse --abbrev-ref HEAD)
REVISION 	=$(shell git rev-parse --verify --short HEAD)
VERSION 	=$(shell git describe --always --tags --exact-match 2>/dev/null || \
				echo $(REVISION))

LDFLAGS =-s -w -extld ld -extldflags -static \
		  -X '$(PACKAGE)/github.projectName=$(PROJECT)' \
		  -X '$(PACKAGE)/github.projectDocs=https://$(PACKAGE)' \
		  -X 'github.com/prometheus/common/version.BuildDate=$(DATE)' \
		  -X 'github.com/prometheus/common/version.Revision=$(REVISION)' \
		  -X 'github.com/prometheus/common/version.Branch=$(BRANCH)' \
		  -X 'github.com/prometheus/common/version.Version=$(VERSION)' \
		  -X 'github.com/prometheus/common/version.BuildUser=$(USER)'
FLAGS	=-trimpath -a -installsuffix cgo -ldflags "$(LDFLAGS)"

GOPATH		=$(shell go env GOPATH)
GOVERS 		=$(shell go version)
GOOS		=$(word 1,$(subst /, ,$(lastword $(GOVERS))))
GOARCH		=$(word 2,$(subst /, ,$(lastword $(GOVERS))))
GOOSES		=darwin freebsd linux netbsd openbsd solaris windows
GOARCHES 	=amd64 arm64
NOARCHES 	=solaris-arm64 windows-arm64

GOCILINT_VER?=v1.30.0
GOCILINT_URL=raw.githubusercontent.com/golangci/golangci-lint/master/install.sh

GOTESTSUM_VER?=v0.4.0
GOTESTSUM_URL=gotest.tools/gotestsum

GOTHUB_VER?=v0.7.0
GOTHUB_URL=github.com/itchio/gothub

GPG_KEY 	?=$(shell git config user.signingkey)

VAULT_TOKEN?=root
VAULT_ADDR?=http://127.0.0.1:8200
VAULT_API_ADDR?=$(VAULT_ADDR)
VAULT_VER?=1.10.0
VAULT_ZIP=vault_$(VAULT_VER)_$(GOOS)_$(GOARCH).zip
VAULT_URL=releases.hashicorp.com/vault/$(VAULT_VER)/$(VAULT_ZIP)

ifeq ($(GITHUB_ACTIONS),true)
CI 	?= true
endif

help: FORMAT="\033[36m%-30s\033[0m	%s\n"
help: ## This help target
	awk 'BEGIN {FS = ":.*?## "} /^[%a-zA-Z_-]+:.*?## / \
		{printf $(FORMAT), $$1, $$2}' $(MAKEFILE_LIST)
	printf $(FORMAT) $(PROJECT)-%-% \
		"Build for a specific OS and arch (where '%' = OS, arch)"
.PHONY: help

default: help
.PHONY: default

update: ## Update Nix flake and Go modules
	nix flake lock --update-input nixpkgs
	direnv allow .
	go get -u
	go mod tidy
.PHONY: update

todo: ## Shows TODO items per file
	grep --exclude=Makefile --text -InRo -E ' TODO.*' .
.PHONY: todo

clean: ## Clean transient files
	echo >&2 "==> Cleaning"
	rm -f $(PROJECT)-* SHA256SUM*
	rm -rf test
.PHONY: clean

lint: GOCILINT=$(shell command -v golangci-lint || \
					(curl -sfL "https://$(GOCILINT_URL)" | \
					sh -s -- -b $(GOPATH)/bin $(GOCILINT_VER) && \
					command -v golangci-lint))
lint: ## Linting (heavyweight when `CI=true`)
	echo >&2 "==> Linting"
ifdef CI
	mkdir -p test && \
		$(GOCILINT) run --enable-all --out-format=checkstyle | \
		tee test/checkstyle.xml
	! grep "error" test/checkstyle.xml &>/dev/null
else
	$(GOCILINT) run --enable-all --fast
endif
.PHONY: lint

test: GOTESTSUM=$(shell command -v gotestsum || \
					(go get $(GOTESTSUM_URL)@$(GOTESTSUM_VER) && \
					command -v gotestsum))
test: FORMAT=$(if $(DEBUG:-=),standard-verbose,short-verbose)
test: ## Test (also see the 'integration' targets)
	if [ ! "$(SKIP_LINT)" = "true" ]; then $(MAKE) lint; lint_exit=$$?; fi; \
	echo >&2 "==> Testing"; \
	mkdir -p test; \
	if [ "$(CI)" = true ]; then \
		$(GOTESTSUM) --format $(FORMAT) --junitfile test/junit.xml -- -race \
		$(GOTAGS) -coverprofile=test/coverage.out -covermode=atomic ./...; \
	else \
		$(GOTESTSUM) --format $(FORMAT) --junitfile test/junit.xml -- \
		$(GOTAGS) ./...; \
	fi; \
	! grep "FAIL" test/junit.xml &>/dev/null && \
	exit $$lint_exit # Ensure we exit failure if linting failed
.PHONY: test

# Create a cross-compile target for every os/arch pairing. This will generate a
# non-phony make target for each os/arch pair as well as a phony meta target
# (build) for compiling everything.
_build:
	echo >&2 "==> Building"
.PHONY: _build
define build-target
  $(PROJECT)-$(1)-$(2)$(3):
  ifeq (,$(findstring $(1)-$(2),$(NOARCHES)))
		echo >&2 "===> $$@"
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

build: ## Build for every supported OS and arch combination
.PHONY: build

integration: UNZIP=$(shell command -v unzip || \
				(apt-get -qq update &>/dev/null && \
				apt-get -yqq install unzip &>/dev/null && \
				command -v unzip))
integration: VAULT=$(shell command -v vault || \
					(curl -sfLO "https://$(VAULT_URL)" && \
					$(UNZIP) -od $(GOPATH)/bin $(VAULT_ZIP) 1>/dev/null && \
					rm vault_$(VAULT_VER)_$(GOOS)_$(GOARCH).zip && \
					command -v vault))
integration: LOG_LEVEL=$(if $(DEBUG:-=),trace,error)
integration: $(PROJECT)-$(GOOS)-$(GOARCH) ## Run a local development Vault
	echo >&2 "==> Integration"
	rm -rf test/plugins && mkdir -p test/plugins
	cp $(PROJECT)-$(GOOS)-$(GOARCH) test/plugins/$(PROJECT)
	pkill vault && sleep 2 || true
	$(VAULT) server \
		-dev \
		-dev-plugin-dir=$(WORKDIR)/test/plugins \
		-dev-root-token-id=root \
		-log-level=$(LOG_LEVEL) &
	sleep 2
	$(VAULT) write sys/plugins/catalog/$(PROJECT) \
		sha_256=$$(shasum -a 256 test/plugins/$(PROJECT) | cut -d' ' -f1) \
		command=$(PROJECT)
	$(VAULT) secrets enable \
		-path=github \
		-plugin-name=$(PROJECT) \
		plugin
	$(eval GOTAGS+=-count 1 -tags integration)
.PHONY: integration

integration-test: integration test ## Run a local development Vault and the integration tests
# To run integration tests against a real GitHub App installation:
# $ make integration-test \
# 	BASE_URL=https://api.github.com \
# 	APP_ID=<your application id> \
#	ORG_NAME=<org_name> \
# 	PRV_KEY="$(cat /path/to/your/app/prv_key_file)"
# NOTE: this will automatically skip racyness tests to avoid rate limiting.
.PHONY: integration-test

tag: ## Create a signed commit and tag
	echo >&2 "==> Tagging"
	if [[ ! $(VERSION) =~ ^[0-9]+[.][0-9]+([.][0.9]*)(-rc.[0-9]+)?$  ]]; then \
		echo >&2 "ERROR: VERSION ($(VERSION)) is not a semantic version"; \
		exit 1; \
	fi
	echo >&2 "===> v$(VERSION)"
	git commit \
		--allow-empty \
		--gpg-sign="$(GPG_KEY)" \
		--message "Release v$(VERSION)" \
		--quiet \
		--signoff
	git tag \
		--annotate \
		--create-reflog \
		--local-user "$(GPG_KEY)" \
		--message "Version $(VERSION)" \
		--sign \
		"v$(VERSION)" master
.PHONY: tag

SHA256SUMS:
	echo >&2 "==> Summing"
	shasum --algorithm 256 $(PROJECT)-* > $@

SHA256SUMS.sig: GPG=$(shell command -v gpg || \
				(apt-get -qq update &>/dev/null && \
				apt-get -yqq install gpg &>/dev/null && \
				command -v gpg))
SHA256SUMS.sig: SHA256SUMS
	echo >&2 "==> Signing"
	$(GPG) --default-key "$(GPG_KEY)" --detach-sig SHA256SUMS

# NOTE: Needs BSD xargs.
release: GOTHUB=$(shell command -v gothub || \
					(go get $(GOTHUB_URL)@$(GOTHUB_VER) && \
					command -v gothub))
release: GITHUB_REPO=$(PROJECT)
release: GITHUB_USER=$(word 2,$(subst /, ,$(PACKAGE)))
release: GITHUB_ASSETS=$(wildcard $(PROJECT)-* SHA256SUMS*)
release: tag build SHA256SUMS.sig ## Build, tag and release to GitHub
release:
	echo >&2 "==> Releasing"
ifndef GITHUB_TOKEN
		echo >&2 "ERROR: GITHUB_TOKEN missing"
		exit 127
endif
	echo >&2 "===> v$(VERSION)"
	git push
	git push --tags
	$(GOTHUB) release --name "Release v$(VERSION)" --tag "v$(VERSION)"
	xargs -n1 -P$(words $(GITHUB_ASSETS)) -I{} -- \
		$(GOTHUB) upload --tag v$(VERSION) --name {} --file {} --replace \
		<<< "$(GITHUB_ASSETS)"
.PHONY: release

docker-%: ## Run any other target in Docker (where '%' = target name)
ifdef MAKEFLAGS
	docker-compose run make $* $(MAKEFLAGS)
else
	docker-compose run make $*
endif
.PHONY: docker-%

env-%: ## Echo any make variable (where '%' = variable name)
	echo "$($*)"
.PHONY: env-%
