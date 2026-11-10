PACKAGE_DIRS := $(sort $(patsubst %/,%,$(dir $(wildcard packages/*/pyproject.toml))))
PACKAGES := $(notdir $(PACKAGE_DIRS))
PACKAGE_PROJECTS := $(addsuffix /pyproject.toml,$(PACKAGE_DIRS))
paths = $(if $(wildcard packages/$(1)/src),src tests,tests)
header = @title="$$(printf '%s' "$(1)" | tr '[:lower:]' '[:upper:]')"; printf "\n\n\033[1;36m==> %s\033[0m\n\n" "$$title"
PACKAGE_COMMANDS := build lint format test verify

.DEFAULT_GOAL := help

ifneq ($(filter $(firstword $(MAKECMDGOALS)),$(PACKAGE_COMMANDS)),)
	PACKAGE_SELECTOR := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))

	ifneq ($(strip $(PACKAGE_SELECTOR)),)
		ifneq ($(words $(PACKAGE_SELECTOR)),1)
			$(error Use at most one package: make $(firstword $(MAKECMDGOALS)) [package])
		endif
		ifneq ($(filter $(PACKAGE_SELECTOR),$(PACKAGES)),$(PACKAGE_SELECTOR))
			$(error Unknown package "$(PACKAGE_SELECTOR)". Choose one of: $(PACKAGES))
		endif
	endif
endif

PACKAGE_TARGETS := $(if $(PACKAGE_SELECTOR),$(PACKAGE_SELECTOR),$(PACKAGES))

ifneq ($(filter bump-version,$(MAKECMDGOALS)),)
	BUMP_VERSION := $(filter-out bump-version,$(MAKECMDGOALS))

	ifneq ($(words $(BUMP_VERSION)),1)
		$(error Use exactly one version: make bump-version <version>)
	endif

	.PHONY: $(BUMP_VERSION)
	$(BUMP_VERSION):
		@true
endif

.PHONY: help install install-dev build lint format test verify reuse docs-install docs-build docs-serve bump-version $(PACKAGES)

help: ## Show available commands
	@printf "Usage: make <command> [package]\n\nCommands:\n"
	@awk 'BEGIN { FS = ":.*##" } /^[a-zA-Z0-9_.%-]+:.*##/ { printf "  %-24s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@printf "\nExamples:\n  make test\n  make test cerbia-core\n  make test-cerbia-core\n\nPackages: %s\n" "$(PACKAGES)"

install: ## Install dependencies
	@uv sync --locked --all-packages --all-groups

install-dev: ## Install development dependencies and git hooks
	@$(MAKE) install
	@uv run --locked pre-commit install

build: ## Build all packages or one package with: make build <package>
	@$(MAKE) $(addprefix build-,$(PACKAGE_TARGETS))

lint: ## Lint and type-check all packages or one package with: make lint <package>
	@$(MAKE) $(addprefix lint-,$(PACKAGE_TARGETS))

format: ## Check formatting for all packages or one package with: make format <package>
	@$(MAKE) $(addprefix format-,$(PACKAGE_TARGETS))

test: ## Test all packages, or one package with: make test <package>
	@$(MAKE) $(addprefix test-,$(PACKAGE_TARGETS))

verify: ## Run lint and tests for all packages, or one package with: make verify <package>
	@$(MAKE) $(addprefix verify-,$(PACKAGE_TARGETS))

reuse: ## Check repository REUSE compliance
	@uv run --locked reuse lint

docs-install: ## Install locked Docouture/Antora dependencies
	@npm --prefix docs ci

docs-build: ## Build persistent versioned Docouture output (stop live dev first)
	@npm --prefix docs run build

docs-serve: ## Serve Docouture locally with live reload
	@npm --prefix docs run dev

bump-version: ## Set every package and internal dependency to one version
	$(call header,Bumping version to $(BUMP_VERSION))
	@uv run --locked python -c 'from packaging.version import Version; import sys; value = sys.argv[1]; normalized = str(Version(value)); sys.exit(0 if value == normalized else "Version must be canonical PEP 440: " + normalized)' "$(BUMP_VERSION)"
	@perl -pi -e 's/^version = "[^"]+"/version = "$(BUMP_VERSION)"/; s/"(cerbia(?:-[A-Za-z0-9_.-]+)?)==[^"]+"/"$$1==$(BUMP_VERSION)"/g' $(PACKAGE_PROJECTS)
	@uv lock
	@uv sync --locked --all-packages --all-groups

$(PACKAGES):
	@true

build-%: ## Build one package
	$(call header,Building $*)
	@cp LICENSE packages/$*/LICENSE
	@cp NOTICE packages/$*/NOTICE
	@uv build --no-sources --package $*

lint-%: ## Lint and type-check one package
	$(call header,Linting and type-checking $*)
	@echo "Running ruff check"
	@uv run --locked --package $* --directory packages/$* ruff check $(call paths,$*) --fix --exit-non-zero-on-fix
	@echo "Running ty check"
	@if [ -d packages/$*/src ]; then uv run --locked --package $* --directory packages/$* ty check src; else echo "Skipping ty check (no source directory)"; fi
	@echo "Checking format"
	@uv run --locked --package $* --directory packages/$* ruff format --check $(call paths,$*) --exit-non-zero-on-format

format-%: ## Apply formatting to one package
	$(call header,Formatting $*)
	@uv run --locked --package $* --directory packages/$* ruff format $(call paths,$*)

test-%: ## Test one package
	$(call header,Testing $*)
	@uv run --locked --package $* --directory packages/$* pytest $(if $(wildcard packages/$*/src),--cov-reset --cov=src,--no-cov)

$(addprefix verify-,$(PACKAGES)): verify-%: ## Run lint and tests for one package
	@$(MAKE) lint-$*
	@$(MAKE) test-$*
