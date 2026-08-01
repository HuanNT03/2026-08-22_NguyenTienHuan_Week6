.DEFAULT_GOAL := help

SHELL := /usr/bin/env bash
PYTHON ?= python3
VENV ?= .venv

VENV_PYTHON := $(VENV)/bin/python
VENV_PIP := $(VENV)/bin/pip

.PHONY: help venv install doctor setup-target verify-target build up wait smoke down logs status \
	lint test test-contracts test-python quality sast sast-semgrep sast-codeql dast validate-reports week1 normalize clean-reports clean

help: ## Show available commands.
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

venv: ## Create the local Python virtual environment.
	$(PYTHON) -m venv $(VENV)

install: venv ## Install runtime and development Python dependencies.
	$(VENV_PIP) install --upgrade pip
	$(VENV_PIP) install -e '.[dev]'

doctor: ## Check host prerequisites and Docker daemon access.
	@./scripts/doctor.sh

setup-target: ## Clone the pinned target if absent, then verify it.
	@./scripts/setup-target.sh

verify-target: ## Verify the existing target without changing it.
	@./scripts/verify-target.sh

build: verify-target ## Build the pinned Juice Shop image.
	docker compose build juice-shop

up: verify-target ## Start Juice Shop in the background.
	docker compose up -d juice-shop

wait: ## Wait for target HTTP readiness.
	@./scripts/wait-for-target.sh

smoke: ## Test host HTTP access and response content.
	@./scripts/smoke-test.sh

down: ## Stop Sentinel Compose resources.
	docker compose down --remove-orphans

logs: ## Follow Juice Shop logs.
	docker compose logs --follow juice-shop

status: ## Show Compose service status.
	docker compose ps

lint: ## Syntax-check scripts and validate Compose configuration.
	bash -n scripts/*.sh
	docker compose config --quiet

test: test-contracts test-python ## Run repository and Python tests.

test-contracts: ## Run repository contract tests.
	@./tests/test-repository-contracts.sh

test-python: ## Run normalizer unit and integration tests.
	@$(PYTHON) -m pytest tests/unit tests/integration

quality: ## Run lint followed by repository contract tests.
	@$(MAKE) lint
	@$(MAKE) test

sast: ## Run Semgrep and CodeQL SAST sequentially against the pinned target.
	@$(MAKE) sast-semgrep
	@$(MAKE) sast-codeql

sast-semgrep: ## Run Semgrep SAST against the pinned target.
	@./scripts/run-sast.sh

sast-codeql: verify-target ## Build and run CodeQL SAST against the pinned target.
	docker compose --env-file configs/tool-versions.env --profile scan build codeql-scan
	@./scripts/write-scan-metadata.sh --tool codeql --report reports/raw/codeql.sarif
	HOST_UID="$$(id -u)" HOST_GID="$$(id -g)" docker compose --env-file configs/tool-versions.env --profile scan run --rm codeql-scan

dast: ## Run ZAP Baseline against the already-running target.
	@./scripts/run-dast.sh

validate-reports: ## Validate both raw scanner reports.
	@./scripts/validate-reports.sh all

week1: ## Run the complete Week 1 flow with guaranteed runtime cleanup.
	@./scripts/run-week1.sh

normalize: ## Normalize all raw scanner reports into unified JSONL.
	@$(PYTHON) -m src.normalizers.cli normalize-all --raw-dir reports/raw --output reports/normalized/unified-findings.jsonl

clean-reports: ## Remove generated reports while preserving tracked directories.
	@./scripts/clean.sh reports

clean: ## Stop runtime and remove generated reports and target clone.
	@./scripts/clean.sh full

.PHONY: kb-validate kb-build-documents kb-build-index kb-build kb-rebuild kb-search \
	kb-inspect kb-stats kb-test kb-lint kb-clean

kb-validate: ## Validate all knowledge sources and SQLite capabilities.
	@$(VENV_PYTHON) -m src.retrieval.cli validate

kb-build-documents: ## Build deterministic canonical knowledge documents.
	@$(VENV_PYTHON) -m src.retrieval.cli build-documents

kb-build-index: ## Build the generated SQLite FTS5 index.
	@$(VENV_PYTHON) -m src.retrieval.cli build-index

kb-build: ## Validate and build knowledge documents and index.
	@$(VENV_PYTHON) -m src.retrieval.cli build

kb-rebuild: ## Remove generated knowledge artifacts and rebuild them.
	@$(VENV_PYTHON) -m src.retrieval.cli clean
	@$(VENV_PYTHON) -m src.retrieval.cli build

kb-search: ## Search knowledge; for example QUERY="SQL Injection".
	@test -n "$(QUERY)" || \
		(echo 'Usage: make kb-search QUERY="SQL Injection"' && exit 1)
	@$(VENV_PYTHON) -m src.retrieval.cli search \
		"$(QUERY)" \
		--top-k "$(or $(TOP_K),5)" \
		$(if $(DOC_TYPE),--doc-type "$(DOC_TYPE)",)

kb-inspect: ## Inspect a canonical document by DOC_ID.
	@test -n "$(DOC_ID)" || \
		(echo 'Usage: make kb-inspect DOC_ID="cwe-89"' && exit 1)
	@$(VENV_PYTHON) -m src.retrieval.cli inspect "$(DOC_ID)"

kb-stats: ## Display canonical knowledge and index statistics.
	@$(VENV_PYTHON) -m src.retrieval.cli stats

kb-test: ## Run knowledge-base unit and integration tests.
	@$(VENV_PYTHON) -m pytest tests/retrieval -q

kb-lint: ## Lint knowledge-base source and tests.
	@$(VENV_PYTHON) -m ruff check src/retrieval tests/retrieval

kb-clean: ## Remove only generated knowledge-base artifacts.
	@$(VENV_PYTHON) -m src.retrieval.cli clean
