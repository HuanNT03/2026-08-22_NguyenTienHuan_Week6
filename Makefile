.DEFAULT_GOAL := help

SHELL := /usr/bin/env bash
PYTHON ?= python3
VENV ?= .venv

VENV_PYTHON := $(VENV)/bin/python
VENV_PIP := $(VENV)/bin/pip

.PHONY: help venv install doctor setup-target verify-target down status \
	target-build target-up target-wait target-smoke target-down target-logs target-status \
	gateway-up gateway-down gateway-logs gateway-status test-request stest-request gateway-test \
	lint test test-contracts test-python quality sast sast-semgrep sast-codeql dast dast-zap-fullscan dast-zap-admin dast-zap-fullscan-admin dast-sqlmap validate-reports week1 normalize clean-reports clean \
	ui-build ui-rebuild ui ui-down ui-logs

help: ## Show available commands.
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

venv: ## Create the local Python virtual environment.
	@./scripts/setup-kb-venv.sh "$(PYTHON)" "$(VENV)"

install: venv ## Install runtime and development Python dependencies.
	$(VENV_PIP) install --upgrade pip
	$(VENV_PIP) install -e '.[dev]'

doctor: ## Check host prerequisites and Docker daemon access.
	@./scripts/doctor.sh

setup-target: ## Clone the pinned target if absent, then verify it.
	@./scripts/setup-target.sh

verify-target: ## Verify the existing target without changing it.
	@./scripts/verify-target.sh

target-build: verify-target ## Build the pinned Juice Shop target image.
	docker compose build juice-shop

target-up: verify-target ## Start Juice Shop target container in the background.
	docker compose up -d juice-shop

target-wait: ## Wait for Juice Shop target HTTP readiness.
	@./scripts/wait-for-target.sh

target-smoke: ## Test host HTTP access to Juice Shop target.
	@./scripts/smoke-test.sh

target-down: ## Stop and remove ONLY the Juice Shop target container (without stopping sentinel-ui).
	docker compose stop juice-shop && docker compose rm -f juice-shop

target-logs: ## Follow Juice Shop target container logs.
	docker compose logs --follow juice-shop

target-status: ## Show Juice Shop target container status.
	docker compose ps juice-shop

gateway-up: verify-target ## Start Kong Gateway and Juice Shop together with host port 3000 mapped to Gateway.
	docker compose -f docker-compose.yml -f docker-compose.gateway.yml up -d juice-shop kong-gateway

gateway-down: ## Stop and remove Kong Gateway and Juice Shop containers.
	docker compose -f docker-compose.yml -f docker-compose.gateway.yml stop kong-gateway juice-shop && \
	docker compose -f docker-compose.yml -f docker-compose.gateway.yml rm -f kong-gateway juice-shop

gateway-logs: ## Follow Kong Gateway container logs.
	docker compose -f docker-compose.yml -f docker-compose.gateway.yml logs --follow kong-gateway

gateway-status: ## Show Kong Gateway and Juice Shop service status.
	docker compose -f docker-compose.yml -f docker-compose.gateway.yml ps kong-gateway juice-shop

test-request: kb-python-check ## Send safe HTTP probe request via API Gateway (e.g. make test-request ARGS="--url /api/Products").
	@$(VENV_PYTHON) -m src.gateway.safe_requester $(ARGS)

gateway-test: kb-python-check ## Run API Gateway and Safe Requester tests.
	@$(VENV_PYTHON) -m pytest tests/gateway -v

down: ## Stop all Sentinel Compose resources.
	docker compose -f docker-compose.yml -f docker-compose.gateway.yml down --remove-orphans

status: ## Show Compose service status.
	docker compose -f docker-compose.yml -f docker-compose.gateway.yml ps

lint: ## Lint Python, syntax-check shell scripts, and validate Compose configuration.
	@if [[ -x "$(VENV_PYTHON)" ]]; then \
		"$(VENV_PYTHON)" -m ruff check src tests scripts; \
	else \
		"$(PYTHON)" -m ruff check src tests scripts; \
	fi
	bash -n scripts/*.sh
	docker compose config --quiet
	docker compose -f docker-compose.yml -f docker-compose.gateway.yml config --quiet

test: test-contracts test-python ## Run repository and Python tests.

test-contracts: ## Run repository contract tests.
	@./tests/test-repository-contracts.sh
	@./tests/test-kb-python-env.sh

test-python: kb-python-check ## Run normalizer unit and integration tests.
	@$(VENV_PYTHON) -m pytest tests/unit tests/integration

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
	@$(PYTHON) scripts/validate-sast-scope.py --tool codeql --report reports/raw/codeql.sarif

dast: ## Run ZAP Baseline against the already-running target.
	@./scripts/run-dast.sh

dast-zap-fullscan: ## Run ZAP Full Scan with mandatory Client Spider against the running target.
	@./scripts/run-dast-zap-fullscan.sh

dast-zap-admin: ## Run ZAP Baseline with Admin authentication against the running target.
	@./scripts/run-dast-admin.sh

dast-zap-fullscan-admin: ## Run ZAP Full Scan with Admin authentication against the running target.
	@./scripts/run-dast-zap-fullscan-admin.sh

dast-sqlmap: ## Run bounded sqlmap detection and DBMS fingerprinting against the running target.
	@./scripts/run-dast-sqlmap.sh

validate-reports: ## Validate all raw scanner reports and metadata sidecars.
	@./scripts/validate-reports.sh all

week1: ## Run the complete Week 1 flow with guaranteed runtime cleanup.
	@./scripts/run-week1.sh

normalize: kb-python-check ## Normalize reports into unified JSONL (optional: SUMMARY=path/to/summary.json).
	@./scripts/verify-target.sh >&2
	@$(VENV_PYTHON) -m src.normalizers.cli normalize-all --raw-dir reports/raw \
		--output-dir reports/normalized --source-root target-app/juice-shop $(if $(SUMMARY),--summary "$(SUMMARY)",)

clean-reports: ## Remove generated reports while preserving tracked directories.
	@./scripts/clean.sh reports

clean: ## Stop runtime, remove target data volumes, and remove the target clone.
	@./scripts/clean.sh target

.PHONY: kb-python-check kb-validate kb-build-documents kb-build-index kb-build kb-rebuild kb-search \
	kb-inspect kb-stats kb-test kb-lint kb-clean

kb-python-check:
	@./scripts/check-kb-python.sh "$(VENV_PYTHON)"

kb-validate: kb-python-check ## Validate all knowledge sources and SQLite capabilities.
	@$(VENV_PYTHON) -m src.retrieval.cli validate

kb-build-documents: kb-python-check ## Build deterministic canonical knowledge documents.
	@$(VENV_PYTHON) -m src.retrieval.cli build-documents

kb-build-index: kb-python-check ## Build the generated SQLite FTS5 index.
	@$(VENV_PYTHON) -m src.retrieval.cli build-index

kb-build: kb-python-check ## Validate and build knowledge documents and index.
	@$(VENV_PYTHON) -m src.retrieval.cli build

kb-rebuild: kb-python-check ## Remove generated knowledge artifacts and rebuild them.
	@$(VENV_PYTHON) -m src.retrieval.cli clean
	@$(VENV_PYTHON) -m src.retrieval.cli build

kb-search: kb-python-check ## Search knowledge using Hybrid mode; for example QUERY="SQL Injection".
	@test -n "$(QUERY)" || \
		(echo 'Usage: make kb-search QUERY="SQL Injection" [MODE=hybrid|keyword|semantic]' && exit 1)
	@$(VENV_PYTHON) -m src.retrieval.cli search \
		"$(QUERY)" \
		--top-k "$(or $(TOP_K),5)" \
		--mode "$(or $(MODE),hybrid)" \
		$(if $(DOC_TYPE),--doc-type "$(DOC_TYPE)",)

kb-search-keyword: kb-python-check ## Search knowledge using Sparse BM25 keyword matching (e.g. QUERY="cwe 89 và owasp a05:2025").
	@test -n "$(QUERY)" || \
		(echo 'Usage: make kb-search-keyword QUERY="SQL Injection"' && exit 1)
	@$(VENV_PYTHON) -m src.retrieval.cli search \
		"$(QUERY)" \
		--top-k "$(or $(TOP_K),5)" \
		--mode keyword \
		$(if $(DOC_TYPE),--doc-type "$(DOC_TYPE)",)

kb-search-semantic: kb-python-check ## Search knowledge using Dense Vector similarity (e.g. QUERY="database injection vulnerabilities").
	@test -n "$(QUERY)" || \
		(echo 'Usage: make kb-search-semantic QUERY="SQL Injection"' && exit 1)
	@$(VENV_PYTHON) -m src.retrieval.cli search \
		"$(QUERY)" \
		--top-k "$(or $(TOP_K),5)" \
		--mode semantic \
		$(if $(DOC_TYPE),--doc-type "$(DOC_TYPE)",)

kb-search-hybrid: kb-python-check ## Search knowledge using Two-Stage Hybrid (RRF + Pure MMR).
	@test -n "$(QUERY)" || \
		(echo 'Usage: make kb-search-hybrid QUERY="SQL Injection"' && exit 1)
	@$(VENV_PYTHON) -m src.retrieval.cli search \
		"$(QUERY)" \
		--top-k "$(or $(TOP_K),5)" \
		--mode hybrid \
		$(if $(DOC_TYPE),--doc-type "$(DOC_TYPE)",)

kb-inspect: kb-python-check ## Inspect a canonical document by DOC_ID.
	@test -n "$(DOC_ID)" || \
		(echo 'Usage: make kb-inspect DOC_ID="cwe-89"' && exit 1)
	@$(VENV_PYTHON) -m src.retrieval.cli inspect "$(DOC_ID)"

kb-stats: kb-python-check ## Display canonical knowledge and index statistics.
	@$(VENV_PYTHON) -m src.retrieval.cli stats

kb-test: kb-python-check ## Run knowledge-base unit and integration tests.
	@$(VENV_PYTHON) -m pytest tests/retrieval -q

kb-lint: kb-python-check ## Lint knowledge-base source and tests.
	@$(VENV_PYTHON) -m ruff check src/retrieval tests/retrieval

kb-clean: kb-python-check ## Remove only generated knowledge-base artifacts.
	@$(VENV_PYTHON) -m src.retrieval.cli clean

.PHONY: agent-analyze agent-test agent-lint

agent-analyze: kb-python-check ## Run Security Analysis Agent on FINDINGS=path (optional: OUTPUT_DIR=path, MODEL=model, MODE=react|static, MAX_STEPS=5).
	@test -n "$(FINDINGS)" || \
		(echo 'Usage: make agent-analyze FINDINGS=reports/normalized/unified-findings-YYYYMMDDTHHMMSSZ.jsonl [MODE=react|static] [MAX_STEPS=5]' && exit 1)
	@$(VENV_PYTHON) -m src.agent.cli analyze --findings "$(FINDINGS)" \
		$(if $(OUTPUT_DIR),--output-dir "$(OUTPUT_DIR)",) \
		$(if $(MODEL),--model "$(MODEL)",) \
		$(if $(MODE),--mode "$(MODE)",) \
		$(if $(MAX_STEPS),--max-steps "$(MAX_STEPS)",)


agent-test: kb-python-check ## Run Security Analysis Agent tests.
	@$(VENV_PYTHON) -m pytest tests/agent -v

agent-lint: kb-python-check ## Lint Security Analysis Agent code.
	@$(VENV_PYTHON) -m ruff check src/agent tests/agent

.PHONY: ui-build ui-rebuild ui ui-down ui-logs

ui-build: ## Build the Streamlit Web UI Docker container.
	docker compose build sentinel-ui

ui-rebuild: ## Clean rebuild the Sentinel UI Docker container (no cache & pull latest base).
	docker compose build --no-cache --pull sentinel-ui

ui: ## Start the Sentinel Web UI in the background.
	docker compose up -d sentinel-ui
	@echo "Sentinel UI is running at http://localhost:8501"

ui-down: ## Stop the Sentinel Web UI container.
	docker compose stop sentinel-ui

ui-logs: ## Follow Sentinel Web UI logs.
	docker compose logs --follow sentinel-ui

.PHONY: mock-server-up test-mock-guardrails test-live-mock-probe

mock-server-up: ## Start the Vulnerable Mock Server on port 3000 (PORT=3000).
	@$(VENV_PYTHON) api-server/mock_server.py --port $(or $(PORT),3000)

test-mock-guardrails: ## Run end-to-end empirical tests with Vulnerable Mock Server.
	@$(VENV_PYTHON) -m pytest tests/guardrails/test_vulnerable_mock_guardrails.py -v

test-live-mock-probe: ## Run the interactive 4-stage Live Mock Probe and Guardrails verification.
	@$(VENV_PYTHON) scripts/live_mock_probe_demo.py

