.DEFAULT_GOAL := help

SHELL := /usr/bin/env bash

.PHONY: help doctor setup-target verify-target build up wait smoke down logs status \
	lint test quality sast sast-semgrep sast-codeql dast validate-reports week1 normalize clean-reports clean

help: ## Show available commands.
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

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

test: ## Run repository contract tests.
	@./tests/test-repository-contracts.sh

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
	@python3 -m src.normalizers.cli normalize-all --raw-dir reports/raw --output reports/normalized/unified-findings.jsonl

clean-reports: ## Remove generated reports while preserving tracked directories.
	@./scripts/clean.sh reports

clean: ## Stop runtime and remove generated reports and target clone.
	@./scripts/clean.sh full
