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

help: ## Hiển thị danh sách tất cả các lệnh và hướng dẫn tham số.
	@echo "=========================================================================================="
	@echo "                     PROJECT SENTINEL - DANH SÁCH LỆNH VẬN HÀNH (MAKE HELP)              "
	@echo "=========================================================================================="
	@awk 'BEGIN {FS = ":.*## "} \
		/^[a-zA-Z0-9_-]+:.*## / { \
			printf "  %-24s %s\n", $$1, $$2 \
		}' $(MAKEFILE_LIST)
	@echo "=========================================================================================="

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

test-request: kb-python-check ## Gửi probe HTTP an toàn qua Gateway. Tham số: ARGS="--url <endpoint> [--method GET|POST|OPTIONS] [--payload-category <cat>] [--payload-value <val>] [--burst <N>] [--oversized] [--auto-approve]"
	@$(VENV_PYTHON) -m src.gateway.safe_requester $(ARGS)

gateway-test: kb-python-check ## Chạy test suite cho API Gateway, Safe Requester và HITL queue.
	@$(VENV_PYTHON) -m pytest tests/gateway -v

down: ## Dừng và xóa toàn bộ Compose containers (Juice Shop, Gateway, Scanners).
	docker compose -f docker-compose.yml -f docker-compose.gateway.yml down --remove-orphans

status: ## Hiển thị trạng thái các container trong Compose network.
	docker compose -f docker-compose.yml -f docker-compose.gateway.yml ps

lint: ## Kiểm tra cú pháp Python (Ruff), Shell (bash -n) và Docker Compose configuration.
	@if [[ -x "$(VENV_PYTHON)" ]]; then \
		"$(VENV_PYTHON)" -m ruff check src tests scripts; \
	else \
		"$(PYTHON)" -m ruff check src tests scripts; \
	fi
	bash -n scripts/*.sh
	docker compose config --quiet
	docker compose -f docker-compose.yml -f docker-compose.gateway.yml config --quiet

test: test-contracts test-python ## Chạy toàn bộ repository contract tests và Python unit/integration tests.

test-contracts: ## Chạy bộ test kiểm tra cấu trúc repository và môi trường.
	@./tests/test-repository-contracts.sh
	@./tests/test-kb-python-env.sh

test-python: kb-python-check ## Chạy bộ test cho normalizers và app bridges.
	@$(VENV_PYTHON) -m pytest tests/unit tests/integration

quality: ## Chạy lint kiểm tra mã nguồn kết hợp chạy toàn bộ test contracts.
	@$(MAKE) lint
	@$(MAKE) test

sast: ## Chạy tuần tự cả Semgrep và CodeQL SAST trên target ứng dụng.
	@$(MAKE) sast-semgrep
	@$(MAKE) sast-codeql

sast-semgrep: ## Chạy Semgrep SAST trên target ứng dụng (xuất reports/raw/semgrep.json).
	@./scripts/run-sast.sh

sast-codeql: verify-target ## Xây dựng DB và chạy CodeQL SAST deep taint analysis (xuất reports/raw/codeql.sarif).
	docker compose --env-file configs/tool-versions.env --profile scan build codeql-scan
	@./scripts/write-scan-metadata.sh --tool codeql --report reports/raw/codeql.sarif
	HOST_UID="$$(id -u)" HOST_GID="$$(id -g)" docker compose --env-file configs/tool-versions.env --profile scan run --rm codeql-scan
	@$(PYTHON) scripts/validate-sast-scope.py --tool codeql --report reports/raw/codeql.sarif

dast: ## Chạy OWASP ZAP Baseline DAST (User) quét target (xuất reports/raw/zap.json).
	@./scripts/run-dast.sh

dast-zap-fullscan: ## Chạy OWASP ZAP Full Scan DAST (User) với Client Spider.
	@./scripts/run-dast-zap-fullscan.sh

dast-zap-admin: ## Chạy OWASP ZAP Baseline DAST với xác thực quyền Admin.
	@./scripts/run-dast-admin.sh

dast-zap-fullscan-admin: ## Chạy OWASP ZAP Full Scan DAST với xác thực quyền Admin.
	@./scripts/run-dast-zap-fullscan-admin.sh

dast-sqlmap: ## Chạy sqlmap DAST kiểm thử SQLi có kiểm soát trên endpoint tìm kiếm.
	@./scripts/run-dast-sqlmap.sh

validate-reports: ## Kiểm tra tính hợp lệ của toàn bộ raw scanner reports và metadata.
	@./scripts/validate-reports.sh all

week1: ## Chạy toàn bộ luồng tự động Week 1 với dọn dẹp runtime an toàn.
	@./scripts/run-week1.sh

normalize: kb-python-check ## Chuẩn hóa raw reports sang Unified Findings JSONL. Tham số tùy chọn: SUMMARY=<path/to/summary.json>
	@./scripts/verify-target.sh >&2
	@$(VENV_PYTHON) -m src.normalizers.cli normalize-all --raw-dir reports/raw \
		--output-dir reports/normalized --source-root target-app/juice-shop $(if $(SUMMARY),--summary "$(SUMMARY)",)

clean-reports: ## Xóa các file báo cáo generated trong reports/ trong khi giữ nguyên thư mục.
	@./scripts/clean.sh reports

clean: ## Dừng runtime, xóa target data volumes và dọn dẹp clone.
	@./scripts/clean.sh target

.PHONY: kb-python-check kb-validate kb-build-documents kb-build-index kb-build kb-rebuild kb-search \
	kb-inspect kb-stats kb-test kb-lint kb-clean

kb-python-check:
	@./scripts/check-kb-python.sh "$(VENV_PYTHON)"

kb-validate: kb-python-check ## Kiểm tra nguồn tri thức và tính tương thích SQLite FTS5.
	@$(VENV_PYTHON) -m src.retrieval.cli validate

kb-build-documents: kb-python-check ## Xây dựng 442+ tài liệu canonical chuẩn hóa từ nguồn thô.
	@$(VENV_PYTHON) -m src.retrieval.cli build-documents

kb-build-index: kb-python-check ## Xây dựng chỉ mục tìm kiếm SQLite FTS5 (knowledge.db).
	@$(VENV_PYTHON) -m src.retrieval.cli build-index

kb-build: kb-python-check ## Kiểm tra và xây dựng đầy đủ tài liệu canonical và SQLite index.
	@$(VENV_PYTHON) -m src.retrieval.cli build

kb-rebuild: kb-python-check ## Xóa toàn bộ artifacts tri thức cũ và build lại từ đầu.
	@$(VENV_PYTHON) -m src.retrieval.cli clean
	@$(VENV_PYTHON) -m src.retrieval.cli build

kb-search: kb-python-check ## Tra cứu tri thức bảo mật Hybrid (FTS5 + Vector). Tham số: QUERY="<từ khóa>" [MODE=hybrid|keyword|semantic] [TOP_K=5] [DOC_TYPE=cwe|owasp|asvs]
	@test -n "$(QUERY)" || \
		(echo 'Usage: make kb-search QUERY="SQL Injection" [MODE=hybrid|keyword|semantic] [TOP_K=5] [DOC_TYPE=cwe|owasp|asvs]' && exit 1)
	@$(VENV_PYTHON) -m src.retrieval.cli search \
		"$(QUERY)" \
		--top-k "$(or $(TOP_K),5)" \
		--mode "$(or $(MODE),hybrid)" \
		$(if $(DOC_TYPE),--doc-type "$(DOC_TYPE)",)

kb-search-keyword: kb-python-check ## Tra cứu tri thức từ khóa Sparse BM25. Tham số: QUERY="<từ khóa>" [TOP_K=5] [DOC_TYPE=cwe|owasp|asvs]
	@test -n "$(QUERY)" || \
		(echo 'Usage: make kb-search-keyword QUERY="SQL Injection" [TOP_K=5] [DOC_TYPE=cwe|owasp|asvs]' && exit 1)
	@$(VENV_PYTHON) -m src.retrieval.cli search \
		"$(QUERY)" \
		--top-k "$(or $(TOP_K),5)" \
		--mode keyword \
		$(if $(DOC_TYPE),--doc-type "$(DOC_TYPE)",)

kb-search-semantic: kb-python-check ## Tra cứu tri thức ngữ nghĩa Dense Vector. Tham số: QUERY="<câu hỏi/từ khóa>" [TOP_K=5] [DOC_TYPE=cwe|owasp|asvs]
	@test -n "$(QUERY)" || \
		(echo 'Usage: make kb-search-semantic QUERY="SQL Injection" [TOP_K=5] [DOC_TYPE=cwe|owasp|asvs]' && exit 1)
	@$(VENV_PYTHON) -m src.retrieval.cli search \
		"$(QUERY)" \
		--top-k "$(or $(TOP_K),5)" \
		--mode semantic \
		$(if $(DOC_TYPE),--doc-type "$(DOC_TYPE)",)

kb-search-hybrid: kb-python-check ## Tra cứu tri thức kết hợp RRF + MMR. Tham số: QUERY="<từ khóa>" [TOP_K=5] [DOC_TYPE=cwe|owasp|asvs]
	@test -n "$(QUERY)" || \
		(echo 'Usage: make kb-search-hybrid QUERY="SQL Injection" [TOP_K=5] [DOC_TYPE=cwe|owasp|asvs]' && exit 1)
	@$(VENV_PYTHON) -m src.retrieval.cli search \
		"$(QUERY)" \
		--top-k "$(or $(TOP_K),5)" \
		--mode hybrid \
		$(if $(DOC_TYPE),--doc-type "$(DOC_TYPE)",)

kb-inspect: kb-python-check ## Xem chi tiết toàn văn 1 tài liệu canonical. Tham số: DOC_ID="<id>" (Ví dụ: DOC_ID=cwe-89)
	@test -n "$(DOC_ID)" || \
		(echo 'Usage: make kb-inspect DOC_ID="cwe-89"' && exit 1)
	@$(VENV_PYTHON) -m src.retrieval.cli inspect "$(DOC_ID)"

kb-stats: kb-python-check ## Hiển thị thống kê tổng quan về kho tri thức và SQLite index.
	@$(VENV_PYTHON) -m src.retrieval.cli stats

kb-test: kb-python-check ## Chạy test suite cho kho tri thức và retrieval service.
	@$(VENV_PYTHON) -m pytest tests/retrieval -q

kb-lint: kb-python-check ## Kiểm tra linting mã nguồn module retrieval.
	@$(VENV_PYTHON) -m ruff check src/retrieval tests/retrieval

kb-clean: kb-python-check ## Xóa toàn bộ artifacts tri thức đã sinh.
	@$(VENV_PYTHON) -m src.retrieval.cli clean

.PHONY: agent-analyze agent-test agent-lint

agent-analyze: kb-python-check ## Chạy ReAct Security Analysis Agent. Tham số: FINDINGS=<path.jsonl> [MODE=react|static] [MAX_STEPS=5] [MODEL=<model>] [OUTPUT_DIR=<path>]
	@test -n "$(FINDINGS)" || \
		(echo 'Usage: make agent-analyze FINDINGS=reports/normalized/unified-findings-YYYYMMDDTHHMMSSZ.jsonl [MODE=react|static] [MAX_STEPS=5] [MODEL=my-combo] [OUTPUT_DIR=reports/analyzed]' && exit 1)
	@$(VENV_PYTHON) -m src.agent.cli analyze --findings "$(FINDINGS)" \
		$(if $(OUTPUT_DIR),--output-dir "$(OUTPUT_DIR)",) \
		$(if $(MODEL),--model "$(MODEL)",) \
		$(if $(MODE),--mode "$(MODE)",) \
		$(if $(MAX_STEPS),--max-steps "$(MAX_STEPS)",)


agent-test: kb-python-check ## Chạy test suite cho ReAct Agent.
	@$(VENV_PYTHON) -m pytest tests/agent -v

agent-lint: kb-python-check ## Kiểm tra linting mã nguồn module agent.
	@$(VENV_PYTHON) -m ruff check src/agent tests/agent

.PHONY: ui-build ui-rebuild ui ui-down ui-logs

ui-build: ## Build container Docker cho Streamlit Web UI.
	docker compose build sentinel-ui

ui-rebuild: ## Build lại container Docker cho UI không dùng cache.
	docker compose build --no-cache --pull sentinel-ui

ui: ## Khởi động giao diện Streamlit Web UI tại http://localhost:8501.
	docker compose up -d sentinel-ui
	@echo "Sentinel UI is running at http://localhost:8501"

ui-down: ## Dừng container Streamlit Web UI.
	docker compose stop sentinel-ui

ui-logs: ## Xem live logs từ container Streamlit Web UI.
	docker compose logs --follow sentinel-ui

.PHONY: mock-server-up mock-server-down test-mock-guardrails test-live-mock-probe

mock-server-up: ## Khởi động Vulnerable Mock Server. Tham số tùy chọn: PORT=<cổng> (Mặc định: PORT=3000)
	@$(VENV_PYTHON) api-server/mock_server.py --port $(or $(PORT),3000)

mock-server-down: ## Dừng toàn bộ tiến trình Vulnerable Mock Server đang chạy ngầm.
	@fuser -k 3000/tcp 2>/dev/null || pkill -f "python.*mock_server.py" 2>/dev/null || true
	@echo "Vulnerable Mock Server stopped."

test-mock-guardrails: ## Chạy bài kiểm thử thực nghiệm E2E Guardrails với Mock Server.
	@$(VENV_PYTHON) -m pytest tests/guardrails/test_vulnerable_mock_guardrails.py -v

test-live-mock-probe: ## Chạy kịch bản 4 chặng Live Mock Probe trực quan trên Terminal.
	@$(VENV_PYTHON) scripts/live_mock_probe_demo.py

