# Week 3 Security Analysis Agent Specification

## Scope and Architecture

The Security Analysis Agent consumes normalized findings v2 (`reports/normalized/unified-findings-*.jsonl`) and the SQLite knowledge base index (`knowledge-base/index/knowledge.db`) to produce structured, machine-readable security analysis reports (`reports/analyzed/security-analysis-report-*.jsonl`).

The architecture follows a three-phase pipeline:
1. **Pre-Grouping & Correlation**: Findings are loaded and clustered using normalizer `group_key` identifiers, CWE intersections, title similarity, and parameter-to-dataflow matching.
2. **Agentic Analysis Loop**: Each analysis group is processed in isolation. The agent retrieves relevant knowledge documents, redacts sensitive content, and prompts an OpenAI-compatible model (Alibaba Qwen / OpenRouter) using structured JSON output mode.
3. **Post-Processing & Coverage Guarantee**: Every input finding's fingerprint must appear in the final report. If an LLM call fails after retries, fallback error entries are generated to maintain 100% coverage.

## Analysis Report Schema

The output contract is governed by `schemas/security_analysis_report.schema.json`. Output files contain one JSON object per line (JSONL format), representing a 1-to-1 analysis of each input finding.

| Field | Type | Description |
| --- | --- | --- |
| `schema_version` | String | Fixed constant `"1.0.0"`. |
| `analysis_id` | String | Unique, deterministic ID matching `^analysis_[0-9a-f]{32}$`. |
| `analysis_group_id` | String | Identifier matching `^grp_[a-zA-Z0-9_:-]+$` linking related findings. |
| `analysis_status` | Enum | `"success"` or `"error"`. |
| `fingerprint` | String | SHA-256 fingerprint of the analyzed input finding. |
| `finding_id` | String | Input finding identifier (`fnd_...`). |
| `tool` | Enum | `"semgrep"`, `"zap"`, or `"codeql"`. |
| `scan_type` | Enum | `"SAST"` or `"DAST"`. |
| `title` | String | Vulnerability title in Vietnamese with English technical terms in parentheses. |
| `primary_cwe_id` | String / null | Primary CWE identifier (`CWE-89`). |
| `all_cwe_ids` | Array[String] | All unique CWE identifiers associated with the finding. |
| `owasp_category` | String / null | OWASP Top 10 category mapping (`OWASP-A03:2021`). |
| `location_summary` | String | Source code line summary or HTTP endpoint/parameter description. |
| `severity` | Object | Structured severity containing `agent_assessment`, `original_scanner`, and `rationale`. |
| `confidence` | Object | Structured confidence containing `level` (`confirmed`, `high`, `medium`, `low`, `false_positive`) and `rationale`. |
| `correlation_type` | Enum | `"sast_only"`, `"dast_only"`, `"sast_dast_confirmed"`, `"sast_dast_suspected"`, or `"multi_sast"`. |
| `correlated_with` | Array[String] | Fingerprints of all other findings within the same analysis group. |
| `evidence_summary` | String | Concise summary of code snippets, taint flows, or HTTP requests. |
| `explanation` | String | Technical explanation of vulnerability root cause in Vietnamese. |
| `recommended_action` | String | Specific remediation guidance. |
| `proposed_test_request` | Object / null | Data-only proposed HTTP request (`method`, `endpoint`, `headers`, `payload`, `rationale`). |
| `knowledge_references` | Array[Object] | Provenance links to retrieved canonical knowledge documents (`doc_id`, `title`, `relevance`). |
| `metadata` | Object | Execution lineage (`analyzed_at`, `model`, `prompt_version`, `grouping_source`, `retry_count`). |

## Hybrid Grouping and SAST-DAST Correlation

Findings are grouped deterministically prior to model invocation:
- **Base Cluster**: Findings sharing identical `group_key` values.
- **Same-Tool Merge**: Clusters sharing CWE IDs and matching file paths or similar titles are merged.
- **Cross-Tool Correlation**: SAST and DAST clusters sharing CWE IDs and title similarity or parameter-to-dataflow matches are merged and flagged with `correlation_type = "sast_dast_suspected"`.
- **Broad CWE Filter**: Broad CWEs (`CWE-400`, `CWE-20`, `CWE-116`, etc.) require explicit location or title similarity to merge, preventing false cross-file aggregation.
- **Orphan Protection**: Any un-grouped finding is wrapped in a single-finding group to prevent data loss.

## Redaction and Safe Prompting

Before constructing model prompts, all evidence and metadata fields undergo automated redaction (`src/agent/redaction.py`):
- Email addresses are replaced with `[REDACTED_EMAIL]`.
- Phone numbers are replaced with `[REDACTED_PHONE]`.
- Bearer tokens and secret API keys are replaced with `[REDACTED_SECRET]`.
- Password strings in JSON/text are replaced with `[REDACTED_PASSWORD]`.

Prompt content from scanner reports, HTTP traffic, and knowledge base snippets are treated as untrusted data. The system prompt (`src/agent/prompts/system_v1.md`) instructs the model to ignore any embedded user or system instructions within evidence.

## LLM Execution, Retries, and Fallback Isolation

The analyzer utilizes the `openai` Python SDK configured via `.env` (`LLM_API_KEY`, `LLM_BASE_URL`, `LLM_MODEL`).
- Requests enforce `response_format={"type": "json_object"}`.
- Model responses are sanitized by `sanitize_llm_entry_dict` to normalize minor formatting variances (such as string severity levels or missing wrappers) before Pydantic schema validation.
- If JSON parsing or Pydantic validation fails, the agent retries up to `max_retries` (default: 2), feeding validation error details back into the message history.
- If max retries are exceeded or an unhandled provider exception occurs, the orchestrator generates fallback entries with `analysis_status = "error"` for every finding in the group.

## Output and Verification Contract

The CLI (`python3 -m src.agent.cli analyze`) produces two artifacts in `reports/analyzed/`:
1. `security-analysis-report-YYYYMMDDTHHMMSSZ.jsonl`: The machine-readable analysis lines.
2. `analysis-summary-YYYYMMDDTHHMMSSZ.json`: Summary metadata containing input/output counts, status distributions, and coverage metrics.

Phase 3 verifies that every input fingerprint is present in the output. An incomplete run raises a `RuntimeError` and halts execution.
