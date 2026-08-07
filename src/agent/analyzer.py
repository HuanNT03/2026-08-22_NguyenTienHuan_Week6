"""LLM Analysis Engine for Project Sentinel Security Analysis Agent."""

import hashlib
import json
import logging
from datetime import UTC, datetime
from typing import Any

from openai import OpenAI
from pydantic import ValidationError

from src.agent.config import AgentConfig
from src.agent.models import (
    AnalysisGroup,
    AnalysisMetadata,
    ConfidenceAssessment,
    ReportEntry,
    SeverityAssessment,
)
from src.agent.prompt_builder import build_user_prompt, fetch_kb_context_for_group
from src.retrieval.service import KnowledgeSearchService

logger = logging.getLogger(__name__)


def create_fallback_error_entry(
    finding: dict[str, Any],
    group: AnalysisGroup,
    error_msg: str,
    config: AgentConfig,
    retry_count: int,
) -> ReportEntry:
    """Create a structured fallback error ReportEntry when LLM analysis fails after max retries."""
    fp = finding["fingerprint"]
    fnd_id = finding["finding_id"]
    tool_name = finding.get("tool", {}).get("name", "unknown")
    scan_type = finding.get("tool", {}).get("scan_type", "SAST")
    cwes = finding.get("cwe_ids") or []
    primary_cwe = cwes[0] if cwes else None
    owasp = (finding.get("owasp_categories") or [None])[0]

    # Generate deterministic analysis_id
    id_hash = hashlib.md5(f"fallback_{fp}_{retry_count}".encode()).hexdigest()
    analysis_id = f"analysis_{id_hash}"

    loc = finding.get("location") or {}
    if loc.get("kind") == "code":
        loc_summary = f"{loc.get('path', 'unknown')} dòng {loc.get('start_line', 1)}"
    else:
        loc_summary = f"{loc.get('endpoint', '/')} param={loc.get('parameter')}"

    return ReportEntry(
        schema_version="1.0.0",
        analysis_id=analysis_id,
        analysis_group_id=group.group_id,
        analysis_status="error",
        fingerprint=fp,
        finding_id=fnd_id,
        tool=tool_name if tool_name in ("semgrep", "zap", "codeql") else "semgrep",
        scan_type="SAST" if scan_type == "SAST" else "DAST",
        title=finding.get("title") or "Lỗi Phân Tích (Analysis Error)",
        primary_cwe_id=primary_cwe if primary_cwe and primary_cwe.startswith("CWE-") else None,
        all_cwe_ids=[c for c in cwes if c.startswith("CWE-")],
        owasp_category=owasp if owasp and owasp.startswith("OWASP-A") else None,
        location_summary=loc_summary,
        severity=SeverityAssessment(
            agent_assessment=finding.get("severity", "unknown") if finding.get("severity") in ("info", "low", "medium", "high", "critical") else "unknown",
            original_scanner=finding.get("severity"),
            rationale=f"Lỗi khi gọi mô hình phân tích LLM: {error_msg}",
        ),
        confidence=ConfidenceAssessment(
            level="low",
            rationale="Chưa thể phân tích tự động thành công do lỗi hệ thống.",
        ),
        correlation_type=group.correlation_type,
        correlated_with=group.correlated_fingerprints,
        evidence_summary=f"Phân tích tự động thất bại sau {retry_count} lần thử. Lỗi: {error_msg}",
        explanation=f"Quá trình phân tích LLM gặp sự cố: {error_msg}. Cần kiểm tra lại cấu hình API key hoặc provider.",
        recommended_action="Kiểm tra lại log của agent và thực hiện phân tích thủ công.",
        proposed_test_request=None,
        knowledge_references=[],
        metadata=AnalysisMetadata(
            analyzed_at=datetime.now(UTC).isoformat(),
            model=config.model,
            prompt_version=config.prompt_version,
            grouping_source=group.source,
            retry_count=retry_count,
        ),
    )


def analyze_group(
    group: AnalysisGroup,
    kb_service: KnowledgeSearchService,
    client: OpenAI | None = None,
    config: AgentConfig | None = None,
) -> list[ReportEntry]:
    """Execute LLM security analysis for a single AnalysisGroup with retry & fallback."""
    cfg = config or AgentConfig()

    if client is None:
        client = OpenAI(
            api_key=cfg.api_key or "placeholder_key",
            base_url=cfg.base_url,
        )

    system_prompt = cfg.system_prompt_path.read_text(encoding="utf-8") if cfg.system_prompt_path.is_file() else "System Prompt"

    # Step 1: KB retrieval
    kb_snippets, kb_results = fetch_kb_context_for_group(group, kb_service=kb_service)

    # Step 2: Build user prompt
    user_prompt = build_user_prompt(group, kb_snippets)

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    last_error_msg = ""
    for attempt in range(cfg.max_retries + 1):
        try:
            logger.info("Analyzing group %s (attempt %d/%d)", group.group_id, attempt + 1, cfg.max_retries + 1)
            response = client.chat.completions.create(
                model=cfg.model,
                temperature=cfg.temperature,
                messages=messages,
                response_format={"type": "json_object"},
            )

            raw_content = response.choices[0].message.content or ""
            parsed_data = json.loads(raw_content)

            # Handle object with `entries` key or direct list
            if isinstance(parsed_data, dict) and "entries" in parsed_data:
                entries_raw = parsed_data["entries"]
            elif isinstance(parsed_data, list):
                entries_raw = parsed_data
            elif isinstance(parsed_data, dict):
                entries_raw = [parsed_data]
            else:
                raise ValueError("LLM response format must be a JSON object with 'entries' key or array.")

            validated_entries: list[ReportEntry] = []
            for item in entries_raw:
                # Fill missing schema_version or metadata defaults if omitted by LLM
                if isinstance(item, dict):
                    item.setdefault("schema_version", "1.0.0")
                    item.setdefault("analysis_group_id", group.group_id)
                    item.setdefault("analysis_status", "success")
                    if "metadata" in item and isinstance(item["metadata"], dict):
                        item["metadata"].setdefault("analyzed_at", datetime.now(UTC).isoformat())
                        item["metadata"].setdefault("model", cfg.model)
                        item["metadata"].setdefault("prompt_version", cfg.prompt_version)
                        item["metadata"].setdefault("grouping_source", group.source)
                        item["metadata"].setdefault("retry_count", attempt)
                
                entry = ReportEntry.model_validate(item)
                validated_entries.append(entry)

            # Verify that every finding in the group has a matching entry
            covered_fps = {e.fingerprint for e in validated_entries}
            group_fps = {f["fingerprint"] for f in group.findings}

            if not group_fps.issubset(covered_fps):
                # If some findings are missing in LLM output, generate entries for missing findings
                for f in group.findings:
                    if f["fingerprint"] not in covered_fps:
                        fallback_entry = create_fallback_error_entry(
                            f, group, "LLM response omitted this finding from output entries list.", cfg, attempt
                        )
                        validated_entries.append(fallback_entry)

            return validated_entries

        except (json.JSONDecodeError, ValidationError, ValueError, Exception) as err:  # noqa: BLE001
            last_error_msg = str(err)
            logger.warning("Group %s attempt %d failed: %s", group.group_id, attempt + 1, last_error_msg)

            if attempt < cfg.max_retries:
                # Add retry feedback message for next attempt
                messages.append({"role": "assistant", "content": raw_content if 'raw_content' in locals() else ""})
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            f"Lần thử trước bị lỗi format/validation: {last_error_msg}. "
                            "Hãy sửa lại và trả về JSON object hợp lệ tuân thủ chính xác Pydantic schema."
                        ),
                    }
                )

    # Max retries exceeded -> return fallback error entries for all group findings
    logger.error("Group %s failed after %d retries. Generating fallback entries.", group.group_id, cfg.max_retries)
    return [
        create_fallback_error_entry(f, group, last_error_msg, cfg, cfg.max_retries)
        for f in group.findings
    ]
