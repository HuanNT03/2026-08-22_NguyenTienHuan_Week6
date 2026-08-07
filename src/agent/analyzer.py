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


def sanitize_llm_entry_dict(
    item: dict[str, Any],
    group: AnalysisGroup,
    idx: int,
    cfg: AgentConfig,
    retry_count: int,
) -> dict[str, Any]:
    """Sanitize and normalize raw LLM output dictionary before Pydantic validation."""
    if not isinstance(item, dict):
        return item

    # 1. Match finding context if available
    if "finding_id" not in item and "entry_id" in item:
        item["finding_id"] = item["entry_id"]

    finding_context = None
    if "finding_id" in item:
        for f in group.findings:
            if f.get("finding_id") == item["finding_id"]:
                finding_context = f
                break
    if not finding_context and "fingerprint" in item:
        for f in group.findings:
            if f.get("fingerprint") == item["fingerprint"]:
                finding_context = f
                break
    if not finding_context and len(group.findings) > idx:
        finding_context = group.findings[idx]

    # 2. Fix fingerprint & finding_id
    if finding_context:
        item.setdefault("fingerprint", finding_context.get("fingerprint"))
        item.setdefault("finding_id", finding_context.get("finding_id"))
        tool_data = finding_context.get("tool", {})
        if isinstance(tool_data, dict):
            item.setdefault("tool", tool_data.get("name", "semgrep"))
            item.setdefault("scan_type", tool_data.get("scan_type", "SAST"))

    # Fix tool if LLM returned object like {"name": "semgrep", ...}
    if isinstance(item.get("tool"), dict):
        item["tool"] = item["tool"].get("name", "semgrep")
    if item.get("tool") not in ("semgrep", "zap", "codeql"):
        item["tool"] = "semgrep"

    if item.get("scan_type") not in ("SAST", "DAST"):
        item["scan_type"] = "SAST"

    # 3. Fix analysis_id pattern (^analysis_[0-9a-f]{32}$)
    raw_aid = str(item.get("analysis_id", ""))
    if not (raw_aid.startswith("analysis_") and len(raw_aid) == 41):
        fp = item.get("fingerprint") or f"idx_{idx}"
        id_hash = hashlib.md5(f"{group.group_id}_{fp}_{idx}".encode()).hexdigest()
        item["analysis_id"] = f"analysis_{id_hash}"

    # 4. Fix analysis_group_id
    item["analysis_group_id"] = group.group_id
    item["schema_version"] = "1.0.0"
    item.setdefault("analysis_status", "success")

    # 5. Fix severity
    sev = item.get("severity")
    orig_sev = finding_context.get("severity") if finding_context else "unknown"
    if isinstance(sev, str):
        sev_lower = sev.lower()
        agent_assessment = "unknown"
        for level in ("critical", "high", "medium", "low", "info"):
            if level in sev_lower:
                agent_assessment = level
                break
        item["severity"] = {
            "agent_assessment": agent_assessment,
            "original_scanner": orig_sev,
            "rationale": sev,
        }
    elif isinstance(sev, dict):
        ag = str(sev.get("agent_assessment", "")).lower()
        valid_ag = "unknown"
        for level in ("critical", "high", "medium", "low", "info"):
            if level in ag:
                valid_ag = level
                break
        sev["agent_assessment"] = valid_ag
        sev.setdefault("original_scanner", orig_sev)
        sev.setdefault("rationale", "Phân tích tác động lỗ hổng.")

    # 6. Fix confidence
    conf = item.get("confidence")
    if isinstance(conf, str):
        conf_lower = conf.lower()
        level = "unknown"
        for l_key in ("confirmed", "high", "medium", "low", "false_positive"):
            if l_key in conf_lower:
                level = l_key
                break
        item["confidence"] = {
            "level": level,
            "rationale": conf,
        }
    elif isinstance(conf, dict):
        lvl = str(conf.get("level", "")).lower()
        valid_lvl = "unknown"
        for l_key in ("confirmed", "high", "medium", "low", "false_positive"):
            if l_key in lvl:
                valid_lvl = l_key
                break
        conf["level"] = valid_lvl
        conf.setdefault("rationale", "Đánh giá độ tin cậy.")

    # 7. Fix correlation_type
    c_type = item.get("correlation_type")
    if c_type not in ("sast_only", "dast_only", "sast_dast_confirmed", "sast_dast_suspected", "multi_sast"):
        item["correlation_type"] = group.correlation_type

    # 8. Fix primary_cwe_id
    primary = item.get("primary_cwe_id")
    if not (isinstance(primary, str) and primary.startswith("CWE-")):
        item["primary_cwe_id"] = group.primary_cwe if (group.primary_cwe and group.primary_cwe.startswith("CWE-")) else None

    # 9. Fix location_summary
    if not item.get("location_summary"):
        loc = finding_context.get("location") if finding_context else {}
        if isinstance(loc, dict) and loc.get("kind") == "code":
            item["location_summary"] = f"{loc.get('path', 'unknown')} dòng {loc.get('start_line', 1)}"
        elif isinstance(loc, dict) and loc.get("kind") == "http":
            item["location_summary"] = f"{loc.get('endpoint', '/')} param={loc.get('parameter')}"
        else:
            item["location_summary"] = "Vị trí không xác định"

    # Fix string fields if LLM returned a list of strings
    for str_field in ("recommended_action", "explanation", "evidence_summary", "location_summary", "title"):
        val = item.get(str_field)
        if isinstance(val, list):
            item[str_field] = "\n".join(str(v) for v in val)

    # 10. Fix proposed_test_request
    ptr = item.get("proposed_test_request")
    if ptr is not None:
        if isinstance(ptr, dict):
            m = str(ptr.get("method", "")).upper()
            ep = str(ptr.get("endpoint", ""))
            if m not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS") or not ep.startswith("/"):
                item["proposed_test_request"] = None
        else:
            item["proposed_test_request"] = None

    # 9. Fix metadata
    meta = item.get("metadata")
    if not isinstance(meta, dict):
        meta = {}
    meta.setdefault("analyzed_at", datetime.now(UTC).isoformat())
    meta.setdefault("model", cfg.model)
    meta.setdefault("prompt_version", cfg.prompt_version)
    meta.setdefault("grouping_source", group.source)
    meta.setdefault("retry_count", retry_count)
    item["metadata"] = meta

    return item


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
            for idx, raw_item in enumerate(entries_raw):
                sanitized_item = sanitize_llm_entry_dict(raw_item, group, idx, cfg, attempt)
                entry = ReportEntry.model_validate(sanitized_item)
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
