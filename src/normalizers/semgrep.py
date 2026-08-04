from typing import Any

from src.normalizers.common.confidence import normalize_confidence
from src.normalizers.common.finding import (
    base_finding,
    fingerprint_collision_count,
    native_string,
    optional_string,
    positive_int,
    reference_urls,
    string_array,
    utc_now,
)
from src.normalizers.common.hashing import canonical_sha256
from src.normalizers.common.models import ToolNormalizationResult
from src.normalizers.common.paths import normalize_code_path
from src.normalizers.common.severity import normalize_severity
from src.normalizers.common.taxonomy import normalize_cwe_ids, normalize_owasp_categories
from src.normalizers.context import NormalizationContext


def _trace_node(location: Any, content: Any, step_index: int) -> dict[str, Any] | None:
    if not isinstance(location, dict):
        return None
    start = location.get("start") if isinstance(location.get("start"), dict) else {}
    node = {
        "step_index": step_index,
        "path": normalize_code_path(location.get("path")),
        "line": positive_int(start.get("line")),
        "column": positive_int(start.get("col")),
        "content": optional_string(content),
        "message": None,
    }
    if all(node[key] is None for key in ("path", "line", "column", "content", "message")):
        return None
    return node


def _tuple_trace_node(value: Any, step_index: int) -> dict[str, Any] | None:
    if not isinstance(value, list) or len(value) < 2:
        return None
    payload = value[1]
    if not isinstance(payload, list) or len(payload) < 2:
        return None
    return _trace_node(payload[0], payload[1], step_index)


def _normalize_data_flow(raw_trace: Any) -> list[dict[str, Any]] | None:
    if not isinstance(raw_trace, dict):
        return None
    source = _tuple_trace_node(raw_trace.get("taint_source"), 0)
    intermediate_values = raw_trace.get("intermediate_vars")
    if not isinstance(intermediate_values, list):
        intermediate_values = []
    steps: list[dict[str, Any]] = []
    for raw_step in intermediate_values:
        if not isinstance(raw_step, dict):
            continue
        node = _trace_node(raw_step.get("location"), raw_step.get("content"), len(steps) + 1)
        if node is not None:
            steps.append(node)
    sink = _tuple_trace_node(raw_trace.get("taint_sink"), len(steps) + 1)
    if source is None or sink is None:
        return None
    return [{"kind": "taint", "engine": "semgrep", "source": source, "steps": steps, "sink": sink}]


def _semgrep_fingerprint(
    *,
    context: NormalizationContext,
    rule_id: str,
    path: str,
    native_fingerprint: str | None,
    start_line: int,
    start_column: int | None,
) -> str:
    payload: dict[str, Any] = {
        "target": context.target_name,
        "tool": "semgrep",
        "rule_id": rule_id,
        "path": path,
    }
    if native_fingerprint is not None:
        payload["native_fingerprint"] = native_fingerprint
    else:
        payload["start_line"] = start_line
        payload["start_column"] = start_column
    return canonical_sha256("fp", "v1", payload)


def _group_key(context: NormalizationContext, cwe_ids: list[str], path: str, start_line: int, rule_id: str) -> str:
    payload = {
        "target": context.target_name,
        "cwe_ids": cwe_ids,
        "location": {"path": path, "start_line": start_line},
        "method": None,
        "canonical_endpoint": None,
        "parameter": None,
        "fallback_rule_id": rule_id if not cwe_ids else None,
        "rule_reference": None,
    }
    return canonical_sha256("grp", "v1", payload)


def normalize_semgrep_report(
    report: dict[str, Any],
    context: NormalizationContext,
    *,
    normalized_at: str | None = None,
) -> ToolNormalizationResult:
    results = report.get("results")
    if not isinstance(results, list):
        raise TypeError("Semgrep report.results must be an array")
    normalized_at = normalized_at or utc_now()
    findings: list[dict[str, Any]] = []
    for result_index, result in enumerate(results):
        if not isinstance(result, dict):
            raise TypeError(f"Semgrep result {result_index} must be an object")
        extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
        metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        start = result.get("start") if isinstance(result.get("start"), dict) else {}
        end = result.get("end") if isinstance(result.get("end"), dict) else {}
        rule_id = optional_string(result.get("check_id"))
        path = normalize_code_path(result.get("path"))
        start_line = positive_int(start.get("line"))
        if rule_id is None or path is None or start_line is None:
            raise ValueError(f"Semgrep result {result_index} is missing rule or primary location")
        start_column = positive_int(start.get("col"))
        end_line = positive_int(end.get("line")) or start_line
        end_column = positive_int(end.get("col"))
        native_severity = native_string(extra.get("severity"))
        native_confidence = native_string(metadata.get("confidence"))
        cwe_ids = normalize_cwe_ids(metadata.get("cwe"))
        vulnerability_classes = string_array(metadata.get("vulnerability_class"))
        title = vulnerability_classes[0] if vulnerability_classes else None
        finding = base_finding(
            context=context,
            normalized_at=normalized_at,
            tool_name="semgrep",
            tool_version=native_string(report.get("version")),
            scan_type="SAST",
            rule={
                "id": rule_id,
                "reference_id": None,
                "name": None,
                "native_severity": native_severity,
                "native_confidence": native_confidence,
            },
        )
        finding.update({
            "fingerprint": _semgrep_fingerprint(
                context=context,
                rule_id=rule_id,
                path=path,
                native_fingerprint=optional_string(extra.get("fingerprint")),
                start_line=start_line,
                start_column=start_column,
            ),
            "group_key": _group_key(context, cwe_ids, path, start_line, rule_id),
            "title": title,
            "description": optional_string(extra.get("message")),
            "categories": string_array(metadata.get("category")),
            "severity": normalize_severity("semgrep", native_severity),
            "confidence": normalize_confidence("semgrep", native_confidence),
            "cwe_ids": cwe_ids,
            "owasp_categories": normalize_owasp_categories(metadata.get("owasp")),
            "wasc_ids": [],
            "location": {
                "kind": "code",
                "path": path,
                "start_line": start_line,
                "start_column": start_column,
                "end_line": end_line,
                "end_column": end_column,
            },
            "evidence": None,
            "data_flow": _normalize_data_flow(extra.get("dataflow_trace")),
            "solution": optional_string(extra.get("fix")),
            "references": reference_urls(metadata.get("references")),
            "raw_sources": [{
                "format": "semgrep-json",
                "report_path": context.report_path,
                "json_pointer": f"/results/{result_index}",
            }],
        })
        findings.append(finding)
    scanner_errors = report.get("errors")
    warnings = {
        "scanner_errors": len(scanner_errors) if isinstance(scanner_errors, list) else 0,
        "fingerprint_collisions": fingerprint_collision_count(findings),
    }
    return ToolNormalizationResult(
        findings=findings,
        raw_counts={"raw_findings": len(results), "findings_written": len(findings)},
        warnings=warnings,
    )
