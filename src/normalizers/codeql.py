from typing import Any

from src.normalizers.common.confidence import normalize_confidence
from src.normalizers.common.finding import (
    base_finding,
    fingerprint_collision_count,
    native_string,
    optional_string,
    positive_int,
    utc_now,
)
from src.normalizers.common.hashing import canonical_sha256
from src.normalizers.common.models import ToolNormalizationResult
from src.normalizers.common.paths import normalize_code_path
from src.normalizers.common.severity import normalize_severity
from src.normalizers.common.taxonomy import normalize_cwe_ids, normalize_owasp_categories
from src.normalizers.context import NormalizationContext


def _message_text(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    return optional_string(value.get("text"))


def _physical_location(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    physical = value.get("physicalLocation")
    return physical if isinstance(physical, dict) else {}


def _code_location(physical: dict[str, Any]) -> dict[str, Any] | None:
    artifact = physical.get("artifactLocation") if isinstance(physical.get("artifactLocation"), dict) else {}
    region = physical.get("region") if isinstance(physical.get("region"), dict) else {}
    path = normalize_code_path(artifact.get("uri"))
    start_line = positive_int(region.get("startLine"))
    if path is None or start_line is None:
        return None
    return {
        "kind": "code",
        "path": path,
        "start_line": start_line,
        "start_column": positive_int(region.get("startColumn")),
        "end_line": positive_int(region.get("endLine")) or start_line,
        "end_column": positive_int(region.get("endColumn")),
    }


def _flow_node(value: Any, step_index: int) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    location = value.get("location") if isinstance(value.get("location"), dict) else {}
    physical = _physical_location(location)
    artifact = physical.get("artifactLocation") if isinstance(physical.get("artifactLocation"), dict) else {}
    region = physical.get("region") if isinstance(physical.get("region"), dict) else {}
    node = {
        "step_index": step_index,
        "path": normalize_code_path(artifact.get("uri")),
        "line": positive_int(region.get("startLine")),
        "column": positive_int(region.get("startColumn")),
        "content": None,
        "message": _message_text(location.get("message")),
    }
    if all(node[key] is None for key in ("path", "line", "column", "content", "message")):
        return None
    return node


def _data_flows(result: dict[str, Any]) -> list[dict[str, Any]] | None:
    code_flows = result.get("codeFlows")
    if not isinstance(code_flows, list):
        return None
    flows: list[dict[str, Any]] = []
    for code_flow in code_flows:
        if not isinstance(code_flow, dict):
            continue
        thread_flows = code_flow.get("threadFlows")
        if not isinstance(thread_flows, list):
            continue
        for thread_flow in thread_flows:
            if not isinstance(thread_flow, dict):
                continue
            locations = thread_flow.get("locations")
            if not isinstance(locations, list) or not locations:
                continue
            source = _flow_node(locations[0], 0)
            steps = [
                node
                for index, raw_node in enumerate(locations[1:-1], start=1)
                if (node := _flow_node(raw_node, index)) is not None
            ]
            sink = _flow_node(locations[-1], len(locations) - 1)
            if source is None or sink is None:
                continue
            flows.append({
                "kind": "taint",
                "engine": "codeql",
                "source": source,
                "steps": steps,
                "sink": sink,
            })
    return flows or None


def _fingerprint(
    context: NormalizationContext,
    result: dict[str, Any],
    rule_id: str,
    location: dict[str, Any],
) -> str:
    partial = result.get("partialFingerprints") if isinstance(result.get("partialFingerprints"), dict) else {}
    line_hash = optional_string(partial.get("primaryLocationLineHash"))
    column_fingerprint = optional_string(partial.get("primaryLocationStartColumnFingerprint"))
    payload: dict[str, Any] = {
        "target": context.target_name,
        "tool": "codeql",
        "rule_id": rule_id,
        "path": location["path"],
    }
    if line_hash is not None:
        payload["primary_location_line_hash"] = line_hash
    else:
        payload["start_line"] = location["start_line"]
        payload["end_line"] = location["end_line"]
    if column_fingerprint is not None:
        payload["primary_location_start_column_fingerprint"] = column_fingerprint
    else:
        payload["start_column"] = location["start_column"]
    return canonical_sha256("fp", "v1", payload)


def _group_key(
    context: NormalizationContext,
    cwe_ids: list[str],
    location: dict[str, Any],
    rule_id: str,
) -> str:
    return canonical_sha256("grp", "v1", {
        "target": context.target_name,
        "cwe_ids": cwe_ids,
        "location": {"path": location["path"], "start_line": location["start_line"]},
        "method": None,
        "canonical_endpoint": None,
        "parameter": None,
        "fallback_rule_id": rule_id if not cwe_ids else None,
        "rule_reference": None,
    })


def _rule_descriptor(
    result: dict[str, Any],
    rules: list[Any],
    rules_by_id: dict[str, tuple[int, dict[str, Any]]],
    rule_id: str,
) -> tuple[int | None, dict[str, Any] | None]:
    rule_index = result.get("ruleIndex")
    if isinstance(rule_index, int) and not isinstance(rule_index, bool) and 0 <= rule_index < len(rules):
        descriptor = rules[rule_index]
        if isinstance(descriptor, dict) and optional_string(descriptor.get("id")) == rule_id:
            return rule_index, descriptor
    return rules_by_id.get(rule_id, (None, None))


def _diagnostics(sarif: dict[str, Any]) -> tuple[int, int, int]:
    extraction_errors = 0
    parse_errors = 0
    affected_files: set[str] = set()
    runs = sarif.get("runs") if isinstance(sarif.get("runs"), list) else []
    for run in runs:
        if not isinstance(run, dict):
            continue
        invocations = run.get("invocations") if isinstance(run.get("invocations"), list) else []
        for invocation in invocations:
            if not isinstance(invocation, dict):
                continue
            notifications = invocation.get("toolExecutionNotifications")
            if not isinstance(notifications, list):
                continue
            for notification in notifications:
                if not isinstance(notification, dict):
                    continue
                descriptor = notification.get("descriptor") if isinstance(notification.get("descriptor"), dict) else {}
                diagnostic_id = descriptor.get("id")
                if diagnostic_id == "js/diagnostics/extraction-errors":
                    extraction_errors += 1
                    locations = notification.get("locations")
                    if isinstance(locations, list) and locations:
                        physical = _physical_location(locations[0])
                        artifact = physical.get("artifactLocation") if isinstance(physical.get("artifactLocation"), dict) else {}
                        uri = optional_string(artifact.get("uri"))
                        if uri is not None:
                            affected_files.add(uri)
                elif diagnostic_id == "js/parse-error":
                    parse_errors += 1
    return extraction_errors, parse_errors, len(affected_files)


def normalize_codeql_report(
    sarif: dict[str, Any],
    context: NormalizationContext,
    *,
    normalized_at: str | None = None,
) -> ToolNormalizationResult:
    if sarif.get("version") != "2.1.0":
        raise ValueError(f"Unsupported SARIF version: {sarif.get('version')!r}")
    runs = sarif.get("runs")
    if not isinstance(runs, list):
        raise TypeError("SARIF runs must be an array")
    normalized_at = normalized_at or utc_now()
    findings: list[dict[str, Any]] = []
    missing_rule_descriptors = 0
    raw_findings = 0
    for run_index, run in enumerate(runs):
        if not isinstance(run, dict):
            raise TypeError(f"SARIF run {run_index} must be an object")
        tool = run.get("tool") if isinstance(run.get("tool"), dict) else {}
        driver = tool.get("driver") if isinstance(tool.get("driver"), dict) else {}
        rules = driver.get("rules") if isinstance(driver.get("rules"), list) else []
        rules_by_id: dict[str, tuple[int, dict[str, Any]]] = {}
        for index, rule in enumerate(rules):
            if not isinstance(rule, dict):
                continue
            normalized_rule_id = optional_string(rule.get("id"))
            if normalized_rule_id is not None:
                rules_by_id[normalized_rule_id] = (index, rule)
        results = run.get("results") if isinstance(run.get("results"), list) else []
        tool_version = native_string(driver.get("version")) or native_string(driver.get("semanticVersion"))
        for result_index, result in enumerate(results):
            raw_findings += 1
            if not isinstance(result, dict):
                raise TypeError(f"CodeQL result {result_index} must be an object")
            rule_id = optional_string(result.get("ruleId"))
            if rule_id is None:
                raise ValueError(f"CodeQL result {result_index} is missing ruleId")
            locations = result.get("locations")
            if not isinstance(locations, list) or not locations:
                raise ValueError(f"CodeQL result {result_index} is missing primary location")
            location = _code_location(_physical_location(locations[0]))
            if location is None:
                raise ValueError(f"CodeQL result {result_index} has an incomplete primary location")
            rule_index, descriptor = _rule_descriptor(result, rules, rules_by_id, rule_id)
            if descriptor is None:
                missing_rule_descriptors += 1
                descriptor = {}
            properties = descriptor.get("properties") if isinstance(descriptor.get("properties"), dict) else {}
            short_description = _message_text(descriptor.get("shortDescription"))
            full_description = _message_text(descriptor.get("fullDescription"))
            native_severity = native_string(properties.get("security-severity"))
            native_confidence = native_string(properties.get("precision"))
            cwe_ids = normalize_cwe_ids(properties.get("tags"))
            finding = base_finding(
                context=context,
                normalized_at=normalized_at,
                tool_name="codeql",
                tool_version=tool_version,
                scan_type="SAST",
                rule={
                    "id": rule_id,
                    "reference_id": None,
                    "name": optional_string(properties.get("name")) or short_description,
                    "native_severity": native_severity,
                    "native_confidence": native_confidence,
                },
            )
            raw_sources = [{
                "format": "codeql-sarif",
                "report_path": context.report_path,
                "json_pointer": f"/runs/{run_index}/results/{result_index}",
            }]
            if rule_index is not None:
                raw_sources.append({
                    "format": "codeql-sarif-rule",
                    "report_path": context.report_path,
                    "json_pointer": f"/runs/{run_index}/tool/driver/rules/{rule_index}",
                })
            finding.update({
                "fingerprint": _fingerprint(context, result, rule_id, location),
                "group_key": _group_key(context, cwe_ids, location, rule_id),
                "title": short_description,
                "description": _message_text(result.get("message")) or full_description,
                "categories": [],
                "severity": normalize_severity("codeql", native_severity),
                "confidence": normalize_confidence("codeql", native_confidence),
                "cwe_ids": cwe_ids,
                "owasp_categories": normalize_owasp_categories(properties.get("tags")),
                "wasc_ids": [],
                "location": location,
                "evidence": None,
                "data_flow": _data_flows(result),
                "solution": None,
                "references": [],
                "raw_sources": raw_sources,
            })
            findings.append(finding)
    extraction_errors, parse_errors, affected_files = _diagnostics(sarif)
    return ToolNormalizationResult(
        findings=findings,
        raw_counts={"raw_findings": raw_findings, "findings_written": len(findings)},
        warnings={
            "extraction_errors": extraction_errors,
            "parse_errors": parse_errors,
            "affected_files": affected_files,
            "missing_rule_descriptors": missing_rule_descriptors,
            "fingerprint_collisions": fingerprint_collision_count(findings),
        },
    )
