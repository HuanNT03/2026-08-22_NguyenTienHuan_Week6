from typing import Any

from src.normalizers.common.confidence import normalize_confidence
from src.normalizers.common.finding import (
    base_finding,
    fingerprint_collision_count,
    native_string,
    optional_string,
    string_array,
    utc_now,
)
from src.normalizers.common.hashing import canonical_sha256
from src.normalizers.common.models import ToolNormalizationResult
from src.normalizers.common.severity import normalize_severity
from src.normalizers.common.taxonomy import normalize_cwe_ids, normalize_wasc_ids
from src.normalizers.common.text import strip_html_with_status
from src.normalizers.common.urls import canonicalize_endpoint, extract_urls_with_status
from src.normalizers.context import NormalizationContext


def _sites(report: dict[str, Any]) -> list[tuple[int | None, dict[str, Any]]]:
    raw_sites = report.get("site")
    if isinstance(raw_sites, list):
        return [(index, site) for index, site in enumerate(raw_sites) if isinstance(site, dict)]
    if isinstance(raw_sites, dict):
        return [(None, raw_sites)]
    raise ValueError("ZAP report.site must be an object or array")


def _pointer(site_index: int | None, alert_index: int, instance_index: int) -> str:
    site_token = f"/site/{site_index}" if site_index is not None else "/site"
    return f"{site_token}/alerts/{alert_index}/instances/{instance_index}"


def _fingerprint(
    context: NormalizationContext,
    plugin_id: str,
    alert_ref: str | None,
    method: str | None,
    endpoint: str,
    parameter: str | None,
) -> str:
    return canonical_sha256("fp", "v1", {
        "target": context.target_name,
        "tool": "zap",
        "plugin_id": plugin_id,
        "alert_ref": alert_ref,
        "method": method,
        "endpoint": endpoint,
        "parameter": parameter,
    })


def _group_key(
    context: NormalizationContext,
    cwe_ids: list[str],
    method: str | None,
    endpoint: str,
    parameter: str | None,
    rule_reference: str,
) -> str:
    return canonical_sha256("grp", "v1", {
        "target": context.target_name,
        "cwe_ids": cwe_ids,
        "location": {"path": None, "start_line": None},
        "method": method,
        "canonical_endpoint": endpoint,
        "parameter": parameter,
        "fallback_rule_id": None,
        "rule_reference": rule_reference,
    })


def normalize_zap_report(
    report: dict[str, Any],
    context: NormalizationContext,
    *,
    normalized_at: str | None = None,
) -> ToolNormalizationResult:
    normalized_at = normalized_at or utc_now()
    findings: list[dict[str, Any]] = []
    raw_alerts = 0
    raw_instances = 0
    alerts_without_instances = 0
    text_parse_errors = 0
    for site_index, site in _sites(report):
        alerts = site.get("alerts")
        if not isinstance(alerts, list):
            continue
        for alert_index, alert in enumerate(alerts):
            if not isinstance(alert, dict):
                raise ValueError(f"ZAP alert {alert_index} must be an object")
            raw_alerts += 1
            instances = alert.get("instances")
            if not isinstance(instances, list):
                instances = []
            if not instances:
                alerts_without_instances += 1
                continue
            plugin_id = native_string(alert.get("pluginid"))
            if plugin_id is None:
                raise ValueError(f"ZAP alert {alert_index} is missing pluginid")
            alert_ref = native_string(alert.get("alertRef"))
            native_severity = native_string(alert.get("riskcode"))
            native_confidence = native_string(alert.get("confidence"))
            name = optional_string(alert.get("name")) or optional_string(alert.get("alert"))
            description_result = strip_html_with_status(alert.get("desc"))
            solution_result = strip_html_with_status(alert.get("solution"))
            references_result = extract_urls_with_status(alert.get("reference"))
            text_parse_errors += sum((
                description_result.had_error,
                solution_result.had_error,
                references_result.had_error,
            ))
            cwe_ids = normalize_cwe_ids(alert.get("cweid"))
            wasc_ids = normalize_wasc_ids(alert.get("wascid"))
            for instance_index, instance in enumerate(instances):
                raw_instances += 1
                if not isinstance(instance, dict):
                    raise ValueError(f"ZAP instance {instance_index} must be an object")
                uri = optional_string(instance.get("uri"))
                endpoint = canonicalize_endpoint(uri)
                if uri is None or endpoint is None:
                    raise ValueError(f"ZAP instance {instance_index} is missing URI location")
                method_value = optional_string(instance.get("method"))
                method = method_value.upper() if method_value is not None else None
                parameter = optional_string(instance.get("param"))
                rule_reference = alert_ref or plugin_id
                finding = base_finding(
                    context=context,
                    normalized_at=normalized_at,
                    tool_name="zap",
                    tool_version=native_string(report.get("@version")),
                    scan_type="DAST",
                    rule={
                        "id": plugin_id,
                        "reference_id": alert_ref,
                        "name": name,
                        "native_severity": native_severity,
                        "native_confidence": native_confidence,
                    },
                )
                finding.update({
                    "fingerprint": _fingerprint(context, plugin_id, alert_ref, method, endpoint, parameter),
                    "group_key": _group_key(context, cwe_ids, method, endpoint, parameter, rule_reference),
                    "title": optional_string(alert.get("name")),
                    "description": description_result.value,
                    "categories": [],
                    "severity": normalize_severity("zap", native_severity),
                    "confidence": normalize_confidence("zap", native_confidence),
                    "cwe_ids": cwe_ids,
                    "owasp_categories": [],
                    "wasc_ids": wasc_ids,
                    "location": {
                        "kind": "http",
                        "uri": uri,
                        "endpoint": endpoint,
                        "method": method,
                        "parameter": parameter,
                    },
                    "evidence": None,
                    "data_flow": None,
                    "solution": solution_result.value,
                    "references": references_result.urls,
                    "raw_sources": [{
                        "format": "zap-json",
                        "report_path": context.report_path,
                        "json_pointer": _pointer(site_index, alert_index, instance_index),
                    }],
                })
                findings.append(finding)
    return ToolNormalizationResult(
        findings=findings,
        raw_counts={
            "raw_alerts": raw_alerts,
            "raw_instances": raw_instances,
            "findings_written": len(findings),
        },
        warnings={
            "alerts_without_instances": alerts_without_instances,
            "text_parse_errors": text_parse_errors,
            "fingerprint_collisions": fingerprint_collision_count(findings),
        },
    )
