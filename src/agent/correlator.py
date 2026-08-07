"""Correlation engine for Project Sentinel Security Analysis Agent."""

import re
from typing import Any

from src.agent.models import CorrelationResult

BROAD_CWES: set[str] = {
    "CWE-400",
    "CWE-20",
    "CWE-116",
    "CWE-770",
    "CWE-250",
    "CWE-732",
    "CWE-307",
    "CWE-807",
    "CWE-497",
    "CWE-598",
}

# Standardized vulnerability domain keyword synonyms (specific vulnerability types)
SYNONYM_GROUPS: list[set[str]] = [
    {"sql", "sqli", "database", "query"},
    {"redirect", "url", "open-redirect"},
    {"nosql", "mongodb"},
    {"traversal", "path", "directory"},
    {"xss", "scripting"},
    {"stacktrace", "stack-trace", "error-trace"},
    {"ip-disclosure", "private-ip"},
    {"timestamp-disclosure", "unix-timestamp"},
    {"session-id", "session-rewrite"},
]


def extract_keywords(text: str | None) -> set[str]:
    """Extract normalized security keywords from a title or description string."""
    if not text:
        return set()
    cleaned = re.sub(r"[^a-zA-Z0-9\s-]", " ", text.lower())
    words = {w.strip() for w in cleaned.split() if len(w.strip()) > 1}

    # Expand with domain synonyms
    expanded = set(words)
    for word in words:
        for syn_set in SYNONYM_GROUPS:
            if word in syn_set:
                expanded.update(syn_set)

    return expanded


def titles_are_similar(title1: str | None, title2: str | None) -> bool:
    """Compare two finding titles using keyword intersection."""
    kw1 = extract_keywords(title1)
    kw2 = extract_keywords(title2)
    if not kw1 or not kw2:
        return False

    intersection = kw1 & kw2
    # Ignore generic words like 'and', 'or', 'the', 'in', 'exposure', 'disclosure'
    generic = {
        "and",
        "or",
        "the",
        "in",
        "from",
        "for",
        "with",
        "of",
        "to",
        "on",
        "a",
        "an",
        "is",
        "exposure",
        "disclosure",
        "information",
        "data",
        "vulnerability",
        "check",
        "issue",
        "rule",
        "audit",
        "test",
        "security",
        "improper",
        "use",
        "used",
    }
    meaningful = intersection - generic
    return len(meaningful) >= 1


def match_param_to_dataflow(parameter: str | None, data_flow: list[dict[str, Any]] | None) -> bool:
    """Check if DAST attack parameter appears anywhere in SAST data flow steps."""
    if not parameter or not data_flow:
        return False
    param_clean = parameter.strip().lower()
    if not param_clean:
        return False

    for flow in data_flow:
        # Check source, steps, sink
        nodes = []
        if flow.get("source"):
            nodes.append(flow["source"])
        if flow.get("steps"):
            nodes.extend(flow["steps"])
        if flow.get("sink"):
            nodes.append(flow["sink"])

        for node in nodes:
            content = (node.get("content") or "").lower()
            if param_clean in content:
                return True

    return False


def correlate_findings(finding_a: dict[str, Any], finding_b: dict[str, Any]) -> CorrelationResult:
    """Evaluate cross-tool or cross-location correlation between two unified findings."""
    cwes_a = set(finding_a.get("cwe_ids") or [])
    cwes_b = set(finding_b.get("cwe_ids") or [])
    cwe_overlap = sorted(cwes_a & cwes_b)

    if not cwe_overlap:
        return CorrelationResult(
            is_correlated=False,
            confidence="none",
            cwe_overlap=[],
            reason="No overlapping CWE IDs.",
        )

    title_a = finding_a.get("title")
    title_b = finding_b.get("title")
    is_title_sim = titles_are_similar(title_a, title_b)

    tool_a = finding_a.get("tool", {}).get("scan_type", "")
    tool_b = finding_b.get("tool", {}).get("scan_type", "")
    is_cross_tool = (tool_a != tool_b) and bool(tool_a) and bool(tool_b)

    # Location check
    loc_a = finding_a.get("location", {})
    loc_b = finding_b.get("location", {})
    same_location = False
    if loc_a.get("kind") == "code" and loc_b.get("kind") == "code":
        same_location = loc_a.get("path") == loc_b.get("path")
    elif loc_a.get("kind") == "http" and loc_b.get("kind") == "http":
        same_location = loc_a.get("endpoint") == loc_b.get("endpoint")

    # Parameter check if DAST vs SAST
    dast_param = loc_a.get("parameter") if loc_a.get("kind") == "http" else loc_b.get("parameter")
    sast_flow = finding_a.get("data_flow") if loc_a.get("kind") == "code" else finding_b.get("data_flow")
    is_param_match = match_param_to_dataflow(dast_param, sast_flow)

    # Check if ALL overlapping CWEs are broad
    only_broad_cwes = all(cwe in BROAD_CWES for cwe in cwe_overlap)

    if only_broad_cwes and not (same_location or is_title_sim or is_param_match):
        return CorrelationResult(
            is_correlated=False,
            confidence="none",
            cwe_overlap=cwe_overlap,
            is_title_similar=is_title_sim,
            reason="Broad CWE overlap without location or title match.",
        )

    # Calculate correlation confidence
    if is_cross_tool and (is_title_sim or is_param_match or same_location):
        confidence = "high" if (is_param_match or is_title_sim) else "medium"
        return CorrelationResult(
            is_correlated=True,
            confidence=confidence,
            cwe_overlap=cwe_overlap,
            is_title_similar=is_title_sim,
            is_param_match=is_param_match,
            reason="Cross-tool correlation matched via CWE and title/param.",
        )
    elif same_location or is_title_sim:
        return CorrelationResult(
            is_correlated=True,
            confidence="medium",
            cwe_overlap=cwe_overlap,
            is_title_similar=is_title_sim,
            is_route_match=same_location,
            reason="Same-tool or same-location correlation matched via CWE and title/file.",
        )

    return CorrelationResult(
        is_correlated=False,
        confidence="none",
        cwe_overlap=cwe_overlap,
        is_title_similar=is_title_sim,
        reason="CWE overlap without title or location similarity.",
    )
