"""Grouping orchestrator for Project Sentinel Security Analysis Agent."""

import json
from pathlib import Path
from typing import Any

from src.agent.correlator import correlate_findings
from src.agent.models import AnalysisGroup


def load_and_validate_findings(findings_path: Path) -> list[dict[str, Any]]:
    """Load JSONL file of unified findings and validate basic required fields."""
    if not findings_path.is_file():
        raise FileNotFoundError(f"Unified findings file not found at {findings_path}")

    findings: list[dict[str, Any]] = []
    with findings_path.open("r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            line_str = line.strip()
            if not line_str:
                continue
            try:
                data = json.loads(line_str)
                if not isinstance(data, dict):
                    raise TypeError(f"Line {idx} is not a valid JSON object.")
                if "fingerprint" not in data or "finding_id" not in data:
                    raise ValueError(f"Line {idx} is missing 'fingerprint' or 'finding_id'.")
                findings.append(data)
            except json.JSONDecodeError as e:
                raise ValueError(f"Line {idx} in {findings_path} contains malformed JSON: {e}") from e

    return findings


def build_analysis_groups(findings: list[dict[str, Any]]) -> list[AnalysisGroup]:
    """Group unified findings using a 4-step hybrid correlation algorithm."""
    if not findings:
        return []

    # Step 1: Initial grouping by normalizer `group_key`
    group_map: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        gk = f.get("group_key") or f"grp_{f['fingerprint']}"
        if gk not in group_map:
            group_map[gk] = []
        group_map[gk].append(f)

    initial_clusters: list[list[dict[str, Any]]] = list(group_map.values())

    # Step 2: Merge clusters using correlation rules
    merged_clusters: list[list[dict[str, Any]]] = []

    for cluster in initial_clusters:
        merged = False
        for target in merged_clusters:
            # Check if any finding in cluster correlates with any finding in target
            correlated = False
            for f_a in cluster:
                for f_b in target:
                    res = correlate_findings(f_a, f_b)
                    if res.is_correlated:
                        correlated = True
                        break
                if correlated:
                    break

            if correlated:
                target.extend(cluster)
                merged = True
                break

        if not merged:
            merged_clusters.append(list(cluster))

    # Step 3: Deduplicate findings within each cluster by fingerprint
    final_groups: list[AnalysisGroup] = []
    processed_fingerprints: set[str] = set()

    for idx, cluster in enumerate(merged_clusters, start=1):
        unique_findings_dict: dict[str, dict[str, Any]] = {}
        for f in cluster:
            fp = f["fingerprint"]
            if fp not in unique_findings_dict:
                unique_findings_dict[fp] = f
            processed_fingerprints.add(fp)

        unique_findings = list(unique_findings_dict.values())
        all_fps = [f["fingerprint"] for f in unique_findings]

        # Determine primary CWE
        cwe_counts: dict[str, int] = {}
        for f in unique_findings:
            for cwe in f.get("cwe_ids") or []:
                cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
        primary_cwe = max(cwe_counts, key=cwe_counts.get) if cwe_counts else None

        # Determine scan types present
        scan_types = {f.get("tool", {}).get("scan_type") for f in unique_findings}
        tools = {f.get("tool", {}).get("name") for f in unique_findings}

        if "SAST" in scan_types and "DAST" in scan_types:
            correlation_type = "sast_dast_suspected"
        elif len(tools) > 1 and "SAST" in scan_types:
            correlation_type = "multi_sast"
        elif "DAST" in scan_types:
            correlation_type = "dast_only"
        else:
            correlation_type = "sast_only"

        # Generate readable group_id
        slug_cwe = primary_cwe.lower().replace("-", "") if primary_cwe else "general"
        group_id = f"grp_{slug_cwe}_{idx:03d}"

        final_groups.append(
            AnalysisGroup(
                group_id=group_id,
                primary_cwe=primary_cwe,
                findings=unique_findings,
                correlation_type=correlation_type,
                correlated_fingerprints=all_fps,
                source="cwe_title_hybrid",
            )
        )

    # Step 4: Safety net (Orphan check for 100% coverage guarantee)
    all_input_fps = {f["fingerprint"] for f in findings}
    missing_fps = all_input_fps - processed_fingerprints
    if missing_fps:
        idx = len(final_groups) + 1
        for f in findings:
            if f["fingerprint"] in missing_fps:
                cwes = f.get("cwe_ids") or []
                primary = cwes[0] if cwes else None
                slug = primary.lower().replace("-", "") if primary else "orphan"
                scan_type = f.get("tool", {}).get("scan_type")
                corr_type = "dast_only" if scan_type == "DAST" else "sast_only"

                final_groups.append(
                    AnalysisGroup(
                        group_id=f"grp_{slug}_{idx:03d}",
                        primary_cwe=primary,
                        findings=[f],
                        correlation_type=corr_type,
                        correlated_fingerprints=[f["fingerprint"]],
                        source="orphan_safety_net",
                    )
                )
                idx += 1

    return final_groups
