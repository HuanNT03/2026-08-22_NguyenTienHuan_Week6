"""Main 3-phase orchestration pipeline for Security Analysis Agent."""

import json
import logging
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from openai import OpenAI

from src.agent.analyzer import analyze_group
from src.agent.config import AgentConfig
from src.agent.grouper import build_analysis_groups, load_and_validate_findings
from src.agent.models import ReportEntry
from src.retrieval.service import KnowledgeSearchService

logger = logging.getLogger(__name__)


def verify_coverage(
    input_findings: list[dict[str, Any]],
    report_entries: list[ReportEntry],
) -> dict[str, Any]:
    """Verify that every unique input fingerprint is covered by at least one report entry."""
    input_fps = {f["fingerprint"] for f in input_findings if "fingerprint" in f}
    covered_fps = {e.fingerprint for e in report_entries}

    missing = sorted(input_fps - covered_fps)
    return {
        "total_input": len(input_fps),
        "total_covered": len(covered_fps),
        "missing_fingerprints": missing,
        "is_complete": len(missing) == 0,
    }


def run_analysis(
    findings_path: Path,
    output_dir: Path | None = None,
    config: AgentConfig | None = None,
    client: OpenAI | None = None,
    kb_service: KnowledgeSearchService | None = None,
) -> dict[str, Any]:
    """Execute full 3-phase Security Analysis Agent pipeline.

    Phase 1: Pre-grouping & correlation
    Phase 2: Agentic loop & KB retrieval
    Phase 3: Post-processing, 100% coverage verification, & report output
    """
    cfg = config or AgentConfig()
    target_out_dir = output_dir or cfg.output_dir
    target_out_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")

    logger.info("=== Phase 1: Pre-Grouping & Correlation ===")
    findings = load_and_validate_findings(findings_path)
    logger.info("Loaded %d unified findings from %s", len(findings), findings_path)

    groups = build_analysis_groups(findings)
    logger.info("Assembled %d analysis groups", len(groups))

    logger.info("=== Phase 2: Agentic Analysis Loop ===")
    if kb_service is None:
        kb_service = KnowledgeSearchService()

    all_entries: list[ReportEntry] = []
    for idx, group in enumerate(groups, start=1):
        logger.info("[%d/%d] Analyzing group %s (%d findings, correlation: %s)", idx, len(groups), group.group_id, len(group.findings), group.correlation_type)
        entries = analyze_group(group, kb_service=kb_service, client=client, config=cfg)
        all_entries.extend(entries)

    logger.info("=== Phase 3: Post-Processing & Coverage Verification ===")
    coverage = verify_coverage(findings, all_entries)
    if not coverage["is_complete"]:
        logger.error("Coverage check FAILED! Missing fingerprints: %s", coverage["missing_fingerprints"])
        raise RuntimeError(f"Analysis failed 100% coverage check. Missing fingerprints: {coverage['missing_fingerprints']}")

    # Write report JSONL file
    report_filename = f"security-analysis-report-{timestamp}.jsonl"
    report_file_path = target_out_dir / report_filename

    with report_file_path.open("w", encoding="utf-8") as f:
        for entry in all_entries:
            line = json.dumps(entry.model_dump(mode="json"), ensure_ascii=False)
            f.write(line + "\n")

    logger.info("Wrote %d report entries to %s", len(all_entries), report_file_path)

    # Generate summary metadata
    status_counts = Counter(e.analysis_status for e in all_entries)
    corr_counts = Counter(e.correlation_type for e in all_entries)

    summary_metadata = {
        "schema_version": "1.0.0",
        "analyzed_at": datetime.now(UTC).isoformat(),
        "input_file": str(findings_path),
        "report_file": str(report_file_path),
        "total_input_findings": len(findings),
        "total_report_entries": len(all_entries),
        "total_analysis_groups": len(groups),
        "coverage": coverage,
        "entries_by_status": dict(status_counts),
        "entries_by_correlation_type": dict(corr_counts),
        "config": {
            "model": cfg.model,
            "base_url": cfg.base_url,
            "temperature": cfg.temperature,
            "max_retries": cfg.max_retries,
            "prompt_version": cfg.prompt_version,
        },
    }

    summary_file_path = target_out_dir / f"analysis-summary-{timestamp}.json"
    with summary_file_path.open("w", encoding="utf-8") as f:
        json.dump(summary_metadata, f, indent=2, ensure_ascii=False)

    logger.info("Wrote summary metadata to %s", summary_file_path)
    return summary_metadata
