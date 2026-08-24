"""Main 3-phase orchestration pipeline for Security Analysis Agent."""

import json
import logging
import time
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
        "is_complete": len(missing) == 0,
        "total_expected": len(input_fps),
        "total_analyzed": len(covered_fps),
        "missing_fingerprints": missing,
        "total_input": len(input_fps),
        "total_covered": len(covered_fps),
    }


def run_analysis(
    findings_path: Path,
    output_dir: Path | None = None,
    config: AgentConfig | None = None,
    client: OpenAI | None = None,
    kb_service: KnowledgeSearchService | None = None,
    log_file: Path | str | None = None,
    progress_callback: Any = None,
) -> dict[str, Any]:
    """Execute full 3-phase Security Analysis Agent pipeline.

    Phase 1: Pre-grouping & correlation
    Phase 2: Agentic loop & KB retrieval
    Phase 3: Post-processing, 100% coverage verification, & report output

    Args:
        findings_path: Path to the unified findings JSONL file.
        output_dir: Optional output directory for analyzed reports.
        config: Agent configuration instance.
        client: Optional OpenAI client.
        kb_service: Optional KnowledgeSearchService instance.
        log_file: Optional log file path.
        progress_callback: Optional callable(idx, total, group, status_text) for progress reporting.

    Returns:
        dict[str, Any]: Summary dictionary of the analysis execution.
    """
    start_time = time.time()
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

    default_log_file = log_file or str(Path("logs/agent-runner.log"))
    from src.agent.trace_logger import TraceLogger
    trace_logger = TraceLogger(log_file=default_log_file)

    all_entries: list[ReportEntry] = []
    total_prompt_tokens = 0
    total_completion_tokens = 0

    for idx, group in enumerate(groups, start=1):
        if progress_callback is not None:
            try:
                progress_callback(idx, len(groups), group, "analyzing")
            except Exception as exc:  # noqa: BLE001
                logger.debug("Progress callback error (analyzing): %s", exc)

        logger.info(
            "[%d/%d] Analyzing group %s (%d findings, correlation: %s)",
            idx,
            len(groups),
            group.group_id,
            len(group.findings),
            group.correlation_type,
        )
        t_grp_start = time.time()
        trace_logger.log_span(
            group_id=group.group_id,
            step_index=0,
            run_type="chain",
            name="GroupAnalysisOrchestrator",
            start_time=t_grp_start,
            end_time=t_grp_start,
            status="running",
            inputs={"group_id": group.group_id, "correlation_type": group.correlation_type, "findings_count": len(group.findings)},
            outputs=None,
            metadata={
                "model": cfg.model,
                "agent_mode": cfg.agent_mode,
                "prompt_version": cfg.prompt_version,
                "fingerprints": [f["fingerprint"] for f in group.findings],
            },
        )

        entries = analyze_group(group, kb_service=kb_service, client=client, config=cfg, trace_logger=trace_logger)
        all_entries.extend(entries)

        t_grp_end = time.time()
        trace_logger.log_span(
            group_id=group.group_id,
            step_index=0,
            run_type="chain",
            name="GroupAnalysisOrchestrator",
            start_time=t_grp_start,
            end_time=t_grp_end,
            status="success" if any(e.analysis_status == "success" for e in entries) else "error",
            inputs={"group_id": group.group_id, "correlation_type": group.correlation_type, "findings_count": len(group.findings)},
            outputs={"entries_count": len(entries), "statuses": [e.analysis_status for e in entries]},
            metadata={
                "model": cfg.model,
                "agent_mode": cfg.agent_mode,
                "prompt_version": cfg.prompt_version,
                "fingerprints": [f["fingerprint"] for f in group.findings],
            },
        )

        if progress_callback is not None:
            try:
                progress_callback(idx, len(groups), group, "completed")
            except Exception as exc:  # noqa: BLE001
                logger.debug("Progress callback error (completed): %s", exc)

    logger.info("=== Phase 3: Post-Processing & Coverage Verification ===")
    coverage = verify_coverage(findings, all_entries)
    if not coverage["is_complete"]:
        logger.error("Coverage check FAILED! Missing fingerprints: %s", coverage["missing_fingerprints"])
        raise RuntimeError(
            f"Analysis failed 100% coverage check. Missing fingerprints: {coverage['missing_fingerprints']}"
        )

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
    execution_duration = round(time.time() - start_time, 2)
    default_log_file = log_file or str(Path("logs/agent-runner.log"))

    summary_metadata = {
        "schema_version": "1.0.0",
        "analyzed_at": datetime.now(UTC).isoformat(),
        "input_file": str(findings_path),
        "report_file": str(report_file_path),
        "log_file": str(default_log_file),
        "total_input_findings": len(findings),
        "total_report_entries": len(all_entries),
        "total_analysis_groups": len(groups),
        "coverage": {
            "is_complete": coverage["is_complete"],
            "total_expected": coverage["total_expected"],
            "total_analyzed": coverage["total_analyzed"],
            "missing_fingerprints": coverage["missing_fingerprints"],
        },
        "entries_by_status": dict(status_counts),
        "entries_by_correlation_type": dict(corr_counts),
        "token_usage": {
            "prompt_tokens": total_prompt_tokens,
            "completion_tokens": total_completion_tokens,
            "total_tokens": total_prompt_tokens + total_completion_tokens,
        },
        "execution_time_seconds": execution_duration,
        "config": {
            "agent_mode": cfg.agent_mode,
            "model": cfg.model,
            "base_url": cfg.base_url,
            "temperature": cfg.temperature,
            "max_retries": cfg.max_retries,
            "max_react_steps": cfg.max_react_steps,
            "prompt_version": cfg.prompt_version,
        },
    }

    summary_file_path = target_out_dir / f"analysis-summary-{timestamp}.json"
    with summary_file_path.open("w", encoding="utf-8") as f:
        json.dump(summary_metadata, f, indent=2, ensure_ascii=False)

    logger.info("Wrote summary metadata to %s", summary_file_path)
    return summary_metadata
