import argparse
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from src.normalizers import NORMALIZER_VERSION, SCHEMA_VERSION
from src.normalizers.codeql import normalize_codeql_report
from src.normalizers.common.finding import utc_now
from src.normalizers.common.json_pointer import resolve_json_pointer
from src.normalizers.common.models import ToolNormalizationResult
from src.normalizers.common.validation import build_validator, load_schema, validate_finding
from src.normalizers.context import NormalizationContext
from src.normalizers.semgrep import normalize_semgrep_report
from src.normalizers.summary import build_summary, failed_tool_summary, skipped_tool_summary, successful_tool_summary
from src.normalizers.zap import normalize_zap_report

TOOLS = ("semgrep", "zap", "codeql")
REPORT_NAMES = {"semgrep": "semgrep.json", "zap": "zap.json", "codeql": "codeql.sarif"}
META_NAMES = {tool: f"{tool}.meta.json" for tool in TOOLS}
NORMALIZERS: dict[str, Callable[..., ToolNormalizationResult]] = {
    "semgrep": normalize_semgrep_report,
    "zap": normalize_zap_report,
    "codeql": normalize_codeql_report,
}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Normalize security scanner findings")
    parser.add_argument("--tool", choices=TOOLS, required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--metadata", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--schema", default="schemas/unified_findings.schema.json")
    parser.add_argument("--summary")
    return parser


def _all_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Normalize all scanner reports")
    parser.add_argument("--raw-dir", default="reports/raw")
    parser.add_argument("--output", default="reports/normalized/unified-findings.jsonl")
    parser.add_argument("--schema", default="schemas/unified_findings.schema.json")
    parser.add_argument("--summary", default="reports/normalized/normalization-summary.json")
    return parser


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise TypeError(f"JSON document must be an object: {path}")
    return value


def _required_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Metadata field {field} must be a non-empty string")
    return value.strip()


def _context(metadata: dict[str, Any], report_path: str) -> NormalizationContext:
    target = metadata.get("target")
    if not isinstance(target, dict):
        raise TypeError("Metadata target must be an object")
    return NormalizationContext(
        schema_version=SCHEMA_VERSION,
        normalizer_version=NORMALIZER_VERSION,
        run_id=_required_string(metadata.get("run_id"), "run_id"),
        pipeline_run_id=metadata.get("pipeline_run_id") if isinstance(metadata.get("pipeline_run_id"), str) else None,
        scanned_at=_required_string(metadata.get("scanned_at"), "scanned_at"),
        target_name=_required_string(target.get("name"), "target.name"),
        target_version=target.get("version") if isinstance(target.get("version"), str) else None,
        target_commit_sha=target.get("commit_sha") if isinstance(target.get("commit_sha"), str) else None,
        target_base_url=target.get("base_url") if isinstance(target.get("base_url"), str) else None,
        report_path=report_path,
    )


def _normalize_tool(tool: str, report_path: Path, metadata_path: Path, normalized_at: str, validator: Any) -> ToolNormalizationResult:
    report = _load_json(report_path)
    metadata = _load_json(metadata_path)
    context = _context(metadata, report_path.as_posix())
    result = NORMALIZERS[tool](report, context, normalized_at=normalized_at)
    for finding in result.findings:
        validate_finding(finding, validator)
        for raw_source in finding["raw_sources"]:
            resolve_json_pointer(report, raw_source["json_pointer"])
    return result


def _remove_old(*paths: Path) -> None:
    for path in paths:
        if path.exists():
            path.unlink()


def _write_jsonl(path: Path, findings: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        for finding in findings:
            handle.write(json.dumps(finding, ensure_ascii=False, separators=(",", ":")))
            handle.write("\n")
    os.replace(temporary, path)


def _write_summary(path: Path, summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(summary, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    os.replace(temporary, path)


def _run(selected: tuple[str, ...], paths: dict[str, tuple[Path, Path]], output_path: Path, summary_path: Path, schema_path: Path) -> int:
    _remove_old(output_path, summary_path)
    normalized_at = utc_now()
    validator = build_validator(load_schema(schema_path))
    all_findings: list[dict[str, Any]] = []
    tool_summaries: dict[str, dict[str, Any]] = {}
    failed = False
    for tool in TOOLS:
        if tool not in selected:
            tool_summaries[tool] = skipped_tool_summary()
            continue
        report_path, metadata_path = paths[tool]
        try:
            result = _normalize_tool(tool, report_path, metadata_path, normalized_at, validator)
        except Exception as exc:  # noqa: BLE001  # Isolate each untrusted scanner input.
            failed = True
            tool_summaries[tool] = failed_tool_summary(exc)
            print(f"{tool}: normalization failed: {exc}", file=sys.stderr)
            continue
        all_findings.extend(result.findings)
        tool_summaries[tool] = successful_tool_summary(result)
    if any(tool in selected and tool_summaries[tool]["status"] != "failed" for tool in TOOLS):
        _write_jsonl(output_path, all_findings)
    _write_summary(summary_path, build_summary(
        schema_version=SCHEMA_VERSION,
        normalizer_version=NORMALIZER_VERSION,
        normalized_at=normalized_at,
        tools=tool_summaries,
    ))
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "normalize-all":
        args = _all_parser().parse_args(argv[1:])
        raw_dir = Path(args.raw_dir)
        return _run(
            TOOLS,
            {tool: (raw_dir / REPORT_NAMES[tool], raw_dir / META_NAMES[tool]) for tool in TOOLS},
            Path(args.output),
            Path(args.summary),
            Path(args.schema),
        )
    args = _parser().parse_args(argv)
    output_path = Path(args.output)
    return _run(
        (args.tool,),
        {args.tool: (Path(args.input), Path(args.metadata))},
        output_path,
        Path(args.summary) if args.summary else output_path.with_name("normalization-summary.json"),
        Path(args.schema),
    )


if __name__ == "__main__":
    raise SystemExit(main())
