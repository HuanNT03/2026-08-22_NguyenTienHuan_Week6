import argparse
import json
import os
import sys
from collections.abc import Callable
from datetime import UTC, datetime
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
from src.normalizers.summary import (
    build_summary,
    failed_tool_summary,
    missing_input_tool_summary,
    skipped_tool_summary,
    successful_tool_summary,
)
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
    parser.add_argument("--output-dir", default="reports/normalized")
    parser.add_argument("--source-root", default="target-app/juice-shop")
    parser.add_argument("--schema", default="schemas/unified_findings.schema.json")
    parser.add_argument("--summary")
    return parser


def _all_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Normalize all scanner reports")
    parser.add_argument("--raw-dir", default="reports/raw")
    parser.add_argument("--output-dir", default="reports/normalized")
    parser.add_argument("--source-root", default="target-app/juice-shop")
    parser.add_argument("--schema", default="schemas/unified_findings.schema.json")
    parser.add_argument("--summary")
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


def _context(metadata: dict[str, Any], report_path: str, source_root: Path) -> NormalizationContext:
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
        source_root=source_root,
    )


def _normalize_tool(
    tool: str,
    report_path: Path,
    metadata_path: Path,
    normalized_at: str,
    validator: Any,
    source_root: Path,
) -> ToolNormalizationResult:
    report = _load_json(report_path)
    metadata = _load_json(metadata_path)
    context = _context(metadata, report_path.as_posix(), source_root)
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


def _run_timestamp(clock: Callable[[], str]) -> tuple[str, str]:
    normalized_at = clock()
    try:
        instant = datetime.fromisoformat(normalized_at)
    except ValueError as exc:
        raise ValueError(f"Normalization clock returned an invalid timestamp: {normalized_at!r}") from exc
    if instant.tzinfo is None:
        raise ValueError("Normalization clock must return a timezone-aware timestamp")
    utc_instant = instant.astimezone(UTC).replace(microsecond=0)
    normalized_at = utc_instant.isoformat(timespec="seconds").replace("+00:00", "Z")
    filename_timestamp = utc_instant.strftime("%Y%m%dT%H%M%SZ")
    return normalized_at, filename_timestamp


def _run(
    selected: tuple[str, ...],
    paths: dict[str, tuple[Path, Path]],
    output_dir: Path,
    summary_path: Path | None,
    schema_path: Path,
    source_root: Path,
    clock: Callable[[], str],
) -> int:
    normalized_at, filename_timestamp = _run_timestamp(clock)
    output_path = output_dir / f"unified-findings-{filename_timestamp}.jsonl"
    resolved_summary_path = (
        summary_path
        if summary_path is not None
        else output_dir / f"normalization-summary-{filename_timestamp}.json"
    )
    _remove_old(output_path, resolved_summary_path)
    all_findings: list[dict[str, Any]] = []
    tool_summaries: dict[str, dict[str, Any]] = {}
    try:
        validator = build_validator(load_schema(schema_path))
    except Exception as exc:  # noqa: BLE001  # Convert setup failures into the CLI failure contract.
        for tool in TOOLS:
            tool_summaries[tool] = failed_tool_summary(exc) if tool in selected else skipped_tool_summary()
        print(f"schema: normalization setup failed: {exc}", file=sys.stderr)
        _write_summary(resolved_summary_path, build_summary(
            schema_version=SCHEMA_VERSION,
            normalizer_version=NORMALIZER_VERSION,
            normalized_at=normalized_at,
            output_path=None,
            tools=tool_summaries,
        ))
        return 1
    failed = False
    successful = False
    for tool in TOOLS:
        if tool not in selected:
            tool_summaries[tool] = skipped_tool_summary()
            continue
        report_path, metadata_path = paths[tool]
        missing_paths = [
            path.as_posix()
            for path in (report_path, metadata_path)
            if not path.exists()
        ]
        if missing_paths:
            tool_summaries[tool] = missing_input_tool_summary(missing_paths)
            print(f"{tool}: skipped: missing input file(s): {', '.join(missing_paths)}", file=sys.stderr)
            continue
        try:
            result = _normalize_tool(tool, report_path, metadata_path, normalized_at, validator, source_root)
        except Exception as exc:  # noqa: BLE001  # Isolate each untrusted scanner input.
            failed = True
            tool_summaries[tool] = failed_tool_summary(exc)
            print(f"{tool}: normalization failed: {exc}", file=sys.stderr)
            continue
        all_findings.extend(result.findings)
        tool_summaries[tool] = successful_tool_summary(result)
        successful = True
    if successful:
        _write_jsonl(output_path, all_findings)
    _write_summary(resolved_summary_path, build_summary(
        schema_version=SCHEMA_VERSION,
        normalizer_version=NORMALIZER_VERSION,
        normalized_at=normalized_at,
        output_path=output_path.as_posix() if successful else None,
        tools=tool_summaries,
    ))
    if successful:
        print(output_path.as_posix())
    return 1 if failed or not successful else 0


def main(argv: list[str] | None = None, *, clock: Callable[[], str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    clock = clock or utc_now
    if argv and argv[0] == "normalize-all":
        args = _all_parser().parse_args(argv[1:])
        raw_dir = Path(args.raw_dir)
        return _run(
            TOOLS,
            {tool: (raw_dir / REPORT_NAMES[tool], raw_dir / META_NAMES[tool]) for tool in TOOLS},
            Path(args.output_dir),
            Path(args.summary) if args.summary else None,
            Path(args.schema),
            Path(args.source_root),
            clock,
        )
    args = _parser().parse_args(argv)
    output_dir = Path(args.output_dir)
    return _run(
        (args.tool,),
        {args.tool: (Path(args.input), Path(args.metadata))},
        output_dir,
        Path(args.summary) if args.summary else None,
        Path(args.schema),
        Path(args.source_root),
        clock,
    )


if __name__ == "__main__":
    raise SystemExit(main())
