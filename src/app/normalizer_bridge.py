"""Cầu nối thực thi chuẩn hóa raw scanner reports sang Unified Findings."""

import json
import os
from pathlib import Path
from typing import Any


def execute_normalization(
    selected_files: list[str] | None = None,
    raw_dir: str = "reports/raw",
    output_dir: str = "reports/normalized",
    source_root: str = "target-app/juice-shop",
    schema_path: str = "schemas/unified_findings.schema.json",
) -> tuple[bool, dict[str, Any]]:
    """
    Kích hoạt chuẩn hóa các raw scanner reports được chọn (hoặc tất cả nếu None) sang Unified Findings.

    Args:
        selected_files: Danh sách đường dẫn file raw được chọn để chuẩn hóa (hoặc None/rỗng để chuẩn hóa tất cả)
        raw_dir: Thư mục chứa raw reports (mặc định 'reports/raw')
        output_dir: Thư mục chứa file jsonl normalized (mặc định 'reports/normalized')
        source_root: Thư mục gốc target application
        schema_path: Đường dẫn schema unified findings

    Returns:
        tuple[bool, dict]: (Thành công hay không, Thông tin tóm tắt kết quả / summary dict)
    """
    from src.normalizers.cli import (
        META_NAMES,
        REPORT_NAMES,
        TOOLS,
        _run,
        utc_now,
    )

    raw_path = Path(raw_dir)
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    if selected_files is not None and len(selected_files) > 0:
        selected_tools_list: list[str] = []
        tool_paths: dict[str, tuple[Path, Path]] = {}

        for tool in TOOLS:
            matching_files = [f for f in selected_files if tool in Path(f).name.lower()]
            if matching_files:
                selected_tools_list.append(tool)
                report_file = Path(matching_files[0])
                meta_candidate = report_file.with_name(f"{tool}.meta.json")
                if not meta_candidate.exists():
                    meta_candidate = raw_path / f"{tool}.meta.json"
                tool_paths[tool] = (report_file, meta_candidate)
            else:
                tool_paths[tool] = (raw_path / REPORT_NAMES[tool], raw_path / META_NAMES[tool])

        selected_tools = tuple(selected_tools_list)
        if not selected_tools:
            return False, {"error": "Không có tệp scanner hợp lệ nào (semgrep, zap, codeql) được chọn để chuẩn hóa."}

        exit_code = _run(
            selected=selected_tools,
            paths=tool_paths,
            output_dir=out_path,
            summary_path=None,
            schema_path=Path(schema_path),
            source_root=Path(source_root),
            clock=utc_now,
        )
    else:
        exit_code = _run(
            selected=TOOLS,
            paths={tool: (raw_path / REPORT_NAMES[tool], raw_path / META_NAMES[tool]) for tool in TOOLS},
            output_dir=out_path,
            summary_path=None,
            schema_path=Path(schema_path),
            source_root=Path(source_root),
            clock=utc_now,
        )

    summary_files = list(out_path.glob("normalization-summary-*.json")) if out_path.exists() else []
    summary_data: dict[str, Any] = {"exit_code": exit_code}

    if summary_files:
        latest_summary = max(summary_files, key=os.path.getmtime)
        try:
            with latest_summary.open(encoding="utf-8") as f:
                summary_data = json.load(f)
                summary_data["summary_path"] = str(latest_summary)
        except Exception as exc:  # noqa: BLE001
            summary_data["error"] = f"Không thể đọc summary file: {exc}"

    success = exit_code == 0
    return success, summary_data


def save_uploaded_report(file_name: str, file_bytes: bytes, raw_dir: str = "reports/raw") -> str:
    """
    Lưu tập tin report được upload từ người dùng vào thư mục raw_dir.

    Args:
        file_name: Tên tập tin gốc (vd: 'semgrep.json', 'zap.json', 'codeql.sarif')
        file_bytes: Dữ liệu nhị phân của tập tin
        raw_dir: Thư mục lưu trữ

    Returns:
        str: Đường dẫn tuyệt đối tới tập tin đã lưu
    """
    target_dir = Path(raw_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    # Chuẩn hóa tên tập tin để tránh directory traversal
    safe_basename = Path(file_name).name
    destination = target_dir / safe_basename

    with destination.open("wb") as handle:
        handle.write(file_bytes)

    return str(destination)


def list_raw_report_files(raw_dir: str = "reports/raw") -> list[dict[str, Any]]:
    """
    Trả về danh sách chi tiết các file raw scanner report trong raw_dir.

    Lọc bỏ các file metadata (*.meta.json), file cấu hình hoặc file không phải báo cáo quét.
    """
    target_dir = Path(raw_dir)
    if not target_dir.exists():
        return []

    valid_extensions = {".json", ".sarif", ".xml"}
    files = [
        f
        for f in target_dir.glob("*")
        if f.is_file()
        and not f.name.startswith(".")
        and f.suffix.lower() in valid_extensions
        and not f.name.endswith(".meta.json")
        and not f.name.endswith(".meta.yaml")
    ]
    files.sort(key=os.path.getmtime, reverse=True)

    results = []
    for f in files:
        results.append(
            {
                "name": f.name,
                "path": str(f),
                "size": f.stat().st_size,
                "mtime": f.stat().st_mtime,
            }
        )
    return results


def list_normalized_files(output_dir: str = "reports/normalized") -> list[str]:
    """Trả về danh sách file normalized JSONL đã sắp xếp theo thời gian mới nhất."""
    target_dir = Path(output_dir)
    if not target_dir.exists():
        return []

    files = list(target_dir.glob("unified-findings-*.jsonl"))
    files.sort(key=os.path.getmtime, reverse=True)
    return [str(f) for f in files]


def load_unified_findings(file_path: str) -> list[dict[str, Any]]:
    """
    Đọc và parse file Unified Findings JSONL thành danh sách dict.

    Args:
        file_path: Đường dẫn tới file .jsonl

    Returns:
        list[dict]: Danh sách từng finding object
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Tập tin findings không tồn tại: {file_path}")

    findings: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                findings.append(item)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Dòng {line_number} trong {file_path} không phải JSON hợp lệ: {exc}") from exc

    return findings
