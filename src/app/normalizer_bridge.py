"""Cầu nối thực thi chuẩn hóa raw scanner reports sang Unified Findings."""

import json
import os
from pathlib import Path
from typing import Any

from src.normalizers.cli import main as normalizer_cli_main


def execute_normalization(
    raw_dir: str = "reports/raw",
    output_dir: str = "reports/normalized",
    source_root: str = "target-app/juice-shop",
    schema_path: str = "schemas/unified_findings.schema.json",
) -> tuple[bool, dict[str, Any]]:
    """
    Kích hoạt chuẩn hóa tất cả các raw scanner reports trong raw_dir sang Unified Findings.

    Args:
        raw_dir: Thư mục chứa raw reports (mặc định 'reports/raw')
        output_dir: Thư mục chứa file jsonl normalized (mặc định 'reports/normalized')
        source_root: Thư mục gốc target application
        schema_path: Đường dẫn schema unified findings

    Returns:
        tuple[bool, dict]: (Thành công hay không, Thông tin tóm tắt kết quả / summary dict)
    """
    args = [
        "normalize-all",
        "--raw-dir", raw_dir,
        "--output-dir", output_dir,
        "--source-root", source_root,
        "--schema", schema_path,
    ]
    exit_code = normalizer_cli_main(args)
    
    # Tìm file normalization summary mới nhất trong output_dir
    output_path = Path(output_dir)
    summary_files = list(output_path.glob("normalization-summary-*.json")) if output_path.exists() else []
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
    """Trả về danh sách chi tiết các file raw report trong raw_dir."""
    target_dir = Path(raw_dir)
    if not target_dir.exists():
        return []

    files = [f for f in target_dir.glob("*") if f.is_file() and not f.name.startswith(".")]
    files.sort(key=os.path.getmtime, reverse=True)
    
    results = []
    for f in files:
        results.append({
            "name": f.name,
            "path": str(f),
            "size": f.stat().st_size,
            "mtime": f.stat().st_mtime,
        })
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
