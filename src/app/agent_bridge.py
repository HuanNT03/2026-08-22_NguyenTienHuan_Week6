"""Cầu nối kích hoạt AI Security Analysis Agent và đọc kết quả phân tích cho Web App."""

import json
import os
from pathlib import Path
from typing import Any

from src.agent.config import AgentConfig
from src.agent.orchestrator import run_analysis


def get_configured_model() -> str:
    """Trả về tên mô hình LLM được cấu hình trong file .env (mặc định 'qwen-plus')."""
    return AgentConfig().model


def run_agent_analysis(
    findings_path: str,
    model: str | None = None,
    output_dir: str = "reports/analyzed",
) -> tuple[bool, dict[str, Any]]:
    """
    Kích hoạt Security Analysis Agent chạy phân tích trên tập findings_path.

    Args:
        findings_path: Đường dẫn tới file Unified Findings JSONL
        model: Tên mô hình LLM tùy chọn (vd: 'qwen-plus')
        output_dir: Thư mục chứa báo cáo xuất ra

    Returns:
        tuple[bool, dict]: (Thành công hay không, Thông tin tóm tắt kết quả analysis summary)
    """
    findings = Path(findings_path)
    if not findings.exists():
        return False, {"error": f"Tập tin findings không tồn tại: {findings_path}"}

    config = AgentConfig()
    if model:
        config.model = model
    config.output_dir = Path(output_dir)

    try:
        summary = run_analysis(findings_path=findings, config=config)
        return True, summary
    except Exception as exc:  # noqa: BLE001
        return False, {"error": f"Lỗi trong quá trình chạy Security Analysis Agent: {exc}"}


def list_analyzed_reports(analyzed_dir: str = "reports/analyzed") -> list[str]:
    """Trả về danh sách file Security Analysis Report JSONL mới nhất."""
    target_dir = Path(analyzed_dir)
    if not target_dir.exists():
        return []

    files = list(target_dir.glob("security-analysis-report-*.jsonl"))
    files.sort(key=os.path.getmtime, reverse=True)
    return [str(f) for f in files]


def load_analysis_report(report_path: str) -> list[dict[str, Any]]:
    """
    Đọc và parse file Security Analysis Report JSONL thành danh sách dict.

    Args:
        report_path: Đường dẫn tới file security-analysis-report-*.jsonl

    Returns:
        list[dict]: Danh sách các câu trả lời phân tích ReportEntry
    """
    path = Path(report_path)
    if not path.exists():
        raise FileNotFoundError(f"Tập tin báo cáo phân tích không tồn tại: {report_path}")

    entries: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                entries.append(item)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Dòng {line_number} trong {report_path} không phải JSON hợp lệ: {exc}") from exc

    return entries
