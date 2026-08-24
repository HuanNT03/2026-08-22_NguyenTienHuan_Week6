import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.agent.config import AgentConfig
from src.agent.orchestrator import run_analysis


@dataclass
class AgentRunState:
    """Đại diện cho trạng thái thực thi phiên phân tích của Agent."""

    run_id: str
    is_running: bool = False
    is_finished: bool = False
    error: str | None = None
    summary: dict[str, Any] | None = None
    start_time: float = 0.0
    elapsed_seconds: float = 0.0
    # Tiến độ phân tích thời gian thực (Realtime Live Progress)
    current_group_idx: int = 0
    total_groups: int = 0
    current_group_id: str = ""
    current_cwe: str = ""
    current_title: str = ""
    current_location: str = ""
    current_correlation_type: str = ""
    current_tools: list[str] = field(default_factory=list)
    current_status_text: str = ""


class AsyncAgentRunner:
    """Quản lý chạy nền bất đồng bộ của AI Security Analysis Agent."""

    def __init__(self) -> None:
        """Khởi tạo trạng thái rỗng và lock đồng bộ."""
        self.state = AgentRunState(run_id="idle", is_running=False)
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def start(
        self,
        findings_path: str,
        model: str | None = None,
        agent_mode: str = "react",
        max_react_steps: int = 5,
        output_dir: str = "reports/analyzed",
        log_file: str | None = None,
        approval_callback: Any = None,
    ) -> bool:
        """Bắt đầu tiến trình chạy phân tích nền nếu chưa có tiến trình nào đang hoạt động.

        Args:
            findings_path: Đường dẫn tệp findings JSONL.
            model: Tên mô hình LLM.
            agent_mode: Chế độ 'react' hoặc 'static'.
            max_react_steps: Số bước ReAct tối đa.
            output_dir: Thư mục chứa báo cáo.
            log_file: Tệp ghi log.
            approval_callback: Callback xử lý HITL in-flight.

        Returns:
            bool: True nếu khởi động thành công, False nếu đang có tiến trình chạy.
        """
        with self._lock:
            if self.state.is_running:
                return False

            run_id = f"run_{uuid.uuid4().hex[:12]}"
            start_t = time.time()
            self.state = AgentRunState(
                run_id=run_id,
                is_running=True,
                is_finished=False,
                start_time=start_t,
                elapsed_seconds=0.0,
            )

        def _on_progress(idx: int, total: int, group: Any, status_text: str) -> None:
            with self._lock:
                self.state.current_group_idx = idx
                self.state.total_groups = total
                self.state.current_group_id = getattr(group, "group_id", "")
                self.state.current_cwe = getattr(group, "primary_cwe", "")
                self.state.current_title = getattr(group, "title", "")
                self.state.current_location = getattr(group, "location_summary", "")
                self.state.current_correlation_type = getattr(group, "correlation_type", "")
                self.state.current_tools = list(getattr(group, "tools", []))
                self.state.current_status_text = status_text

        def _worker() -> None:
            success, res = run_agent_analysis(
                findings_path=findings_path,
                model=model,
                agent_mode=agent_mode,
                max_react_steps=max_react_steps,
                output_dir=output_dir,
                log_file=log_file,
                approval_callback=approval_callback,
                progress_callback=_on_progress,
            )
            with self._lock:
                self.state.is_running = False
                self.state.is_finished = True
                self.state.elapsed_seconds = round(time.time() - start_t, 2)
                if success:
                    self.state.summary = res
                else:
                    self.state.error = res.get("error", "Lỗi không xác định khi chạy Agent")

        self._thread = threading.Thread(target=_worker, daemon=True)
        self._thread.start()
        return True

    def get_status(self) -> AgentRunState:
        """Lấy trạng thái thực thi hiện tại của Agent."""
        with self._lock:
            if self.state.is_running:
                self.state.elapsed_seconds = round(time.time() - self.state.start_time, 2)
            return self.state

    def reset(self) -> None:
        """Đặt lại trạng thái runner về mặc định."""
        with self._lock:
            self.state = AgentRunState(run_id="idle", is_running=False)
            self._thread = None


def get_configured_model() -> str:
    """Trả về tên mô hình LLM được cấu hình trong file .env (mặc định 'qwen-plus')."""
    return AgentConfig().model


def run_agent_analysis(
    findings_path: str,
    model: str | None = None,
    agent_mode: str = "react",
    max_react_steps: int = 5,
    output_dir: str = "reports/analyzed",
    log_file: str | None = None,
    approval_callback: Any = None,
    progress_callback: Any = None,
) -> tuple[bool, dict[str, Any]]:
    """
    Kích hoạt Security Analysis Agent chạy phân tích trên tập findings_path.

    Args:
        findings_path: Đường dẫn tới file Unified Findings JSONL
        model: Tên mô hình LLM tùy chọn (vd: 'qwen-plus')
        agent_mode: Chế độ suy luận ('react' hoặc 'static')
        max_react_steps: Số bước ReAct tối đa cho mỗi nhóm
        output_dir: Thư mục chứa báo cáo xuất ra
        log_file: Tệp ghi log tùy chọn
        approval_callback: Hàm callback phê duyệt rủi ro HITL (nếu có)
        progress_callback: Callback báo cáo tiến độ nhóm đang xử lý

    Returns:
        tuple[bool, dict]: (Thành công hay không, Thông tin tóm tắt kết quả analysis summary)
    """
    findings = Path(findings_path)
    if not findings.exists():
        return False, {"error": f"Tập tin findings không tồn tại: {findings_path}"}

    config = AgentConfig()
    if model:
        config.model = model
    config.agent_mode = "react" if agent_mode.lower() == "react" else "static"
    config.max_react_steps = int(max_react_steps)
    config.output_dir = Path(output_dir)
    if approval_callback is not None:
        config.approval_callback = approval_callback

    target_log_file = log_file or str(Path("logs/agent-runner.log"))

    try:
        summary = run_analysis(
            findings_path=findings,
            config=config,
            log_file=target_log_file,
            progress_callback=progress_callback,
        )
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


def export_report_to_markdown(report_entries: list[dict[str, Any]]) -> str:
    """
    Chuyển đổi danh sách các bản ghi ReportEntry thành tài liệu Markdown có cấu trúc hoàn chỉnh.

    Args:
        report_entries: Danh sách các bản ghi kết quả phân tích theo security_analysis_report.schema.json.

    Returns:
        str: Nội dung tài liệu báo cáo an ninh theo định dạng Markdown chuẩn, không chứa emoji.
    """
    if not report_entries:
        return "# BÁO CÁO PHÂN TÍCH AN NINH & SUY LUẬN AI (PROJECT SENTINEL)\n\n*Không có dữ liệu phân tích nào được ghi nhận.*"

    first_meta = report_entries[0].get("metadata", {})
    model_name = first_meta.get("model", "qwen-plus")
    prompt_ver = first_meta.get("prompt_version", "system_v2")
    analyzed_at = first_meta.get("analyzed_at", "")

    # Gom nhóm theo analysis_group_id
    groups_dict: dict[str, list[dict[str, Any]]] = {}
    for entry in report_entries:
        grp_id = entry.get("analysis_group_id", "grp_unknown")
        groups_dict.setdefault(grp_id, []).append(entry)

    total_findings = len(report_entries)
    total_groups = len(groups_dict)
    confirmed_count = sum(1 for e in report_entries if e.get("confidence", {}).get("level") == "confirmed")
    fp_count = sum(1 for e in report_entries if e.get("confidence", {}).get("level") == "false_positive")
    injection_count = sum(1 for e in report_entries if e.get("metadata", {}).get("prompt_injection_detected", False))

    md_lines: list[str] = [
        "# BÁO CÁO PHÂN TÍCH AN NINH & SUY LUẬN AI (PROJECT SENTINEL)",
        "",
        "## 1. TỔNG QUAN PHÂN TÍCH (EXECUTIVE SUMMARY)",
        f"- Thời gian phân tích: {analyzed_at or 'N/A'}",
        f"- Mô hình AI thực thi: `{model_name}` (Phiên bản System Prompt: `{prompt_ver}`)",
        f"- Tổng số phát hiện (Findings): **{total_findings}** | Tổng số nhóm lỗ hổng: **{total_groups}**",
        f"- Xác nhận True Positive (Confirmed): **{confirmed_count}** | False Positive loại trừ: **{fp_count}**",
        f"- Đòn tấn công Prompt Injection bị vô hiệu hóa: **{injection_count}**",
        "",
        "## 2. BẢNG MA TRẬN MỨC ĐỘ NGHIÊM TRỌNG (SEVERITY MATRIX)",
        "| Nhóm Lỗ Hổng | Primary CWE | Danh Mục OWASP | Severity (Agent / Scanner Gốc) | Độ Tin Cậy (Confidence) | Tương Quan |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    for grp_id, items in groups_dict.items():
        first = items[0]
        title = first.get("title", "Lỗ hổng bảo mật")
        primary_cwe = first.get("primary_cwe_id") or "N/A"
        owasp = first.get("owasp_category") or "N/A"
        sev_obj = first.get("severity", {})
        agent_sev = str(sev_obj.get("agent_assessment", "unknown")).upper()
        orig_sev = str(sev_obj.get("original_scanner", "N/A")).upper()
        conf_obj = first.get("confidence", {})
        conf_lvl = str(conf_obj.get("level", "unknown")).upper()
        corr = first.get("correlation_type", "sast_only")

        md_lines.append(f"| [{grp_id}] {title} | `{primary_cwe}` | `{owasp}` | **{agent_sev}** ({orig_sev}) | `{conf_lvl}` | `{corr}` |")

    md_lines.extend([
        "",
        "## 3. CHI TIẾT CÁC NHÓM LỖ HỔNG & BẰNG CHỨNG (DETAILED FINDINGS)",
        "",
    ])

    for grp_idx, (grp_id, items) in enumerate(groups_dict.items(), 1):
        first = items[0]
        title = first.get("title", "Lỗ hổng bảo mật")
        primary_cwe = first.get("primary_cwe_id") or "N/A"
        all_cwes = ", ".join(first.get("all_cwe_ids") or [primary_cwe])
        owasp = first.get("owasp_category") or "N/A"
        corr_type = first.get("correlation_type", "sast_only")
        sev_obj = first.get("severity", {})
        conf_obj = first.get("confidence", {})
        expl = first.get("explanation", "Chưa có phân tích chi tiết.")
        rec_act = first.get("recommended_action", "Chưa có khuyến nghị cụ thể.")

        md_lines.extend([
            f"### Nhóm {grp_idx}: [{grp_id}] {title}",
            f"- **Phân loại CWE**: `{primary_cwe}` (Tất cả: `{all_cwes}`)",
            f"- **Danh mục OWASP**: `{owasp}`",
            f"- **Mức độ nghiêm trọng (Severity)**: Agent `{sev_obj.get('agent_assessment')}` | Gốc `{sev_obj.get('original_scanner')}`",
            f"  * *Lý do đánh giá mức độ*: {sev_obj.get('rationale', 'N/A')}",
            f"- **Độ tin cậy (Confidence)**: `{conf_obj.get('level')}`",
            f"  * *Căn cứ xác định độ tin cậy*: {conf_obj.get('rationale', 'N/A')}",
            f"- **Kiểu tương quan (Correlation Type)**: `{corr_type}`",
            "",
            "#### A. Nguyên nhân gốc rễ & Phân tích tác động (Root Cause & Explanation)",
            f"{expl}",
            "",
            "#### B. Khuyến nghị khắc phục (Recommended Actions)",
            f"{rec_act}",
            "",
        ])

        # Proposed test request if any
        ptr = first.get("proposed_test_request")
        if ptr:
            headers_str = json.dumps(ptr.get("headers", {}), ensure_ascii=False)
            payload_str = json.dumps(ptr.get("payload"), ensure_ascii=False) if ptr.get("payload") is not None else "null"
            md_lines.extend([
                "#### C. Đề xuất kiểm thử an toàn (Proposed Test Request)",
                f"- **Trạng thái**: `{ptr.get('status', 'not_sent')}`",
                f"- **HTTP Request**: `{ptr.get('method', 'GET')} {ptr.get('endpoint', '/')}`",
                f"- **Headers**: `{headers_str}`",
                f"- **Payload**: `{payload_str}`",
                f"- **Căn cứ & Mục đích probe**: {ptr.get('rationale', 'N/A')}",
                "",
            ])

        # Knowledge references
        kb_refs = first.get("knowledge_references", [])
        if kb_refs:
            md_lines.extend([
                "#### D. Tài liệu tri thức bảo mật tham chiếu (Knowledge References)",
            ])
            for ref in kb_refs:
                md_lines.append(f"- **[{ref.get('doc_id')}] {ref.get('title')}**: {ref.get('relevance')}")
            md_lines.append("")

        # Sub-findings list
        md_lines.extend([
            f"#### E. Danh sách phát hiện thành phần ({len(items)} Findings)",
        ])
        for f_idx, item in enumerate(items, 1):
            f_id = item.get("finding_id", "N/A")
            f_tool = item.get("tool", "N/A")
            f_scan = item.get("scan_type", "N/A")
            f_loc = item.get("location_summary", "N/A")
            f_ev = item.get("evidence_summary", "N/A")
            f_fp = item.get("fingerprint", "N/A")
            f_stat = item.get("analysis_status", "success")

            md_lines.extend([
                f"{f_idx}. **Finding ID**: `{f_id}` | **Công cụ**: `{f_tool}` ({f_scan}) | **Trạng thái**: `{f_stat}`",
                f"   - **Vị trí**: `{f_loc}`",
                f"   - **Fingerprint**: `{f_fp}`",
                f"   - **Bằng chứng trích xuất**: {f_ev}",
            ])
        md_lines.append("")

    return "\n".join(md_lines)
