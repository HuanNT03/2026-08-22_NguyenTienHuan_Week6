import json
import os
import threading
import time
import uuid
from dataclasses import dataclass
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

        def _worker() -> None:
            success, res = run_agent_analysis(
                findings_path=findings_path,
                model=model,
                agent_mode=agent_mode,
                max_react_steps=max_react_steps,
                output_dir=output_dir,
                log_file=log_file,
                approval_callback=approval_callback,
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
        summary = run_analysis(findings_path=findings, config=config, log_file=target_log_file)
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
