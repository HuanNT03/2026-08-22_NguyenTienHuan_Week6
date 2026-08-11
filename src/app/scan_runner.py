"""Module thực thi scanner SAST/DAST an toàn cho Web Application."""

import os
import subprocess
from collections.abc import Mapping

# Mapping tool names to executable commands
TOOL_COMMANDS: Mapping[str, list[str]] = {
    "semgrep": ["./scripts/run-sast.sh"],
    "codeql": ["make", "sast-codeql"],
    "zap_baseline": ["./scripts/run-dast.sh"],
    "zap_fullscan": ["./scripts/run-dast-zap-fullscan.sh"],
    "zap_admin": ["./scripts/run-dast-admin.sh"],
    "zap_fullscan_admin": ["./scripts/run-dast-zap-fullscan-admin.sh"],
    "sqlmap": ["./scripts/run-dast-sqlmap.sh"],
    "full_scan_admin": ["./scripts/run-week1.sh"],
}


def get_supported_scanners() -> list[str]:
    """Trả về danh sách các scanner hỗ trợ."""
    return list(TOOL_COMMANDS.keys())


def run_scanner(tool_name: str, cwd: str = ".", timeout_seconds: int = 1800) -> tuple[bool, str]:
    """
    Thực thi bài quét bảo mật theo tool_name.

    Args:
        tool_name: Tên scanner (vd: 'semgrep', 'codeql', 'zap_baseline', 'zap_fullscan', 'zap_admin', 'zap_fullscan_admin', 'sqlmap', 'full_scan_admin')
        cwd: Thư mục thực thi lệnh (mặc định là gốc project '.')
        timeout_seconds: Thời gian chờ tối đa bằng giây (mặc định 1800s / 30 phút)

    Returns:
        tuple[bool, str]: (Thành công hay không, Log output chi tiết)
    """
    if tool_name not in TOOL_COMMANDS:
        supported = ", ".join(TOOL_COMMANDS.keys())
        return False, f"Scanner '{tool_name}' không được hỗ trợ. Các scanner hợp lệ: {supported}"

    command = TOOL_COMMANDS[tool_name]
    env = os.environ.copy()

    try:
        process = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        output = f"--- STDOUT ---\n{process.stdout}\n\n--- STDERR ---\n{process.stderr}"
        if process.returncode == 0:
            return True, output
        else:
            return False, f"Lỗi thực thi {tool_name} (Exit code {process.returncode}):\n{output}"
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        return False, f"Bài quét {tool_name} vượt quá thời gian cho phép ({timeout_seconds}s):\nSTDOUT: {stdout}\nSTDERR: {stderr}"
    except Exception as exc:  # noqa: BLE001
        return False, f"Ngoại lệ không xác định khi chạy {tool_name}: {exc}"
