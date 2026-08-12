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


# Mapping internal target management action keys to explicit Makefile target execution commands
TARGET_COMMANDS: Mapping[str, list[str]] = {
    "up": ["make", "target-up"],
    "wait": ["make", "target-wait"],
    "down": ["make", "target-down"],
    "status": ["make", "target-status"],
}


def get_supported_scanners() -> list[str]:
    """Trả về danh sách các scanner hỗ trợ."""
    return list(TOOL_COMMANDS.keys())


def _execute_command(command: list[str], cwd: str = ".", timeout_seconds: int = 1800) -> tuple[bool, str]:
    """Helper nội bộ để thực thi command subprocess và trả về (success, log)."""
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
            return False, f"Exit code {process.returncode}:\n{output}"
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        return False, f"Vượt quá thời gian cho phép ({timeout_seconds}s):\nSTDOUT: {stdout}\nSTDERR: {stderr}"
    except FileNotFoundError as exc:
        cmd_str = exc.filename or command[0]
        return False, f"Không tìm thấy lệnh '{cmd_str}' trong hệ thống. Vui lòng kiểm tra xem công cụ (make, jq, docker) đã được cài đặt chưa."
    except Exception as exc:  # noqa: BLE001
        return False, f"Ngoại lệ không xác định: {exc}"


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
    success, output = _execute_command(command, cwd=cwd, timeout_seconds=timeout_seconds)
    if not success:
        return False, f"Lỗi thực thi {tool_name} {output}"
    return True, output


def run_target_command(action: str, cwd: str = ".") -> tuple[bool, str]:
    """
    Quản lý vòng đời của Target App (OWASP Juice Shop) bằng các lệnh Makefile/Docker.

    Args:
        action: Chuỗi phím hành động nội bộ ('up' -> make target-up & target-wait, 'down' -> make target-down, 'status' -> make target-status)
        cwd: Thư mục thực thi lệnh (mặc định '.')

    Returns:
        tuple[bool, str]: (Thành công hay không, Log output)
    """
    if action not in TARGET_COMMANDS:
        supported = ", ".join(TARGET_COMMANDS.keys())
        return False, f"Hành động target '{action}' không hợp lệ. Các hành động hỗ trợ: {supported}"

    if action == "up":
        res_up, out_up = _execute_command(TARGET_COMMANDS["up"], cwd=cwd, timeout_seconds=300)
        if not res_up:
            return False, f"Lỗi khi khởi động Target App:\n{out_up}"
        res_wait, out_wait = _execute_command(TARGET_COMMANDS["wait"], cwd=cwd, timeout_seconds=300)
        output = f"{out_up}\n\n--- WAITING TARGET READINESS ---\n{out_wait}"
        return res_wait, output
    else:
        return _execute_command(TARGET_COMMANDS[action], cwd=cwd, timeout_seconds=300)


def check_target_health() -> tuple[bool, int, str]:
    """
    Kiểm tra xem Target App (Juice Shop) có đang phản hồi HTTP hay không.

    Thử lần lượt các URL endpoint khả dĩ:
    1. http://127.0.0.1:{port}/ (khi chạy ngoài máy Host)
    2. http://juice-shop:3000/ (khi chạy từ container UI trong mạng Docker Compose sentinel-security)
    3. http://localhost:{port}/ (fallback khác)

    Returns:
        tuple[bool, int, str]: (Đang hoạt động hay không, HTTP Status Code / 0, URL target phản hồi thành công hoặc mặc định)
    """
    import urllib.error
    import urllib.request

    port = os.getenv("JUICE_SHOP_PORT", "3000")
    candidate_urls = [
        f"http://127.0.0.1:{port}/",
        "http://juice-shop:3000/",
        f"http://localhost:{port}/",
    ]

    for target_url in candidate_urls:
        try:
            req = urllib.request.Request(target_url, headers={"User-Agent": "Sentinel-HealthCheck"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                return True, resp.status, target_url
        except urllib.error.HTTPError as exc:
            return True, exc.code, target_url
        except Exception:  # noqa: BLE001, S112
            continue

    return False, 0, f"http://127.0.0.1:{port}/"

