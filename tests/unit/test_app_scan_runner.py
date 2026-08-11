"""Unit test cho src/app/scan_runner.py."""

import subprocess

from src.app.scan_runner import check_target_health, get_supported_scanners, run_scanner, run_target_command


def test_get_supported_scanners_contains_all_tools():
    """Kiểm tra get_supported_scanners trả về đầy đủ các công cụ bao gồm DAST Admin và Full Scan Admin."""
    scanners = get_supported_scanners()
    expected_tools = [
        "semgrep",
        "codeql",
        "zap_baseline",
        "zap_fullscan",
        "zap_admin",
        "zap_fullscan_admin",
        "sqlmap",
        "full_scan_admin",
    ]
    for tool in expected_tools:
        assert tool in scanners, f"Thiếu tool {tool} trong get_supported_scanners()"


def test_run_scanner_invalid_tool():
    """Kiểm tra run_scanner với tool_name không hợp lệ."""
    success, output = run_scanner("invalid_tool_name_xyz")
    assert success is False
    assert "không được hỗ trợ" in output


def test_run_scanner_missing_binary(monkeypatch):
    """Kiểm tra run_scanner khi binary (ví dụ: make hoặc script) không tìm thấy trên hệ thống."""

    def mock_run(*args, **kwargs):
        raise FileNotFoundError(2, "No such file or directory", "make")

    monkeypatch.setattr(subprocess, "run", mock_run)
    success, output = run_scanner("codeql")
    assert success is False
    assert "Không tìm thấy lệnh 'make'" in output


def test_run_target_command_invalid():
    """Kiểm tra run_target_command với action không hợp lệ."""
    success, output = run_target_command("invalid_action")
    assert success is False
    assert "không hợp lệ" in output


def test_run_target_command_valid(monkeypatch):
    """Kiểm tra run_target_command với action hợp lệ (mocked)."""

    class DummyProcess:
        returncode = 0
        stdout = "OK"
        stderr = ""

    def mock_run(*args, **kwargs):
        return DummyProcess()

    monkeypatch.setattr(subprocess, "run", mock_run)
    success, output = run_target_command("status")
    assert success is True
    assert "Exit code 0" in output or "STDOUT" in output


def test_check_target_health():
    """Kiểm tra hàm check_target_health trả về tuple hợp lệ."""
    is_alive, code, url = check_target_health()
    assert isinstance(is_alive, bool)
    assert isinstance(code, int)
    assert "http://" in url



