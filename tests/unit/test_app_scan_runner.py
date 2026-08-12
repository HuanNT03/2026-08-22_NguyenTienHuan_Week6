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


def test_run_scanner_stream_invalid():
    """Kiểm tra run_scanner_stream với tool_name không hợp lệ."""
    from src.app.scan_runner import run_scanner_stream

    stream = list(run_scanner_stream("invalid_tool"))
    assert len(stream) == 1
    is_done, full_log, _line = stream[0]
    assert is_done is False
    assert "không được hỗ trợ" in full_log


def test_run_target_command_stream_invalid():
    """Kiểm tra run_target_command_stream với action không hợp lệ."""
    from src.app.scan_runner import run_target_command_stream

    stream = list(run_target_command_stream("invalid_action"))
    assert len(stream) == 1
    is_done, full_log, _line = stream[0]
    assert is_done is False
    assert "không hợp lệ" in full_log


def test_check_target_health():
    """Kiểm tra hàm check_target_health trả về tuple hợp lệ."""
    is_alive, code, url = check_target_health()
    assert isinstance(is_alive, bool)
    assert isinstance(code, int)
    assert "http://" in url


def test_check_target_health_fallback_success(monkeypatch):
    """Kiểm tra check_target_health tự động fallback sang URL thứ 2 khi URL 1 bị Connection Refused."""
    import urllib.error
    import urllib.request

    class DummyResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

    def mock_urlopen(req, timeout=3):
        url = req.full_url
        if "127.0.0.1" in url:
            raise urllib.error.URLError("Connection Refused")
        if "juice-shop" in url:
            return DummyResponse()
        raise urllib.error.URLError("Failed")

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)
    is_alive, code, url = check_target_health()
    assert is_alive is True
    assert code == 200
    assert url == "http://juice-shop:3000/"


def test_check_target_health_all_fail(monkeypatch):
    """Kiểm tra check_target_health trả về False khi tất cả candidate URL đều lỗi."""
    import urllib.request

    def mock_urlopen(req, timeout=3):
        raise urllib.error.URLError("Connection Refused")

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)
    is_alive, code, url = check_target_health()
    assert is_alive is False
    assert code == 0
    assert "http://127.0.0.1:" in url




