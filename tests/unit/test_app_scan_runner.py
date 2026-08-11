"""Unit test cho src/app/scan_runner.py."""

from src.app.scan_runner import get_supported_scanners, run_scanner


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
    import subprocess

    def mock_run(*args, **kwargs):
        raise FileNotFoundError(2, "No such file or directory", "make")

    monkeypatch.setattr(subprocess, "run", mock_run)
    success, output = run_scanner("codeql")
    assert success is False
    assert "Không tìm thấy lệnh 'make'" in output

