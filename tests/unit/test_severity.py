import pytest

from src.normalizers.common.severity import normalize_severity


@pytest.mark.parametrize(("tool", "native", "expected"), [
    ("semgrep", "CRITICAL", "critical"), ("semgrep", "ERROR", "high"),
    ("semgrep", "WARNING", "medium"), ("zap", "0", "info"), ("zap", "3", "high"),
    ("codeql", "9.1", "critical"), ("codeql", "7.5", "high"),
    ("codeql", "4.0", "medium"), ("codeql", None, "unknown"),
])
def test_severity_mapping(tool, native, expected):
    assert normalize_severity(tool, native) == expected
