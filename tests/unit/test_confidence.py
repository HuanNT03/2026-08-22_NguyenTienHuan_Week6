import pytest

from src.normalizers.common.confidence import normalize_confidence


@pytest.mark.parametrize(("tool", "native", "expected"), [
    ("semgrep", "HIGH", "high"), ("semgrep", "LOW", "low"),
    ("zap", "0", "false_positive"), ("zap", "4", "confirmed"),
    ("codeql", "very-high", "high"), ("codeql", "medium", "medium"),
    ("codeql", None, "unknown"),
])
def test_confidence_mapping(tool, native, expected):
    assert normalize_confidence(tool, native) == expected
