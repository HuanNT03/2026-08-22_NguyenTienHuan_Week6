from pathlib import Path

import pytest

from src.normalizers.common.evidence import nullable_text, read_code_evidence, resolve_source_path


def _write_source(root: Path, content: str, name: str = "routes/example.ts") -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content.encode("utf-8"))
    return path


def test_nullable_text_preserves_code_formatting() -> None:
    assert nullable_text("  const value = 1\n") == "  const value = 1\n"
    assert nullable_text(" \t\n") is None
    assert nullable_text(None) is None


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_reads_multiline_content_and_five_line_context(tmp_path: Path, newline: str) -> None:
    _write_source(tmp_path, newline.join(f"  line {number}" for number in range(1, 15)) + newline)

    result = read_code_evidence(tmp_path, "routes/example.ts", 7, 8)

    assert result.content == "  line 7\n  line 8"
    assert result.context_before == [
        {"line": number, "content": f"  line {number}"} for number in range(2, 7)
    ]
    assert result.context_after == [
        {"line": number, "content": f"  line {number}"} for number in range(9, 14)
    ]
    assert result.source_succeeded is True
    assert result.warning is None


def test_context_is_clamped_at_first_and_last_line(tmp_path: Path) -> None:
    _write_source(tmp_path, "first\nsecond\nlast\n")

    first = read_code_evidence(tmp_path, "routes/example.ts", 1, 1)
    last = read_code_evidence(tmp_path, "routes/example.ts", 3, 3)

    assert first.context_before == []
    assert first.context_after == [
        {"line": 2, "content": "second"},
        {"line": 3, "content": "last"},
    ]
    assert last.context_before == [
        {"line": 1, "content": "first"},
        {"line": 2, "content": "second"},
    ]
    assert last.context_after == []


def test_known_semgrep_container_prefix_maps_to_source_root(tmp_path: Path) -> None:
    expected = _write_source(tmp_path, "matched\n")

    resolved, error = resolve_source_path(tmp_path, "/src/target-app/juice-shop/routes/example.ts")

    assert resolved == expected.resolve()
    assert error is None

    file_uri, uri_error = resolve_source_path(
        tmp_path,
        "file:///workspace/target-app/juice-shop/routes/example.ts",
    )
    assert file_uri == expected.resolve()
    assert uri_error is None


@pytest.mark.parametrize(
    "path",
    [
        "../outside.ts",
        "/etc/passwd",
        "C:/Windows/system.ini",
        "https://example.invalid/source.ts",
    ],
)
def test_rejects_untrusted_source_paths(tmp_path: Path, path: str) -> None:
    resolved, error = resolve_source_path(tmp_path, path)

    assert resolved is None
    assert error


def test_missing_file_and_out_of_range_location_return_controlled_failure(tmp_path: Path) -> None:
    missing = read_code_evidence(tmp_path, "routes/missing.ts", 1, 1)
    _write_source(tmp_path, "only line\n")
    outside = read_code_evidence(tmp_path, "routes/example.ts", 2, 2)

    for result in (missing, outside):
        assert result.content is None
        assert result.context_before == []
        assert result.context_after == []
        assert result.source_succeeded is False
        assert result.warning


def test_symlink_escape_is_rejected(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    outside = _write_source(tmp_path, "secret\n", "outside.ts")
    link = source_root / "escape.ts"
    try:
        link.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlinks are unavailable: {exc}")

    resolved, error = resolve_source_path(source_root, "escape.ts")

    assert resolved is None
    assert error == "resolved source path escapes source root"
