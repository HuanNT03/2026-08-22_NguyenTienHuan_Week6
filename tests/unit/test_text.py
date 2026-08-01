from src.normalizers.common import text


def test_strip_html_handles_null_non_string_and_malformed_html():
    assert text.strip_html(None) is None
    assert text.strip_html(42) == "42"
    assert text.strip_html("<p>Hello <b>world") == "Hello world"
    assert text.strip_html("<p>Xin chào&nbsp;世界</p>") == "Xin chào 世界"


def test_strip_html_falls_back_on_parser_error(monkeypatch):
    monkeypatch.setattr(text.html, "unescape", lambda _value: (_ for _ in ()).throw(ValueError("bad")))
    result = text.strip_html_with_status("<p>broken</p>")
    assert result.had_error is True
    assert result.value == "<p>broken</p>"
