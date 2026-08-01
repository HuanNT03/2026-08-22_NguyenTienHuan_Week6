from src.normalizers.common import text, urls
from src.normalizers.common.text import strip_html_with_status
from src.normalizers.common.urls import extract_urls_with_status


def test_url_parser_exception_is_contained(monkeypatch):
    monkeypatch.setattr(urls.html, "unescape", lambda _value: (_ for _ in ()).throw(ValueError("bad")))
    result = extract_urls_with_status("https://example.test")
    assert result.urls == []
    assert result.had_error is True


def test_html_parser_exception_is_contained(monkeypatch):
    monkeypatch.setattr(text.html, "unescape", lambda _value: (_ for _ in ()).throw(ValueError("bad")))
    result = strip_html_with_status("<p>broken</p>")
    assert result.value == "<p>broken</p>"
    assert result.had_error is True
