from src.normalizers.common.urls import canonicalize_endpoint, extract_urls


def test_canonicalize_endpoint_discards_query_and_host():
    assert canonicalize_endpoint("http://juice-shop:3000/ftp/package.json.bak?x=1") == "/ftp/package.json.bak"
    assert canonicalize_endpoint("http://juice-shop:3000") == "/"


def test_extract_urls_deduplicates_and_rejects_non_strings():
    raw = "<p>https://example.test/a.</p> https://example.test/a"
    assert extract_urls(raw) == ["https://example.test/a"]
    assert extract_urls({"url": "https://example.test"}) == []
