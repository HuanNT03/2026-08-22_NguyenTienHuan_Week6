from src.normalizers.common.taxonomy import normalize_cwe_ids, normalize_owasp_categories, normalize_wasc_ids


def test_cwe_normalization():
    assert normalize_cwe_ids(["CWE-089", "CWE-89: description", "external/cwe/cwe-079", -1, None]) == ["CWE-79", "CWE-89"]


def test_wasc_normalization():
    assert normalize_wasc_ids(["WASC-014", "14", -1]) == ["WASC-14"]


def test_owasp_normalization_and_sorting():
    assert normalize_owasp_categories(["A08:2025 - Integrity", "A03:2021 - Injection", "bad"]) == [
        "OWASP-A03:2021", "OWASP-A08:2025"
    ]
