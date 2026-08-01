from src.normalizers.common.paths import normalize_code_path


def test_absolute_workspace_paths_share_target_relative_path():
    assert normalize_code_path("/src/target-app/juice-shop/routes/search.ts") == "routes/search.ts"
    assert normalize_code_path("/home/runner/work/project/target-app/juice-shop/routes/search.ts") == "routes/search.ts"


def test_codeql_relative_path_is_preserved():
    assert normalize_code_path("routes/search.ts") == "routes/search.ts"


def test_path_rejects_empty_and_parent_traversal():
    assert normalize_code_path(None) is None
    assert normalize_code_path("../routes/search.ts") is None
