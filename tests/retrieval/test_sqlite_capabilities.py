from src.retrieval.indexers.sqlite_fts import validate_sqlite_capabilities


def test_active_sqlite_has_json_and_fts5() -> None:
    validate_sqlite_capabilities()
