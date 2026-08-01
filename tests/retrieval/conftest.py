from pathlib import Path

import pytest

from src.retrieval.config import DOCUMENTS_PATH, MANIFEST_PATH
from src.retrieval.indexers.sqlite_fts import build_index


@pytest.fixture(scope="session")
def canonical_index(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build the full canonical index once for integration search tests."""
    directory = tmp_path_factory.mktemp("canonical-index")
    path = directory / "knowledge.db"
    build_index(DOCUMENTS_PATH, MANIFEST_PATH, path)
    return path
