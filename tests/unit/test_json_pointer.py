import pytest

from src.normalizers.common.json_pointer import JsonPointerError, resolve_json_pointer


def test_resolve_json_pointer_and_escaping():
    document = {"a/b": [{"~key": 3}]}
    assert resolve_json_pointer(document, "/a~1b/0/~0key") == 3


def test_invalid_pointer_raises():
    with pytest.raises(JsonPointerError):
        resolve_json_pointer({"items": []}, "/items/0")
