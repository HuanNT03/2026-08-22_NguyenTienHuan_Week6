from src.normalizers.common.hashing import canonical_json, canonical_sha256


def test_canonical_json_sorts_keys():
    assert canonical_json({"b": 2, "a": 1}) == canonical_json({"a": 1, "b": 2})
    assert canonical_json({"b": 2, "a": 1}) == '{"a":1,"b":2}'


def test_canonical_json_preserves_null_keys():
    assert canonical_json({"fallback_rule_id": None, "rule_reference": None}) == (
        '{"fallback_rule_id":null,"rule_reference":null}'
    )


def test_hash_is_stable_and_changes_with_payload():
    left = canonical_sha256("fp", "v1", {"b": 2, "a": 1})
    right = canonical_sha256("fp", "v1", {"a": 1, "b": 2})
    assert left == right
    assert left != canonical_sha256("fp", "v1", {"a": 1, "b": 3})
