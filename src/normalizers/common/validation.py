import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError


class FindingValidationError(ValueError):
    pass


def load_schema(path: str | Path) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as handle:
        schema = json.load(handle)
    Draft202012Validator.check_schema(schema)
    return schema


def build_validator(schema: dict[str, Any]) -> Draft202012Validator:
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise FindingValidationError(f"Invalid unified finding schema: {exc.message}") from exc
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate_finding(finding: dict[str, Any], validator: Draft202012Validator) -> None:
    errors = sorted(validator.iter_errors(finding), key=lambda error: list(error.absolute_path))
    if errors:
        first = errors[0]
        path = "/".join(str(item) for item in first.absolute_path) or "<root>"
        raise FindingValidationError(f"{path}: {first.message}")
