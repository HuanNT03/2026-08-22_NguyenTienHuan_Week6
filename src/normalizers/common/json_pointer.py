from typing import Any


class JsonPointerError(ValueError):
    pass


def escape_json_pointer_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def resolve_json_pointer(document: Any, pointer: str) -> Any:
    if pointer == "":
        return document
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise JsonPointerError(f"Invalid JSON Pointer: {pointer!r}")
    current = document
    for encoded in pointer[1:].split("/"):
        token = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            if token == "-" or not token.isdigit() or (len(token) > 1 and token.startswith("0")):
                raise JsonPointerError(f"Invalid array index in JSON Pointer: {token!r}")
            index = int(token)
            if index >= len(current):
                raise JsonPointerError(f"Array index out of range: {index}")
            current = current[index]
        elif isinstance(current, dict):
            if token not in current:
                raise JsonPointerError(f"Object key not found: {token!r}")
            current = current[token]
        else:
            raise JsonPointerError(f"Cannot traverse into {type(current).__name__}")
    return current
