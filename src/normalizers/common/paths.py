import re
from urllib.parse import unquote, urlparse


_TARGET_MARKER = re.compile(r"(?:^|/)target-app/[^/]+/(.*)$")


def normalize_code_path(raw_path: str | None) -> str | None:
    if raw_path is None or not isinstance(raw_path, str):
        return None
    value = raw_path.strip().replace("\\", "/")
    if not value:
        return None
    if value.startswith("file:"):
        value = unquote(urlparse(value).path)
    value = re.sub(r"/+", "/", value)
    marker = _TARGET_MARKER.search(value)
    if marker:
        value = marker.group(1)
    else:
        value = value.lstrip("/")
    while value.startswith("./"):
        value = value[2:]
    parts = [part for part in value.split("/") if part not in {"", "."}]
    if not parts or ".." in parts:
        return None
    return "/".join(parts)
