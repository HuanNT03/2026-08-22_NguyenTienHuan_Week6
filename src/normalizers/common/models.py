from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolNormalizationResult:
    findings: list[dict[str, Any]] = field(default_factory=list)
    raw_counts: dict[str, int] = field(default_factory=dict)
    warnings: dict[str, Any] = field(default_factory=dict)
