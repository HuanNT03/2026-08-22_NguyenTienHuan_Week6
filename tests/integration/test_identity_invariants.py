import hashlib
import json
from itertools import count
from pathlib import Path
from uuid import UUID

import src.normalizers.common.finding as finding_module
from src.normalizers.codeql import normalize_codeql_report
from src.normalizers.context import NormalizationContext
from src.normalizers.semgrep import normalize_semgrep_report
from src.normalizers.zap import normalize_zap_report

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests/fixtures/scanners"


def _context(tool: str, report_path: Path, base_url: str | None) -> NormalizationContext:
    return NormalizationContext(
        schema_version="2.0.0",
        normalizer_version="2.0.0",
        run_id=f"{tool}_identity",
        pipeline_run_id=None,
        scanned_at="2026-08-05T00:00:00Z",
        target_name="juice-shop",
        target_version="20.1.1",
        target_commit_sha="f915bddd82790d0f3018902d36ae9b4241a5f51f",
        target_base_url=base_url,
        report_path=report_path.as_posix(),
    )


def test_scope_filter_preserves_identity_and_raw_order_for_retained_findings(monkeypatch) -> None:
    sequence = count(1)
    monkeypatch.setattr(finding_module, "uuid4", lambda: UUID(int=next(sequence)))
    configurations = [
        ("semgrep", "semgrep.json", normalize_semgrep_report, None),
        ("zap", "zap.json", normalize_zap_report, "http://juice-shop:3000"),
        ("codeql", "codeql.sarif", normalize_codeql_report, None),
    ]
    identities = []
    for tool, name, normalizer, base_url in configurations:
        report_path = FIXTURES / name
        report = json.loads(report_path.read_text(encoding="utf-8"))
        normalized = normalizer(
            report,
            _context(tool, report_path, base_url),
            normalized_at="2026-08-05T01:00:00Z",
        )
        identities.extend({
            "finding_id": finding["finding_id"],
            "fingerprint": finding["fingerprint"],
            "group_key": finding["group_key"],
            "raw_pointer": finding["raw_sources"][0]["json_pointer"],
        } for finding in normalized.findings)

    canonical = json.dumps(identities, sort_keys=True, separators=(",", ":")).encode()
    expected = (FIXTURES / "identity-v1.sha256").read_text(encoding="utf-8").strip()

    assert len(identities) == 160
    assert hashlib.sha256(canonical).hexdigest() == expected
