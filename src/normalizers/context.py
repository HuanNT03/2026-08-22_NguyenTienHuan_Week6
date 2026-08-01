from dataclasses import dataclass


@dataclass(frozen=True)
class NormalizationContext:
    schema_version: str
    normalizer_version: str

    run_id: str
    pipeline_run_id: str | None
    scanned_at: str

    target_name: str
    target_version: str | None
    target_commit_sha: str | None
    target_base_url: str | None

    report_path: str
