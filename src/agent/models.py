"""Pydantic data models for Security Analysis Agent."""

from typing import Any, Literal

from pydantic import BaseModel, Field


class SeverityAssessment(BaseModel):
    """Structured severity evaluation combining scanner & agent rationale."""

    agent_assessment: Literal["info", "low", "medium", "high", "critical", "unknown"]
    original_scanner: str | None = None
    rationale: str = Field(min_length=1)


class ConfidenceAssessment(BaseModel):
    """Structured confidence evaluation with rationale."""

    level: Literal["false_positive", "low", "medium", "high", "confirmed", "unknown"]
    rationale: str = Field(min_length=1)


class ProposedTestRequest(BaseModel):
    """Data-only proposed security verification request (not executed in Week 3)."""

    method: str = Field(pattern=r"^[A-Z]+$")
    endpoint: str = Field(pattern=r"^/")
    headers: dict[str, str] = Field(default_factory=dict)
    payload: Any = None
    rationale: str = Field(min_length=1)


class KnowledgeReference(BaseModel):
    """Provenance reference to a canonical Knowledge Base document."""

    doc_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    relevance: str = Field(min_length=1)


class AnalysisMetadata(BaseModel):
    """Execution metadata for auditability and lineage."""

    analyzed_at: str = Field(description="ISO-8601 formatted timestamp")
    model: str = Field(min_length=1)
    prompt_version: str = Field(min_length=1)
    grouping_source: str = Field(min_length=1)
    retry_count: int = Field(ge=0, default=0)


class ReportEntry(BaseModel):
    """One single finding security analysis report entry (1 entry / fingerprint)."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    analysis_id: str = Field(pattern=r"^analysis_[0-9a-f]{32}$")
    analysis_group_id: str = Field(pattern=r"^grp_[a-zA-Z0-9_:-]+$")
    analysis_status: Literal["success", "error"] = "success"

    fingerprint: str = Field(pattern=r"^fp_sha256:v1:[0-9a-f]{64}$")
    finding_id: str = Field(pattern=r"^fnd_[0-9a-f]{32}$")
    tool: Literal["semgrep", "zap", "codeql"]
    scan_type: Literal["SAST", "DAST"]

    title: str = Field(min_length=1)
    primary_cwe_id: str | None = Field(default=None, pattern=r"^CWE-[1-9][0-9]*$")
    all_cwe_ids: list[str] = Field(default_factory=list)
    owasp_category: str | None = Field(default=None, pattern=r"^OWASP-A(0[1-9]|10):[0-9]{4}$")
    location_summary: str = Field(min_length=1)

    severity: SeverityAssessment
    confidence: ConfidenceAssessment
    correlation_type: Literal[
        "sast_only", "dast_only", "sast_dast_confirmed", "sast_dast_suspected", "multi_sast"
    ]
    correlated_with: list[str] = Field(default_factory=list)

    evidence_summary: str = Field(min_length=1)
    explanation: str = Field(min_length=1)
    recommended_action: str = Field(min_length=1)
    proposed_test_request: ProposedTestRequest | None = None
    knowledge_references: list[KnowledgeReference] = Field(default_factory=list)

    metadata: AnalysisMetadata


class CorrelationResult(BaseModel):
    """Result of evaluating cross-tool correlation between findings."""

    is_correlated: bool
    confidence: Literal["none", "low", "medium", "high"]
    cwe_overlap: list[str] = Field(default_factory=list)
    is_title_similar: bool = False
    is_route_match: bool = False
    is_param_match: bool = False
    reason: str = ""


class AnalysisGroup(BaseModel):
    """Group of related unified findings assembled for single LLM prompt context."""

    group_id: str = Field(min_length=1)
    primary_cwe: str | None = None
    findings: list[dict[str, Any]] = Field(default_factory=list)
    correlation_type: Literal[
        "sast_only", "dast_only", "sast_dast_confirmed", "sast_dast_suspected", "multi_sast"
    ] = "sast_only"
    correlated_fingerprints: list[str] = Field(default_factory=list)
    source: str = "group_key"
