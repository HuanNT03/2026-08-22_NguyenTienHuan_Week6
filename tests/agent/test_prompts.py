"""Unit tests for ReAct System Prompt v2 and Prompt Builder."""

from pathlib import Path

from src.agent.models import AnalysisGroup
from src.agent.prompt_builder import build_react_user_prompt, compress_finding

SYSTEM_V2_PATH = Path(__file__).resolve().parent.parent.parent / "src" / "agent" / "prompts" / "system_v2.md"


def test_system_v2_prompt_exists_and_contains_rules() -> None:
    """Verify that system_v2.md exists and contains strict security rules & schema constraints."""
    assert SYSTEM_V2_PATH.is_file()
    content = SYSTEM_V2_PATH.read_text(encoding="utf-8")

    # Check Core Persona & ReAct loop instructions
    assert "Project Sentinel" in content
    assert "ReAct" in content or "Thought" in content
    assert "untrusted_http_response" in content

    # Check Schema Enums mentioned
    assert "sast_dast_confirmed" in content
    assert "false_positive" in content
    assert "confirmed" in content

    # Check Zero Secret Leakage rule
    assert "AGENT_API_KEY" in content or "API Key" in content
    assert "Tuyệt đối không" in content or "TUYỆT ĐỐI" in content


def test_build_react_user_prompt_structure() -> None:
    """Verify build_react_user_prompt generates valid JSON payload with compressed findings."""
    mock_group = AnalysisGroup(
        group_id="grp_cwe89_001",
        primary_cwe="CWE-89",
        correlation_type="sast_dast_suspected",
        correlated_fingerprints=["fp_1", "fp_2"],
        findings=[
            {
                "fingerprint": "fp_1",
                "finding_id": "fnd_1",
                "title": "Possible SQL Injection in login",
                "severity": "high",
                "cwe_ids": ["CWE-89"],
                "location": {"kind": "code", "path": "routes/login.ts", "start_line": 25},
                "schema_version": "1.0.0",  # Should be compressed out
            }
        ],
    )

    prompt_str = build_react_user_prompt(mock_group)
    assert isinstance(prompt_str, str)
    assert "grp_cwe89_001" in prompt_str
    assert "CWE-89" in prompt_str
    assert "routes/login.ts" in prompt_str
    assert "schema_version" not in prompt_str  # Compressed
