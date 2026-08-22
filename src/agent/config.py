"""Central configuration for Project Sentinel Security Analysis Agent."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv

# Load .env if present
PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_PATH = PROJECT_ROOT / ".env"
if ENV_PATH.is_file():
    load_dotenv(ENV_PATH)


@dataclass
class AgentConfig:
    """Agent runtime configuration settings."""

    agent_mode: Literal["react", "static"] = os.getenv("AGENT_MODE", "react")  # type: ignore[assignment]
    api_key: str = os.getenv("LLM_API_KEY", "")
    base_url: str = os.getenv("LLM_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")
    model: str = os.getenv("LLM_MODEL", "qwen-plus")
    temperature: float = float(os.getenv("LLM_TEMPERATURE", "0.1"))
    max_retries: int = int(os.getenv("LLM_MAX_RETRIES", "2"))
    max_react_steps: int = int(os.getenv("MAX_REACT_STEPS", "5"))
    tool_timeout: float = float(os.getenv("TOOL_TIMEOUT", "7.0"))
    prompt_version: str = "system_v2"

    project_root: Path = PROJECT_ROOT
    prompts_dir: Path = PROJECT_ROOT / "src" / "agent" / "prompts"
    system_prompt_path: Path = PROJECT_ROOT / "src" / "agent" / "prompts" / "system_v2.md"
    schema_path: Path = PROJECT_ROOT / "schemas" / "security_analysis_report.schema.json"
    output_dir: Path = PROJECT_ROOT / "reports" / "analyzed"
