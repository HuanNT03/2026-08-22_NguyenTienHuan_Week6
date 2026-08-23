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


def reload_env() -> None:
    """Reload .env file to pick up live configuration changes."""
    if ENV_PATH.is_file():
        load_dotenv(ENV_PATH, override=True)


reload_env()


@dataclass
class AgentConfig:
    """Agent runtime configuration settings."""

    agent_mode: Literal["react", "static"] = "react"
    api_key: str = ""
    base_url: str = ""
    model: str = ""
    temperature: float = 0.1
    max_retries: int = 2
    max_react_steps: int = 5
    tool_timeout: float = 7.0
    prompt_version: str = "system_v2"
    auto_approve: bool = False

    project_root: Path = PROJECT_ROOT
    prompts_dir: Path = PROJECT_ROOT / "src" / "agent" / "prompts"
    system_prompt_path: Path = PROJECT_ROOT / "src" / "agent" / "prompts" / "system_v2.md"
    schema_path: Path = PROJECT_ROOT / "schemas" / "security_analysis_report.schema.json"
    output_dir: Path = PROJECT_ROOT / "reports" / "analyzed"

    def __post_init__(self) -> None:
        """Initialize and resolve configuration defaults from environment or .env."""
        reload_env()
        if not self.api_key:
            self.api_key = os.getenv("LLM_API_KEY", "")
        if not self.base_url:
            self.base_url = os.getenv("LLM_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")
        if not self.model:
            self.model = os.getenv("LLM_MODEL", "qwen-plus")
        if self.temperature == 0.1 and os.getenv("LLM_TEMPERATURE"):
            self.temperature = float(os.getenv("LLM_TEMPERATURE", "0.1"))
        if self.max_retries == 2 and os.getenv("LLM_MAX_RETRIES"):
            self.max_retries = int(os.getenv("LLM_MAX_RETRIES", "2"))
        if self.max_react_steps == 5 and os.getenv("MAX_REACT_STEPS"):
            self.max_react_steps = int(os.getenv("MAX_REACT_STEPS", "5"))
        if not self.auto_approve and os.getenv("AGENT_AUTO_APPROVE"):
            self.auto_approve = os.getenv("AGENT_AUTO_APPROVE", "0") in ("1", "true", "True")

        # Automatically resolve localhost inside Docker container
        if Path("/.dockerenv").is_file():
            if "localhost" in self.base_url:
                self.base_url = self.base_url.replace("localhost", "host.docker.internal")
            elif "127.0.0.1" in self.base_url:
                self.base_url = self.base_url.replace("127.0.0.1", "host.docker.internal")
