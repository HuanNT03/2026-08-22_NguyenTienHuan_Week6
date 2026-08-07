"""Central configuration for Project Sentinel Security Analysis Agent."""

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

# Load .env if present
PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_PATH = PROJECT_ROOT / ".env"
if ENV_PATH.is_file():
    load_dotenv(ENV_PATH)


@dataclass
class AgentConfig:
    """Agent runtime configuration settings."""

    api_key: str = os.getenv("LLM_API_KEY", "")
    base_url: str = os.getenv("LLM_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")
    model: str = os.getenv("LLM_MODEL", "qwen-plus")
    temperature: float = float(os.getenv("LLM_TEMPERATURE", "0.1"))
    max_retries: int = int(os.getenv("LLM_MAX_RETRIES", "2"))
    prompt_version: str = "system_v1"

    project_root: Path = PROJECT_ROOT
    prompts_dir: Path = PROJECT_ROOT / "src" / "agent" / "prompts"
    system_prompt_path: Path = PROJECT_ROOT / "src" / "agent" / "prompts" / "system_v1.md"
    schema_path: Path = PROJECT_ROOT / "schemas" / "security_analysis_report.schema.json"
    output_dir: Path = PROJECT_ROOT / "reports" / "analyzed"
