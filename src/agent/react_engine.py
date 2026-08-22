"""ReAct Execution Engine for Project Sentinel Security Analysis Agent.

This module implements the multi-turn Thought -> Tool Call -> Observation -> Synthesis
loop using Native OpenAI Tool Calling API, enforces loop guards (max steps, repetitive
action guard, tool timeouts), and guarantees 100% finding coverage via deterministic fallback.
"""

from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING, Any

from openai import OpenAI

from src.agent.models import AnalysisGroup, ReportEntry
from src.agent.prompt_builder import build_react_user_prompt
from src.agent.tools import AGENT_TOOLS, ToolDispatcher

if TYPE_CHECKING:
    from src.agent.config import AgentConfig

logger = logging.getLogger(__name__)


def extract_json_payload(raw_text: str | None) -> Any:
    """Extract and parse JSON content from raw LLM output string, stripping markdown fences."""
    if not raw_text or not raw_text.strip():
        raise ValueError("Raw LLM response content is empty.")

    cleaned = raw_text.strip()
    # Match markdown code block if present
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned)
    if match:
        cleaned = match.group(1).strip()

    return json.loads(cleaned)


class ReActAnalysisEngine:
    """Orchestrates multi-turn ReAct reasoning and tool calling for an AnalysisGroup."""

    def __init__(
        self,
        client: OpenAI,
        config: AgentConfig,
        dispatcher: ToolDispatcher,
    ) -> None:
        """Initialize ReActAnalysisEngine with OpenAI client, config, and ToolDispatcher.

        Args:
            client: OpenAI client instance.
            config: Agent runtime configuration.
            dispatcher: ToolDispatcher instance for executing tool calls.
        """
        self.client = client
        self.config = config
        self.dispatcher = dispatcher

    def run_group_analysis(
        self,
        group: AnalysisGroup,
        system_prompt: str,
    ) -> list[ReportEntry]:
        """Execute full ReAct loop for a single AnalysisGroup.

        Args:
            group: The AnalysisGroup containing related unified findings.
            system_prompt: The system prompt guiding agent persona and rules.

        Returns:
            list[ReportEntry]: List of validated ReportEntry objects for each finding in the group.
        """
        from src.agent.analyzer import create_fallback_error_entry, sanitize_llm_entry_dict

        # Reset tool dispatcher history for fresh group session
        self.dispatcher.reset_history()

        initial_user_prompt = build_react_user_prompt(group)
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": initial_user_prompt},
        ]

        last_error_msg = ""
        max_steps = self.config.max_react_steps

        for step in range(max_steps):
            try:
                logger.info(
                    "Group %s: ReAct step %d/%d",
                    group.group_id,
                    step + 1,
                    max_steps,
                )

                # Execute ChatCompletion with native tool calling enabled
                response = self.client.chat.completions.create(
                    model=self.config.model,
                    temperature=self.config.temperature,
                    messages=messages,
                    tools=AGENT_TOOLS,
                    tool_choice="auto",
                )

                choice = response.choices[0].message
                tool_calls = getattr(choice, "tool_calls", None) or []

                # Build assistant message object
                assistant_msg: dict[str, Any] = {"role": "assistant"}
                if choice.content is not None:
                    assistant_msg["content"] = choice.content
                if tool_calls:
                    assistant_msg["tool_calls"] = tool_calls

                messages.append(assistant_msg)

                # If the model requested tool calls -> execute them and continue loop
                if tool_calls:
                    logger.info(
                        "Group %s step %d: LLM requested %d tool calls: %s",
                        group.group_id,
                        step + 1,
                        len(tool_calls),
                        [tc.function.name for tc in tool_calls],
                    )

                    for tc in tool_calls:
                        tool_name = tc.function.name
                        tool_args = tc.function.arguments
                        tool_result = self.dispatcher.execute(tool_name, tool_args)

                        # Append tool response message according to OpenAI specification
                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": tc.id,
                                "name": tool_name,
                                "content": json.dumps(tool_result, ensure_ascii=False),
                            }
                        )

                    # If this was the next-to-last step, instruct agent to conclude
                    if step == max_steps - 1:
                        messages.append(
                            {
                                "role": "user",
                                "content": (
                                    "Đã đạt giới hạn số bước ReAct tối đa. "
                                    "Hãy tổng hợp toàn bộ quan sát đã thu thập và xuất kết quả JSON "
                                    "chứa khóa 'entries' tuân theo Pydantic schema ReportEntry ngay lập tức."
                                ),
                            }
                        )
                    continue

                # If no tool calls were requested, LLM provided its final synthesis
                raw_content = choice.content or ""
                parsed_data = extract_json_payload(raw_content)

                if isinstance(parsed_data, dict) and "entries" in parsed_data:
                    entries_raw = parsed_data["entries"]
                elif isinstance(parsed_data, list):
                    entries_raw = parsed_data
                elif isinstance(parsed_data, dict):
                    entries_raw = [parsed_data]
                else:
                    raise ValueError("Phản hồi JSON của LLM phải chứa danh sách các entry hợp lệ.")

                validated_entries: list[ReportEntry] = []
                for idx, raw_item in enumerate(entries_raw):
                    sanitized = sanitize_llm_entry_dict(raw_item, group, idx, self.config, retry_count=0)
                    entry = ReportEntry.model_validate(sanitized)
                    validated_entries.append(entry)

                # Ensure 100% Finding Coverage
                covered_fps = {e.fingerprint for e in validated_entries}
                group_fps = {f["fingerprint"] for f in group.findings}

                if not group_fps.issubset(covered_fps):
                    for f in group.findings:
                        if f["fingerprint"] not in covered_fps:
                            fallback = create_fallback_error_entry(
                                f, group, "LLM omitted this finding from final output entries.", self.config, step
                            )
                            validated_entries.append(fallback)

                logger.info(
                    "Group %s: Successfully generated %d ReportEntry objects at step %d",
                    group.group_id,
                    len(validated_entries),
                    step + 1,
                )
                return validated_entries

            except Exception as err:  # noqa: BLE001
                last_error_msg = str(err)
                logger.warning(
                    "Group %s step %d encountered error: %s",
                    group.group_id,
                    step + 1,
                    last_error_msg,
                )

        # If loop finishes without valid structured JSON return, attempt one forced final synthesis
        try:
            logger.info("Group %s: Forcing final structured JSON synthesis call", group.group_id)
            messages.append(
                {
                    "role": "user",
                    "content": (
                        "Hãy tổng hợp toàn bộ các phát hiện và quan sát ở trên để xuất kết quả JSON cuối cùng "
                        "có cấu trúc {'entries': [...]} tuân theo Pydantic schema cho tất cả findings trong nhóm."
                    ),
                }
            )
            force_resp = self.client.chat.completions.create(
                model=self.config.model,
                temperature=self.config.temperature,
                messages=messages,
                response_format={"type": "json_object"},
            )
            force_content = force_resp.choices[0].message.content or ""
            parsed = extract_json_payload(force_content)
            entries_raw = parsed.get("entries", [parsed]) if isinstance(parsed, dict) else parsed

            validated_entries = []
            for idx, raw_item in enumerate(entries_raw if isinstance(entries_raw, list) else [entries_raw]):
                sanitized = sanitize_llm_entry_dict(raw_item, group, idx, self.config, retry_count=max_steps)
                validated_entries.append(ReportEntry.model_validate(sanitized))

            covered_fps = {e.fingerprint for e in validated_entries}
            for f in group.findings:
                if f["fingerprint"] not in covered_fps:
                    validated_entries.append(
                        create_fallback_error_entry(f, group, "Omitted during final synthesis", self.config, max_steps)
                    )

            return validated_entries

        except Exception as final_err:  # noqa: BLE001
            last_error_msg = str(final_err)
            logger.error("Group %s: ReAct engine failed completely: %s", group.group_id, last_error_msg)

        # Guaranteed 100% Coverage Fallback
        return [
            create_fallback_error_entry(f, group, last_error_msg, self.config, max_steps) for f in group.findings
        ]
