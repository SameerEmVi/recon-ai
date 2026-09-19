"""
Assessor — single structured LLM call.

Uses Anthropic tool_use with `tool_choice: {"type": "tool"}` so the model is
forced to respond with the given schema. This gives us typed, validated output
rather than free text we'd have to parse.

The model never sees raw tool output or HTTP responses — only sanitized
structured prompts built from DB records.
"""

from __future__ import annotations

import logging

import anthropic

from ai.prompts.system import SYSTEM_PROMPT

log = logging.getLogger(__name__)

DEFAULT_MODEL = "claude-sonnet-4-6"
MAX_TOKENS = 2048


class Assessor:
    def __init__(
        self,
        client: anthropic.AsyncAnthropic,
        model: str = DEFAULT_MODEL,
    ) -> None:
        self._client = client
        self._model = model

    async def call(
        self,
        user_prompt: str,
        tool: dict,
        system: str | None = None,
    ) -> dict:
        """Make one structured LLM call. Returns the tool input dict or {} on error."""
        try:
            response = await self._client.messages.create(
                model=self._model,
                max_tokens=MAX_TOKENS,
                system=system or SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
                tools=[tool],
                tool_choice={"type": "tool", "name": tool["name"]},
            )
        except anthropic.APIError as exc:
            log.error("LLM call failed: %s", exc)
            return {}

        for block in response.content:
            if block.type == "tool_use":
                return block.input  # type: ignore[return-value]

        log.warning("LLM returned no tool_use block (model=%s)", self._model)
        return {}
