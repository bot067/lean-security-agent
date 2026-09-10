"""Парсер tool_call из ответа LLM."""

import json
import re

TOOL_CALL_RE = re.compile(r"<tool_call>(.*?)</tool_call>", re.DOTALL)
JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*\n?(\{.*?\})\n?```", re.DOTALL)
BARE_JSON_RE = re.compile(r'\{"tool":\s*"run_command".*?"argv":\s*\[.*?\].*?\}', re.DOTALL)


def parse_tool_call(text: str) -> dict | None:
    """Извлекает JSON из ответа LLM. Поддерживает <tool_call>, fenced JSON, bare JSON."""
    for pattern in (TOOL_CALL_RE, JSON_BLOCK_RE, BARE_JSON_RE):
        match = pattern.search(text)
        if match:
            raw = match.group(1).strip()
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                continue
    return None