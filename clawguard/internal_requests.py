"""Protocol-native payloads for ClawGuard's internal model calls."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping

from .adapters import upstreams


def text_request(
    *,
    upstream_format: str,
    model: str,
    system_prompt: str,
    user_text: str,
    max_tokens: int,
    disable_thinking: bool = False,
) -> Dict[str, Any]:
    """Build a text-only request for Task Scope diagnostics or Skill Judge."""

    upstream_format = upstreams.normalize_upstream_format(upstream_format)
    if upstream_format == upstreams.OPENAI_CHAT_COMPLETION:
        payload: Dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_text},
            ],
            "stream": False,
            "n": 1,
            "max_tokens": max_tokens,
            "parallel_tool_calls": False,
        }
        if disable_thinking:
            payload["thinking"] = {"type": "disabled"}
        return payload

    if upstream_format == upstreams.OPENAI_RESPONSE:
        payload = {
            "model": model,
            "instructions": system_prompt,
            "input": user_text,
            "stream": False,
            "max_output_tokens": max_tokens,
            "parallel_tool_calls": False,
        }
        if disable_thinking:
            payload["reasoning"] = {"effort": "none"}
        return payload

    if upstream_format == upstreams.ANTHROPIC_MESSAGE:
        payload = {
            "model": model,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_text}],
            "stream": False,
            "max_tokens": max_tokens,
        }
        if disable_thinking:
            payload["thinking"] = {"type": "disabled"}
        return payload

    raise ValueError(f"unsupported upstream_format: {upstream_format}")


def tool_request(
    *,
    upstream_format: str,
    model: str,
    system_prompt: str,
    user_text: str,
    tools: List[Mapping[str, Any]],
    forced_tool_name: str,
    max_tokens: int | None = None,
    options: Mapping[str, Any] | None = None,
    disable_thinking: bool = False,
) -> Dict[str, Any]:
    """Build a protocol-native request that forces one internal tool call."""

    upstream_format = upstreams.normalize_upstream_format(upstream_format)
    selected_options = dict(options or {})
    if upstream_format == upstreams.OPENAI_CHAT_COMPLETION:
        payload: Dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_text},
            ],
            "stream": False,
            "n": 1,
            "parallel_tool_calls": False,
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": str(tool.get("name") or ""),
                        "description": tool.get("description"),
                        "parameters": tool.get("parameters") or {
                            "type": "object",
                            "properties": {},
                        },
                    },
                }
                for tool in tools
            ],
            "tool_choice": {
                "type": "function",
                "function": {"name": forced_tool_name},
            },
        }
        if disable_thinking:
            payload["thinking"] = {"type": "disabled"}
        for key in (
            "temperature",
            "top_p",
            "max_tokens",
            "max_completion_tokens",
            "reasoning_effort",
            "seed",
        ):
            if selected_options.get(key) is not None:
                payload[key] = selected_options[key]
        if max_tokens is not None and not any(
            key in payload for key in ("max_tokens", "max_completion_tokens")
        ):
            payload["max_tokens"] = max_tokens
        return payload

    if upstream_format == upstreams.OPENAI_RESPONSE:
        payload = {
            "model": model,
            "instructions": system_prompt,
            "input": user_text,
            "stream": False,
            "parallel_tool_calls": False,
            "tools": [
                {
                    "type": "function",
                    "name": str(tool.get("name") or ""),
                    "description": tool.get("description"),
                    "parameters": tool.get("parameters") or {
                        "type": "object",
                        "properties": {},
                    },
                }
                for tool in tools
            ],
            "tool_choice": {"type": "function", "name": forced_tool_name},
        }
        if max_tokens is not None:
            payload["max_output_tokens"] = max_tokens
        if selected_options.get("max_output_tokens") is not None:
            payload["max_output_tokens"] = selected_options["max_output_tokens"]
        for key in ("temperature", "top_p"):
            if selected_options.get(key) is not None:
                payload[key] = selected_options[key]
        if selected_options.get("reasoning") is not None:
            payload["reasoning"] = selected_options["reasoning"]
        if disable_thinking:
            payload["reasoning"] = {"effort": "none"}
        return payload

    if upstream_format == upstreams.ANTHROPIC_MESSAGE:
        payload = {
            "model": model,
            "max_tokens": max_tokens or 4096,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_text}],
            "stream": False,
            "tools": [
                {
                    "name": str(tool.get("name") or ""),
                    "description": tool.get("description"),
                    "input_schema": tool.get("parameters") or {
                        "type": "object",
                        "properties": {},
                    },
                }
                for tool in tools
            ],
            "tool_choice": {"type": "tool", "name": forced_tool_name},
        }
        for key in ("temperature", "top_p", "output_config"):
            if selected_options.get(key) is not None:
                payload[key] = selected_options[key]
        if selected_options.get("max_tokens") is not None:
            payload["max_tokens"] = selected_options["max_tokens"]
        if disable_thinking:
            payload["thinking"] = {"type": "disabled"}
        return payload

    raise ValueError(f"unsupported upstream_format: {upstream_format}")


def assistant_text(payload: Mapping[str, Any], upstream_format: str) -> str:
    """Extract assistant text from any configured non-streaming response."""

    upstream_format = upstreams.normalize_upstream_format(upstream_format)
    if upstream_format == upstreams.OPENAI_CHAT_COMPLETION:
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            return ""
        choice = choices[0]
        message = choice.get("message") if isinstance(choice, Mapping) else None
        content = message.get("content") if isinstance(message, Mapping) else None
        return content if isinstance(content, str) else ""

    if upstream_format == upstreams.OPENAI_RESPONSE:
        parts: List[str] = []
        for item in payload.get("output") or []:
            if not isinstance(item, Mapping) or item.get("type") != "message":
                continue
            content = item.get("content")
            if not isinstance(content, list):
                continue
            for part in content:
                if isinstance(part, Mapping) and isinstance(part.get("text"), str):
                    parts.append(part["text"])
        return "\n".join(parts)

    if upstream_format == upstreams.ANTHROPIC_MESSAGE:
        parts = []
        for part in payload.get("content") or []:
            if isinstance(part, Mapping) and part.get("type") == "text":
                text = part.get("text")
                if isinstance(text, str):
                    parts.append(text)
        return "\n".join(parts)

    return ""


def request_path(upstream_format: str) -> str:
    return upstreams.request_path(
        upstreams.normalize_upstream_format(upstream_format)
    )
