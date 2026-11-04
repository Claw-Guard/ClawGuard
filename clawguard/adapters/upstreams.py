"""Upstream wire-format selection without payload conversion."""

from __future__ import annotations

from typing import Any, Dict, Mapping


OPENAI_RESPONSE = "openai_response"
OPENAI_CHAT_COMPLETION = "openai_chat_completion"
ANTHROPIC_MESSAGE = "anthropic_message"
SUPPORTED_FORMATS = {
    OPENAI_RESPONSE,
    OPENAI_CHAT_COMPLETION,
    ANTHROPIC_MESSAGE,
}


def normalize_upstream_format(value: Any) -> str:
    normalized = str(value or OPENAI_CHAT_COMPLETION).strip().lower()
    if normalized not in SUPPORTED_FORMATS:
        choices = ", ".join(sorted(SUPPORTED_FORMATS))
        raise ValueError(f"upstream_format must be one of: {choices}")
    return normalized


def request_path(upstream_format: str) -> str:
    if upstream_format == OPENAI_RESPONSE:
        return "/v1/responses"
    if upstream_format == ANTHROPIC_MESSAGE:
        return "/v1/messages"
    return "/v1/chat/completions"


def matches_client_protocol(upstream_format: str, client_protocol: str) -> bool:
    """Return whether the inbound endpoint matches the configured upstream."""

    expected = {
        OPENAI_RESPONSE: "responses",
        OPENAI_CHAT_COMPLETION: "chat_completions",
        ANTHROPIC_MESSAGE: "anthropic_messages",
    }
    return expected.get(upstream_format) == client_protocol


def format_for_client_protocol(client_protocol: str) -> str:
    return {
        "responses": OPENAI_RESPONSE,
        "chat_completions": OPENAI_CHAT_COMPLETION,
        "anthropic_messages": ANTHROPIC_MESSAGE,
    }.get(client_protocol, OPENAI_CHAT_COMPLETION)


def protocol_label(value: str) -> str:
    return {
        OPENAI_RESPONSE: "OpenAI Responses",
        OPENAI_CHAT_COMPLETION: "OpenAI Chat Completions",
        ANTHROPIC_MESSAGE: "Anthropic Messages",
        "responses": "OpenAI Responses",
        "chat_completions": "OpenAI Chat Completions",
        "anthropic_messages": "Anthropic Messages",
    }.get(value, value)


def anthropic_headers(headers: Mapping[str, str]) -> Dict[str, str]:
    """Return Anthropic-compatible authentication headers."""

    result = {str(key): str(value) for key, value in headers.items()}
    result.pop("Authorization", None)
    auth = headers.get("Authorization") or headers.get("authorization")
    if isinstance(auth, str) and auth.casefold().startswith("bearer "):
        result["x-api-key"] = auth[7:].strip()
    result.setdefault("anthropic-version", "2023-06-01")
    result["Content-Type"] = "application/json"
    return result
