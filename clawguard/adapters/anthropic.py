"""Anthropic Messages protocol helpers used for direct passthrough."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any, Callable, Dict, List, Mapping, Optional

from . import responses as responses_protocol


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts: List[str] = []
    for block in content:
        if isinstance(block, str):
            parts.append(block)
        elif isinstance(block, Mapping):
            if isinstance(block.get("text"), str):
                parts.append(block["text"])
            elif block.get("type") == "tool_result":
                parts.append(_text(block.get("content")))
    return "\n".join(parts)


def request_messages(payload: Mapping[str, Any]) -> List[Dict[str, Any]]:
    messages: List[Dict[str, Any]] = []
    system = payload.get("system")
    if isinstance(system, str) and system:
        messages.append({"role": "system", "content": system})
    elif isinstance(system, list):
        system_text = _text(system)
        if system_text:
            messages.append({"role": "system", "content": system_text})

    for message in payload.get("messages") or []:
        if not isinstance(message, Mapping):
            continue
        role = str(message.get("role") or "user")
        content = message.get("content")
        if isinstance(content, str):
            messages.append({"role": role, "content": content})
            continue
        if not isinstance(content, list):
            continue

        visible_text: List[str] = []
        tool_calls: List[Dict[str, Any]] = []
        for block in content:
            if not isinstance(block, Mapping):
                continue
            block_type = str(block.get("type") or "")
            if block_type in {"text", "thinking"}:
                text = block.get("text")
                if isinstance(text, str):
                    visible_text.append(text)
            elif block_type in {"tool_use", "server_tool_use"}:
                tool_calls.append(
                    {
                        "id": str(block.get("id") or ""),
                        "type": "function",
                        "function": {
                            "name": str(block.get("name") or ""),
                            "arguments": json.dumps(
                                block.get("input") or {},
                                ensure_ascii=False,
                                separators=(",", ":"),
                            ),
                        },
                    }
                )
            elif block_type == "tool_result":
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": str(block.get("tool_use_id") or ""),
                        "content": _text(block.get("content")),
                    }
                )
        if visible_text or tool_calls:
            entry: Dict[str, Any] = {
                "role": role,
                "content": "\n".join(visible_text) or None,
            }
            if tool_calls:
                entry["tool_calls"] = tool_calls
            messages.append(entry)
    return messages


def extract_tool_calls(payload: Mapping[str, Any]) -> List[Dict[str, Any]]:
    calls: List[Dict[str, Any]] = []
    content = payload.get("content")
    if not isinstance(content, list):
        return calls
    for block in content:
        if not isinstance(block, Mapping):
            continue
        if block.get("type") not in {"tool_use", "server_tool_use"}:
            continue
        calls.append(
            {
                "id": str(block.get("id") or f"anthropic-{len(calls)}"),
                "name": str(block.get("name") or ""),
                "arguments": json.dumps(
                    block.get("input") or {},
                    ensure_ascii=False,
                    separators=(",", ":"),
                ),
                "protocol": "anthropic_messages",
            }
        )
    return calls


def extract_stream_tool_calls(
    events: List[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    calls: Dict[str, Dict[str, Any]] = {}
    aliases: Dict[str, str] = {}
    for event in events:
        event_type = str(event.get("type") or "")
        index = str(event.get("index", 0))
        if event_type == "content_block_start":
            block = event.get("content_block")
            if not isinstance(block, Mapping):
                continue
            if block.get("type") not in {"tool_use", "server_tool_use"}:
                continue
            call_id = str(block.get("id") or f"anthropic-{index}")
            aliases[index] = call_id
            calls[call_id] = {
                "id": call_id,
                "name": str(block.get("name") or ""),
                "arguments": "",
                "protocol": "anthropic_messages",
            }
        elif event_type == "content_block_delta":
            delta = event.get("delta")
            if not isinstance(delta, Mapping) or delta.get("type") != "input_json_delta":
                continue
            call_id = aliases.get(index)
            if not call_id:
                continue
            calls[call_id]["arguments"] += str(delta.get("partial_json") or "")
        elif event_type == "content_block_stop":
            call_id = aliases.get(index)
            if call_id and not calls[call_id]["arguments"]:
                calls[call_id]["arguments"] = "{}"
    return list(calls.values())


def sanitize_stream_events(
    frames: List[Mapping[str, Any]],
    sanitizer: Any,
    sanitize_value: Callable[[Any, Any, str, Optional[str]], Any],
) -> List[Dict[str, Any]]:
    cleaned: List[Dict[str, Any]] = []
    for frame in frames:
        current = dict(frame)
        data = current.get("data")
        if isinstance(data, Mapping):
            current["data"] = sanitize_value(dict(data), sanitizer, "output", None)
        cleaned.append(current)

    text_groups: Dict[str, List[tuple[int, str]]] = {}
    json_groups: Dict[str, List[tuple[int, str]]] = {}
    for frame_index, frame in enumerate(frames):
        data = frame.get("data")
        if not isinstance(data, Mapping):
            continue
        index = str(data.get("index", 0))
        delta = data.get("delta")
        if not isinstance(delta, Mapping):
            continue
        if delta.get("type") == "text_delta" and isinstance(delta.get("text"), str):
            text_groups.setdefault(index, []).append((frame_index, delta["text"]))
        elif delta.get("type") == "input_json_delta" and isinstance(
            delta.get("partial_json"), str
        ):
            json_groups.setdefault(index, []).append(
                (frame_index, delta["partial_json"])
            )

    for field, groups, value_key in (
        ("text", text_groups, "text"),
        ("json", json_groups, "partial_json"),
    ):
        for fragments in groups.values():
            combined = "".join(value for _, value in fragments)
            sanitized = sanitizer.sanitize_output(combined)
            for frame_index, _value in fragments:
                data = cleaned[frame_index].get("data")
                delta = data.get("delta") if isinstance(data, dict) else None
                if isinstance(delta, dict):
                    delta[value_key] = ""
            last_data = cleaned[fragments[-1][0]].get("data")
            last_delta = last_data.get("delta") if isinstance(last_data, dict) else None
            if isinstance(last_delta, dict):
                last_delta[value_key] = sanitized
    return cleaned


def policy_denied_response(message: str, model: str = "clawguard") -> Dict[str, Any]:
    return {
        "id": f"msg_clawguard_{uuid.uuid4().hex[:16]}",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": [{"type": "text", "text": f"ClawGuard blocked: {message}"}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 0, "output_tokens": 0},
        "clawguard": {"decision": "deny", "reason": message},
    }


def policy_denied_stream(message: str, model: str = "clawguard") -> bytes:
    prompt_text = f"ClawGuard blocked: {message}"
    message_id = f"msg_clawguard_{uuid.uuid4().hex[:16]}"
    frames: List[Dict[str, Any]] = [
        {
            "event": "message_start",
            "data": {
                "type": "message_start",
                "message": {
                    "id": message_id,
                    "type": "message",
                    "role": "assistant",
                    "model": model,
                    "content": [],
                    "stop_reason": None,
                    "stop_sequence": None,
                    "usage": {"input_tokens": 0, "output_tokens": 0},
                },
            },
        },
        {
            "event": "content_block_start",
            "data": {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
        },
        {
            "event": "content_block_delta",
            "data": {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": prompt_text},
            },
        },
        {
            "event": "content_block_stop",
            "data": {"type": "content_block_stop", "index": 0},
        },
        {
            "event": "message_delta",
            "data": {
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                "usage": {"output_tokens": 0},
            },
        },
        {"event": "message_stop", "data": {"type": "message_stop"}},
    ]
    return responses_protocol.serialize_sse_frames(frames, include_done=False)


def starts_stream_event(event: Mapping[str, Any]) -> bool:
    event_type = str(event.get("type") or "")
    return event_type in {
        "message_start",
        "content_block_start",
        "content_block_delta",
        "content_block_stop",
        "message_delta",
        "message_stop",
        "ping",
    }
