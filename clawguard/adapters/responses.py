"""Helpers for the OpenAI Responses wire protocol.

The gateway keeps Chat Completions and Responses as separate adapters.  These
helpers only translate protocol shapes into the gateway's existing internal
tool-call and conversation representations; policy decisions remain in
``gateway.py`` and ``rules.py``.
"""

from __future__ import annotations

import copy
import json
import time
import uuid
from typing import Any, Callable, Dict, List, Mapping, Optional


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts: List[str] = []
    for part in content:
        if isinstance(part, str):
            parts.append(part)
        elif isinstance(part, Mapping):
            text = part.get("text")
            if isinstance(text, str):
                parts.append(text)
    return "\n".join(parts)


def responses_input_to_messages(input_value: Any) -> List[Dict[str, Any]]:
    """Convert Responses input items into the gateway's message view.

    The returned messages are used for session detection, audit text, and task
    scope planning.  They are never forwarded upstream in place of the original
    Responses payload.
    """

    if isinstance(input_value, str):
        return [{"role": "user", "content": input_value}]
    if not isinstance(input_value, list):
        return []

    messages: List[Dict[str, Any]] = []
    for item in input_value:
        if not isinstance(item, Mapping):
            continue
        item_type = str(item.get("type") or "").strip().casefold()
        role = str(item.get("role") or "").strip().casefold()

        if item_type == "function_call_output":
            output = item.get("output")
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": str(item.get("call_id") or item.get("id") or ""),
                    "content": _content_text(output) if not isinstance(output, str) else output,
                }
            )
            continue

        if item_type == "function_call":
            name = str(item.get("name") or "").strip()
            arguments = item.get("arguments")
            messages.append(
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": str(item.get("call_id") or item.get("id") or ""),
                            "type": "function",
                            "function": {
                                "name": name,
                                "arguments": arguments if isinstance(arguments, str) else json.dumps(arguments or {}),
                            },
                        }
                    ],
                }
            )
            continue

        # Standard message items may omit ``type`` and use only ``role``.
        if role in {"system", "developer", "user", "assistant"}:
            messages.append({"role": role, "content": _content_text(item.get("content"))})

    return messages


def extract_responses_tool_calls(payload: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Extract function calls from a non-streaming Responses object."""

    calls: List[Dict[str, Any]] = []
    output = payload.get("output")
    if not isinstance(output, list):
        return calls

    for item in output:
        if not isinstance(item, Mapping):
            calls.append({"id": f"invalid-{len(calls)}", "name": "", "arguments": ""})
            continue
        item_type = str(item.get("type") or "").strip()
        if item_type == "message":
            continue
        if item_type != "function_call" and not item.get("name"):
            # Keep provider-side calls visible to the policy layer.  They have
            # no function schema and will normally fail closed as unknown.
            if item_type.endswith("_call"):
                calls.append(
                    {
                        "id": str(item.get("call_id") or item.get("id") or f"provider-{len(calls)}"),
                        "name": item_type,
                        "arguments": "",
                        "protocol": "responses",
                    }
                )
            continue

        arguments = (
            item.get("input")
            if item_type == "custom_tool_call"
            else item.get("arguments")
        )
        if isinstance(arguments, str):
            serialized_arguments = arguments
        elif arguments is None:
            serialized_arguments = ""
        else:
            serialized_arguments = json.dumps(arguments, ensure_ascii=False, separators=(",", ":"))
        calls.append(
            {
                "id": str(item.get("call_id") or item.get("id") or f"response-{len(calls)}"),
                "name": str(item.get("name") or "").strip(),
                "arguments": serialized_arguments,
                "protocol": "responses",
            }
        )
    return calls


def parse_sse_frames(body: bytes) -> List[Dict[str, Any]]:
    """Parse SSE frames while retaining the Responses event name."""

    frames: List[Dict[str, Any]] = []
    event_name = ""
    data_lines: List[str] = []

    def flush() -> None:
        nonlocal event_name, data_lines
        if not data_lines:
            event_name = ""
            return
        raw_data = "\n".join(data_lines).strip()
        data_lines = []
        if raw_data == "[DONE]":
            frames.append({"event": "done", "data": None})
        else:
            try:
                parsed = json.loads(raw_data)
            except (TypeError, ValueError):
                parsed = None
            frames.append({"event": event_name or "message", "data": parsed})
        event_name = ""

    text = body.decode("utf-8", errors="replace")
    for line in text.splitlines():
        if not line.strip():
            flush()
            continue
        if line.startswith(":"):
            continue
        if line.startswith("event:"):
            event_name = line[6:].strip()
        elif line.startswith("data:"):
            data_lines.append(line[5:].lstrip())
    flush()
    return frames


def stream_frames_to_response(
    frames: List[Mapping[str, Any]],
    model: str = "clawguard",
) -> Dict[str, Any]:
    """Convert a Responses SSE stream into one non-streaming response object."""

    for frame in reversed(frames):
        data = frame.get("data")
        if not isinstance(data, Mapping):
            continue
        response = data.get("response")
        if isinstance(response, Mapping):
            return copy.deepcopy(dict(response))
        if str(data.get("type") or frame.get("event") or "") in {
            "response.completed",
            "response.done",
        } and data.get("object") == "response":
            return copy.deepcopy(dict(data))

    # Older compatible providers may omit the final completed response. Build
    # a minimally valid response from the deltas so clients that requested a
    # non-streaming response still receive the correct wire shape.
    text_by_item: Dict[str, List[str]] = {}
    final_items: Dict[str, Dict[str, Any]] = {}
    response_id = ""
    response_model = model
    usage: Mapping[str, Any] = {}
    for frame in frames:
        data = frame.get("data")
        if not isinstance(data, Mapping):
            continue
        event_type = str(data.get("type") or frame.get("event") or "")
        response_id = str(data.get("response_id") or response_id)
        response_model = str(data.get("model") or response_model)
        item = data.get("item")
        if isinstance(item, Mapping):
            item_id = str(item.get("id") or data.get("item_id") or "")
            if item_id:
                final_items[item_id] = copy.deepcopy(dict(item))
        if event_type == "response.output_text.delta":
            item_id = str(data.get("item_id") or data.get("output_index") or "0")
            text_by_item.setdefault(item_id, []).append(str(data.get("delta") or ""))
        response = data.get("response")
        if isinstance(response, Mapping):
            response_id = str(response.get("id") or response_id)
            response_model = str(response.get("model") or response_model)
            if isinstance(response.get("usage"), Mapping):
                usage = response["usage"]

    output_items: List[Dict[str, Any]] = []
    for item_id, fragments in text_by_item.items():
        text = "".join(fragments)
        item = final_items.get(item_id, {})
        if item.get("type") == "function_call":
            continue
        output_items.append(
            {
                "id": item.get("id") or f"msg_{item_id}",
                "type": "message",
                "status": "completed",
                "role": "assistant",
                "content": [
                    {"type": "output_text", "text": text, "annotations": []}
                ],
            }
        )
    output_items.extend(
        item
        for item in final_items.values()
        if item.get("type") != "message"
    )
    return {
        "id": response_id or f"resp_clawguard_{uuid.uuid4().hex[:16]}",
        "object": "response",
        "created_at": int(time.time()),
        "status": "completed",
        "model": response_model,
        "output": output_items,
        "usage": dict(usage),
    }


def serialize_sse_frames(
    frames: List[Mapping[str, Any]],
    *,
    include_done: bool = True,
) -> bytes:
    """Serialize Responses SSE frames, preserving event names."""

    chunks: List[bytes] = []
    saw_done = False
    for frame in frames:
        event_name = str(frame.get("event") or "message")
        data = frame.get("data")
        if event_name == "done" or data is None:
            if event_name == "done":
                saw_done = True
                chunks.append(b"data: [DONE]\n\n")
            continue
        if isinstance(data, Mapping) and data.get("type"):
            event_name = str(data.get("type"))
        payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        chunks.append(f"event: {event_name}\ndata: {payload}\n\n".encode("utf-8"))
    if include_done and not saw_done:
        chunks.append(b"data: [DONE]\n\n")
    return b"".join(chunks)


def extract_responses_stream_tool_calls(
    events: List[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    """Assemble function calls from Responses streaming events."""

    calls: Dict[str, Dict[str, Any]] = {}
    aliases: Dict[str, str] = {}

    def call_for(key: str) -> Dict[str, Any]:
        return calls.setdefault(
            key,
            {"id": key, "name": "", "arguments": "", "protocol": "responses"},
        )

    def resolve(value: Any) -> str:
        key = str(value or "").strip()
        return aliases.get(key, key)

    def bind(item: Mapping[str, Any], key: str, output_index: Any = None) -> None:
        for alias in (item.get("id"), item.get("call_id")):
            alias_text = str(alias or "").strip()
            if alias_text:
                aliases[alias_text] = key
        if output_index is not None:
            aliases[f"index:{output_index}"] = key

    for event in events:
        event_type = str(event.get("type") or "").strip()
        item = event.get("item")

        if event_type in {"response.output_item.added", "response.output_item.done"} and isinstance(
            item, Mapping
        ):
            item_type = str(item.get("type") or "").strip()
            if item_type == "message":
                continue
            call_id = str(item.get("call_id") or "").strip()
            item_id = str(item.get("id") or "").strip()
            name = str(item.get("name") or "").strip()
            if item_type != "function_call" and not name:
                if not item_type.endswith("_call"):
                    continue
                name = item_type
            key = resolve(call_id) if call_id else resolve(item_id)
            if not key or key == "None":
                key = f"provider-{len(calls)}"
            bind(item, key, event.get("output_index"))
            call = call_for(key)
            call["id"] = call_id or key
            call["name"] = name or call["name"] or item_type
            arguments = (
                item.get("input")
                if item_type == "custom_tool_call"
                else item.get("arguments")
            )
            if isinstance(arguments, str) and (
                event_type == "response.output_item.done" or not call["arguments"]
            ):
                call["arguments"] = arguments
            continue

        if event_type in {
            "response.function_call_arguments.delta",
            "response.custom_tool_call_input.delta",
        }:
            delta = event.get("delta")
            if not isinstance(delta, str):
                continue
            raw_key = event.get("item_id") or event.get("call_id")
            if raw_key:
                key = aliases.get(str(raw_key), str(raw_key))
            else:
                key = aliases.get(f"index:{event.get('output_index')}", f"index:{event.get('output_index', 0)}")
            call_for(key)["arguments"] += delta
            continue

        if event_type in {
            "response.function_call_arguments.done",
            "response.custom_tool_call_input.done",
        }:
            raw_key = event.get("item_id") or event.get("call_id")
            if raw_key:
                key = aliases.get(str(raw_key), str(raw_key))
            else:
                key = aliases.get(f"index:{event.get('output_index')}", f"index:{event.get('output_index', 0)}")
            call = call_for(key)
            arguments = (
                event.get("input")
                if event_type == "response.custom_tool_call_input.done"
                else event.get("arguments")
            )
            if isinstance(arguments, str):
                call["arguments"] = arguments

    return [calls[key] for key in calls]


def sanitize_responses_stream_events(
    frames: List[Mapping[str, Any]],
    sanitizer: Any,
    sanitize_value: Callable[[Any, Any, str, Optional[str]], Any],
) -> List[Dict[str, Any]]:
    """Sanitize Responses frames and assembled text/argument streams."""

    cleaned: List[Dict[str, Any]] = []
    for frame in frames:
        current = dict(frame)
        data = current.get("data")
        if isinstance(data, Mapping):
            current["data"] = sanitize_value(dict(data), sanitizer, "output", None)
        cleaned.append(current)

    groups: Dict[tuple[str, str], List[tuple[int, str]]] = {}
    final_items: Dict[str, Dict[str, Any]] = {}
    for index, frame in enumerate(frames):
        data = frame.get("data")
        if not isinstance(data, Mapping):
            continue
        event_type = str(data.get("type") or frame.get("event") or "")
        item_id = str(data.get("item_id") or data.get("output_index") or "0")
        if event_type == "response.output_text.delta" and isinstance(data.get("delta"), str):
            groups.setdefault(("text", item_id), []).append((index, data["delta"]))
        elif event_type == "response.function_call_arguments.delta" and isinstance(
            data.get("delta"), str
        ):
            groups.setdefault(("arguments", item_id), []).append((index, data["delta"]))
        item = data.get("item")
        if isinstance(item, Mapping):
            final_items[item_id] = dict(item)
        response = data.get("response")
        if isinstance(response, Mapping):
            output = response.get("output")
            if isinstance(output, list):
                for item in output:
                    if isinstance(item, Mapping) and item.get("id"):
                        final_items[str(item["id"])] = dict(item)

    for (field, item_id), fragments in groups.items():
        combined = "".join(fragment for _, fragment in fragments)
        sanitized_combined = (
            sanitizer.sanitize_output(combined)
            if field == "text"
            else sanitizer.sanitize_output(combined)
        )
        if sanitized_combined == combined:
            continue

        for frame_index, _fragment in fragments:
            frame = cleaned[frame_index]
            data = frame.get("data")
            if isinstance(data, dict):
                data["delta"] = ""
        final_frame_index = fragments[-1][0]
        final_data = cleaned[final_frame_index].get("data")
        if isinstance(final_data, dict):
            final_data["delta"] = sanitized_combined

        final_item = final_items.get(item_id)
        if final_item is not None:
            if field == "text":
                content = final_item.get("content")
                if isinstance(content, list):
                    for part in content:
                        if isinstance(part, dict) and part.get("type") in {"output_text", "text"}:
                            part["text"] = sanitized_combined
            else:
                final_item["arguments"] = sanitized_combined

    # Update final item snapshots in all output_item.done/completed events.
    for frame in cleaned:
        data = frame.get("data")
        if not isinstance(data, dict):
            continue
        event_type = str(data.get("type") or frame.get("event") or "")
        item = data.get("item")
        if (
            event_type == "response.output_item.done"
            and isinstance(item, dict)
            and str(item.get("id") or "") in final_items
        ):
            data["item"] = final_items[str(item.get("id"))]
        response = data.get("response")
        if isinstance(response, dict) and isinstance(response.get("output"), list):
            updated_output = []
            for output_item in response["output"]:
                if isinstance(output_item, Mapping) and str(output_item.get("id") or "") in final_items:
                    updated_output.append(final_items[str(output_item.get("id"))])
                else:
                    updated_output.append(output_item)
            response["output"] = updated_output
    return cleaned


def policy_denied_response(message: str, model: str = "clawguard") -> Dict[str, Any]:
    """Return a chat-like assistant response that contains no function call."""

    response_id = f"resp_clawguard_{uuid.uuid4().hex[:16]}"
    message_id = f"msg_clawguard_{uuid.uuid4().hex[:12]}"
    return {
        "id": response_id,
        "object": "response",
        "created_at": int(time.time()),
        "status": "completed",
        "model": model,
        "output": [
            {
                "id": message_id,
                "type": "message",
                "status": "completed",
                "role": "assistant",
                "content": [
                    {
                        "type": "output_text",
                        "text": f"ClawGuard blocked: {message}",
                        "annotations": [],
                    }
                ],
            }
        ],
        "parallel_tool_calls": False,
        "tool_choice": "none",
        "tools": [],
        "clawguard": {"decision": "deny", "reason": message},
    }


def policy_denied_stream(message: str, model: str = "clawguard") -> bytes:
    """Return valid Responses SSE for a denied tool call."""

    response = policy_denied_response(message, model)
    message_item = dict(response["output"][0])
    text = message_item["content"][0]["text"]
    in_progress_item = {
        **message_item,
        "status": "in_progress",
        "content": [],
    }
    created_response = {**response, "status": "in_progress", "output": []}
    frames: List[Dict[str, Any]] = [
        {
            "event": "response.created",
            "data": {
                "type": "response.created",
                "sequence_number": 0,
                "response": created_response,
            },
        },
        {
            "event": "response.in_progress",
            "data": {
                "type": "response.in_progress",
                "sequence_number": 1,
                "response": created_response,
            },
        },
        {
            "event": "response.output_item.added",
            "data": {
                "type": "response.output_item.added",
                "sequence_number": 2,
                "output_index": 0,
                "item": in_progress_item,
            },
        },
        {
            "event": "response.output_text.delta",
            "data": {
                "type": "response.output_text.delta",
                "sequence_number": 3,
                "item_id": message_item["id"],
                "output_index": 0,
                "content_index": 0,
                "delta": text,
            },
        },
        {
            "event": "response.output_text.done",
            "data": {
                "type": "response.output_text.done",
                "sequence_number": 4,
                "item_id": message_item["id"],
                "output_index": 0,
                "content_index": 0,
                "text": text,
            },
        },
        {
            "event": "response.output_item.done",
            "data": {
                "type": "response.output_item.done",
                "sequence_number": 5,
                "output_index": 0,
                "item": message_item,
            },
        },
        {
            "event": "response.completed",
            "data": {
                "type": "response.completed",
                "sequence_number": 6,
                "response": response,
            },
        },
    ]
    return serialize_sse_frames(frames)


def nonstream_to_stream_payload(payload: Mapping[str, Any]) -> bytes:
    """Convert a completed Responses object to a minimal valid SSE stream."""

    response = dict(payload)
    frames: List[Dict[str, Any]] = [
        {
            "event": "response.created",
            "data": {
                "type": "response.created",
                "sequence_number": 0,
                "response": {**response, "status": "in_progress", "output": []},
            },
        },
    ]
    sequence = 1
    output = response.get("output")
    if isinstance(output, list):
        for output_index, raw_item in enumerate(output):
            if not isinstance(raw_item, Mapping):
                continue
            item = copy.deepcopy(dict(raw_item))
            item_id = str(
                item.get("id")
                or f"item_clawguard_{output_index}_{uuid.uuid4().hex[:8]}"
            )
            item["id"] = item_id
            added_item = copy.deepcopy(item)
            added_item["status"] = "in_progress"
            item_type = str(item.get("type") or "message")
            if item_type == "message":
                added_item["content"] = []
            elif item_type == "function_call":
                added_item["arguments"] = ""
            frames.append(
                {
                    "event": "response.output_item.added",
                    "data": {
                        "type": "response.output_item.added",
                        "sequence_number": sequence,
                        "output_index": output_index,
                        "item": added_item,
                    },
                }
            )
            sequence += 1

            if item_type == "message":
                content = item.get("content")
                if isinstance(content, list):
                    for content_index, part in enumerate(content):
                        if not isinstance(part, Mapping):
                            continue
                        part_type = str(part.get("type") or "output_text")
                        frames.append(
                            {
                                "event": "response.content_part.added",
                                "data": {
                                    "type": "response.content_part.added",
                                    "sequence_number": sequence,
                                    "item_id": item_id,
                                    "output_index": output_index,
                                    "content_index": content_index,
                                    "part": {"type": part_type, "text": ""},
                                },
                            }
                        )
                        sequence += 1
                        text = str(part.get("text") or "")
                        if text:
                            frames.append(
                                {
                                    "event": "response.output_text.delta",
                                    "data": {
                                        "type": "response.output_text.delta",
                                        "sequence_number": sequence,
                                        "item_id": item_id,
                                        "output_index": output_index,
                                        "content_index": content_index,
                                        "delta": text,
                                    },
                                }
                            )
                            sequence += 1
                        frames.append(
                            {
                                "event": "response.content_part.done",
                                "data": {
                                    "type": "response.content_part.done",
                                    "sequence_number": sequence,
                                    "item_id": item_id,
                                    "output_index": output_index,
                                    "content_index": content_index,
                                    "part": part,
                                },
                            }
                        )
                        sequence += 1
            elif item_type == "function_call":
                arguments = str(item.get("arguments") or "")
                if arguments:
                    frames.append(
                        {
                            "event": "response.function_call_arguments.delta",
                            "data": {
                                "type": "response.function_call_arguments.delta",
                                "sequence_number": sequence,
                                "item_id": item_id,
                                "output_index": output_index,
                                "delta": arguments,
                            },
                        }
                    )
                    sequence += 1
                frames.append(
                    {
                        "event": "response.function_call_arguments.done",
                        "data": {
                            "type": "response.function_call_arguments.done",
                            "sequence_number": sequence,
                            "item_id": item_id,
                            "output_index": output_index,
                            "arguments": arguments,
                        },
                    }
                )
                sequence += 1

            frames.append(
                {
                    "event": "response.output_item.done",
                    "data": {
                        "type": "response.output_item.done",
                        "sequence_number": sequence,
                        "output_index": output_index,
                        "item": item,
                    },
                }
            )
            sequence += 1

    frames.append(
        {
            "event": "response.completed",
            "data": {
                "type": "response.completed",
                "sequence_number": sequence,
                "response": response,
            },
        }
    )
    return serialize_sse_frames(frames)
