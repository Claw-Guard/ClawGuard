from clawguard import responses
from clawguard.sanitizer import Sanitizer
from clawguard.gateway import _sanitize_json_value


def test_responses_stream_converts_to_nonstream_response():
    frames = [
        {
            "event": "response.output_text.delta",
            "data": {
                "type": "response.output_text.delta",
                "item_id": "msg_1",
                "delta": "AgentWorm",
            },
        },
        {
            "event": "response.completed",
            "data": {
                "type": "response.completed",
                "response": {
                    "id": "resp_1",
                    "object": "response",
                    "status": "completed",
                    "model": "deepseek-v4-pro",
                    "output": [
                        {
                            "id": "msg_1",
                            "type": "message",
                            "role": "assistant",
                            "content": [
                                {
                                    "type": "output_text",
                                    "text": "AgentWorm",
                                    "annotations": [],
                                }
                            ],
                        }
                    ],
                },
            },
        },
    ]

    converted = responses.stream_frames_to_response(
        frames,
        "deepseek-v4-pro",
    )

    assert converted["object"] == "response"
    assert converted["id"] == "resp_1"
    assert converted["output"][0]["content"][0]["text"] == "AgentWorm"


def test_responses_stream_delta_order_is_preserved_without_redaction():
    frames = [
        {
            "event": "response.output_item.added",
            "data": {
                "type": "response.output_item.added",
                "output_index": 0,
                "item": {"id": "msg_1", "type": "message"},
            },
        },
        {
            "event": "response.output_text.delta",
            "data": {
                "type": "response.output_text.delta",
                "item_id": "msg_1",
                "output_index": 0,
                "delta": "Agent",
            },
        },
        {
            "event": "response.output_text.delta",
            "data": {
                "type": "response.output_text.delta",
                "item_id": "msg_1",
                "output_index": 0,
                "delta": "Worm",
            },
        },
        {
            "event": "response.output_item.done",
            "data": {
                "type": "response.output_item.done",
                "item": {
                    "id": "msg_1",
                    "type": "message",
                    "status": "completed",
                    "content": [
                        {
                            "type": "output_text",
                            "text": "AgentWorm",
                            "annotations": [],
                        }
                    ],
                },
            },
        },
    ]

    sanitized = responses.sanitize_responses_stream_events(
        frames,
        Sanitizer(),
        _sanitize_json_value,
    )

    assert sanitized == frames


def test_nonstream_response_to_sse_has_item_lifecycle():
    payload = {
        "id": "resp_1",
        "object": "response",
        "status": "completed",
        "model": "deepseek-v4-pro",
        "output": [
            {
                "id": "call_1",
                "type": "function_call",
                "status": "completed",
                "call_id": "call_1",
                "name": "exec_command",
                "arguments": '{"cmd":"curl -s https://sunjun.site"}',
            }
        ],
    }

    frames = responses.parse_sse_frames(
        responses.nonstream_to_stream_payload(payload)
    )
    event_types = [
        frame["data"]["type"]
        for frame in frames
        if isinstance(frame.get("data"), dict)
    ]

    added = event_types.index("response.output_item.added")
    delta = event_types.index("response.function_call_arguments.delta")
    done = event_types.index("response.output_item.done")
    assert added < delta < done
