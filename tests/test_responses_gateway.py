import asyncio
import json
from types import SimpleNamespace

import httpx
import yaml

import clawguard.gateway as gateway
from clawguard.adapters.responses import (
    extract_responses_stream_tool_calls,
    extract_responses_tool_calls,
)


class FakeResponse:
    def __init__(self, payload=None, content_type="application/json"):
        self.status_code = 200
        self.headers = {"content-type": content_type}
        if content_type == "text/event-stream":
            self.content = payload
        else:
            self.content = json.dumps(payload or {}).encode("utf-8")

    def json(self):
        return json.loads(self.content.decode("utf-8"))


class FakeUpstreamClient:
    queued = []
    calls = []

    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, json=None, headers=None):
        self.__class__.calls.append({"url": url, "json": json, "headers": headers})
        return self.__class__.queued.pop(0)


def _app(
    tmp_path,
    monkeypatch,
    responses,
    *,
    enabled=True,
    upstream_format="openai_response",
    agent="openclaw",
):
    config_path = tmp_path / "config.yaml"
    rules_path = tmp_path / "rules.yaml"
    audit_path = tmp_path / "audit.db"
    config_path.write_text(
        yaml.safe_dump(
            {
                "gateway": {
                    "agent": agent,
                    "upstream_base_url": "http://upstream.test/v1",
                    "policy_mode": "strict",
                    "enable_responses_api": enabled,
                    "upstream_format": upstream_format,
                },
                "policy": {"approval_timeout": 0.05},
                "audit": {"db_path": str(audit_path)},
            }
        ),
        encoding="utf-8",
    )
    rules_path.write_text(
        yaml.safe_dump(
            {
                "command_rules": {
                    "blacklist": [
                        {
                            "pattern": r"cat\s+/etc/shadow",
                            "action": "deny",
                            "reason": "secret file",
                        }
                    ],
                    "whitelist": [{"pattern": r"^ls$", "action": "allow"}],
                    "supervised": [],
                },
                "file_rules": {"allowed_paths": [], "denied_paths": [], "sensitive_patterns": []},
                "network_rules": {
                    "allowed_domains": [],
                    "denied_domains": [],
                    "default_action": "deny",
                },
            }
        ),
        encoding="utf-8",
    )
    FakeUpstreamClient.queued = list(responses)
    FakeUpstreamClient.calls = []
    monkeypatch.setattr(
        gateway,
        "httpx",
        SimpleNamespace(AsyncClient=FakeUpstreamClient, HTTPError=httpx.HTTPError),
    )
    return gateway.create_gateway_app(str(config_path), str(rules_path))


def _post(app, payload):
    return _post_path(app, "/v1/responses", payload)


def _post_path(app, path, payload):
    async def send():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.post(path, json=payload)

    return asyncio.run(send())


def _message_response(text):
    return FakeResponse(
        {
            "id": "resp_test",
            "object": "response",
            "status": "completed",
            "model": "test-model",
            "output": [
                {
                    "id": "msg_test",
                    "type": "message",
                    "status": "completed",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": text, "annotations": []}],
                }
            ],
        }
    )


def _anthropic_message_response(text):
    return FakeResponse(
        {
            "id": "msg_upstream",
            "type": "message",
            "role": "assistant",
            "model": "deepseek-flash",
            "content": [{"type": "text", "text": text}],
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": {"input_tokens": 2, "output_tokens": 3},
        }
    )


def test_responses_endpoint_is_opt_in(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch, [], enabled=False)
    result = _post(app, {"model": "test-model", "input": "hello"})
    assert result.status_code == 501
    assert "enable_responses_api" in result.json()["error"]["message"]

    async def status():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.get("/api/status")

    assert asyncio.run(status()).json()["responses_api"] is False


def test_responses_history_is_forwarded_verbatim_without_tools(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch, [_message_response("ok")])
    payload = {
        "model": "test-model",
        "stream": False,
        "instructions": "Keep this instruction unchanged.",
        "input": [
            {
                "type": "reasoning",
                "summary": [],
                "content": [
                    {
                        "type": "reasoning_text",
                        "text": "Preserve this reasoning text.",
                    }
                ],
                "encrypted_content": "opaque-protocol-value",
            },
            {
                "type": "message",
                "role": "user",
                "content": [
                    {"type": "input_text", "text": "token=ghp_" + "A" * 36}
                ],
            },
        ],
    }

    result = _post(app, payload)

    assert result.status_code == 200
    assert FakeUpstreamClient.calls[0]["json"] == payload


def test_responses_environment_switch(monkeypatch):
    monkeypatch.setenv("CLAWGUARD_ENABLE_RESPONSES_API", "true")
    settings = gateway.GatewaySettings.from_files()
    assert settings.enable_responses_api is True


def test_all_wire_formats_feed_the_same_policy_engine():
    rules = gateway.RuleEngine(
        {
            "command_rules": {
                "blacklist": [
                    {
                        "pattern": r"cat\s+/etc/shadow",
                        "action": "deny",
                        "reason": "secret file",
                    }
                ],
                "whitelist": [],
                "supervised": [],
            },
            "file_rules": {"denied_paths": ["/etc/shadow"]},
            "network_rules": {},
        }
    )
    settings = gateway.GatewaySettings(
        upstream_format="openai_response",
        policy_mode="strict",
    )
    registry = {"exec": {"name": "exec", "parameters": {"type": "object"}}}
    chat_payload = {
        "choices": [
            {
                "message": {
                    "tool_calls": [
                        {
                            "id": "chat_call",
                            "type": "function",
                            "function": {
                                "name": "exec",
                                "arguments": '{"command":"cat /etc/shadow"}',
                            },
                        }
                    ]
                }
            }
        ]
    }
    responses_payload = {
        "object": "response",
        "output": [
            {
                "type": "function_call",
                "id": "response_item",
                "call_id": "response_call",
                "name": "exec",
                "arguments": '{"command":"cat /etc/shadow"}',
            }
        ],
    }
    anthropic_payload = {
        "type": "message",
        "content": [
            {
                "type": "tool_use",
                "id": "anthropic_call",
                "name": "exec",
                "input": {"command": "cat /etc/shadow"},
            }
        ],
    }

    matches = []
    for payload in (chat_payload, responses_payload, anthropic_payload):
        calls = gateway._extract_nonstream_tool_calls(payload)
        assert len(calls) == 1
        matches.append(
            gateway.classify_tool_call(calls[0], registry, rules, settings)
        )

    assert {match.action.value for match in matches} == {"deny"}
    assert {match.rule_type for match in matches} == {matches[0].rule_type}
    assert {match.reason for match in matches} == {matches[0].reason}


def test_native_web_fetch_fallback_still_uses_network_rules():
    registry = gateway._with_native_network_tools({"read": {"name": "read"}})
    assert "web_fetch" in registry
    assert "web_search" in registry
    assert "exec" not in registry

    rules = gateway.RuleEngine(
        {
            "command_rules": {},
            "file_rules": {},
            "network_rules": {
                "allowed_domains": ["sunjun.site"],
                "denied_domains": ["blocked.example"],
                "default_action": "deny",
            },
        }
    )
    settings = gateway.GatewaySettings(
        upstream_format="openai_chat_completion",
        policy_mode="strict",
    )
    allowed = gateway.classify_tool_call(
        {
            "id": "fetch_allowed",
            "name": "web_fetch",
            "arguments": '{"url":"https://sunjun.site"}',
        },
        registry,
        rules,
        settings,
    )
    denied = gateway.classify_tool_call(
        {
            "id": "fetch_denied",
            "name": "web_fetch",
            "arguments": '{"url":"https://blocked.example"}',
        },
        registry,
        rules,
        settings,
    )
    assert allowed.action.value == "allow"
    assert denied.action.value == "deny"


def test_openclaw_tool_bridge_uses_task_scope_and_discovery_is_allowed():
    rules = gateway.RuleEngine(
        {
            "command_rules": {},
            "file_rules": {},
            "network_rules": {
                "allowed_domains": [],
                "denied_domains": [],
                "default_action": "approve",
            },
        }
    )
    rules.set_task_scope(
        "visit sunjun",
        allowed_tools=["web_fetch"],
        network=["sunjun.site"],
    )
    settings = gateway.GatewaySettings(policy_mode="supervised")
    registry = gateway._with_native_network_tools(
        {
            "tool_search": {"name": "tool_search"},
            "tool_call": {"name": "tool_call"},
        }
    )
    fetch = gateway.classify_tool_call(
        {
            "id": "bridge_fetch",
            "name": "openclaw:core:web_fetch",
            "wrapper": "tool_call",
            "arguments": '{"url":"https://sunjun.site/publications/"}',
        },
        registry,
        rules,
        settings,
    )
    discovery = gateway.classify_tool_call(
        {
            "id": "search_tools",
            "name": "tool_search",
            "arguments": '{"query":"fetch web content"}',
        },
        registry,
        rules,
        settings,
    )
    assert fetch.action.value == "allow"
    assert fetch.rule_type == "task_scope"
    assert discovery.action.value == "allow"
    assert discovery.rule_type == "tool_discovery"


def test_upstream_format_environment_switch(monkeypatch):
    monkeypatch.setenv("CLAWGUARD_UPSTREAM_FORMAT", "anthropic_message")
    settings = gateway.GatewaySettings.from_files()
    assert settings.upstream_format == "anthropic_message"


def test_invalid_upstream_format_is_rejected(monkeypatch):
    monkeypatch.setenv("CLAWGUARD_UPSTREAM_FORMAT", "unknown")
    try:
        gateway.GatewaySettings.from_files()
    except ValueError as exc:
        assert "upstream_format" in str(exc)
    else:
        raise AssertionError("invalid upstream_format should fail validation")


def test_deepseek_planner_disables_thinking_for_forced_tool_choice():
    planner = gateway._scope_planning_payload(
        {"model": "deepseek-v4-pro", "thinking": {"type": "enabled"}},
        {"role": "user", "content": "hello"},
        {"exec": {"name": "exec"}},
        protocol="chat_completions",
        disable_thinking=True,
    )
    assert planner["thinking"] == {"type": "disabled"}
    assert gateway._is_deepseek_upstream("https://api.deepseek.com")
    assert not gateway._is_deepseek_upstream("https://example.com")

    responses_planner = gateway._scope_planning_payload(
        {"model": "deepseek-v4-pro", "reasoning": {"effort": "high"}},
        {"role": "user", "content": "hello"},
        {"exec": {"name": "exec"}},
        protocol="responses",
        disable_thinking=True,
    )
    assert responses_planner["reasoning"] == {"effort": "none"}


def test_chat_upstream_rejects_responses_client(tmp_path, monkeypatch):
    app = _app(
        tmp_path,
        monkeypatch,
        [],
        upstream_format="openai_chat_completion",
    )
    result = _post(app, {"model": "deepseek-flash", "input": "hello"})

    assert result.status_code == 400
    assert result.json()["error"]["type"] == "protocol_mismatch"
    assert FakeUpstreamClient.calls == []


def test_response_upstream_rejects_chat_client(tmp_path, monkeypatch):
    app = _app(
        tmp_path,
        monkeypatch,
        [],
        upstream_format="openai_response",
    )
    result = _post_path(
        app,
        "/v1/chat/completions",
        {
            "model": "deepseek-flash",
            "messages": [{"role": "user", "content": "hello"}],
        },
    )

    assert result.status_code == 400
    assert result.json()["error"]["type"] == "protocol_mismatch"
    assert FakeUpstreamClient.calls == []


def test_anthropic_upstream_rejects_unsupported_client_protocol(tmp_path, monkeypatch):
    app = _app(
        tmp_path,
        monkeypatch,
        [],
        upstream_format="anthropic_message",
    )
    result = _post(app, {"model": "deepseek-flash", "input": "hello"})

    assert result.status_code == 400
    assert result.json()["error"]["type"] == "protocol_mismatch"
    assert result.json()["error"]["upstream_format"] == "anthropic_message"
    assert FakeUpstreamClient.calls == []


def test_anthropic_message_round_trip(tmp_path, monkeypatch):
    app = _app(
        tmp_path,
        monkeypatch,
        [_anthropic_message_response("anthro ok")],
        upstream_format="anthropic_message",
    )
    result = _post_path(
        app,
        "/v1/messages",
        {
            "model": "deepseek-flash",
            "max_tokens": 64,
            "system": "Be concise.",
            "messages": [{"role": "user", "content": "hello"}],
        },
    )

    assert result.status_code == 200
    assert result.json()["content"][0]["text"] == "anthro ok"
    sent = FakeUpstreamClient.calls[0]
    assert sent["url"] == "http://upstream.test/v1/messages"
    assert sent["json"]["system"] == "Be concise."
    assert sent["headers"]["anthropic-version"] == "2023-06-01"


def test_anthropic_tool_use_is_denied(tmp_path, monkeypatch):
    app = _app(
        tmp_path,
        monkeypatch,
        [
            FakeResponse(
                {
                    "id": "msg_tool",
                    "type": "message",
                    "role": "assistant",
                    "model": "deepseek-flash",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_1",
                            "name": "exec",
                            "input": {"command": "cat /etc/shadow"},
                        }
                    ],
                    "stop_reason": "tool_use",
                    "stop_sequence": None,
                    "usage": {"input_tokens": 2, "output_tokens": 3},
                }
            )
        ],
        upstream_format="anthropic_message",
    )
    app.state.rules.task_scope_locked = True
    result = _post_path(
        app,
        "/v1/messages",
        {
            "model": "deepseek-flash",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "read a file"}],
            "tools": [
                {
                    "name": "exec",
                    "description": "Run a command",
                    "input_schema": {"type": "object"},
                }
            ],
        },
    )

    assert result.status_code == 200
    payload = result.json()
    assert payload["type"] == "message"
    assert payload["content"][0]["type"] == "text"
    assert "ClawGuard blocked" in payload["content"][0]["text"]
    assert payload["clawguard"]["decision"] == "deny"


def test_anthropic_auto_task_scope_uses_same_planner(tmp_path, monkeypatch):
    scope_arguments = {
        "task_description": "List files",
        "allowed_tools": ["exec"],
        "file_read": [],
        "file_write": [],
        "commands": ["ls"],
        "network": [],
        "disabled_tools": [],
    }
    planner = FakeResponse(
        {
            "id": "msg_scope",
            "type": "message",
            "role": "assistant",
            "model": "deepseek-flash",
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_scope",
                    "name": "set_task_scope",
                    "input": scope_arguments,
                }
            ],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 2, "output_tokens": 3},
        }
    )
    tool_response = FakeResponse(
        {
            "id": "msg_tool",
            "type": "message",
            "role": "assistant",
            "model": "deepseek-flash",
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_ls",
                    "name": "exec",
                    "input": {"command": "ls"},
                }
            ],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 2, "output_tokens": 3},
        }
    )
    app = _app(
        tmp_path,
        monkeypatch,
        [planner, tool_response],
        upstream_format="anthropic_message",
    )
    result = _post_path(
        app,
        "/v1/messages",
        {
            "model": "deepseek-flash",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "list files"}],
            "tools": [
                {
                    "name": "exec",
                    "description": "Run a command",
                    "input_schema": {"type": "object"},
                }
            ],
        },
    )

    assert result.status_code == 200
    assert len(FakeUpstreamClient.calls) == 2
    planner_request = FakeUpstreamClient.calls[0]["json"]
    assert planner_request["tools"][0]["name"] == "set_task_scope"
    assert planner_request["tool_choice"] == {
        "type": "tool",
        "name": "set_task_scope",
    }
    assert result.json()["content"][0]["type"] == "tool_use"


def test_anthropic_streaming_tool_use_is_denied(tmp_path, monkeypatch):
    stream = b"".join(
        [
            b'event: message_start\n',
            b'data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"model":"deepseek-flash","usage":{"input_tokens":1,"output_tokens":0}}}\n\n',
            b'event: content_block_start\n',
            b'data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"exec","input":{}}}\n\n',
            b'event: content_block_delta\n',
            b'data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\\"command\\":\\"cat /etc/shadow\\"}"}}\n\n',
            b'event: content_block_stop\n',
            b'data: {"type":"content_block_stop","index":0}\n\n',
            b'event: message_delta\n',
            b'data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":3}}\n\n',
            b'event: message_stop\n',
            b'data: {"type":"message_stop"}\n\n',
        ]
    )
    app = _app(
        tmp_path,
        monkeypatch,
        [FakeResponse(stream, "text/event-stream")],
        upstream_format="anthropic_message",
    )
    app.state.rules.task_scope_locked = True
    result = _post_path(
        app,
        "/v1/messages",
        {
            "model": "deepseek-flash",
            "stream": True,
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "read a file"}],
            "tools": [
                {
                    "name": "exec",
                    "description": "Run a command",
                    "input_schema": {"type": "object"},
                }
            ],
        },
    )

    assert result.status_code == 200
    assert "event: message_start" in result.text
    assert "ClawGuard blocked" in result.text
    assert "cat /etc/shadow" not in result.text


def test_responses_text_round_trip_preserves_input_history(tmp_path, monkeypatch):
    input_token = "ghp_" + "A" * 36
    output_token = "ghp_" + "B" * 36
    app = _app(tmp_path, monkeypatch, [_message_response(f"result={output_token}")])
    result = _post(
        app,
        {
            "model": "test-model",
            "input": [
                {
                    "type": "message",
                    "role": "user",
                    "content": f"token={input_token}",
                }
            ],
        },
    )

    assert result.status_code == 200
    assert result.json()["object"] == "response"
    assert output_token not in json.dumps(result.json())
    assert FakeUpstreamClient.calls[0]["url"] == "http://upstream.test/v1/responses"
    forwarded = json.dumps(FakeUpstreamClient.calls[0]["json"])
    assert input_token in forwarded


def test_responses_flat_tool_registry_and_previous_response_id(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch, [_message_response("ok")])
    previous_id = "123e4567-e89b-12d3-a456-426614174000"
    result = _post(
        app,
        {
            "model": "test-model",
            "previous_response_id": previous_id,
            "input": "continue",
        },
    )

    assert result.status_code == 200
    assert FakeUpstreamClient.calls[0]["json"]["previous_response_id"] == previous_id
    registry = gateway._extract_client_tool_registry(
        [
            {
                "type": "function",
                "name": "exec",
                "description": "Run a command",
                "parameters": {"type": "object"},
            },
            {
                "type": "custom",
                "name": "apply_patch",
                "description": "Apply a patch",
            },
        ],
        protocol="responses",
    )
    assert registry["exec"]["name"] == "exec"
    assert registry["apply_patch"]["type"] == "custom"


def test_responses_function_call_passes_when_base_rules_allow(tmp_path, monkeypatch):
    call = {
        "id": "item_1",
        "type": "function_call",
        "status": "completed",
        "call_id": "call_1",
        "name": "exec",
        "arguments": '{"command":"ls"}',
    }
    app = _app(
        tmp_path,
        monkeypatch,
        [
            FakeResponse(
                {
                    "id": "resp_tool",
                    "object": "response",
                    "status": "completed",
                    "model": "test-model",
                    "output": [call],
                }
            )
        ],
    )
    app.state.rules.task_scope_locked = True
    result = _post(
        app,
        {
            "model": "test-model",
            "input": "list files",
            "tools": [
                {
                    "type": "function",
                    "name": "exec",
                    "description": "Run a command",
                    "parameters": {"type": "object"},
                }
            ],
        },
    )

    assert result.status_code == 200
    output = result.json()["output"]
    assert output[0]["type"] == "function_call"
    assert output[0]["call_id"] == "call_1"


def test_codex_native_tool_calls_appear_in_native_audit(tmp_path, monkeypatch):
    call = {
        "id": "item_codex",
        "type": "function_call",
        "status": "completed",
        "call_id": "call_codex",
        "name": "exec_command",
        "arguments": '{"command":"ls"}',
    }
    app = _app(
        tmp_path,
        monkeypatch,
        [
            FakeResponse(
                {
                    "id": "resp_codex",
                    "object": "response",
                    "status": "completed",
                    "model": "test-model",
                    "output": [call],
                }
            )
        ],
        agent="codex",
    )
    app.state.rules.task_scope_locked = True
    result = _post(
        app,
        {
            "model": "test-model",
            "input": "list files",
            "tools": [
                {
                    "type": "function",
                    "name": "exec_command",
                    "description": "Run a command",
                    "parameters": {"type": "object"},
                }
            ],
        },
    )
    assert result.status_code == 200

    async def read_audit():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            status = await client.get("/status")
            logs = await client.get(
                "/audit/logs?limit=100&action=model_tool_call&native_only=true"
            )
        return status, logs

    status, logs = asyncio.run(read_audit())
    assert status.json()["native_tool_audit"]["total_operations"] == 1
    native_logs = logs.json()["logs"]
    assert [log["operation"] for log in native_logs] == ["exec_command"]
    details = json.loads(native_logs[0]["details"])
    assert details["native_tool"] is True
    assert details["tool_kind"] == "native"
    assert details["registered"] is True
    assert details["display_operation"] == "exec_command → ls"
    assert details["command_names"] == ["ls"]


def test_responses_stream_call_id_and_item_id_are_one_call():
    calls = extract_responses_stream_tool_calls(
        [
            {
                "type": "response.output_item.added",
                "output_index": 0,
                "item": {
                    "id": "item_1",
                    "type": "function_call",
                    "call_id": "call_1",
                    "name": "exec",
                    "arguments": "",
                },
            },
            {
                "type": "response.function_call_arguments.delta",
                "item_id": "item_1",
                "output_index": 0,
                "delta": '{"command":"ls"}',
            },
            {
                "type": "response.output_item.done",
                "output_index": 0,
                "item": {
                    "id": "item_1",
                    "type": "function_call",
                    "call_id": "call_1",
                    "name": "exec",
                    "arguments": '{"command":"ls"}',
                },
            },
        ]
    )
    assert len(calls) == 1
    assert calls[0]["id"] == "call_1"
    assert calls[0]["name"] == "exec"
    assert calls[0]["arguments"] == '{"command":"ls"}'


def test_responses_custom_tool_call_preserves_freeform_input():
    patch = "*** Begin Patch\n*** Add File: output/example.txt\n+ok\n*** End Patch\n"
    calls = extract_responses_tool_calls(
        {
            "object": "response",
            "output": [
                {
                    "type": "custom_tool_call",
                    "id": "item_patch",
                    "call_id": "call_patch",
                    "name": "apply_patch",
                    "input": patch,
                }
            ],
        }
    )
    streamed = extract_responses_stream_tool_calls(
        [
            {
                "type": "response.output_item.added",
                "output_index": 0,
                "item": {
                    "id": "item_patch",
                    "type": "custom_tool_call",
                    "call_id": "call_patch",
                    "name": "apply_patch",
                    "input": "",
                },
            },
            {
                "type": "response.custom_tool_call_input.delta",
                "item_id": "item_patch",
                "output_index": 0,
                "delta": patch,
            },
            {
                "type": "response.output_item.done",
                "output_index": 0,
                "item": {
                    "id": "item_patch",
                    "type": "custom_tool_call",
                    "call_id": "call_patch",
                    "name": "apply_patch",
                    "input": patch,
                },
            },
        ]
    )

    assert calls[0]["name"] == "apply_patch"
    assert calls[0]["arguments"] == patch
    assert streamed[0]["name"] == "apply_patch"
    assert streamed[0]["arguments"] == patch


def test_codex_custom_apply_patch_path_is_discovered_for_scope_checks():
    from clawguard.adapters import agent_adapters

    rules = gateway.RuleEngine()
    rules.set_task_scope(
        "Create one output file",
        allowed_tools=["apply_patch"],
        file_write=["clawguard-utility-fixtures/output/example.txt"],
    )
    registry = agent_adapters.canonicalize_tool_registry(
        "codex",
        {"apply_patch": {"type": "custom", "name": "apply_patch"}},
    )
    patch = (
        "*** Begin Patch\n"
        "*** Add File: clawguard-utility-fixtures/output/example.txt\n"
        "+ok\n"
        "*** End Patch\n"
    )
    match = gateway.classify_tool_call(
        {
            "id": "call_patch",
            "name": "apply_patch",
            "arguments": patch,
        },
        registry,
        rules,
        gateway.GatewaySettings(
            agent="codex",
            upstream_format="openai_response",
        ),
    )

    assert match.action.value == "allow"
    assert match.rule_type == "task_scope"


def test_responses_tool_call_bridge_is_unwrapped():
    calls = gateway._extract_nonstream_tool_calls(
        {
            "object": "response",
            "output": [
                {
                    "type": "function_call",
                    "id": "item_1",
                    "call_id": "call_1",
                    "name": "tool_call",
                    "arguments": json.dumps(
                        {
                            "id": "openclaw:core:web_fetch",
                            "args": {"url": "https://sunjun.site/publications/"},
                        }
                    ),
                }
            ],
        }
    )
    assert len(calls) == 1
    assert calls[0]["wrapper"] == "tool_call"
    assert calls[0]["name"] == "openclaw:core:web_fetch"
    assert json.loads(calls[0]["arguments"])["url"] == "https://sunjun.site/publications/"


def test_responses_auto_task_scope_uses_responses_planner(tmp_path, monkeypatch):
    scope_arguments = {
        "task_description": "List files",
        "allowed_tools": ["exec"],
        "file_read": [],
        "file_write": [],
        "commands": ["ls"],
        "network": [],
        "disabled_tools": [],
    }
    planner = FakeResponse(
        {
            "id": "resp_scope",
            "object": "response",
            "status": "completed",
            "model": "test-model",
            "output": [
                {
                    "id": "item_scope",
                    "type": "function_call",
                    "call_id": "call_scope",
                    "name": "set_task_scope",
                    "arguments": json.dumps(scope_arguments),
                }
            ],
        }
    )
    tool_response = FakeResponse(
        {
            "id": "resp_tool",
            "object": "response",
            "status": "completed",
            "model": "test-model",
            "output": [
                {
                    "id": "item_tool",
                    "type": "function_call",
                    "call_id": "call_ls",
                    "name": "exec",
                    "arguments": '{"command":"ls"}',
                }
            ],
        }
    )
    app = _app(tmp_path, monkeypatch, [planner, tool_response])
    result = _post(
        app,
        {
            "model": "test-model",
            "input": "list files",
            "tools": [
                {
                    "type": "function",
                    "name": "exec",
                    "description": "Run a command",
                    "parameters": {"type": "object"},
                }
            ],
        },
    )

    assert result.status_code == 200
    assert len(FakeUpstreamClient.calls) == 2
    planner_request = FakeUpstreamClient.calls[0]["json"]
    assert "input" in planner_request
    assert planner_request["tools"][0]["name"] == "set_task_scope"
    assert result.json()["output"][0]["type"] == "function_call"


def test_responses_function_call_is_replaced_when_denied(tmp_path, monkeypatch):
    app = _app(
        tmp_path,
        monkeypatch,
        [
            FakeResponse(
                {
                    "id": "resp_tool",
                    "object": "response",
                    "status": "completed",
                    "model": "test-model",
                    "output": [
                        {
                            "id": "item_1",
                            "type": "function_call",
                            "call_id": "call_1",
                            "name": "exec",
                            "arguments": '{"command":"cat /etc/shadow"}',
                        }
                    ],
                }
            )
        ],
    )
    app.state.rules.task_scope_locked = True
    result = _post(
        app,
        {
            "model": "test-model",
            "input": "read a file",
            "tools": [
                {
                    "type": "function",
                    "name": "exec",
                    "description": "Run a command",
                    "parameters": {"type": "object"},
                }
            ],
        },
    )

    assert result.status_code == 200
    payload = result.json()
    assert not any(item.get("type") == "function_call" for item in payload["output"])
    assert "ClawGuard blocked" in json.dumps(payload)
    assert payload["clawguard"]["decision"] == "deny"


def test_responses_streaming_function_call_is_blocked(tmp_path, monkeypatch):
    stream = b"".join(
        [
            b'event: response.output_item.added\n',
            b'data: {"type":"response.output_item.added","output_index":0,"item":{"id":"item_1","type":"function_call","call_id":"call_1","name":"exec","arguments":""}}\n\n',
            b'event: response.function_call_arguments.delta\n',
            b'data: {"type":"response.function_call_arguments.delta","item_id":"item_1","output_index":0,"delta":"{\\"command\\":\\"cat /etc/shadow\\"}"}\n\n',
            b'event: response.output_item.done\n',
            b'data: {"type":"response.output_item.done","output_index":0,"item":{"id":"item_1","type":"function_call","call_id":"call_1","name":"exec","arguments":"{\\"command\\":\\"cat /etc/shadow\\"}"}}\n\n',
            b"data: [DONE]\n\n",
        ]
    )
    app = _app(tmp_path, monkeypatch, [FakeResponse(stream, "text/event-stream")])
    app.state.rules.task_scope_locked = True
    result = _post(
        app,
        {
            "model": "test-model",
            "stream": True,
            "input": "read a file",
            "tools": [
                {
                    "type": "function",
                    "name": "exec",
                    "description": "Run a command",
                    "parameters": {"type": "object"},
                }
            ],
        },
    )

    assert result.status_code == 200
    assert result.headers["content-type"].startswith("text/event-stream")
    assert "event: response.completed" in result.text
    assert "ClawGuard blocked" in result.text
    assert "cat /etc/shadow" not in result.text


def test_responses_stream_text_is_sanitized(tmp_path, monkeypatch):
    token = "ghp_" + "B" * 36
    stream = b"".join(
        [
            b'event: response.created\n',
            b'data: {"type":"response.created","response":{"id":"resp_stream","object":"response","status":"in_progress","output":[]}}\n\n',
            b'event: response.output_text.delta\n',
            (
                'data: '
                + json.dumps(
                    {
                        "type": "response.output_text.delta",
                        "item_id": "msg_1",
                        "output_index": 0,
                        "content_index": 0,
                        "delta": token[:12],
                    }
                )
                + "\n\n"
            ).encode("utf-8"),
            b'event: response.output_text.delta\n',
            (
                'data: '
                + json.dumps(
                    {
                        "type": "response.output_text.delta",
                        "item_id": "msg_1",
                        "output_index": 0,
                        "content_index": 0,
                        "delta": token[12:],
                    }
                )
                + "\n\n"
            ).encode("utf-8"),
            b'event: response.completed\n',
            (
                'data: '
                + json.dumps(
                    {
                        "type": "response.completed",
                        "response": {
                            "id": "resp_stream",
                            "object": "response",
                            "status": "completed",
                            "output": [
                                {
                                    "id": "msg_1",
                                    "type": "message",
                                    "role": "assistant",
                                    "content": [{"type": "output_text", "text": token}],
                                }
                            ],
                        },
                    }
                )
                + "\n\n"
            ).encode("utf-8"),
            b"data: [DONE]\n\n",
        ]
    )
    app = _app(tmp_path, monkeypatch, [FakeResponse(stream, "text/event-stream")])
    result = _post(app, {"model": "test-model", "stream": True, "input": "hello"})

    assert result.status_code == 200
    assert token not in result.text
    assert "REDACTED" in result.text
