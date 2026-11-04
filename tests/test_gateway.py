import asyncio
import json
import os
from types import SimpleNamespace

import httpx
import pytest
import yaml

import clawguard.gateway as gateway
from clawguard.gateway import (
    _extract_client_tool_registry,
    _extract_nonstream_tool_calls,
    _extract_stream_tool_calls,
    create_gateway_app,
    is_native_openclaw_tool,
    is_special_model_tool,
)


class FakeResponse:
    def __init__(self, payload=None, content_type="application/json", status_code=200):
        self.status_code = status_code
        self.headers = {"content-type": content_type}
        if content_type == "text/event-stream" or isinstance(payload, (bytes, str)):
            self.content = payload
            if isinstance(self.content, str):
                self.content = self.content.encode("utf-8")
        else:
            self.content = json.dumps(payload or {}).encode("utf-8")

    def json(self):
        return json.loads(self.content.decode("utf-8"))


class FakeUpstreamClient:
    response = None
    responses = []
    calls = []

    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs
        self.closed = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        self.closed = True
        return False

    async def post(self, url, json=None, headers=None):
        if self.closed:
            raise RuntimeError("Cannot send a request, as the client has been closed.")
        self.__class__.calls.append({"url": url, "json": json, "headers": headers})
        if self.__class__.responses:
            return self.__class__.responses.pop(0)
        return self.__class__.response

    async def get(self, url, headers=None):
        return FakeResponse({"object": "list", "data": []})


def _app(
    tmp_path,
    monkeypatch,
    response,
    *,
    allowed_paths=None,
    denied_paths=None,
    allowed_domains=None,
    denied_domains=None,
    network_default_action="deny",
    policy_mode="strict",
):
    config_path = tmp_path / "config.yaml"
    rules_path = tmp_path / "rules.yaml"
    audit_path = tmp_path / "audit.db"
    config_path.write_text(
        yaml.safe_dump(
            {
                "gateway": {
                    "upstream_base_url": "http://upstream.test/v1",
                    "policy_mode": policy_mode,
                    "unknown_tool_action": "deny",
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
                        {"pattern": r"cat\s+/etc/shadow", "action": "deny", "reason": "secret file"}
                    ],
                    "whitelist": [{"pattern": r"^ls$", "action": "allow"}],
                    "supervised": [],
                },
                "file_rules": {
                    "allowed_paths": list(allowed_paths or []),
                    "denied_paths": list(denied_paths or ["/etc/shadow"]),
                    "sensitive_patterns": [],
                },
                "network_rules": {
                    "allowed_domains": ["api.openai.com"] + list(allowed_domains or []),
                    "denied_domains": list(denied_domains or []),
                    "default_action": network_default_action,
                },
            }
        ),
        encoding="utf-8",
    )
    if isinstance(response, list):
        FakeUpstreamClient.responses = list(response)
        FakeUpstreamClient.response = response[-1] if response else None
    else:
        FakeUpstreamClient.responses = []
        FakeUpstreamClient.response = response
    FakeUpstreamClient.calls = []
    monkeypatch.setattr(
        gateway,
        "httpx",
        SimpleNamespace(AsyncClient=FakeUpstreamClient, HTTPError=httpx.HTTPError),
    )
    return create_gateway_app(str(config_path), str(rules_path))


async def _post(app, payload, headers=None):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post("/v1/chat/completions", json=payload, headers=headers or {})


def _scope_response(
    allowed_tools,
    *,
    file_read=None,
    file_write=None,
    commands=None,
    network=None,
    disabled_tools=None,
    task_description="test scope",
):
    arguments = {
        "task_description": task_description,
        "allowed_tools": allowed_tools,
        "file_read": file_read or [],
        "file_write": file_write or [],
        "commands": commands or [],
        "network": network or [],
        "disabled_tools": disabled_tools or [],
    }
    return FakeResponse(
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "cg_scope_1",
                                "type": "function",
                                "function": {
                                    "name": "set_task_scope",
                                    "arguments": json.dumps(arguments),
                                },
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ]
        }
    )


def _tool_call_response(
    name,
    arguments,
    *,
    tool_call_id="model_call_1",
    content=None,
):
    return FakeResponse(
        {
            "id": "chatcmpl-model",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": content,
                        "tool_calls": [
                            {
                                "id": tool_call_id,
                                "type": "function",
                                "function": {
                                    "name": name,
                                    "arguments": arguments,
                                },
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
        }
    )


def _text_response(content="Recovered with an allowed alternative."):
    return FakeResponse(
        {
            "id": "chatcmpl-model",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }
            ],
        }
    )


def test_openai_tool_shapes_are_parsed():
    registry = _extract_client_tool_registry(
        [{"type": "function", "function": {"name": "exec", "parameters": {}}}],
        [{"name": "legacy_read", "parameters": {}}],
    )
    assert set(registry) == {"exec", "legacy_read"}

    calls = _extract_nonstream_tool_calls(
        {"choices": [{"message": {"function_call": {"name": "exec", "arguments": "{}"}}}]}
    )
    assert calls[0].name == "exec"

    events = [
        {"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "call_1", "function": {"name": "exec"}}]}}]},
        {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": '{"command":"ls"}'}}]}}]},
    ]
    assert _extract_stream_tool_calls(events)[0].arguments == '{"command":"ls"}'

    unsupported = _extract_nonstream_tool_calls(
        {"choices": [{"message": {"tool_calls": [{"id": "x", "type": "computer_call"}]}}]}
    )
    assert unsupported[0].name == "computer_call"


def test_gateway_does_not_expose_legacy_tool_execution_route(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch, FakeResponse({"choices": []}))
    assert not any(getattr(route, "path", None) == "/api/tool/call" for route in app.routes)


def test_apply_patch_requires_and_checks_file_targets(tmp_path):
    from clawguard.gateway import classify_tool_call, GatewaySettings
    from clawguard.rules import RuleEngine

    target = str(tmp_path / "secret.txt")
    rules = RuleEngine({"file_rules": {"denied_paths": [target]}})
    registry = {"apply_patch": {"name": "apply_patch"}}
    match = classify_tool_call(
        {
            "name": "apply_patch",
            "arguments": json.dumps({"patch": f"*** Update File: {target}\\n@@\\n"}),
        },
        registry,
        rules,
        GatewaySettings(policy_mode="strict"),
    )
    assert match.action.value == "deny"


def test_stream_sanitizer_handles_split_secret():
    from clawguard.gateway import _sanitize_stream_events
    from clawguard.sanitizer import Sanitizer

    token = "ghp_" + "A" * 36
    events = [
        {"choices": [{"delta": {"content": token[:12]}}]},
        {"choices": [{"delta": {"content": token[12:]}}]},
    ]
    sanitized = _sanitize_stream_events(events, Sanitizer())
    assert token not in json.dumps(sanitized)
    assert "REDACTED" in json.dumps(sanitized)

    legacy = [
        {"choices": [{"delta": {"function_call": {"arguments": token[:10]}}}]},
        {"choices": [{"delta": {"function_call": {"arguments": token[10:]}}}]},
    ]
    legacy_sanitized = _sanitize_stream_events(legacy, Sanitizer())
    assert token not in json.dumps(legacy_sanitized)


def test_tool_result_content_is_sanitized():
    from clawguard.gateway import _sanitize_json_value
    from clawguard.sanitizer import Sanitizer

    token = "ghp_" + "B" * 36
    payload = {"messages": [{"role": "tool", "tool_call_id": "call_1", "content": token}]}
    sanitized = _sanitize_json_value(payload, Sanitizer(), "input")
    assert sanitized["messages"][0]["tool_call_id"] == "call_1"
    assert token not in json.dumps(sanitized)


def test_task_scope_aliases_apply_to_native_tool_names():
    from clawguard.rules import RuleEngine

    rules = RuleEngine()
    rules.set_task_scope("read only", file_read=["README.md"])
    assert rules.is_tool_disabled("exec")
    assert rules.is_tool_disabled("web_fetch")
    assert not rules.is_tool_disabled("read")


def test_registered_opaque_tool_is_not_silently_allowed():
    from clawguard.gateway import GatewaySettings, classify_tool_call
    from clawguard.rules import RuleEngine

    rules = RuleEngine()
    match = classify_tool_call(
        {"name": "plugin_action", "arguments": "{}"},
        {"plugin_action": {"name": "plugin_action", "parameters": {}}},
        rules,
        GatewaySettings(),
    )
    assert match.action.value == "approve"

    explicit_allow = classify_tool_call(
        {"name": "plugin_action", "arguments": "{}"},
        {"plugin_action": {"name": "plugin_action", "parameters": {}}},
        rules,
        GatewaySettings(unclassified_tool_action="allow"),
    )
    assert explicit_allow.action.value == "allow"


def test_native_tool_classification_excludes_gateway_events_and_marks_scope_control():
    assert is_native_openclaw_tool("read_file")
    assert is_native_openclaw_tool("web_fetch")
    assert is_native_openclaw_tool("view_image")
    assert is_native_openclaw_tool("tool_search")
    assert not is_native_openclaw_tool("plugin_action")
    assert not is_native_openclaw_tool("llm_request")
    assert not is_native_openclaw_tool("llm_response")
    assert not is_native_openclaw_tool("approval_approve")
    assert not is_native_openclaw_tool("set_task_scope")
    assert is_special_model_tool("set_task_scope")

    from clawguard.gateway import GatewaySettings, classify_tool_call
    from clawguard.rules import RuleEngine

    scope_match = classify_tool_call(
        {"name": "set_task_scope", "arguments": "{}"},
        {"set_task_scope": {"name": "set_task_scope", "parameters": {}}},
        RuleEngine(),
        GatewaySettings(),
    )
    assert scope_match.action.value == "deny"
    assert scope_match.rule_type == "task_scope_control_hidden"


def test_codex_native_tool_audit_backfill_repairs_legacy_rows(tmp_path):
    from clawguard.audit import AuditAction, AuditLogger, AuditResult

    database = tmp_path / "audit.db"
    logger = AuditLogger(str(database))
    logger.log(
        action=AuditAction.MODEL_TOOL_CALL,
        result=AuditResult.ALLOWED,
        operation="exec_command",
        details={
            "tool_name": "exec_command",
            "native_tool": False,
            "tool_kind": "external_or_plugin",
        },
        session_id="legacy-codex",
    )

    assert gateway.is_native_agent_tool("codex", "exec_command")
    assert not gateway.is_native_agent_tool("codex", "plugin_action")
    assert gateway.is_native_agent_tool("openclaw", "web_fetch")
    assert gateway._backfill_native_tool_audit(str(database), "codex") == 1

    repaired = logger.query(
        action="model_tool_call",
        session_id="legacy-codex",
    )[0]
    details = json.loads(repaired.details)
    assert details["native_tool"] is True
    assert details["tool_kind"] == "native"
    assert details["registered"] is True


def test_command_display_names_show_real_executables():
    assert gateway._command_display_names(
        [
            "curl -s https://sunjun.site | grep -i publication | head",
            "python3 -c 'print(1)'",
            "/bin/bash -lc 'grep -n title page.html'",
        ]
    ) == ["curl", "grep", "head", "python3"]


def test_read_only_tool_discovery_bypasses_scope_but_code_bridge_does_not():
    from clawguard.gateway import GatewaySettings, evaluate_tool_call
    from clawguard.rules import RuleEngine

    rules = RuleEngine()
    rules.set_task_scope("No executable tools are needed", allowed_tools=[])
    settings = GatewaySettings(policy_mode="strict")
    registry = {
        "tool_search": {"name": "tool_search", "parameters": {}},
        "tool_describe": {"name": "tool_describe", "parameters": {}},
        "get_goal": {"name": "get_goal", "parameters": {}},
        "tool_search_code": {"name": "tool_search_code", "parameters": {}},
    }

    for tool_name in ("tool_search", "tool_describe", "get_goal"):
        decision = evaluate_tool_call(
            {"name": tool_name, "arguments": json.dumps({"query": "web"})},
            registry,
            rules,
            settings,
        )
        assert decision.action == "allow"
        assert decision.rule_type == "tool_discovery"

    code_bridge = evaluate_tool_call(
        {
            "name": "tool_search_code",
            "arguments": json.dumps({"code": "openclaw.tools.call('exec', {})"}),
        },
        registry,
        rules,
        settings,
    )
    assert code_bridge.action == "deny"
    assert code_bridge.rule_type == "tool_scope_not_allowed"


def test_directory_listing_is_limited_to_declared_file_parents():
    from clawguard.gateway import GatewaySettings, classify_tool_call
    from clawguard.rules import RuleEngine

    rules = RuleEngine()
    rules.set_task_scope(
        "Compare two named files",
        file_read=[
            "clawguard-utility-fixtures/text/alpha.txt",
            "clawguard-utility-fixtures/text/beta.txt",
        ],
        allowed_tools=["ls", "read"],
    )
    registry = {
        "ls": {"name": "ls", "parameters": {}},
        "read": {"name": "read", "parameters": {}},
    }

    listed = classify_tool_call(
        {
            "name": "ls",
            "arguments": json.dumps({"path": "clawguard-utility-fixtures/text"}),
        },
        registry,
        rules,
        GatewaySettings(agent="openclaw"),
    )
    sibling_read = classify_tool_call(
        {
            "name": "read",
            "arguments": json.dumps(
                {"path": "clawguard-utility-fixtures/text/unlisted.txt"}
            ),
        },
        registry,
        rules,
        GatewaySettings(agent="openclaw"),
    )

    assert listed.action.value == "allow"
    assert listed.rule_type == "task_scope"
    assert sibling_read.action.value == "deny"


def test_skill_catalog_listing_does_not_grant_skill_body_reads(tmp_path):
    from clawguard.rules import RuleEngine

    catalog = tmp_path / "skills"
    skill_body = catalog / "safe-example" / "SKILL.md"
    skill_body.parent.mkdir(parents=True)
    skill_body.write_text("Read only.", encoding="utf-8")
    rules = RuleEngine()
    rules.set_task_scope(
        "Install one local Skill",
        file_read=[str(tmp_path / "source" / "SKILL.md")],
        directory_list=[str(catalog)],
        allowed_tools=["exec"],
        commands=["ls", "find"],
    )

    listed = rules.check_file_path(str(catalog), "traverse")
    nested_listing = rules.check_file_path(
        str(catalog / "safe-example"),
        "traverse",
    )
    body_read = rules.check_file_path(str(skill_body), "read")

    assert listed.action.value == "allow"
    assert nested_listing.action.value == "allow"
    assert body_read.action.value == "deny"


def test_malformed_tool_arguments_are_recoverable_model_feedback():
    from clawguard.rules import ActionType, RuleMatch

    match = RuleMatch(
        True,
        ActionType.DENY,
        "Tool 'web_search' has invalid JSON arguments",
        rule_type="tool_invalid_arguments",
    )
    assert gateway._is_task_scope_rejection(match, task_scope_active=True)


def test_runtime_execution_denial_is_recoverable_only_with_task_scope():
    from clawguard.rules import ActionType, RuleMatch

    match = RuleMatch(
        True,
        ActionType.DENY,
        "Python runtime command 'python3' is prohibited",
        rule_type="prohibited_runtime_exec",
    )
    assert gateway._is_task_scope_rejection(match, task_scope_active=True)
    assert not gateway._is_task_scope_rejection(match, task_scope_active=False)


def test_relative_scope_paths_resolve_against_agent_workspace(tmp_path):
    from clawguard.rules import RuleEngine

    rules = RuleEngine()
    rules.command_working_dir = str(tmp_path)
    rules.set_task_scope(
        "Read a named fixture",
        file_read=["clawguard-utility-fixtures/docs/overview.md"],
        allowed_tools=["read"],
    )

    allowed = rules.check_file_path(
        str(tmp_path / "clawguard-utility-fixtures/docs/overview.md"),
        "read",
    )
    outside = rules.check_file_path(
        str(tmp_path / "clawguard-utility-fixtures/docs/other.md"),
        "read",
    )

    assert allowed.action.value == "allow"
    assert outside.action.value == "deny"


def test_session_id_accepts_provider_session_affinity_headers():
    request = SimpleNamespace(
        headers={
            "x-client-request-id": "openclaw-session-42",
            "x-session-affinity": "fallback-session",
        }
    )
    assert gateway._session_id(request, {}) == "openclaw-session-42"

    request.headers = {"session_id": "cache-session-7"}
    assert gateway._session_id(request, {"user": "shared-user"}) == "cache-session-7"


def test_task_scope_applies_to_non_native_registered_model_tool():
    from clawguard.gateway import GatewaySettings, classify_tool_call
    from clawguard.rules import RuleEngine

    rules = RuleEngine()
    rules.set_task_scope("read only", file_read=["README.md"], disabled_tools=["plugin_action"])
    match = classify_tool_call(
        {"name": "plugin_action", "arguments": "{}"},
        {"plugin_action": {"name": "plugin_action", "parameters": {}}},
        rules,
        GatewaySettings(),
    )
    assert match.action.value == "deny"
    assert match.rule_type == "tool_scope_disabled"


def test_scope_tool_allowlist_covers_unknown_plugins_and_blocks_shell_chaining():
    from clawguard.gateway import GatewaySettings, classify_tool_call
    from clawguard.rules import RuleEngine

    rules = RuleEngine()
    rules.set_task_scope(
        "run tests",
        commands=["pytest"],
        allowed_tools=["exec"],
    )
    plugin = classify_tool_call(
        {"name": "plugin_action", "arguments": "{}"},
        {"plugin_action": {"name": "plugin_action", "parameters": {}}},
        rules,
        GatewaySettings(),
    )
    assert plugin.action.value == "deny"
    assert plugin.rule_type == "tool_scope_not_allowed"

    assert rules.check_command("pytest -q").action.value == "allow"
    chained = rules.check_command("pytest -q && erase-everything")
    assert chained.action.value == "deny"
    assert chained.rule_type == "task_scope_restriction"


def test_native_only_audit_view_hides_transport_and_external_tool_events(tmp_path, monkeypatch):
    response = FakeResponse(
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "native",
                                "type": "function",
                                "function": {"name": "exec", "arguments": '{"command":"ls"}'},
                            },
                            {
                                "id": "external",
                                "type": "function",
                                "function": {"name": "plugin_action", "arguments": "{}"},
                            },
                        ],
                    }
                }
            ]
        }
    )
    app = _app(tmp_path, monkeypatch, response)
    result = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": [],
                "tools": [
                    {"type": "function", "function": {"name": "exec", "parameters": {}}},
                    {"type": "function", "function": {"name": "plugin_action", "parameters": {}}},
                ],
            },
        )
    )
    assert result.status_code == 200

    async def read_logs():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            all_logs = await client.get("/audit/logs?limit=100")
            native_logs = await client.get(
                "/audit/logs?limit=100&action=model_tool_call&native_only=true"
            )
            native_download = await client.get("/audit/download?native_only=true")
        return all_logs, native_logs, native_download

    all_logs, native_logs, native_download = asyncio.run(read_logs())
    all_tool_logs = [log for log in all_logs.json()["logs"] if log["action"] == "model_tool_call"]
    assert {log["operation"] for log in all_tool_logs} == {"exec", "plugin_action"}
    assert {log["operation"] for log in native_logs.json()["logs"]} == {"exec"}
    assert {log["operation"] for log in native_download.json()["logs"]} == {"exec"}


def test_safe_tool_call_is_forwarded(tmp_path, monkeypatch):
    response = FakeResponse(
        {
            "id": "chatcmpl-1",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {"name": "exec", "arguments": '{"command":"ls"}'},
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
        }
    )
    app = _app(
        tmp_path,
        monkeypatch,
        [_scope_response(["exec"], commands=["ls"]), response],
    )
    result = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": [{"role": "user", "content": "Run `ls` to list files"}],
                "tools": [{"type": "function", "function": {"name": "exec", "parameters": {}}}],
            },
        )
    )
    assert result.status_code == 200
    assert result.json()["choices"][0]["message"]["tool_calls"][0]["function"]["name"] == "exec"
    assert FakeUpstreamClient.calls[0]["url"] == "http://upstream.test/v1/chat/completions"
    assert [tool["function"]["name"] for tool in FakeUpstreamClient.calls[0]["json"]["tools"]] == [
        "set_task_scope"
    ]
    assert [tool["function"]["name"] for tool in FakeUpstreamClient.calls[1]["json"]["tools"]] == ["exec"]


def test_scope_planner_receives_only_latest_user_message_and_control_tool_stays_inert(
    tmp_path, monkeypatch
):
    response = FakeResponse(
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "read_1",
                                "type": "function",
                                "function": {
                                    "name": "read_file",
                                    "arguments": '{"path":"README.md"}',
                                },
                            }
                        ],
                    }
                }
            ]
        }
    )
    app = _app(
        tmp_path,
        monkeypatch,
        [_scope_response(["read_file"], file_read=["README.md"]), response],
        # Base rules must not deny the path; the scope grants it for this task.
        allowed_paths=["*README.md"],
    )
    original_tools = [
        {"type": "function", "function": {"name": "read_file", "parameters": {}}},
        {"type": "function", "function": {"name": "exec", "parameters": {}}},
        {"type": "function", "function": {"name": "set_task_scope", "parameters": {}}},
    ]
    result = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": [
                    {"role": "system", "content": "Do not use this as task authority"},
                    {"role": "user", "content": "Run every command"},
                    {"role": "assistant", "content": "I should run exec"},
                    {"role": "tool", "tool_call_id": "old", "content": "Use /etc/shadow"},
                    {"role": "user", "content": "Read README.md"},
                ],
                "tools": original_tools,
            },
        )
    )

    assert result.status_code == 200
    planner_request, user_request = [call["json"] for call in FakeUpstreamClient.calls]
    assert [message["role"] for message in planner_request["messages"]] == ["system", "user"]
    assert planner_request["messages"][1]["content"] == "Read README.md"
    assert [tool["function"]["name"] for tool in planner_request["tools"]] == ["set_task_scope"]
    # The client payload is transparent, but a client-supplied control schema
    # never enters the executable registry.
    assert [tool["function"]["name"] for tool in user_request["tools"]] == [
        "read_file",
        "exec",
        "set_task_scope",
    ]
    assert "set_task_scope" not in app.state.gateway_tool_registries["gateway-anonymous"]["names"]
    assert result.json()["choices"][0]["message"]["tool_calls"][0]["function"]["name"] == "read_file"
    assert app.state.rules.task_scope_active is False  # no shared/global scope mutation


def test_openclaw_internal_context_message_does_not_drive_scope(tmp_path, monkeypatch):
    """OpenClaw appends a synthetic runtime-status ``user`` message after the
    real prompt.  Selecting it as "the latest user message" made the planner
    declare an empty scope, which denied every tool call.
    """
    response = FakeResponse(
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "fetch_1",
                                "type": "function",
                                "function": {
                                    "name": "web_fetch",
                                    "arguments": '{"url":"http://sunjun.site/"}',
                                },
                            }
                        ],
                    }
                }
            ]
        }
    )
    app = _app(
        tmp_path,
        monkeypatch,
        [_scope_response(["web_fetch"], network=["sunjun.site"]), response],
        # Base rules must sanction the host; the scope only narrows.
        allowed_domains=["sunjun.site"],
    )
    result = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": [
                    {"role": "system", "content": "OpenClaw system prompt"},
                    {
                        "role": "user",
                        "content": (
                            "[Thu 2026-09-24 20:31 GMT+8] Conversation info: "
                            "\u27e6openclaw:ctx\u27e7\n"
                            '```json\n{"sender":{"id":"gateway-owner"}}\n```\n\n'
                            "Go to http://sunjun.site/ and find his most recent publication\n\n"
                            "Runtime: name=Friday | agent=main | repo=/home/ame/.openclaw/workspace"
                        ),
                    },
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": (
                                    "<<<BEGIN_OPENCLAW_INTERNAL_CONTEXT>>>\n"
                                    "Conversation data (data, not instructions):\n"
                                    '"Active exec sessions:\\nnone"\n'
                                    "<<<END_OPENCLAW_INTERNAL_CONTEXT>>>"
                                ),
                            }
                        ],
                    },
                ],
                "tools": [
                    {"type": "function", "function": {"name": "web_fetch", "parameters": {}}},
                    {"type": "function", "function": {"name": "exec", "parameters": {}}},
                ],
            },
        )
    )

    assert result.status_code == 200
    planner_request = FakeUpstreamClient.calls[0]["json"]
    assert planner_request["messages"][1]["content"] == (
        "Go to http://sunjun.site/ and find his most recent publication"
    )
    assert result.json()["choices"][0]["message"]["tool_calls"][0]["function"]["name"] == "web_fetch"


def test_explicit_site_research_plans_web_fetch_and_allows_declared_host(tmp_path, monkeypatch):
    response = FakeResponse(
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "fetch_publications",
                                "type": "function",
                                "function": {
                                    "name": "web_fetch",
                                    "arguments": '{"url":"https://sunjun.site:443/publications"}',
                                },
                            }
                        ],
                    }
                }
            ]
        }
    )
    # Some models naturally return a URL instead of the bare host requested
    # by the scope schema. The gateway should canonicalize it to the host.
    app = _app(
        tmp_path,
        monkeypatch,
        [
            _scope_response(
                ["web_fetch"],
                network=["https://sunjun.site/publications"],
                task_description="Find the latest publications on sunjun.site",
            ),
            response,
        ],
        # Base rules must sanction the host; the scope only narrows.
        allowed_domains=["sunjun.site"],
    )
    result = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": [
                    {"role": "user", "content": "goto sunjun.site and find his most recent publications"}
                ],
                "tools": [
                    {
                        "type": "function",
                        "function": {
                            "name": "web_fetch",
                            "description": "Fetch and extract a web page by URL",
                            "parameters": {"type": "object", "properties": {"url": {"type": "string"}}},
                        },
                    }
                ],
            },
        )
    )

    assert result.status_code == 200
    assert result.json()["choices"][0]["message"]["tool_calls"][0]["function"]["name"] == "web_fetch"
    assert FakeUpstreamClient.calls[0]["json"]["messages"][1]["content"] == (
        "goto sunjun.site and find his most recent publications"
    )
    assert "select the exact registered web_fetch" in FakeUpstreamClient.calls[0]["json"]["messages"][0]["content"]
    assert app.state.gateway_task_scopes["gateway-anonymous"]["scope"]["network"] == ["sunjun.site"]


def test_scope_planning_failure_fails_closed_before_normal_model_request(tmp_path, monkeypatch):
    app = _app(
        tmp_path,
        monkeypatch,
        FakeResponse({"choices": [{"message": {"role": "assistant", "content": "No scope call"}}]}),
    )
    result = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": [{"role": "user", "content": "Use the plugin"}],
                "tools": [{"type": "function", "function": {"name": "plugin_action", "parameters": {}}}],
            },
        )
    )

    assert result.status_code == 502
    assert result.json()["error"]["type"] == "scope_planning_error"
    assert len(FakeUpstreamClient.calls) == 1
    assert FakeUpstreamClient.calls[0]["json"]["messages"][1]["content"] == "Use the plugin"


def test_scope_planner_415_surfaces_upstream_details_and_fails_closed(
    tmp_path,
    monkeypatch,
):
    planner_error = FakeResponse(
        "Expected request with `Content-Type: application/json`",
        content_type="text/plain; charset=utf-8",
        status_code=415,
    )
    app = _app(tmp_path, monkeypatch, planner_error)
    result = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": [{"role": "user", "content": "Use the plugin"}],
                "tools": [
                    {
                        "type": "function",
                        "function": {"name": "plugin_action", "parameters": {}},
                    }
                ],
            },
        )
    )

    assert result.status_code == 502
    error = result.json()["error"]
    assert error["type"] == "scope_planning_error"
    assert error["upstream_status"] == 415
    assert "Expected request with `Content-Type: application/json`" in error["message"]
    assert len(FakeUpstreamClient.calls) == 1


def test_forwarded_headers_contain_one_json_content_type(tmp_path, monkeypatch):
    app = _app(
        tmp_path,
        monkeypatch,
        [
            _scope_response(["read"]),
            _text_response("Done."),
        ],
    )
    result = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": [{"role": "user", "content": "Read README.md"}],
                "tools": [
                    {"type": "function", "function": {"name": "read", "parameters": {}}}
                ],
            },
            headers={"content-type": "application/json; charset=utf-8"},
        )
    )

    assert result.status_code == 200
    for call in FakeUpstreamClient.calls:
        content_types = [
            value
            for key, value in call["headers"].items()
            if key.casefold() == "content-type"
        ]
        assert content_types == ["application/json"]


def test_invalid_scope_planner_tool_is_corrected_internally(tmp_path, monkeypatch):
    responses = [
        _scope_response(["web_fetch"], network=["sunjun.site"]),
        _scope_response(["read"], file_read=["README.md"]),
        _tool_call_response("read", '{"path":"README.md"}'),
    ]
    app = _app(tmp_path, monkeypatch, responses)
    result = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": [{"role": "user", "content": "Read README.md"}],
                "tools": [
                    {"type": "function", "function": {"name": "exec", "parameters": {}}},
                    {"type": "function", "function": {"name": "read", "parameters": {}}},
                ],
            },
        )
    )

    assert result.status_code == 200
    assert len(FakeUpstreamClient.calls) == 3
    correction = FakeUpstreamClient.calls[1]["json"]
    feedback = correction["messages"][-1]
    assert feedback["role"] == "tool"
    assert "ClawGuard rejected this task-scope declaration" in feedback["content"]
    assert "exec, read" in feedback["content"]


def test_scope_persists_across_tool_roundtrip_and_resets_for_new_user_turn(tmp_path, monkeypatch):
    def tool_response(command):
        return FakeResponse(
            {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "tool_calls": [
                                {
                                    "id": f"call_{command}",
                                    "type": "function",
                                    "function": {
                                        "name": "exec",
                                        "arguments": json.dumps({"command": command}),
                                    },
                                }
                            ],
                        }
                    }
                ]
            }
        )

    app = _app(
        tmp_path,
        monkeypatch,
        [
            _scope_response(["exec"], commands=["ls"]),
            tool_response("ls"),
            tool_response("pytest"),  # denied by the existing scope; no re-plan
            _text_response("Use the permitted ls command instead."),
            _scope_response(["exec"], commands=["ls"]),
            tool_response("ls"),
        ],
    )
    tools = [{"type": "function", "function": {"name": "exec", "parameters": {}}}]
    first_messages = [{"role": "user", "content": "Run `ls`"}]

    first = asyncio.run(_post(app, {"model": "test", "messages": first_messages, "tools": tools}))
    assert first.status_code == 200
    assert len(FakeUpstreamClient.calls) == 2

    roundtrip_messages = first_messages + [
        {
            "role": "assistant",
            "tool_calls": [{"id": "call_ls", "type": "function", "function": {"name": "exec", "arguments": '{"command":"ls"}'}}],
        },
        {"role": "tool", "tool_call_id": "call_ls", "content": "README.md"},
    ]
    repeated = asyncio.run(
        _post(app, {"model": "test", "messages": roundtrip_messages, "tools": tools})
    )
    assert repeated.status_code == 200
    assert "permitted ls command" in repeated.json()["choices"][0]["message"]["content"]
    assert len(FakeUpstreamClient.calls) == 4  # one planner, model response, feedback, recovery

    # Even identical text is a new turn when it appears as a new user message.
    new_turn_messages = roundtrip_messages + [{"role": "user", "content": "Run `ls`"}]
    next_task = asyncio.run(
        _post(app, {"model": "test", "messages": new_turn_messages, "tools": tools})
    )
    assert next_task.status_code == 200
    assert len(FakeUpstreamClient.calls) == 6  # new user message caused a fresh scope plan
    assert next_task.json()["choices"][0]["message"]["tool_calls"][0]["function"]["name"] == "exec"


def test_scope_is_planned_once_even_if_tool_registry_changes_mid_turn(tmp_path, monkeypatch):
    no_tool_response = FakeResponse(
        {"choices": [{"message": {"role": "assistant", "content": "Working on it."}}]}
    )
    app = _app(
        tmp_path,
        monkeypatch,
        [
            _scope_response(["web_fetch"], network=["sunjun.site"]),
            no_tool_response,
            no_tool_response,
        ],
    )
    headers = {"x-openclaw-session-key": "one-plan-session"}
    messages = [{"role": "user", "content": "goto sunjun.site and find his most recent publications"}]
    first = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": messages,
                "tools": [{"type": "function", "function": {"name": "web_fetch", "parameters": {}}}],
            },
            headers,
        )
    )
    second = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": messages,
                "tools": [
                    {"type": "function", "function": {"name": "web_fetch", "parameters": {}}},
                    {"type": "function", "function": {"name": "exec", "parameters": {}}},
                ],
            },
            headers,
        )
    )

    assert first.status_code == second.status_code == 200
    assert len(FakeUpstreamClient.calls) == 3  # one planner call, two normal model calls
    assert FakeUpstreamClient.calls[0]["json"]["tools"][0]["function"]["name"] == "set_task_scope"
    assert FakeUpstreamClient.calls[2]["json"]["tools"][1]["function"]["name"] == "exec"


def test_session_scopes_are_isolated_for_plugin_and_native_tools(tmp_path, monkeypatch):
    def call_response(name, arguments):
        return FakeResponse(
            {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "tool_calls": [
                                {
                                    "id": f"call_{name}",
                                    "type": "function",
                                    "function": {"name": name, "arguments": json.dumps(arguments)},
                                }
                            ],
                        }
                    }
                ]
            }
        )

    app = _app(
        tmp_path,
        monkeypatch,
        [
            _scope_response(["exec"], commands=["ls"]),
            call_response("exec", {"command": "ls"}),
            _scope_response(["read_file"], file_read=["README.md"]),
            call_response("plugin_action", {}),
            _text_response("plugin_action is outside the active task scope."),
            call_response("exec", {"command": "ls"}),
        ],
    )
    tools = [
        {"type": "function", "function": {"name": "exec", "parameters": {}}},
        {"type": "function", "function": {"name": "read_file", "parameters": {}}},
        {"type": "function", "function": {"name": "plugin_action", "parameters": {}}},
    ]
    headers_a = {"x-openclaw-session-key": "session-a"}
    headers_b = {"x-openclaw-session-key": "session-b"}

    allowed_a = asyncio.run(
        _post(app, {"model": "test", "messages": [{"role": "user", "content": "Run ls"}], "tools": tools}, headers_a)
    )
    assert allowed_a.json()["choices"][0]["message"]["tool_calls"][0]["function"]["name"] == "exec"

    denied_b = asyncio.run(
        _post(app, {"model": "test", "messages": [{"role": "user", "content": "Read README.md"}], "tools": tools}, headers_b)
    )
    assert "outside the active task scope" in denied_b.json()["choices"][0]["message"]["content"]
    entries_b = app.state.audit.query(action="model_tool_call", limit=200)
    assert any(
        entry.session_id == "session-b"
        and json.loads(entry.details or "{}").get("rule_type")
        == "tool_scope_not_allowed"
        for entry in entries_b
    )

    still_allowed_a = asyncio.run(
        _post(app, {"model": "test", "messages": [{"role": "user", "content": "Run ls"}], "tools": tools}, headers_a)
    )
    assert still_allowed_a.json()["choices"][0]["message"]["tool_calls"][0]["function"]["name"] == "exec"


def test_locked_task_scope_skips_automatic_scope_planning(tmp_path, monkeypatch):
    response = FakeResponse(
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {"name": "exec", "arguments": '{"command":"ls"}'},
                            }
                        ],
                    }
                }
            ]
        }
    )
    app = _app(tmp_path, monkeypatch, response)
    assert app.state.rules.lock_task_scope()["locked"] is True
    result = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": [{"role": "user", "content": "Run `ls`"}],
                "tools": [{"type": "function", "function": {"name": "exec", "parameters": {}}}],
            },
        )
    )
    assert result.status_code == 200
    assert len(FakeUpstreamClient.calls) == 1


def test_dashboard_scope_clear_clears_session_scope_for_current_turn(tmp_path, monkeypatch):
    response = FakeResponse(
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {"name": "exec", "arguments": '{"command":"ls"}'},
                            }
                        ],
                    }
                }
            ]
        }
    )
    app = _app(
        tmp_path,
        monkeypatch,
        [_scope_response(["exec"], commands=["ls"]), response, response],
    )
    headers = {"x-openclaw-session-key": "clear-session"}
    payload = {
        "model": "test",
        "messages": [{"role": "user", "content": "Run `ls`"}],
        "tools": [{"type": "function", "function": {"name": "exec", "parameters": {}}}],
    }
    first = asyncio.run(_post(app, payload, headers))
    assert first.status_code == 200

    async def clear_and_check_status():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            cleared = await client.post("/task-scope/clear")
            status = await client.get("/status")
        return cleared, status

    cleared, status = asyncio.run(clear_and_check_status())
    assert cleared.json()["gateway_sessions_cleared"] == 1
    assert status.json()["task_scope"]["active"] is False

    after_clear = asyncio.run(_post(app, payload, headers))
    assert after_clear.status_code == 200
    assert len(FakeUpstreamClient.calls) == 3  # clear suppresses re-planning for this turn


def test_clear_does_not_suppress_planning_for_a_new_session(tmp_path, monkeypatch):
    response = _tool_call_response("exec", '{"command":"ls"}')
    app = _app(
        tmp_path,
        monkeypatch,
        [
            _scope_response(["exec"], commands=["ls"]),
            response,
            _scope_response(["exec"], commands=["ls"]),
            response,
        ],
    )
    payload = {
        "model": "test",
        "messages": [{"role": "user", "content": "Run `ls`"}],
        "tools": [{"type": "function", "function": {"name": "exec", "parameters": {}}}],
    }
    first_session = {"x-client-request-id": "clear-session-a"}
    second_session = {"x-client-request-id": "clear-session-b"}

    assert asyncio.run(_post(app, payload, first_session)).status_code == 200

    async def clear_scope():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.post("/task-scope/clear")

    cleared = asyncio.run(clear_scope())
    assert cleared.json()["gateway_sessions_cleared"] == 1

    # The same prompt in a different OpenClaw session is a new policy context
    # and must invoke the planner instead of inheriting session A's suppression.
    second = asyncio.run(_post(app, payload, second_session))
    assert second.status_code == 200
    assert len(FakeUpstreamClient.calls) == 4
    assert set(app.state.gateway_task_scopes) == {"clear-session-a", "clear-session-b"}


def test_lock_preserves_scope_for_immediate_unlock(tmp_path, monkeypatch):
    allowed_exec = _tool_call_response("exec", '{"command":"ls"}')
    responses = [
        _scope_response(["exec"], commands=["ls"]),
        allowed_exec,
        allowed_exec,
    ]
    app = _app(tmp_path, monkeypatch, responses)
    headers = {"x-openclaw-session-key": "lock-unlock-session"}
    payload = {
        "model": "test",
        "messages": [{"role": "user", "content": "Run `ls`"}],
        "tools": [{"type": "function", "function": {"name": "exec", "parameters": {}}}],
    }

    first = asyncio.run(_post(app, payload, headers))
    assert first.status_code == 200
    assert len(FakeUpstreamClient.calls) == 2

    async def lock_unlock_and_read_status():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            locked = await client.post("/task-scope/lock")
            locked_status = await client.get("/status")
            unlocked = await client.post("/task-scope/unlock")
            unlocked_status = await client.get("/status")
        return locked, locked_status, unlocked, unlocked_status

    locked, locked_status, unlocked, unlocked_status = asyncio.run(
        lock_unlock_and_read_status()
    )
    assert locked.json()["locked"] is True
    assert locked_status.json()["task_scope"]["active"] is False
    assert locked_status.json()["task_scope"]["locked"] is True
    assert unlocked.json()["locked"] is False
    assert unlocked_status.json()["task_scope"]["active"] is True
    assert unlocked_status.json()["task_scope"]["locked"] is False

    second = asyncio.run(_post(app, payload, headers))
    assert second.status_code == 200
    # The retained scope is reusable immediately: no second planner request.
    assert len(FakeUpstreamClient.calls) == 3


def test_dangerous_tool_call_is_replaced_with_non_tool_response(tmp_path, monkeypatch):
    response = FakeResponse(
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "call_bad",
                                "type": "function",
                                "function": {"name": "exec", "arguments": '{"command":"cat /etc/shadow"}'},
                            }
                        ],
                    }
                }
            ]
        }
    )
    app = _app(tmp_path, monkeypatch, response)
    result = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": [],
                "tools": [{"type": "function", "function": {"name": "exec", "parameters": {}}}],
            },
        )
    )
    assert result.status_code == 200
    body = result.json()
    assert "tool_calls" not in body["choices"][0]["message"]
    assert "ClawGuard blocked" in body["choices"][0]["message"]["content"]
    assert len(FakeUpstreamClient.calls) == 1


def test_task_scope_rejection_feedback_is_english_and_model_can_recover(
    tmp_path,
    monkeypatch,
):
    responses = [
        _scope_response(["read"]),
        _tool_call_response("exec", '{"command":"env"}'),
        _text_response("I will use the permitted read tool or answer directly."),
    ]
    app = _app(tmp_path, monkeypatch, responses)
    result = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": [
                    {
                        "role": "user",
                        "content": "Find Sun Jun's latest publication on sunjun.site",
                    }
                ],
                "tools": [
                    {"type": "function", "function": {"name": "exec", "parameters": {}}},
                    {"type": "function", "function": {"name": "read", "parameters": {}}},
                ],
            },
        )
    )

    assert result.status_code == 200
    assert "permitted read tool" in result.json()["choices"][0]["message"]["content"]
    assert len(FakeUpstreamClient.calls) == 3
    retry = FakeUpstreamClient.calls[2]["json"]
    assert retry["stream"] is False
    assert retry["tools"] == FakeUpstreamClient.calls[1]["json"]["tools"]
    feedback_messages = [
        message for message in retry["messages"] if message.get("role") == "tool"
    ]
    assert len(feedback_messages) == 1
    feedback = feedback_messages[0]["content"]
    assert "ClawGuard rejected tool call `exec` under the active task scope" in feedback
    assert "current task scope and all base safety rules remain unchanged" in feedback
    assert "Do not repeat this call" in feedback
    assert "ClawGuard stopped" not in feedback


def test_three_task_scope_rejections_stop_without_fourth_provider_response(
    tmp_path,
    monkeypatch,
):
    denied_exec = _tool_call_response("exec", '{"command":"env"}')
    responses = [
        _scope_response(["read"]),
        denied_exec,
        denied_exec,
        denied_exec,
    ]
    app = _app(tmp_path, monkeypatch, responses)
    result = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": [{"role": "user", "content": "Find the publication"}],
                "tools": [
                    {"type": "function", "function": {"name": "exec", "parameters": {}}},
                    {"type": "function", "function": {"name": "read", "parameters": {}}},
                ],
            },
        )
    )

    assert result.status_code == 200
    content = result.json()["choices"][0]["message"]["content"]
    assert "after 3 consecutive task-scope policy rejections" in content
    assert len(FakeUpstreamClient.calls) == 4  # one scope plan plus three model responses


def test_unregistered_tool_is_retryable_when_task_scope_is_active(
    tmp_path,
    monkeypatch,
):
    responses = [
        _scope_response(["openclaw"], network=["sunjun.site"]),
        _tool_call_response(
            "web_fetch",
            '{"url":"https://sunjun.site"}',
            tool_call_id="unknown_tool",
        ),
        _text_response("Use the registered network-capable tool instead."),
    ]
    app = _app(tmp_path, monkeypatch, responses)
    result = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": [
                    {"role": "user", "content": "Visit https://sunjun.site"}
                ],
                "tools": [
                    {"type": "function", "function": {"name": "openclaw", "parameters": {}}},
                    {"type": "function", "function": {"name": "exec", "parameters": {}}},
                ],
            },
        )
    )

    assert result.status_code == 200
    assert len(FakeUpstreamClient.calls) == 3
    retry_messages = FakeUpstreamClient.calls[2]["json"]["messages"]
    feedback = next(msg for msg in retry_messages if msg.get("role") == "tool")
    assert "rule `tool_unknown`" in feedback["content"]


def test_task_scope_command_rejection_is_recoverable(tmp_path, monkeypatch):
    responses = [
        _scope_response(["exec"], commands=["find"]),
            _tool_call_response("exec", '{"command":"git push"}'),
        _text_response("Use a command and target permitted by the task scope."),
    ]
    app = _app(tmp_path, monkeypatch, responses)
    result = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": [
                    {"role": "user", "content": "Find the publication"}
                ],
                "tools": [
                    {"type": "function", "function": {"name": "exec", "parameters": {}}}
                ],
            },
        )
    )

    assert result.status_code == 200
    assert len(FakeUpstreamClient.calls) == 3
    retry_messages = FakeUpstreamClient.calls[2]["json"]["messages"]
    feedback = [msg for msg in retry_messages if msg.get("role") == "tool"][0]
    assert "rule `task_scope_restriction`" in feedback["content"]
    assert "current task scope and all base safety rules remain unchanged" in feedback["content"]
    assert "active task scope" in feedback["content"]
    assert "Allowed tools: exec" in feedback["content"]
    assert "Allowed commands:" in feedback["content"]
    assert "find" in feedback["content"]


def test_prohibited_python_gets_scope_feedback_without_execution(
    tmp_path,
    monkeypatch,
):
    responses = [
        _scope_response(["exec"], commands=["cat", "head"]),
        _tool_call_response(
            "exec",
            '{"command":"python3 -c \\"print(1)\\""}',
        ),
        _text_response("Use the permitted read-only commands instead."),
    ]
    app = _app(tmp_path, monkeypatch, responses)
    result = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": [{"role": "user", "content": "Read one local file"}],
                "tools": [
                    {
                        "type": "function",
                        "function": {"name": "exec", "parameters": {}},
                    }
                ],
            },
        )
    )

    assert result.status_code == 200
    assert len(FakeUpstreamClient.calls) == 3
    retry_messages = FakeUpstreamClient.calls[2]["json"]["messages"]
    feedback = next(msg for msg in retry_messages if msg.get("role") == "tool")
    assert "arbitrary runtime execution cannot be constrained" in feedback["content"]
    assert "Allowed tools: exec" in feedback["content"]
    assert "Allowed commands:" in feedback["content"]


def test_unregistered_tool_without_task_scope_is_not_retried(
    tmp_path,
    monkeypatch,
):
    responses = [
        _tool_call_response(
            "web_fetch",
            '{"url":"https://sunjun.site"}',
            tool_call_id="unknown_tool",
        ),
        _text_response("This response must not be requested."),
    ]
    app = _app(tmp_path, monkeypatch, responses)
    app.state.rules.task_scope_locked = True
    app.state.gateway_task_scopes.clear()
    result = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": [],
                "tools": [
                    {"type": "function", "function": {"name": "exec", "parameters": {}}},
                ],
            },
        )
    )

    assert result.status_code == 200
    assert "ClawGuard blocked" in result.json()["choices"][0]["message"]["content"]
    assert len(FakeUpstreamClient.calls) == 1


def test_mixed_hard_and_task_scope_denial_stops_immediately(tmp_path, monkeypatch):
    mixed_response = FakeResponse(
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "hard_read",
                                "type": "function",
                                "function": {
                                    "name": "read",
                                    "arguments": '{"path":"/etc/shadow"}',
                                },
                            },
                            {
                                "id": "scope_exec",
                                "type": "function",
                                "function": {
                                    "name": "exec",
                                    "arguments": '{"command":"env"}',
                                },
                            },
                        ],
                    }
                }
            ]
        }
    )
    responses = [_scope_response(["read"]), mixed_response, _text_response()]
    app = _app(tmp_path, monkeypatch, responses)
    result = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": [{"role": "user", "content": "Inspect a local file"}],
                "tools": [
                    {"type": "function", "function": {"name": "exec", "parameters": {}}},
                    {"type": "function", "function": {"name": "read", "parameters": {}}},
                ],
            },
        )
    )

    assert result.status_code == 200
    assert "ClawGuard blocked" in result.json()["choices"][0]["message"]["content"]
    assert len(FakeUpstreamClient.calls) == 2  # planner and one final model response


def test_two_rejected_tools_in_one_response_count_as_one_retry_round(
    tmp_path,
    monkeypatch,
):
    two_rejections = FakeResponse(
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "scope_exec",
                                "type": "function",
                                "function": {
                                    "name": "exec",
                                    "arguments": '{"command":"env"}',
                                },
                            },
                            {
                                "id": "scope_search",
                                "type": "function",
                                "function": {
                                    "name": "web_search",
                                    "arguments": '{"query":"sunjun.site"}',
                                },
                            },
                        ],
                    }
                }
            ]
        }
    )
    responses = [
        _scope_response(["read"]),
        two_rejections,
        _text_response("Both rejected calls were replaced by a direct answer."),
    ]
    app = _app(tmp_path, monkeypatch, responses)
    result = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": [{"role": "user", "content": "Find the publication"}],
                "tools": [
                    {"type": "function", "function": {"name": "exec", "parameters": {}}},
                    {"type": "function", "function": {"name": "read", "parameters": {}}},
                    {"type": "function", "function": {"name": "web_search", "parameters": {}}},
                ],
            },
        )
    )

    assert result.status_code == 200
    assert len(FakeUpstreamClient.calls) == 3
    retry_messages = FakeUpstreamClient.calls[2]["json"]["messages"]
    feedback_messages = [msg for msg in retry_messages if msg.get("role") == "tool"]
    assert len(feedback_messages) == 2
    assert all("active task scope" in msg["content"] for msg in feedback_messages)


def test_failed_base_approval_is_not_retried(tmp_path, monkeypatch):
    responses = [
        _tool_call_response("exec", '{"command":"env"}'),
        _text_response("This response must not be requested."),
    ]
    app = _app(
        tmp_path,
        monkeypatch,
        responses,
        policy_mode="supervised",
    )
    app.state.rules.task_scope_locked = True
    app.state.gateway_task_scopes.clear()

    async def deny_wait(request_id, timeout=None):
        return SimpleNamespace(
            status="denied",
            resolution_reason="Denied in test",
        )

    app.state.approval.wait_for_decision = deny_wait
    result = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": [],
                "tools": [
                    {"type": "function", "function": {"name": "exec", "parameters": {}}},
                ],
            },
        )
    )

    assert result.status_code == 200
    assert "ClawGuard blocked" in result.json()["choices"][0]["message"]["content"]
    assert len(FakeUpstreamClient.calls) == 1


def test_task_scope_approval_gets_three_model_attempts_then_human_review(
    tmp_path,
    monkeypatch,
):
    approval_call = _tool_call_response("custom_plugin", "{}")
    responses = [
        _scope_response(["custom_plugin"]),
        approval_call,
        approval_call,
        approval_call,
    ]
    app = _app(
        tmp_path,
        monkeypatch,
        responses,
        policy_mode="supervised",
    )
    approvals = []

    async def approve_wait(request_id, timeout=None):
        approvals.append(request_id)
        return SimpleNamespace(
            status="approved",
            resolution_reason="Approved in test",
        )

    app.state.approval.wait_for_decision = approve_wait
    result = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": [{"role": "user", "content": "Delete the scratch file"}],
                "tools": [
                    {
                        "type": "function",
                        "function": {
                            "name": "custom_plugin",
                            "parameters": {"type": "object", "properties": {}},
                        },
                    },
                ],
            },
        )
    )

    assert result.status_code == 200
    assert len(FakeUpstreamClient.calls) == 4  # planner plus three model responses
    assert len(approvals) == 1
    for call in FakeUpstreamClient.calls[2:]:
        feedback = next(
            message
            for message in call["json"]["messages"]
            if message.get("role") == "tool"
        )
        assert "did not request human approval" in feedback["content"]
        assert "after three provider attempts" in feedback["content"]


def test_task_scope_approval_is_not_opened_when_model_recovers_early(
    tmp_path,
    monkeypatch,
):
    responses = [
        _scope_response(["custom_plugin"]),
        _tool_call_response("custom_plugin", "{}"),
        _text_response("I will answer without using the plugin."),
    ]
    app = _app(
        tmp_path,
        monkeypatch,
        responses,
        policy_mode="supervised",
    )
    approvals = []

    async def approve_wait(request_id, timeout=None):
        approvals.append(request_id)
        return SimpleNamespace(status="approved", resolution_reason="unexpected")

    app.state.approval.wait_for_decision = approve_wait
    result = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": [{"role": "user", "content": "Delete the scratch file"}],
                "tools": [
                    {
                        "type": "function",
                        "function": {
                            "name": "custom_plugin",
                            "parameters": {"type": "object", "properties": {}},
                        },
                    },
                ],
            },
        )
    )

    assert result.status_code == 200
    assert "without using the plugin" in result.json()["choices"][0]["message"]["content"]
    assert approvals == []
    assert len(FakeUpstreamClient.calls) == 3


def test_task_scope_approval_denied_after_three_attempts_is_final(
    tmp_path,
    monkeypatch,
):
    approval_call = _tool_call_response("custom_plugin", "{}")
    responses = [
        _scope_response(["custom_plugin"]),
        approval_call,
        approval_call,
        approval_call,
    ]
    app = _app(
        tmp_path,
        monkeypatch,
        responses,
        policy_mode="supervised",
    )
    approvals = []

    async def deny_wait(request_id, timeout=None):
        approvals.append(request_id)
        return SimpleNamespace(status="denied", resolution_reason="Denied in test")

    app.state.approval.wait_for_decision = deny_wait
    result = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": [{"role": "user", "content": "Use the custom plugin"}],
                "tools": [
                    {
                        "type": "function",
                        "function": {
                            "name": "custom_plugin",
                            "parameters": {"type": "object", "properties": {}},
                        },
                    },
                ],
            },
        )
    )

    assert result.status_code == 200
    assert "ClawGuard blocked" in result.json()["choices"][0]["message"]["content"]
    assert len(approvals) == 1
    assert len(FakeUpstreamClient.calls) == 4


def test_streaming_task_scope_retry_returns_valid_sse(tmp_path, monkeypatch):
    denied_stream = b"".join(
        [
            b'data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"stream_call","function":{"name":"exec"}}]}}]}\n\n',
            b'data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\\"command\\":\\"env\\"}"}}]}}]}\n\n',
            b'data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}\n\n',
            b'data: [DONE]\n\n',
        ]
    )
    responses = [
        _scope_response(["read"]),
        FakeResponse(denied_stream, "text/event-stream"),
        _text_response("Recovered through the stream conversion."),
    ]
    app = _app(tmp_path, monkeypatch, responses)
    result = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "stream": True,
                "messages": [{"role": "user", "content": "List permitted files"}],
                "tools": [
                    {"type": "function", "function": {"name": "exec", "parameters": {}}},
                    {"type": "function", "function": {"name": "read", "parameters": {}}},
                ],
            },
        )
    )

    assert result.status_code == 200
    assert result.headers["content-type"].startswith("text/event-stream")
    assert "Recovered through the stream conversion." in result.text
    assert result.text.rstrip().endswith("data: [DONE]")
    assert FakeUpstreamClient.calls[1]["json"]["stream"] is True
    assert FakeUpstreamClient.calls[2]["json"]["stream"] is False


def test_streaming_tool_call_is_checked(tmp_path, monkeypatch):
    stream = b"".join(
        [
            b'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c","function":{"name":"exec"}}]}}]}\n\n',
            b'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\\"command\\":\\"cat /etc/shadow\\"}"}}]}}]}\n\n',
            b'data: [DONE]\n\n',
        ]
    )
    app = _app(tmp_path, monkeypatch, FakeResponse(stream, "text/event-stream"))
    result = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "stream": True,
                "messages": [],
                "tools": [{"type": "function", "function": {"name": "exec", "parameters": {}}}],
            },
        )
    )
    assert result.status_code == 200
    assert "ClawGuard blocked" in result.text


def test_input_history_is_forwarded_without_rewrite(tmp_path, monkeypatch):
    response = FakeResponse({"choices": [{"message": {"role": "assistant", "content": "ok"}}]})
    app = _app(tmp_path, monkeypatch, response)
    token = "ghp_" + "A" * 36
    payload = {
        "model": "test",
        "messages": [{"role": "user", "content": f"token={token}"}],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "set_task_scope",
                    "parameters": {"type": "object"},
                },
            }
        ],
        "tool_choice": {"type": "function", "function": {"name": "set_task_scope"}},
    }
    result = asyncio.run(
        _post(app, payload)
    )
    assert result.status_code == 200
    # Forwarding is transparent even for a client-supplied control-tool schema.
    # The registry keeps that tool non-executable without rewriting the payload.
    assert FakeUpstreamClient.calls[0]["json"] == payload


def test_request_logging_writes_json_and_text_copies(tmp_path, monkeypatch):
    response = FakeResponse({"choices": [{"message": {"role": "assistant", "content": "ok"}}]})
    config_path = tmp_path / "config.yaml"
    rules_path = tmp_path / "rules.yaml"
    audit_path = tmp_path / "audit.db"
    log_dir = tmp_path / "logs"
    config_path.write_text(
        yaml.safe_dump(
            {
                "gateway": {
                    "upstream_base_url": "http://upstream.test/v1",
                    "request_logging": True,
                    "log_dir": str(log_dir),
                },
                "policy": {"approval_timeout": 0.05},
                "audit": {"db_path": str(audit_path)},
            }
        ),
        encoding="utf-8",
    )
    rules_path.write_text(yaml.safe_dump({}), encoding="utf-8")
    FakeUpstreamClient.response = response
    FakeUpstreamClient.calls = []
    monkeypatch.setattr(
        gateway,
        "httpx",
        SimpleNamespace(AsyncClient=FakeUpstreamClient, HTTPError=httpx.HTTPError),
    )
    app = create_gateway_app(str(config_path), str(rules_path))
    result = asyncio.run(
        _post(app, {"model": "test", "messages": [{"role": "user", "content": "hello log"}]})
    )
    assert result.status_code == 200
    json_files = list(log_dir.glob("*.json"))
    text_files = list(log_dir.glob("*.txt"))
    assert len(json_files) == 1
    assert len(text_files) == 1
    saved = json.loads(json_files[0].read_text(encoding="utf-8"))
    assert saved["messages"][0]["content"] == "hello log"
    text = text_files[0].read_text(encoding="utf-8")
    assert "[user]" in text
    assert "hello log" in text


def test_scope_planning_request_and_response_are_logged_when_request_logging_enabled(tmp_path, monkeypatch):
    planner_response = _scope_response(
        ["web_fetch"],
        network=["sunjun.site"],
        task_description="Find the latest publications on sunjun.site",
    )
    model_response = FakeResponse({"choices": [{"message": {"role": "assistant", "content": "Done."}}]})
    config_path = tmp_path / "config.yaml"
    rules_path = tmp_path / "rules.yaml"
    audit_path = tmp_path / "audit.db"
    log_dir = tmp_path / "logs"
    config_path.write_text(
        yaml.safe_dump(
            {
                "gateway": {
                    "upstream_base_url": "http://upstream.test/v1",
                    "request_logging": True,
                    "log_dir": str(log_dir),
                    "policy_mode": "strict",
                },
                "policy": {"approval_timeout": 0.05},
                "audit": {"db_path": str(audit_path)},
            }
        ),
        encoding="utf-8",
    )
    rules_path.write_text(yaml.safe_dump({}), encoding="utf-8")
    FakeUpstreamClient.responses = [planner_response, model_response]
    FakeUpstreamClient.response = None
    FakeUpstreamClient.calls = []
    monkeypatch.setattr(
        gateway,
        "httpx",
        SimpleNamespace(AsyncClient=FakeUpstreamClient, HTTPError=httpx.HTTPError),
    )
    app = create_gateway_app(str(config_path), str(rules_path))

    raw_user_content = "goto sunjun.site and find his most recent publications token=ghp_" + "A" * 36
    result = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": [{"role": "user", "content": raw_user_content}],
                "tools": [
                    {"type": "function", "function": {"name": "web_fetch", "parameters": {}}}
                ],
            },
        )
    )

    assert result.status_code == 200
    scope_json_files = list(log_dir.glob("scope-*.json"))
    scope_text_files = list(log_dir.glob("scope-*.txt"))
    assert len(scope_json_files) == len(scope_text_files) == 1
    saved = json.loads(scope_json_files[0].read_text(encoding="utf-8"))
    assert saved["original_user_message"]["content"] == raw_user_content
    assert "REDACTED" in saved["request"]["messages"][1]["content"]
    assert saved["request"]["tools"][0]["function"]["name"] == "set_task_scope"
    assert saved["response"]["status_code"] == 200
    assert saved["response"]["body"]["choices"][0]["message"]["tool_calls"][0]["function"]["name"] == (
        "set_task_scope"
    )
    text_log = scope_text_files[0].read_text(encoding="utf-8")
    assert "===== REQUEST SENT TO PLANNER =====" in text_log
    assert "===== ORIGINAL USER MESSAGE (UNSANITIZED) =====" in text_log
    assert raw_user_content in text_log
    assert "===== PLANNER RESPONSE =====" in text_log
    assert "sunjun.site" in text_log


def test_scope_allowlist_outranks_category_inference():
    """An explicit allowlist entry must survive the empty-category inference.

    A planner that selects ``web_search`` while declaring no network host used
    to have that choice revoked: the empty-network inference added
    ``http_request``, and the http alias group then matched ``web_search``.
    """
    from clawguard.rules import RuleEngine

    rules = RuleEngine()
    rules.set_task_scope("general web search", allowed_tools=["web_search"])
    assert rules.is_tool_allowed("web_search")
    assert not rules.is_tool_disabled("web_search")
    # Capabilities the caller left undeclared stay disabled.
    assert rules.is_tool_disabled("exec")
    assert rules.is_tool_disabled("write")

    # An explicit declaration still outranks the allowlist.
    strict = RuleEngine()
    strict.set_task_scope(
        "x", allowed_tools=["web_search"], disabled_tools=["web_search"]
    )
    assert strict.is_tool_disabled("web_search")

    # Legacy scopes carry no allowlist and keep their original behavior.
    legacy = RuleEngine()
    legacy.set_task_scope("read only", file_read=["README.md"])
    assert legacy.is_tool_disabled("exec")
    assert legacy.is_tool_disabled("web_fetch")
    assert not legacy.is_tool_disabled("read")


def test_stale_scope_allowlist_is_revalidated_when_catalog_changes(tmp_path, monkeypatch):
    """A cached scope must not keep authorizing a tool the client dropped.

    Mid-turn re-planning is refused by design, so the stored allowlist is
    re-validated against the tool catalog actually in force.
    """
    no_tool_response = FakeResponse(
        {"choices": [{"message": {"role": "assistant", "content": "Working on it."}}]}
    )
    stale_call = FakeResponse(
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "call_fetch",
                                "type": "function",
                                "function": {
                                    "name": "web_fetch",
                                    "arguments": '{"url":"http://sunjun.site/"}',
                                },
                            }
                        ],
                    }
                }
            ]
        }
    )
    app = _app(
        tmp_path,
        monkeypatch,
        [
            _scope_response(["web_fetch"], network=["sunjun.site"]),
            no_tool_response,
            stale_call,
            _text_response("Use only tools retained in the current catalog."),
        ],
    )
    headers = {"x-openclaw-session-key": "drift-session"}
    messages = [
        {"role": "user", "content": "goto sunjun.site and find his most recent publications"}
    ]

    first = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": messages,
                "tools": [{"type": "function", "function": {"name": "web_fetch", "parameters": {}}}],
            },
            headers,
        )
    )
    assert first.status_code == 200

    # Same user turn, but web_fetch has left the client's tool catalog.
    second = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": messages,
                "tools": [{"type": "function", "function": {"name": "exec", "parameters": {}}}],
            },
            headers,
        )
    )
    assert second.status_code == 200
    # One permission decision per user turn: no second planner call.
    assert len(FakeUpstreamClient.calls) == 4
    # The model received the re-validated allowlist denial as English feedback.
    assert "retained in the current catalog" in second.json()["choices"][0]["message"]["content"]

    entries = app.state.audit.query(action="model_tool_call", limit=200)
    rule_types = {
        json.loads(entry.details or "{}").get("rule_type") for entry in entries
    }
    assert "task_scope_catalog_changed" in rule_types


def test_base_match_is_final_and_scope_covers_the_rest():
    """Base rules decide first; the task scope only fills the gaps.

    A base denial or approval is final.  A base allow is necessary but not
    sufficient while task scope is active: the target must also be declared.
    When no base rule matched, the scope grants a declared action directly and
    denies an undeclared one.  With no active scope the base default stands.
    """
    from clawguard.rules import RuleEngine

    rules = RuleEngine(
        {
            "command_rules": {
                "blacklist": [
                    {"pattern": r"^curl\b", "action": "deny", "reason": "network via shell"}
                ],
                "whitelist": [{"pattern": r"^ls$", "action": "allow"}],
                "supervised": [
                    {"pattern": r"^cleanup\b", "action": "approve", "reason": "review cleanup"}
                ],
            },
            "file_rules": {"allowed_paths": [], "denied_paths": [], "sensitive_patterns": []},
            "network_rules": {
                "allowed_domains": ["api.internal"],
                "denied_domains": ["blocked.example"],
                "default_action": "approve",
            },
        }
    )
    rules.set_task_scope(
        "declaration",
        allowed_tools=["exec", "web_fetch"],
        commands=["pytest"],
        network=["sunjun.site"],
    )

    # A matched base rule is final: the scope neither weakens nor vetoes it.
    assert rules.check_command("curl http://evil.example").action.value == "deny"
    assert rules.check_command("rm -rf /").action.value == "deny"
    assert rules.check_command("cleanup archive").action.value == "approve"
    assert rules.check_network("https://blocked.example/x").action.value == "deny"
    assert rules.check_command("ls").action.value == "deny"
    assert rules.check_network("https://api.internal/v1").action.value == "deny"

    # No base rule matched, so the scope is the authorization.
    assert rules.check_command("pytest -q").action.value == "allow"
    assert rules.check_network("https://sunjun.site/x").action.value == "allow"
    assert rules.check_command("echo hi").action.value == "deny"

    # Without an active scope the base verdict stands unchanged: both an
    # unrecognized command and a host outside the base allow-list require human
    # approval rather than being granted implicitly.
    rules.clear_task_scope()
    assert rules.check_command("pytest -q").action.value == "approve"
    assert rules.check_network("https://sunjun.site/x").action.value == "approve"
    assert rules.check_network("https://blocked.example/x").action.value == "deny"


def test_task_scope_cannot_override_base_network_deny_list(tmp_path, monkeypatch):
    """A declared host must not bypass the base network deny-list."""
    response = FakeResponse(
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "fetch_evil",
                                "type": "function",
                                "function": {
                                    "name": "web_fetch",
                                    "arguments": '{"url":"https://evil.example/"}',
                                },
                            }
                        ],
                    }
                }
            ]
        }
    )
    app = _app(
        tmp_path,
        monkeypatch,
        [_scope_response(["web_fetch"], network=["evil.example"]), response],
        denied_domains=["evil.example"],
    )
    result = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": [{"role": "user", "content": "read https://evil.example/"}],
                "tools": [{"type": "function", "function": {"name": "web_fetch", "parameters": {}}}],
            },
        )
    )
    assert result.status_code == 200
    assert "tool_calls" not in result.json()["choices"][0]["message"]


def test_task_scope_cannot_override_base_denied_path(tmp_path, monkeypatch):
    """Declaring a path must not bypass the base denied_paths list."""
    denied_root = str(tmp_path / "vault")
    secret = os.path.join(denied_root, "notes.txt")
    response = FakeResponse(
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "read_notes",
                                "type": "function",
                                "function": {
                                    "name": "read_file",
                                    "arguments": json.dumps({"path": secret}),
                                },
                            }
                        ],
                    }
                }
            ]
        }
    )
    app = _app(
        tmp_path,
        monkeypatch,
        [_scope_response(["read_file"], file_read=[secret]), response],
        denied_paths=[denied_root],
    )
    result = asyncio.run(
        _post(
            app,
            {
                "model": "test",
                "messages": [{"role": "user", "content": f"read {secret}"}],
                "tools": [{"type": "function", "function": {"name": "read_file", "parameters": {}}}],
            },
        )
    )
    assert result.status_code == 200
    assert "tool_calls" not in result.json()["choices"][0]["message"]


def test_file_scope_covers_paths_with_no_base_rule(tmp_path):
    """A path with no base allow/deny rule is decided by the task scope.

    A path the base allow/deny lists do not mention stays approval-gated when
    no scope is active; the scope is what turns declaration into direct access.
    """
    from clawguard.rules import RuleEngine

    target = str(tmp_path / "notes.txt")
    other = str(tmp_path / "other.txt")
    rules = RuleEngine(
        {"file_rules": {"allowed_paths": [], "denied_paths": [], "sensitive_patterns": []}}
    )

    rules.set_task_scope("read notes", file_read=[target])
    assert rules.check_file_path(target).action.value == "allow"
    assert rules.check_file_path(other).action.value == "deny"

    # Without a scope the base default stays approval-gated.
    rules.clear_task_scope()
    assert rules.check_file_path(target).action.value == "approve"


def test_indirect_reads_of_denied_paths_are_caught(tmp_path):
    """A wrapper must not smuggle a denied path past file_rules.

    Path extraction used to require a POSIX ``/`` or ``~/`` prefix, and the
    script analyzer ignored Windows drive paths and ``r"..."`` literals, so on
    Windows nearly every indirect read ran unchecked.
    """
    from clawguard.rules import RuleEngine

    vault = tmp_path / "vault"
    vault.mkdir()
    secret = vault / "secret.txt"
    secret.write_text("TOPSECRET", encoding="utf-8")
    reader = tmp_path / "reader.py"
    reader.write_text("print(open(r'%s').read())\n" % secret, encoding="utf-8")
    shell_reader = tmp_path / "reader.sh"
    shell_reader.write_text('cat "%s"\n' % str(secret).replace("\\", "/"), encoding="utf-8")

    rules = RuleEngine(
        {
            "command_rules": {"blacklist": [], "whitelist": [], "supervised": []},
            "file_rules": {
                "allowed_paths": [],
                "denied_paths": [str(vault)],
                "sensitive_patterns": [],
            },
            "network_rules": {
                "allowed_domains": [],
                "denied_domains": [],
                "default_action": "approve",
            },
        }
    )

    windows_path = str(secret)
    forward_path = str(secret).replace("\\", "/")

    commands = [
        "cat " + windows_path,
        'cat "' + forward_path + '"',
        "base64 " + forward_path,
        "dd if=" + forward_path,
        "grep -r TOPSECRET " + forward_path,
        "sed -n 1p " + forward_path,
        "find " + str(vault).replace("\\", "/"),
        'python -c "print(open(r\'' + windows_path + '\').read())"',
        'python -c "from pathlib import Path; print(Path(r\'' + windows_path + '\').read_text())"',
        'bash -c "cat ' + forward_path + '"',
        "python " + str(reader),
        "bash " + str(shell_reader),
    ]
    for command in commands:
        assert rules.check_command(command).action.value == "deny", command


def test_script_paths_with_no_rule_do_not_force_approval(tmp_path):
    """Only explicit rule hits are reported from script literals.

    A path with no file rule stays a matter for the tool-call policy, so a
    script that merely names an absolute path does not become an approval
    prompt, while an explicitly sensitive path still does.
    """
    from clawguard.rules import RuleEngine
    from clawguard.script_analyzer import ScriptAnalyzer

    rules = RuleEngine(
        {
            "file_rules": {
                "allowed_paths": [],
                "denied_paths": [],
                "sensitive_patterns": ["*.pem"],
            }
        }
    )
    analyzer = ScriptAnalyzer(rule_engine=rules)

    plain = tmp_path / "tool.py"
    plain.write_text('TOOL = "/usr/local/bin/thing"\nprint(TOOL)\n', encoding="utf-8")
    assert analyzer.analyze(str(plain)).recommended_action == "allow"

    key = tmp_path / "keys" / "service.pem"
    key.parent.mkdir()
    key.write_text("PRIVATE", encoding="utf-8")
    reader = tmp_path / "read_key.py"
    reader.write_text("print(open(r'%s').read())\n" % key, encoding="utf-8")
    assert analyzer.analyze(str(reader)).recommended_action == "approve"


def test_explicit_port_cannot_bypass_base_network_blocks():
    """A host:port URL must not dodge the deny-list or the private-IP block.

    Base network rules used to compare against ``netloc`` (host *and* port),
    so ``http://127.0.0.1:8080/`` and a deny-listed host on an explicit port
    both slipped through.
    """
    from clawguard.rules import RuleEngine

    rules = RuleEngine(
        {
            "command_rules": {"blacklist": [], "whitelist": [], "supervised": []},
            "file_rules": {"allowed_paths": [], "denied_paths": [], "sensitive_patterns": []},
            "network_rules": {
                "allowed_domains": ["sunjun.site"],
                "denied_domains": ["evil.example"],
                "default_action": "deny",
            },
        }
    )

    assert rules.check_network("https://evil.example:443/x").action.value == "deny"
    assert rules.check_network("http://127.0.0.1:8080/x").action.value == "deny"
    assert rules.check_network("https://sunjun.site:443/x").action.value == "allow"


def test_policy_overlap_detection_flags_obvious_allow_deny_conflicts():
    """An allow entry that collides with a deny entry is dead policy."""
    from clawguard.rules import find_policy_overlaps

    overlaps = find_policy_overlaps(
        {
            "file_rules": {
                "allowed_paths": ["~/work", "~/notes.md"],
                "denied_paths": ["~/work/secret/**", "/etc/shadow"],
            },
            "network_rules": {
                "allowed_domains": ["api.example.com", "docs.example.com"],
                "denied_domains": ["*.example.com", "pastebin.com"],
            },
        }
    )

    assert any(
        "allowed_paths '~/work'" in item and "denied_paths '~/work/secret/**'" in item
        for item in overlaps
    )
    assert any("allowed_domains 'api.example.com'" in item for item in overlaps)
    assert not any("~/notes.md" in item for item in overlaps)
    assert not any("pastebin.com" in item for item in overlaps)


def test_policy_overlap_detection_is_silent_for_the_shipped_defaults():
    from clawguard.rules import find_policy_overlaps

    with open("config/rules.yaml", encoding="utf-8") as handle:
        config = yaml.safe_load(handle)

    assert find_policy_overlaps(config) == []


def test_engine_records_policy_overlaps():
    from clawguard.rules import RuleEngine

    rules = RuleEngine(
        {
            "file_rules": {
                "allowed_paths": ["/srv/data"],
                "denied_paths": ["/srv/data/private"],
                "sensitive_patterns": [],
            },
            "network_rules": {"allowed_domains": [], "denied_domains": []},
        }
    )

    assert len(rules.policy_overlaps) == 1
    assert "denied_paths '/srv/data/private'" in rules.policy_overlaps[0]
