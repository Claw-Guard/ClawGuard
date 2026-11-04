import json
from pathlib import Path

import pytest
import yaml

from clawguard.adapters import agent_adapters
from clawguard.gateway import (
    GatewaySettings,
    _augment_scope_for_agent_web_research,
    _augment_scope_for_local_file_targets,
    _augment_scope_for_read_only_agent_navigation,
    _augment_scope_for_skill_install_url,
    _augment_scope_with_verified_skill_paths,
    _skill_inspector_options,
    classify_tool_call,
    create_gateway_app,
)
from clawguard.rules import RuleEngine


def test_agent_validation_and_skill_roots():
    assert agent_adapters.normalize_agent("CODEX") == "codex"
    assert agent_adapters.normalize_agent("claude") == "claude"
    with pytest.raises(ValueError):
        agent_adapters.normalize_agent("unknown")

    assert agent_adapters.skill_roots("codex") == (
        "/home/node/.codex/skills",
        "/home/node/.agents/skills",
        "/etc/codex/skills",
    )
    assert agent_adapters.skill_roots("claude") == ("/home/node/.claude/skills",)
    assert "~/.openclaw" not in "".join(agent_adapters.skill_roots("codex"))
    assert "exec_command" in agent_adapters.native_tool_names("codex")
    assert agent_adapters.is_native_tool("codex", "exec_command")
    assert not agent_adapters.is_native_tool("codex", "plugin_action")


def test_codex_registry_is_normalized_to_policy_tool_names():
    registry = agent_adapters.canonicalize_tool_registry(
        "codex",
        {
            "exec_command": {"name": "exec_command"},
            "view_image": {"name": "view_image"},
            "apply_patch": {"name": "apply_patch"},
        },
    )
    assert set(registry) == {"exec", "read", "apply_patch"}
    assert registry["exec"]["agent_tool_name"] == "exec_command"


def test_openclaw_bridged_web_tools_are_policy_known_without_payload_rewrite():
    registry = agent_adapters.canonicalize_tool_registry(
        "openclaw",
        {
            "tool_search": {"name": "tool_search"},
            "tool_call": {"name": "tool_call"},
            "exec": {"name": "exec"},
        },
    )
    assert {"tool_search", "tool_call", "exec", "web_fetch", "web_search"} <= set(
        registry
    )

    rules = RuleEngine()
    rules.set_task_scope(
        "Read one named website",
        allowed_tools=["web_fetch"],
        network=["sunjun.site"],
    )
    match = classify_tool_call(
        {
            "name": "web_fetch",
            "arguments": json.dumps(
                {"url": "https://sunjun.site/publications/"}
            ),
        },
        registry,
        rules,
        GatewaySettings(agent="openclaw"),
    )
    assert match.action.value == "allow"
    assert match.rule_type == "task_scope"


def test_skill_inspector_resolves_relative_sources_from_agent_workspace(
    tmp_path, monkeypatch
):
    workspace = tmp_path / "workspace"
    source = workspace / "fixtures" / "skills-src" / "safe-example"
    source.mkdir(parents=True)
    (source / "SKILL.md").write_text(
        "---\nname: safe-example\ndescription: test\n---\nRead only.\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENCLAW_STATE_DIR", str(tmp_path / ".openclaw"))
    monkeypatch.setenv("OPENCLAW_WORKSPACE_DIR", str(workspace))

    options = _skill_inspector_options(None, data_dir=str(tmp_path / "data"))
    roots = {str(Path(root).resolve()) for root in options["roots"]}
    assert str(workspace.resolve()) in roots


def test_codex_headers_are_filtered_before_upstream():
    headers = agent_adapters.filter_upstream_headers(
        "codex",
        {
            "Authorization": "Bearer test",
            "Content-Type": "application/json",
            "originator": "codex_cli_rs",
            "OpenAI-Beta": "responses=experimental",
            "x-codex-turn-metadata": "{}",
            "x-stainless-runtime": "rust",
            "X-Custom": "keep",
        },
    )
    assert headers == {
        "Authorization": "Bearer test",
        "Content-Type": "application/json",
    }


def test_codex_web_scope_is_completed_by_the_gateway():
    scope = {
        "task_description": "Visit one website",
        "allowed_tools": ["exec"],
        "network": ["sunjun.site"],
        "commands": [],
        "file_read": [],
        "file_write": [],
        "disabled_tools": [],
    }

    result = _augment_scope_for_agent_web_research(
        scope,
        {"exec": {"name": "exec"}},
        GatewaySettings(agent="codex", upstream_format="openai_response"),
    )

    assert {"curl", "wget", "cat", "head", "grep", "wc"} <= set(
        result["commands"]
    )
    assert result["file_read"] == ["/tmp"]
    assert result["file_write"] == ["/tmp"]

    openclaw_result = _augment_scope_for_agent_web_research(
        scope,
        {"exec": {"name": "exec"}},
        GatewaySettings(agent="openclaw"),
    )
    assert openclaw_result["commands"] == result["commands"]
    assert openclaw_result["file_read"] == ["/tmp"]


def test_github_scope_includes_the_official_api_host():
    result = _augment_scope_for_agent_web_research(
        {
            "task_description": "Search GitHub",
            "allowed_tools": ["web_search"],
            "network": ["github.com"],
            "commands": [],
            "file_read": [],
            "file_write": [],
            "disabled_tools": [],
        },
        {"web_search": {"name": "web_search"}},
        GatewaySettings(agent="openclaw"),
    )
    assert result["network"] == [
        "github.com",
        "api.github.com",
        "raw.githubusercontent.com",
        "codeload.github.com",
    ]


def test_shell_agent_scope_gets_read_only_navigation_commands():
    result = _augment_scope_for_read_only_agent_navigation(
        {
            "allowed_tools": ["exec"],
            "commands": ["cat"],
        },
        {"exec": {"name": "exec"}},
    )
    assert {"cat", "cd", "pwd", "ls", "find", "git status", "git log"} <= set(
        result["commands"]
    )


def test_local_file_targets_add_their_common_input_root(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    docs = workspace / "fixtures" / "docs"
    docs.mkdir(parents=True)
    first = docs / "overview.md"
    second = docs / "notes.md"
    first.write_text("one", encoding="utf-8")
    second.write_text("two", encoding="utf-8")
    monkeypatch.setenv("OPENCLAW_WORKSPACE_DIR", str(workspace))

    result = _augment_scope_for_local_file_targets(
        {"file_read": [], "file_write": []},
        "Read `fixtures/docs/overview.md` and `fixtures/docs/notes.md`, "
        "then write `fixtures/output/report.md`.",
    )

    assert str(docs.resolve()) in result["file_read"]
    assert str((workspace / "fixtures" / "output" / "report.md").resolve()) in result[
        "file_write"
    ]


def test_scoped_web_search_does_not_require_a_fake_url():
    rules = RuleEngine()
    rules.set_task_scope(
        "Search GitHub for release readiness examples",
        allowed_tools=["web_search"],
        network=["github.com"],
    )
    match = classify_tool_call(
        {
            "name": "web_search",
            "arguments": json.dumps({"query": "release readiness dashboard"}),
        },
        {"web_search": {"name": "web_search", "parameters": {}}},
        rules,
        GatewaySettings(agent="openclaw"),
    )
    assert match.action.value == "allow"
    assert match.rule_type == "task_scope"


def test_relative_local_skill_install_adds_source_and_safe_destination(
    tmp_path, monkeypatch
):
    workspace = tmp_path / "workspace"
    source = workspace / "fixtures" / "skills-src" / "safe-example"
    source.mkdir(parents=True)
    (source / "SKILL.md").write_text(
        "---\nname: safe-example\ndescription: test\n---\nRead only.\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENCLAW_WORKSPACE_DIR", str(workspace))
    monkeypatch.setenv("OPENCLAW_STATE_DIR", str(tmp_path / ".openclaw"))
    codex_home = tmp_path / ".codex"
    installer_skill = (
        codex_home / "skills" / ".system" / "skill-installer" / "SKILL.md"
    )
    installer_skill.parent.mkdir(parents=True)
    installer_skill.write_text(
        "---\nname: skill-installer\ndescription: test\n---\nRead only.\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CODEX_HOME", str(codex_home))

    augmented = _augment_scope_for_skill_install_url(
        {
            "task_description": "Install a local Skill",
            "allowed_tools": ["read"],
            "file_read": [],
            "file_write": [],
            "commands": [],
            "network": [],
            "disabled_tools": [],
        },
        "从 `fixtures/skills-src/safe-example` 安装 Skill。",
        {
            "exec": {"name": "exec"},
            "read": {"name": "read"},
            "openclaw": {"name": "openclaw"},
        },
        agent="codex",
    )

    assert str(source.resolve()) in augmented["file_read"]
    assert str((workspace / "fixtures").resolve()) in augmented["file_read"]
    assert str(installer_skill.resolve()) in augmented["file_read"]
    assert str((codex_home / "skills").resolve()) in augmented["directory_list"]
    assert str((workspace / "skills").resolve()) in augmented["file_write"]
    assert any(
        Path(path).as_posix().endswith("/.codex/skills")
        for path in augmented["file_write"]
    )
    assert {"mkdir", "cp", "install", "find", "openclaw skills install"} <= set(
        augmented["commands"]
    )


def test_verified_skill_scope_paths_stay_inside_agent_workspace(tmp_path):
    scope = {
        "file_read": [],
        "file_write": [],
    }
    augmented = _augment_scope_with_verified_skill_paths(
        scope,
        {
            "file_reads": [
                "clawguard-utility-fixtures/docs/overview.md",
                "../../../etc/passwd",
                "/etc/shadow",
            ],
            "file_writes": ["clawguard-utility-fixtures/output/*.md"],
        },
        str(tmp_path),
    )

    assert augmented["file_read"] == [
        str(tmp_path / "clawguard-utility-fixtures/docs/overview.md")
    ]
    assert augmented["file_write"] == [
        str(tmp_path / "clawguard-utility-fixtures/output/*.md")
    ]


def test_codex_skill_context_is_extracted_from_responses_input():
    contexts = agent_adapters.extract_skill_contexts(
        {
            "input": [
                {
                    "type": "message",
                    "role": "developer",
                    "content": (
                        "<skill><name>probe</name>"
                        "<path>/home/node/.agents/skills/probe/SKILL.md</path>"
                        "Use exec_command exactly once.</skill>"
                    ),
                }
            ]
        }
    )
    assert contexts == [
        {
            "name": "probe",
            "path": "/home/node/.agents/skills/probe/SKILL.md",
        }
    ]


def test_codex_exec_command_uses_the_shared_command_rules():
    rules = RuleEngine(
        {
            "command_rules": {
                "blacklist": [
                    {
                        "pattern": r"cat\s+/etc/shadow",
                        "action": "deny",
                        "reason": "secret file",
                    }
                ],
            },
            "file_rules": {"denied_paths": ["/etc/shadow"]},
            "network_rules": {},
        }
    )
    registry = agent_adapters.canonicalize_tool_registry(
        "codex",
        {"exec_command": {"name": "exec_command"}},
    )
    match = classify_tool_call(
        {
            "name": "exec_command",
            "arguments": json.dumps({"cmd": "cat /etc/shadow"}),
        },
        registry,
        rules,
        GatewaySettings(agent="codex", upstream_format="openai_response"),
    )
    assert match.action.value == "deny"
    assert match.rule_type in {"command_blacklist", "command_file_check"}


def test_codex_write_stdin_requires_approval_for_actual_input():
    rules = RuleEngine(
        {
            "command_rules": {},
            "file_rules": {},
            "network_rules": {},
        }
    )
    registry = agent_adapters.canonicalize_tool_registry(
        "codex",
        {"write_stdin": {"name": "write_stdin"}},
    )
    settings = GatewaySettings(agent="codex", upstream_format="openai_response")
    inject = classify_tool_call(
        {
            "name": "write_stdin",
            "arguments": json.dumps({"session_id": "1", "chars": "rm file\n"}),
        },
        registry,
        rules,
        settings,
    )
    poll = classify_tool_call(
        {
            "name": "write_stdin",
            "arguments": json.dumps({"session_id": "1", "chars": ""}),
        },
        registry,
        rules,
        settings,
    )
    assert inject.action.value == "approve"
    assert inject.rule_type == "codex_write_stdin"
    assert poll.action.value == "allow"
    assert poll.rule_type == "agent_control"


def test_agent_environment_switch(monkeypatch):
    monkeypatch.setenv("CLAWGUARD_AGENT", "codex")
    settings = GatewaySettings.from_files()
    assert settings.agent == "codex"


def test_agent_default_data_directories_are_isolated(monkeypatch):
    root = Path.home() / ".clawguard"
    openclaw = GatewaySettings(agent="openclaw")
    codex = GatewaySettings(agent="codex")
    claude = GatewaySettings(agent="claude")
    assert Path(openclaw.data_dir) == root / "agents" / "openclaw"
    assert Path(codex.data_dir) == root / "agents" / "codex"
    assert Path(claude.data_dir) == root / "agents" / "claude"
    assert Path(openclaw.log_dir) == root / "agents" / "openclaw" / "logs"
    assert len({openclaw.data_dir, codex.data_dir, claude.data_dir}) == 3

    isolated = str(Path.home() / ".clawguard" / "isolated")
    monkeypatch.setenv("CLAWGUARD_AGENT", "codex")
    monkeypatch.setenv("CLAWGUARD_DATA_DIR", isolated)
    settings = GatewaySettings.from_files()
    assert settings.data_dir == isolated
    assert settings.log_dir == str(Path(isolated) / "logs")


def test_audit_database_uses_agent_data_directory(tmp_path):
    config_path = tmp_path / "config.yaml"
    rules_path = tmp_path / "rules.yaml"
    data_dir = tmp_path / "codex-data"
    config_path.write_text(
        yaml.safe_dump(
            {
                "gateway": {
                    "agent": "codex",
                    "data_dir": str(data_dir),
                    "upstream_format": "openai_response",
                    "enable_responses_api": True,
                },
                "audit": {"db_path": None},
            }
        ),
        encoding="utf-8",
    )
    rules_path.write_text(yaml.safe_dump({}), encoding="utf-8")
    settings = GatewaySettings.from_files(str(config_path))
    app = create_gateway_app(str(config_path), str(rules_path), settings)
    assert Path(app.state.audit.db_path) == data_dir / "audit.db"
    assert Path(app.state.data_dir) == data_dir


def test_dashboard_displays_current_agent_and_data_dir():
    dashboard = (
        Path(__file__).resolve().parents[1]
        / "clawguard"
        / "dashboard"
        / "app-enhanced.js"
    ).read_text(encoding="utf-8")
    assert "data.agent" in dashboard
    assert "data.upstream_format" in dashboard
    assert "data.data_dir" in dashboard
    assert "Agent:" in dashboard
