import json

from clawguard.gateway import (
    GatewaySettings,
    _augment_scope_for_agent_web_research,
    evaluate_tool_call,
)
from clawguard.rules import RuleEngine


def _rules():
    rules = RuleEngine(
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
        "Fetch one declared website",
        allowed_tools=["web_fetch"],
        network=["sunjun.site"],
        capability_adapters=True,
    )
    return rules


def _exec(command):
    return {
        "id": "exec-network-alias",
        "name": "exec",
        "arguments": json.dumps({"command": command}),
    }


def _capability_only_rules(network=None):
    rules = RuleEngine()
    rules.command_working_dir = "/home/node/.openclaw/workspace"
    rules.set_task_scope(
        "Use safe capabilities without explicit command names",
        allowed_tools=["exec"],
        network=list(network or ["sunjun.site"]),
        file_read=["/tmp"],
        file_write=["/tmp"],
        commands=[],
        capability_adapters=False,
    )
    return rules


def test_exec_wget_stdout_uses_read_only_web_fetch_capability():
    decision = evaluate_tool_call(
        _exec("wget -qO- https://sunjun.site/publications"),
        {"exec": {"name": "exec"}},
        _rules(),
        GatewaySettings(),
    )

    assert decision.action == "allow"
    assert decision.rule_type == "task_scope"
    assert decision.target == "sunjun.site"
    assert decision.facts is not None
    assert decision.facts.authorization_capabilities == ("network_read",)
    assert decision.facts.adapter_name == "exec_wget_read"


def test_safe_web_pipeline_needs_network_scope_not_command_allowlist():
    decision = evaluate_tool_call(
        _exec(
            "curl -s https://sunjun.site/publications/ "
            "| grep -E 'ICLR|ICML' | head -20"
        ),
        {"exec": {"name": "exec"}},
        _capability_only_rules(),
        GatewaySettings(agent="codex"),
    )

    assert decision.action == "allow"
    assert decision.rule_type == "safe_capability"


def test_safe_capability_does_not_override_denied_host_or_file():
    denied_host = evaluate_tool_call(
        _exec("curl -s https://blocked.example/data"),
        {"exec": {"name": "exec"}},
        _capability_only_rules(network=["sunjun.site"]),
        GatewaySettings(agent="codex"),
    )
    denied_file = evaluate_tool_call(
        _exec("cat /etc/passwd"),
        {"exec": {"name": "exec"}},
        _capability_only_rules(),
        GatewaySettings(agent="codex"),
    )

    assert denied_host.action == "deny"
    assert denied_file.action == "deny"


def test_safe_capability_does_not_authorize_unknown_or_upload_commands():
    rules = _capability_only_rules()
    unknown = evaluate_tool_call(
        _exec("whoami"),
        {"exec": {"name": "exec"}},
        rules,
        GatewaySettings(agent="codex"),
    )
    upload = evaluate_tool_call(
        _exec("curl -d @/tmp/data https://sunjun.site/upload"),
        {"exec": {"name": "exec"}},
        rules,
        GatewaySettings(agent="codex"),
    )

    assert unknown.action == "deny"
    # Upload/write is not auto-authorized by the read-only capability adapter.
    assert upload.action == "approve"


def test_disk_tokens_as_grep_data_do_not_trigger_disk_command_denial():
    rules = _capability_only_rules()
    grep_data = evaluate_tool_call(
        _exec("grep 'mkfs' /tmp/pubs.html"),
        {"exec": {"name": "exec"}},
        rules,
        GatewaySettings(agent="codex"),
    )
    mkfs = evaluate_tool_call(
        _exec("mkfs.ext4 /dev/sda1"),
        {"exec": {"name": "exec"}},
        rules,
        GatewaySettings(agent="codex"),
    )
    dd = evaluate_tool_call(
        _exec("dd if=/tmp/input of=/tmp/output"),
        {"exec": {"name": "exec"}},
        rules,
        GatewaySettings(agent="codex"),
    )

    assert grep_data.action == "allow"
    assert mkfs.action == "deny"
    assert mkfs.rule_type == "prohibited_runtime_exec"
    assert dd.action == "deny"
    assert dd.rule_type == "prohibited_runtime_exec"


def test_quoted_regex_alternation_is_not_treated_as_shell_pipeline():
    decision = evaluate_tool_call(
        _exec(
            'curl -s https://sunjun.site/publications/ '
            '| grep -E "ICLR|ICML|ACL" | head -20'
        ),
        {"exec": {"name": "exec"}},
        _rules(),
        GatewaySettings(),
    )

    assert decision.action == "allow"
    assert decision.rule_type == "command_network_allowed"


def test_exec_wget_file_output_is_not_granted_as_web_fetch():
    decision = evaluate_tool_call(
        _exec("wget https://sunjun.site/publications"),
        {"exec": {"name": "exec"}},
        _rules(),
        GatewaySettings(),
    )

    assert decision.action == "deny"
    assert decision.rule_type == "tool_network_file_write"


def test_find_is_read_only_but_exec_or_delete_actions_are_prohibited():
    rules = RuleEngine()
    rules.command_working_dir = "/home/node/.openclaw/workspace"
    rules.set_task_scope(
        "Inspect fixture files",
        allowed_tools=["exec"],
        file_read=["clawguard-utility-fixtures"],
        commands=["find"],
    )
    settings = GatewaySettings(agent="codex")
    registry = {"exec": {"name": "exec"}}

    listed = evaluate_tool_call(
        _exec(
            "find clawguard-utility-fixtures -maxdepth 3 -type f"
        ),
        registry,
        rules,
        settings,
    )
    deleted = evaluate_tool_call(
        _exec(
            "find clawguard-utility-fixtures -type f -delete"
        ),
        registry,
        rules,
        settings,
    )

    assert listed.action == "allow"
    assert deleted.action == "deny"
    assert deleted.rule_type == "prohibited_runtime_exec"


def test_exec_wget_cannot_bypass_base_network_denial():
    rules = RuleEngine(
        {
            "command_rules": {},
            "file_rules": {},
            "network_rules": {
                "allowed_domains": [],
                "denied_domains": ["blocked.example"],
                "default_action": "approve",
            },
        }
    )
    rules.set_task_scope(
        "Attempt a denied host",
        allowed_tools=["web_fetch"],
        network=["blocked.example"],
        capability_adapters=True,
    )

    decision = evaluate_tool_call(
        _exec("wget -qO- https://blocked.example/data"),
        {"exec": {"name": "exec"}},
        rules,
        GatewaySettings(),
    )

    assert decision.action == "deny"


def test_agent_web_scope_distinguishes_wget_stdout_and_file_output():
    for agent in ("codex", "openclaw"):
        settings = GatewaySettings(
            agent=agent,
            upstream_format=(
                "openai_response" if agent == "codex" else "openai_chat_completion"
            ),
        )
        scope = _augment_scope_for_agent_web_research(
            {
                "task_description": "Fetch the declared site",
                "allowed_tools": ["exec"],
                "network": ["sunjun.site"],
                "commands": [],
                "file_read": [],
                "file_write": [],
                "disabled_tools": [],
            },
            {"exec": {"name": "exec"}},
            settings,
        )
        rules = RuleEngine(
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
            scope["task_description"],
            file_read=scope["file_read"],
            file_write=scope["file_write"],
            commands=scope["commands"],
            network=scope["network"],
            allowed_tools=scope["allowed_tools"],
            capability_adapters=True,
        )

        stdout_read = evaluate_tool_call(
            _exec("wget -qO- https://sunjun.site/publications"),
            {"exec": {"name": "exec"}},
            rules,
            settings,
        )
        tmp_write = evaluate_tool_call(
            _exec(
                "wget -q -O /tmp/sunjun-publications.html "
                "https://sunjun.site/publications"
            ),
            {"exec": {"name": "exec"}},
            rules,
            settings,
        )
        file_write = evaluate_tool_call(
            _exec("wget https://sunjun.site/publications"),
            {"exec": {"name": "exec"}},
            rules,
            settings,
        )

        assert stdout_read.action == "allow"
        assert tmp_write.action == "allow"
        assert tmp_write.facts is not None
        assert tmp_write.facts.authorization_capabilities == (
            "network_read",
            "file_write",
        )
        assert file_write.action == "deny"
        assert file_write.rule_type == "tool_network_file_write"


def test_tmp_web_cache_is_denied_when_tmp_is_a_base_denied_folder():
    settings = GatewaySettings(agent="codex", upstream_format="openai_response")
    scope = _augment_scope_for_agent_web_research(
        {
            "task_description": "Fetch the declared site",
            "allowed_tools": ["exec"],
            "network": ["sunjun.site"],
            "commands": [],
            "file_read": [],
            "file_write": [],
            "disabled_tools": [],
        },
        {"exec": {"name": "exec"}},
        settings,
    )
    rules = RuleEngine(
        {
            "command_rules": {},
            "file_rules": {"denied_paths": ["/tmp", "/tmp/**"]},
            "network_rules": {
                "allowed_domains": [],
                "denied_domains": [],
                "default_action": "approve",
            },
        }
    )
    rules.set_task_scope(
        scope["task_description"],
        file_read=scope["file_read"],
        file_write=scope["file_write"],
        commands=scope["commands"],
        network=scope["network"],
        allowed_tools=scope["allowed_tools"],
        capability_adapters=True,
    )

    decision = evaluate_tool_call(
        _exec(
            "wget -q -O /tmp/sunjun-publications.html "
            "https://sunjun.site/publications"
        ),
        {"exec": {"name": "exec"}},
        rules,
        settings,
    )

    assert decision.action == "deny"
    assert decision.rule_type in {"file_denied", "task_scope_restriction"}


def test_exec_cannot_escape_into_python_or_shell_runtime_commands():
    settings = GatewaySettings(agent="codex", upstream_format="openai_response")
    scope = _augment_scope_for_agent_web_research(
        {
            "task_description": "Fetch the declared site",
            "allowed_tools": ["exec"],
            "network": ["sunjun.site"],
            "commands": [],
            "file_read": [],
            "file_write": [],
            "disabled_tools": [],
        },
        {"exec": {"name": "exec"}},
        settings,
    )
    rules = RuleEngine(
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
        scope["task_description"],
        file_read=scope["file_read"],
        file_write=scope["file_write"],
        commands=scope["commands"],
        network=scope["network"],
        allowed_tools=scope["allowed_tools"],
        capability_adapters=True,
    )

    safe_read = evaluate_tool_call(
        _exec("curl -sL https://sunjun.site/publications | head -c 12000"),
        {"exec": {"name": "exec"}},
        rules,
        settings,
    )
    python_runtime = evaluate_tool_call(
        _exec('python3 -c "print(123)"'),
        {"exec": {"name": "exec"}},
        rules,
        settings,
    )
    shell_exec = evaluate_tool_call(
        _exec("exec curl -sL https://sunjun.site"),
        {"exec": {"name": "exec"}},
        rules,
        settings,
    )

    assert safe_read.action == "allow"
    assert python_runtime.action == "deny"
    assert python_runtime.rule_type == "prohibited_runtime_exec"
    assert shell_exec.action == "deny"
    assert shell_exec.rule_type == "prohibited_runtime_exec"
