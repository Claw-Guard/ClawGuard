import json
import tempfile
from pathlib import Path

import yaml

from clawguard.gateway import GatewaySettings, classify_tool_call
from clawguard.rules import ActionType, RuleEngine


def assert_action(actual, expected, label):
    assert actual.action == expected, (
        f"{label}: expected {expected.value}, got {actual.action.value}: "
        f"{actual.reason}"
    )


def main():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        allowed = root / "allowed"
        denied = root / "denied"
        allowed.mkdir()
        denied.mkdir()
        (allowed / "input.txt").write_text("allowed\n", encoding="utf-8")
        (allowed / "secret.txt").write_text("sensitive\n", encoding="utf-8")
        (denied / "secret.txt").write_text("denied\n", encoding="utf-8")

        config_path = Path(__file__).resolve().parents[1] / "config" / "rules.yaml"
        with open(config_path, encoding="utf-8") as handle:
            config = yaml.safe_load(handle)
        config["file_rules"]["allowed_paths"] = [str(allowed)]
        config["file_rules"]["denied_paths"] = [str(denied)]
        config["network_rules"]["allowed_domains"] = ["allowed.example"]
        config["network_rules"]["denied_domains"] = ["denied.example"]

        # Base DENY must win even when Task Scope explicitly grants the target.
        engine = RuleEngine(config)
        engine.set_task_scope(
            "scope grants denied targets",
            file_read=[str(denied)],
            file_write=[str(denied)],
            commands=["pwd", "rm -rf /"],
            network=["denied.example"],
            allowed_tools=["read", "write", "exec", "web_fetch"],
        )
        assert_action(
            engine.check_file_path(str(denied / "secret.txt"), "read"),
            ActionType.DENY,
            "base file deny vs scope allow",
        )
        assert_action(
            engine.check_file_path(str(denied / "new.txt"), "write"),
            ActionType.DENY,
            "base file write deny vs scope allow",
        )
        assert_action(
            engine.check_network("https://denied.example/path"),
            ActionType.DENY,
            "base network deny vs scope allow",
        )
        assert_action(
            engine.check_command("rm -rf /"),
            ActionType.DENY,
            "base command deny vs scope allow",
        )

        # Base ALLOW does not bypass a restrictive Task Scope.
        engine = RuleEngine(config)
        engine.set_task_scope(
            "scope has no targets",
            file_read=[],
            file_write=[],
            commands=[],
            network=[],
            allowed_tools=["read", "write", "exec", "web_fetch"],
        )
        assert_action(
            engine.check_file_path(str(allowed / "input.txt"), "read"),
            ActionType.DENY,
            "base file allow vs empty scope",
        )
        assert_action(
            engine.check_network("https://allowed.example/path"),
            ActionType.DENY,
            "base network allow vs empty scope",
        )
        assert_action(
            engine.check_command("pwd"),
            ActionType.DENY,
            "base command allow vs empty scope",
        )

        # Both layers allow: operation is permitted.
        engine = RuleEngine(config)
        engine.set_task_scope(
            "scope and base allow",
            file_read=[str(allowed)],
            file_write=[str(allowed)],
            commands=["pwd", "cat"],
            network=["allowed.example"],
            allowed_tools=["read", "write", "exec", "web_fetch"],
        )
        assert_action(
            engine.check_file_path(str(allowed / "input.txt"), "read"),
            ActionType.ALLOW,
            "base and scope file allow",
        )
        assert_action(
            engine.check_network("https://allowed.example/path"),
            ActionType.ALLOW,
            "base and scope network allow",
        )
        assert_action(
            engine.check_command("pwd"),
            ActionType.ALLOW,
            "base and scope command allow",
        )

        traversal_engine = RuleEngine(config)
        traversal_engine.set_task_scope(
            "traverse parent without listing it",
            file_read=[str(allowed / "input.txt")],
            file_write=[],
            commands=["cd", "cat"],
            network=[],
            disabled_tools=["process"],
            allowed_tools=["read", "exec"],
        )
        assert not traversal_engine.is_tool_disabled("exec")
        assert traversal_engine.is_tool_disabled("process")
        assert_action(
            traversal_engine.check_file_path(str(allowed), "traverse"),
            ActionType.ALLOW,
            "derived parent traversal",
        )
        assert_action(
            traversal_engine.check_file_path(str(allowed), "read"),
            ActionType.DENY,
            "traversal does not grant directory listing",
        )
        assert_action(
            traversal_engine.check_file_path(
                str(allowed / "input.txt"),
                "read",
            ),
            ActionType.ALLOW,
            "declared file read",
        )
        assert_action(
            traversal_engine.check_command(
                f"cd {allowed} && cat input.txt",
            ),
            ActionType.ALLOW,
            "declared file read with cd traversal",
        )

        # A positive base approval remains approval even when scope allows.
        assert_action(
            engine.check_file_path(str(allowed / "secret.txt"), "read"),
            ActionType.APPROVE,
            "base file approval vs scope allow",
        )

    # The same composition must be visible through the model tool boundary.
    restricted = RuleEngine(config)
    restricted.set_task_scope(
        "no file permission",
        file_read=[],
        file_write=[],
        commands=[],
        network=[],
        allowed_tools=["read"],
    )
    read_call = {
        "name": "read",
        "arguments": json.dumps({"path": str(allowed / "input.txt")}),
    }
    result = classify_tool_call(
        read_call,
        {"read": {"name": "read"}},
        restricted,
        GatewaySettings(policy_mode="supervised"),
    )
    assert_action(result, ActionType.DENY, "tool read vs restrictive scope")

    granted = RuleEngine(config)
    granted.set_task_scope(
        "read allowed file",
        file_read=[str(allowed)],
        file_write=[],
        commands=[],
        network=[],
        allowed_tools=["read"],
    )
    result = classify_tool_call(
        read_call,
        {"read": {"name": "read"}},
        granted,
        GatewaySettings(policy_mode="supervised"),
    )
    assert_action(result, ActionType.ALLOW, "tool read vs matching scope")

    print("base/scope policy composition matrix: PASS")


def test_base_scope_policy_composition_matrix() -> None:
    main()


if __name__ == "__main__":
    main()
