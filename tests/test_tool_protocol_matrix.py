import json
import tempfile
from pathlib import Path

import yaml

from clawguard.gateway import (
    GatewaySettings,
    _extract_nonstream_tool_calls,
    _extract_stream_tool_calls,
    apply_policy_decision,
    evaluate_tool_call,
)
from clawguard.rules import ActionType, RuleEngine
from clawguard.adapters.tool_protocol import CanonicalToolCall, PolicyDecision


def main():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        target = root / "input.txt"
        target.write_text("canonical-input\n", encoding="utf-8")

        config_path = Path(__file__).resolve().parents[1] / "config" / "rules.yaml"
        with open(config_path, encoding="utf-8") as handle:
            config = yaml.safe_load(handle)
        config["file_rules"]["allowed_paths"] = [str(root)]
        config["file_rules"]["denied_paths"] = []
        serialized_args = json.dumps({"path": str(target)})

        nonstream = _extract_nonstream_tool_calls(
            {
                "choices": [
                    {
                        "message": {
                            "tool_calls": [
                                {
                                    "id": "call-1",
                                    "type": "function",
                                    "function": {
                                        "name": "read",
                                        "arguments": serialized_args,
                                    },
                                }
                            ]
                        }
                    }
                ]
            }
        )
        stream = _extract_stream_tool_calls(
            [
                {
                    "choices": [
                        {
                            "delta": {
                                "tool_calls": [
                                    {
                                        "index": 0,
                                        "id": "call-1",
                                        "function": {
                                            "name": "read",
                                            "arguments": serialized_args[:10],
                                        },
                                    }
                                ]
                            }
                        }
                    ]
                },
                {
                    "choices": [
                        {
                            "delta": {
                                "tool_calls": [
                                    {
                                        "index": 0,
                                        "function": {
                                            "arguments": serialized_args[10:],
                                        },
                                    }
                                ]
                            }
                        }
                    ]
                },
            ]
        )

        assert len(nonstream) == 1 and isinstance(nonstream[0], CanonicalToolCall)
        assert len(stream) == 1 and isinstance(stream[0], CanonicalToolCall)
        assert nonstream[0].to_dict() == stream[0].to_dict()

        generic = _extract_nonstream_tool_calls(
            {
                "choices": [
                    {
                        "message": {
                            "tool_calls": [
                                {
                                    "id": "call-generic",
                                    "function": {
                                        "name": "tool_call",
                                        "arguments": json.dumps(
                                            {
                                                "id": "read",
                                                "args": {"path": str(target)},
                                            }
                                        ),
                                    },
                                }
                            ]
                        }
                    }
                ]
            }
        )
        assert generic[0].name == "read"
        assert generic[0].wrapper == "tool_call"

        rules = RuleEngine(config)
        settings = GatewaySettings(policy_mode="supervised")
        decision = evaluate_tool_call(
            nonstream[0],
            {"read": {"name": "read"}},
            rules,
            settings,
        )
        assert isinstance(decision, PolicyDecision)
        assert decision.action == ActionType.ALLOW.value
        assert decision.facts is not None
        assert decision.facts.capabilities == ("file_read",)
        assert decision.facts.file_targets == (("read", str(target)),)
        assert decision.target == str(target)

        rules.set_task_scope(
            "no file read",
            file_read=[],
            file_write=[],
            commands=[],
            network=[],
            allowed_tools=["read"],
        )
        denied = evaluate_tool_call(
            nonstream[0],
            {"read": {"name": "read"}},
            rules,
            settings,
        )
        assert denied.action == ActionType.DENY.value
        assert denied.rule_type == "task_scope_restriction"

        legacy_decision = evaluate_tool_call(
            {
                "id": "call-legacy",
                "name": "read",
                "arguments": '{"path": "' + str(target) + '"}',
            },
            {"read": {"name": "read"}},
            rules,
            settings,
        )
        assert legacy_decision.action == denied.action

        approval = PolicyDecision(
            action=ActionType.APPROVE.value,
            rule_type="test_approval",
            reason="approval required",
        )
        assert (
            apply_policy_decision(
                approval,
                GatewaySettings(policy_mode="strict"),
            ).action
            == ActionType.DENY.value
        )
        assert (
            apply_policy_decision(
                approval,
                GatewaySettings(policy_mode="permissive"),
            ).action
            == ActionType.ALLOW.value
        )
        denial = PolicyDecision(
            action=ActionType.DENY.value,
            rule_type="test_denial",
            reason="denied",
        )
        assert (
            apply_policy_decision(
                denial,
                GatewaySettings(policy_mode="permissive"),
            ).action
            == ActionType.DENY.value
        )

    print("canonical tool protocol matrix: PASS")


def test_canonical_tool_protocol_matrix() -> None:
    main()


if __name__ == "__main__":
    main()
