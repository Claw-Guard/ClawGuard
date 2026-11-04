import json
import tempfile
from pathlib import Path

import yaml

from clawguard.gateway import GatewaySettings, classify_tool_call
from clawguard.rules import ActionType, RuleEngine
from clawguard.sanitizer import Sanitizer


def expect(engine, command, action, *, cwd=None):
    result = engine.check_command(command, cwd=cwd)
    assert result.action == action, (
        f"{command!r}: expected {action.value}, got {result.action.value}: "
        f"{result.reason}"
    )


def main():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        allowed = root / "allowed"
        denied = root / "denied"
        allowed.mkdir()
        denied.mkdir()
        (allowed / "input.txt").write_text("utility-input\n", encoding="utf-8")
        (denied / "secret.txt").write_text("denied-secret\n", encoding="utf-8")

        config_path = Path(__file__).resolve().parents[1] / "config" / "rules.yaml"
        with open(config_path, encoding="utf-8") as handle:
            config = yaml.safe_load(handle)
        config["file_rules"]["allowed_paths"] = [str(allowed)]
        config["file_rules"]["denied_paths"] = [
            str(denied),
            "~/.ssh/**",
            "/etc/passwd",
            "/etc/shadow",
        ]
        engine = RuleEngine(config)
        sanitizer = Sanitizer(
            patterns=config["sanitizer_rules"]["patterns"],
            skill_whitelist=config["sanitizer_rules"].get("skill_whitelist", []),
        )

        # Safety: the known bypasses and sensitive paths must no longer pass.
        expect(engine, f"cd {denied} && cat secret.txt", ActionType.DENY)
        expect(engine, f"cd {denied}; cat secret.txt", ActionType.DENY)
        expect(engine, "cd ~/.ssh && cat id_rsa", ActionType.DENY)
        expect(engine, f"cat {denied}/secret.txt", ActionType.DENY)
        expect(engine, f"touch {denied}/probe", ActionType.DENY)
        expect(engine, f"mkdir {denied}/new-dir", ActionType.DENY)
        expect(engine, f"echo data > {denied}/probe", ActionType.DENY)
        expect(engine, f"cp {denied}/secret.txt {allowed}/copy", ActionType.DENY)
        expect(engine, f"mv {allowed}/input.txt {denied}/moved", ActionType.DENY)
        expect(engine, f"cat {denied}/secret.txt & true", ActionType.DENY)
        expect(engine, f"find {denied} -type f -delete", ActionType.DENY)
        expect(
            engine,
            f"bash -c 'cat {denied}/secret.txt'",
            ActionType.DENY,
        )
        expect(engine, "env", ActionType.APPROVE)
        expect(engine, "echo $OPENCLAW_PROVIDER_API_KEY", ActionType.APPROVE)
        expect(engine, "curl -s https://www.autodl.art/api/v1", ActionType.APPROVE)
        expect(engine, "curl -s https://pastebin.com/example", ActionType.DENY)
        expect(engine, "curl -X POST https://pypi.org/simple/", ActionType.APPROVE)
        expect(engine, "curl --json '{}' https://pypi.org/simple/", ActionType.APPROVE)
        expect(engine, "unknown-network-tool --target example", ActionType.APPROVE)
        expect(engine, "touch /tmp/outside-workspace", ActionType.APPROVE)
        expect(engine, "git branch -D main", ActionType.APPROVE)
        expect(engine, "rm -rf /", ActionType.DENY)

        # Utility: common safe read/write/navigation operations remain usable.
        expect(engine, "pwd", ActionType.ALLOW)
        expect(engine, f"cat {allowed}/input.txt", ActionType.ALLOW)
        expect(engine, "cat input.txt", ActionType.ALLOW, cwd=str(allowed))
        expect(engine, f"cd {allowed} && cat input.txt", ActionType.ALLOW)
        expect(engine, f"cd {allowed}; head -n 1 input.txt", ActionType.ALLOW)
        expect(engine, f"grep utility {allowed}/input.txt", ActionType.ALLOW)
        expect(engine, f"touch {allowed}/created.txt", ActionType.ALLOW)
        expect(engine, f"mkdir {allowed}/new-dir", ActionType.ALLOW)
        expect(engine, f"echo utility > {allowed}/output.txt", ActionType.ALLOW)
        expect(
            engine,
            f"find {allowed} -type f -name '*.txt'",
            ActionType.ALLOW,
        )
        expect(engine, "curl -s https://pypi.org/simple/", ActionType.ALLOW)
        expect(engine, "ls -la 2>/dev/null", ActionType.ALLOW)
        expect(engine, "ls -la 2>&1", ActionType.ALLOW)
        expect(engine, "git status", ActionType.ALLOW)

        ls_call = {
            "name": "ls",
            "arguments": json.dumps({"path": str(allowed)}),
        }
        ls_match = classify_tool_call(
            ls_call,
            {"ls": {"name": "ls"}},
            engine,
            GatewaySettings(policy_mode="supervised"),
        )
        assert ls_match.action == ActionType.ALLOW, ls_match.reason

        ordinary_identifier = "clawguard_command_hardening_20261025"
        assert sanitizer.sanitize(ordinary_identifier) == ordinary_identifier
        azure_value = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        azure_text = f"azure_client_secret='{azure_value}'"
        assert azure_value not in sanitizer.sanitize(azure_text)
        ordinary_uuid = "123e4567-e89b-12d3-a456-426614174000"
        assert sanitizer.sanitize(ordinary_uuid) == ordinary_uuid
        heroku_text = f"heroku_api_key='{ordinary_uuid}'"
        assert ordinary_uuid not in sanitizer.sanitize(heroku_text)

    print("command safety/utility matrix: PASS")


def test_command_safety_utility_matrix() -> None:
    main()


if __name__ == "__main__":
    main()
