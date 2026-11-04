import asyncio
import os
import tempfile
from pathlib import Path
from urllib.parse import quote

import httpx
import yaml

from clawguard.api import create_app
from clawguard.rules import ActionType, RuleEngine


def make_rules_file(root: Path) -> Path:
    path = root / "rules.yaml"
    path.write_text(
        """
# Preserve this operator comment.
command_rules:
  # Preserve this command comment.
  blacklist: []
  whitelist: []
  supervised: []
file_rules:
  allowed_paths:
    - /allowed
  denied_paths:
    - /denied
  sensitive_patterns: []
network_rules:
  allowed_domains:
    - allowed.example
  denied_domains:
    - denied.example
  default_action: approve
""".lstrip(),
        encoding="utf-8",
    )
    return path


def test_path_boundaries() -> None:
    rules = RuleEngine(
        {
            "command_rules": {},
            "file_rules": {
                "allowed_paths": ["/allowed"],
                "denied_paths": ["/denied"],
                "sensitive_patterns": [],
            },
            "network_rules": {},
        }
    )
    assert rules.check_file_path("/allowed/file.txt").action == ActionType.ALLOW
    assert rules.check_file_path("/allowed-evil/file.txt").action == ActionType.APPROVE
    assert rules.check_file_path("/denied/file.txt").action == ActionType.DENY
    assert rules.check_file_path("/denied-evil/file.txt").action == ActionType.APPROVE


def test_rule_persistence() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        rules_path = make_rules_file(root)
        config_path = root / "config.yaml"
        config_path.write_text(
            "audit:\n  db_path: audit.db\npolicy:\n  mode: supervised\n",
            encoding="utf-8",
        )
        app = create_app(str(config_path), str(rules_path))
        added_file = "/allowed/persisted.txt"
        added_domain = "persisted.example"

        async def mutate() -> None:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://test",
            ) as client:
                response = await client.post(
                    "/rules/file/deny",
                    params={"path": added_file},
                )
                assert response.status_code == 200, response.text
                assert response.json()["persisted"] is True
                response = await client.post(
                    "/rules/network/allow",
                    params={"domain": added_domain},
                )
                assert response.status_code == 200, response.text
                assert response.json()["persisted"] is True

        asyncio.run(mutate())
        persisted = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
        assert added_file in persisted["file_rules"]["denied_paths"]
        assert added_domain in persisted["network_rules"]["allowed_domains"]
        assert "operator comment" in rules_path.read_text(encoding="utf-8")

        reloaded = create_app(str(config_path), str(rules_path))
        assert added_file in reloaded.state.rules.file_rules["denied_paths"]
        assert added_domain in reloaded.state.rules.network_rules["allowed_domains"]

        async def remove() -> None:
            transport = httpx.ASGITransport(app=reloaded)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://test",
            ) as client:
                response = await client.delete(
                    "/rules/file/deny",
                    params={"path": added_file},
                )
                assert response.status_code == 200, response.text
                assert response.json()["persisted"] is True
                response = await client.delete(
                    f"/rules/network/allow/{quote(added_domain, safe='')}",
                )
                assert response.status_code == 200, response.text
                assert response.json()["persisted"] is True

        asyncio.run(remove())
        reloaded_after_remove = create_app(str(config_path), str(rules_path))
        assert added_file not in reloaded_after_remove.state.rules.file_rules["denied_paths"]
        assert added_domain not in reloaded_after_remove.state.rules.network_rules["allowed_domains"]
        print("rules persistence tests: OK")


def test_command_rule_management() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        rules_path = make_rules_file(root)
        config_path = root / "config.yaml"
        config_path.write_text(
            "audit:\n  db_path: audit.db\npolicy:\n  mode: supervised\n",
            encoding="utf-8",
        )
        app = create_app(str(config_path), str(rules_path))
        allow_pattern = r"^echo dashboard-ok$"
        deny_pattern = r"^dashboard-danger$"

        async def mutate() -> None:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://test",
            ) as client:
                response = await client.get("/rules/list")
                assert response.status_code == 200, response.text
                command = response.json()["command"]
                assert set(command) == {"allowed", "denied"}

                response = await client.post(
                    "/rules/command/allow",
                    params={"pattern": "("},
                )
                assert response.status_code == 400, response.text

                response = await client.post(
                    "/rules/command/allow",
                    params={"pattern": allow_pattern},
                )
                assert response.status_code == 200, response.text
                assert response.json()["persisted"] is True

                response = await client.post(
                    "/rules/command/deny",
                    params={"pattern": deny_pattern},
                )
                assert response.status_code == 200, response.text
                assert response.json()["persisted"] is True

                response = await client.post(
                    "/check/command",
                    json={"command": "echo dashboard-ok"},
                )
                assert response.status_code == 200, response.text
                assert response.json()["allowed"] is True

                response = await client.post(
                    "/check/command",
                    json={"command": "dashboard-danger"},
                )
                assert response.status_code == 200, response.text
                assert response.json()["action"] == "deny"

        asyncio.run(mutate())
        persisted_text = rules_path.read_text(encoding="utf-8")
        assert "Preserve this command comment" in persisted_text
        persisted = yaml.safe_load(persisted_text)
        assert any(
            rule["pattern"] == allow_pattern
            for rule in persisted["command_rules"]["whitelist"]
        )
        assert any(
            rule["pattern"] == deny_pattern
            for rule in persisted["command_rules"]["blacklist"]
        )

        reloaded = create_app(str(config_path), str(rules_path))

        async def remove() -> None:
            transport = httpx.ASGITransport(app=reloaded)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://test",
            ) as client:
                response = await client.delete(
                    "/rules/command/allow",
                    params={"pattern": allow_pattern},
                )
                assert response.status_code == 200, response.text
                assert response.json()["status"] == "removed"
                response = await client.delete(
                    "/rules/command/deny",
                    params={"pattern": deny_pattern},
                )
                assert response.status_code == 200, response.text
                assert response.json()["status"] == "removed"

        asyncio.run(remove())
        reloaded_after_remove = create_app(str(config_path), str(rules_path))
        assert all(
            rule["raw_pattern"] not in {allow_pattern, deny_pattern}
            for rule in reloaded_after_remove.state.rules.command_rules["whitelist"]
        )
        assert all(
            rule["raw_pattern"] != deny_pattern
            for rule in reloaded_after_remove.state.rules.command_rules["blacklist"]
        )
        print("command rule management tests: OK")


if __name__ == "__main__":
    test_path_boundaries()
    print("path boundary tests: OK")
    test_rule_persistence()
    test_command_rule_management()
