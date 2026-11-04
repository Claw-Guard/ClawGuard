import asyncio
import tempfile
from pathlib import Path

import httpx
import yaml

from clawguard.api import create_app
from clawguard.approval import ApprovalQueue, ApprovalType


async def queue_persistence_test(root: Path) -> None:
    db_path = root / "approval.db"
    queue = ApprovalQueue(timeout_seconds=2, db_path=str(db_path))

    approved = await queue.add_request(
        ApprovalType.TOOL_CALL,
        operation="exec: first",
        reason="approval required",
    )
    await queue.approve(approved.id, resolved_by="tester", reason="ok")

    denied = await queue.add_request(
        ApprovalType.TOOL_CALL,
        operation="exec: second",
        reason="approval required",
    )
    await queue.deny(denied.id, resolved_by="tester", reason="no")

    pending = await queue.add_request(
        ApprovalType.TOOL_CALL,
        operation="exec: interrupted",
        reason="approval required",
    )

    current = queue.get_persisted_history(
        include_previous_runs=False,
    )
    assert {item["status"] for item in current} == {
        "approved",
        "denied",
        "pending",
    }

    # A new process must not expose the old pending request as actionable or in
    # its current-process UI history.
    restarted = ApprovalQueue(timeout_seconds=2, db_path=str(db_path))
    assert restarted.get_history() == []
    assert restarted.get_pending() == []

    all_history = restarted.get_persisted_history(
        include_previous_runs=True,
    )
    statuses = {item["operation"]: item["status"] for item in all_history}
    assert statuses["exec: first"] == "approved"
    assert statuses["exec: second"] == "denied"
    assert statuses["exec: interrupted"] == "interrupted"


async def api_history_scoping_test(root: Path) -> None:
    rules_path = root / "rules.yaml"
    rules_path.write_text(
        """
command_rules:
  blacklist: []
  whitelist: []
  supervised: []
file_rules:
  allowed_paths: []
  denied_paths: []
  sensitive_patterns: []
network_rules:
  allowed_domains: []
  denied_domains: []
  default_action: approve
""".lstrip(),
        encoding="utf-8",
    )
    config_path = root / "config.yaml"
    config_path.write_text(
        f"""
audit:
  db_path: {root / "audit.db"}
approval:
  db_path: {root / "approvals-api.db"}
policy:
  approval_timeout: 2
""".lstrip(),
        encoding="utf-8",
    )

    app = create_app(str(config_path), str(rules_path))
    request = await app.state.approval.add_request(
        ApprovalType.TOOL_CALL,
        operation="exec: api-test",
        reason="approval required",
    )
    await app.state.approval.approve(
        request.id,
        resolved_by="api-tester",
        reason="approved",
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        current = (await client.get("/approval/history")).json()
        assert current["source"] == "current_process"
        assert len(current["history"]) == 1

    restarted_app = create_app(str(config_path), str(rules_path))
    transport = httpx.ASGITransport(app=restarted_app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        current = (await client.get("/approval/history")).json()
        assert current["source"] == "current_process"
        assert current["history"] == []

        persistent = (
            await client.get(
                "/approval/history",
                params={"include_previous_runs": "true"},
            )
        ).json()
        assert persistent["source"] == "persistent"
        assert len(persistent["history"]) == 1
        assert persistent["history"][0]["operation"] == "exec: api-test"
        assert persistent["history"][0]["status"] == "approved"


def main() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        asyncio.run(queue_persistence_test(root))
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        asyncio.run(api_history_scoping_test(root))
    print("approval history persistence matrix: PASS")


def test_approval_history_persistence_matrix() -> None:
    main()


if __name__ == "__main__":
    main()
