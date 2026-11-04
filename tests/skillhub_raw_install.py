"""Install SkillHub public SKILL.md text into isolated OpenClaw test aliases."""

from __future__ import annotations

import json
import subprocess
import tempfile
import urllib.request
from pathlib import Path


SKILLS = [
    ("alirezarezvani-claude-skills-senior-data-engineer", "hub-senior-data-engineer"),
    ("inferencesh-skills-ai-content-pipeline", "hub-ai-content-pipeline"),
    ("openclaw-skills-whoabuddy-aibtc-bitcoin-wallet", "hub-aibtc-bitcoin-wallet"),
    ("openclaw-skills-mosonchan2023-binance-grid-trading", "hub-binance-grid-trading"),
    ("openclaw-skills-minara", "hub-minara"),
    ("openclaw-skills-parasyte-x-agentic-wallet-skill", "hub-agentic-wallet"),
]


def fetch_skill_md(slug: str) -> str:
    request = urllib.request.Request(
        f"https://www.skillhub.club/api/v1/skills/{slug}",
        headers={"User-Agent": "ClawGuard-skillhub-e2e/1.0"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.load(response)
    content = payload.get("skill", {}).get("skill_md_raw")
    if not isinstance(content, str) or not content.strip():
        raise RuntimeError("SkillHub returned no SKILL.md")
    return content


root = Path(tempfile.mkdtemp(prefix="clawguard-skillhub-raw-"))
print(f"STAGING_ROOT={root}")
for slug, alias_name in SKILLS:
    target = root / alias_name
    try:
        target.mkdir()
        (target / "SKILL.md").write_text(fetch_skill_md(slug), encoding="utf-8")
        result = subprocess.run(
            [
                "openclaw",
                "skills",
                "install",
                str(target),
                "--agent",
                "main",
                "--as",
                alias_name,
                "--force",
                "--acknowledge-install-policy-warning",
            ],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        if result.returncode == 0:
            print(f"INSTALL_OK\t{alias_name}\t{target}/SKILL.md")
        else:
            reason = (result.stderr or result.stdout).strip().splitlines()[-1:]
            print(f"INSTALL_FAIL\t{alias_name}\t{' '.join(reason)}")
    except Exception as exc:
        print(f"INSTALL_FAIL\t{alias_name}\t{exc}")
