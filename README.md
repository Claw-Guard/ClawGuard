# 🛡️ ClawGuard

**A Runtime Security Framework for Tool-Augmented LLM Agents Against Indirect Prompt Injection**

[![arXiv](https://img.shields.io/badge/arXiv-2604.11790-b31b1b.svg)](https://arxiv.org/abs/2604.11790)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)

> ClawGuard enforces a user-confirmed rule set at every tool-call boundary, transforming unreliable alignment-dependent defense into a **deterministic, auditable mechanism** that intercepts adversarial tool calls before any real-world effect is produced.

---

> **Note:** Due to breaking changes in the OpenClaw plugin API, this repository now ships two plugin variants (`legacy` for OpenClaw < 2026.5.7, `v5` for OpenClaw ≥ 2026.5.7). The installer detects your version automatically, but edge cases may exist. If you run into issues, please [open an issue](https://github.com/Claw-Guard/ClawGuard/issues).

---

## How ClawGuard Works

```
User states objective
        ↓
ClawGuard derives task-specific access constraints
        ↓
Agent makes tool call (file / command / network / skill)
        ↓
ClawGuard rule engine checks call against constraints
        ↓
  ALLOW → execute, sanitize output, return to agent
  DENY  → block immediately, log to audit
  APPROVE → pause, notify human, wait for decision
        ↓
Sanitizer strips secrets & injections from tool output
before it enters conversation history
```

ClawGuard operates as a **sidecar daemon** — no model modification, no infrastructure change, no fine-tuning required.

### Four Layers of Protection

| Layer | Mechanism |
|-------|-----------|
| **L1 — Gateway Tool Block** | Native `exec`/`write`/`edit` tools disabled at the OpenClaw gateway layer; agent can only use `cg_*` tools |
| **L2 — Rule Engine** | Every `cg_*` call checked against command blacklists, file path controls, and domain allowlists |
| **L3 — Sanitizer Engine** | 30+ regex patterns covering API keys, tokens, SSH keys, DB credentials, and crypto keys — stripped bidirectionally from tool I/O before entering conversation history |
| **L4 — Audit Log** | All operations recorded to a local SQLite database (`~/.clawguard/audit.db`); exportable from the dashboard |

---

## Requirements

- Python 3.9+
- Node.js 18+
- Git
- [OpenClaw](https://openclaw.ai)

---

## Installation

### One-liner

```bash
curl -fsSL https://raw.githubusercontent.com/Claw-Guard/ClawGuard/main/install.sh | bash
```

### Manual

```bash
git clone https://github.com/Claw-Guard/ClawGuard.git ~/clawguard-py
cd ~/clawguard-py
bash install.sh
```

The installer will:

1. Detect your OpenClaw version and select the correct plugin variant (`legacy` or `v5`)
2. Ask where to install (default: `~/clawguard-py`)
3. Create a Python venv and install dependencies
4. Copy config templates to `~/.clawguard/` (skipped if already present)
5. Install the matching OpenClaw plugin to `~/.clawguard/openclaw-plugin/`
6. Make `bin/` scripts executable and patch `CLAWGUARD_DIR` into them

---

## Usage

### Enable ClawGuard

```bash
~/clawguard-py/bin/enable-clawguard.sh
```

This will:

1. Start the ClawGuard daemon via `nohup` (logs to `~/.clawguard/daemon.log`, PID at `~/.clawguard/daemon.pid`)
2. Back up your current `openclaw.json` as `openclaw_guardback.json`
3. Patch your OpenClaw config via `transform.js` to enable the plugin and block native tools
4. Install `SKILL.md` into `~/.openclaw/skills/clawguard/` and sync it to `~/.clawguard/openclaw-plugin/`
5. Restart the OpenClaw gateway

### Disable ClawGuard

```bash
~/clawguard-py/bin/disable-clawguard.sh
```

This will:

1. Remove `~/.openclaw/skills/` (the ClawGuard skill directory)
2. Stop the daemon (by PID file, or by process name as fallback)
3. Roll back `openclaw.json` using `rollback.js` (falls back to the backup copy if `rollback.js` is missing)
4. Restart the OpenClaw gateway

### Dashboard

Once the daemon is running, open: **http://127.0.0.1:19821**

The dashboard provides:
- Real-time operation timeline
- Pending approval queue (approve / deny supervised operations)
- Rule management — add or remove file path and network domain rules at runtime
- Audit log with export
- One-click Panic (emergency block all operations) and Resume

---

## Configuration

### `~/.clawguard/config.yaml`

```yaml
daemon:
  api_port: 19821
  log_level: info

policy:
  mode: permissive        # strict | supervised | permissive
  approval_timeout: 60    # seconds to wait for human approval
  timeout_action: deny    # what happens when approval times out: "allow" or "deny"

audit:
  db_path: ~/.clawguard/audit.db
  retention_days: 90

sanitizer:
  enabled: true
  input_sanitization: true
  output_sanitization: true
```

| Mode | Behaviour |
|------|-----------|
| `strict` | Violations are immediately blocked |
| `supervised` | Violations are paused and queued for human approval |
| `permissive` | Violations are logged only (no blocking) |

### `~/.clawguard/rules.yaml`

Controls three rule categories. See [`config/rules.yaml`](config/rules.yaml) for the full template.

**Command rules** — `blacklist` / `whitelist` / `supervised` regex patterns:
- Blacklisted: destructive deletions, reverse shells, credential theft, fork bombs, disk operations, persistence mechanisms
- Whitelisted: read-only inspection (`ls`, `cat`, `git status`, `pip list`, etc.)
- Supervised (require approval): `rm`, `sudo`, `chmod`, HTTP write operations, package installs, git write ops

**File rules** — `allowed_paths` / `denied_paths` / `sensitive_patterns`:
- Denied by default: `~/.ssh`, `~/.aws`, `~/.gnupg`, `/etc/shadow`, browser profiles, password managers, ClawGuard's own internals
- Sensitive filename patterns: `*.pem`, `*.key`, `.env*`, `*password*`, `*.sql`, etc.

**Network rules** — `allowed_domains` / `denied_domains`:
- Allowed: package registries (PyPI, npm, crates.io), AI APIs, documentation sites
- Denied: paste sites, tunneling services (ngrok, localtunnel), URL shorteners, `.onion`/`.i2p`
- Default action for unlisted domains: `approve`

Rules support runtime modification via the REST API or dashboard without restarting the daemon.

---

## REST API

The daemon exposes a REST API on port `19821`. Key endpoints:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/rules/list` | Get all current runtime rules |
| `POST` | `/rules/network/allow?domain=` | Add domain to network allowlist |
| `DELETE` | `/rules/network/allow/{domain}` | Remove domain from allowlist |
| `POST` | `/rules/network/deny?domain=` | Add domain to blocklist |
| `DELETE` | `/rules/network/deny/{domain}` | Remove domain from blocklist |
| `POST` | `/rules/file/allow?path=` | Add path to file allowlist |
| `DELETE` | `/rules/file/allow?path=` | Remove path from allowlist |
| `POST` | `/rules/file/deny?path=` | Add path to file blocklist |
| `DELETE` | `/rules/file/deny?path=` | Remove path from blocklist |
| `POST` | `/task-scope/lock` | Lock task scope (freeze rules) |
| `POST` | `/task-scope/unlock` | Unlock task scope |
| `POST` | `/task-scope/clear` | Clear task scope rules |
| `GET` | `/audit` | Query audit log |
| `GET` | `/audit/download` | Download audit log |
| `POST` | `/panic` | Trigger emergency block |
| `POST` | `/resume` | Resume after panic |
| `GET` | `/status` | Daemon status and stats |

---

## Agent Tools (`cg_*`)

When ClawGuard is active, the agent uses `cg_*` tools instead of native tools:

| Tool | Replaces | Protection |
|------|----------|------------|
| `cg_execute_command` | `exec` / `process` | Command blacklist + output sanitization |
| `cg_read_file` | `read` | Sensitive path blocking + content sanitization |
| `cg_write_file` | `write` | Path access control + write sanitization |
| `cg_edit_file` | `edit` | Path access control + write sanitization |
| `cg_list_directory` | `read` (dir) | Directory access control |
| `cg_http_request` | network tools | Domain allowlist + exfiltration prevention |
| `cg_set_task_scope` | — | Define allowed paths/domains for current task |
| `cg_clear_task_scope` | — | Clear task scope |
| `cg_skill_check` | — | Verify skill is on the allowlist |
| `cg_status` | — | View engine status and audit stats |
| `cg_panic` | — | Emergency block all operations |
| `cg_resume` | — | Resume after panic |

---

## Project Structure

```
clawguard-py/
├── install.sh                    # Installer with OpenClaw version detection
├── main.py                       # Daemon entry point
├── requirements.txt
├── setup.py / pyproject.toml
├── clawguard/                    # Python daemon
│   ├── api.py                    # FastAPI REST + SSE server (port 19821)
│   ├── approval.py               # Human-in-the-loop approval queue
│   ├── audit.py                  # SQLite audit logger
│   ├── rules.py                  # Rule engine (allow / deny / approve)
│   ├── sanitizer.py              # Bidirectional I/O sanitizer (30+ patterns)
│   ├── normalizer.py             # Input normalizer
│   ├── panic.py                  # Emergency panic / resume
│   ├── skill_check.py            # Skill allowlist checker
│   ├── cli.py                    # CLI interface
│   └── dashboard/                # Web dashboard (HTML / JS / CSS)
├── config/
│   ├── config.yaml               # Daemon configuration template
│   └── rules.yaml                # Security rules template
├── openclaw-plugin/
│   ├── legacy/                   # Plugin for OpenClaw < 2026.5.7
│   │   ├── index.js
│   │   ├── SKILL.md
│   │   ├── openclaw.plugin.json
│   │   └── package.json
│   └── v5/                       # Plugin for OpenClaw >= 2026.5.7
│       ├── index.js              # Uses definePluginEntry() SDK pattern
│       ├── SKILL.md
│       ├── openclaw.plugin.json
│       └── package.json
├── bin/
│   ├── enable-clawguard.sh       # Enable + start daemon
│   ├── disable-clawguard.sh      # Disable + restore config
│   ├── clawguard-shell           # Shell wrapper
│   ├── transform.js              # OpenClaw config patcher
│   └── rollback.js               # OpenClaw config rollback
```

---

## Citation

If you use ClawGuard in your research, please cite:

```bibtex
@misc{clawguard2026,
  title         = {A Runtime Security Framework for Tool-Augmented LLM Agents Against Indirect Prompt Injection},
  author        = {Wei Zhao et al.},
  year          = {2026},
  eprint        = {2604.11790},
  archivePrefix = {arXiv},
  primaryClass  = {cs.CR},
  url           = {https://arxiv.org/abs/2604.11790}
}
```

---

## License

MIT — see [LICENSE](LICENSE).
