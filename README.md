# 🛡️ ClawGuard

**A Runtime Security Framework for Tool-Augmented LLM Agents Against Indirect Prompt Injection**

[![arXiv](https://img.shields.io/badge/arXiv-2604.11790-b31b1b.svg)](https://arxiv.org/abs/2604.11790)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)

> ClawGuard enforces a user-confirmed rule set at every tool-call boundary, transforming unreliable alignment-dependent defense into a **deterministic, auditable mechanism** that intercepts adversarial tool calls before any real-world effect is produced.

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
| **L3 — Sanitizer Engine** | 15 categories of sensitive data (API keys, tokens, SSH keys) stripped bidirectionally from tool I/O before entering conversation history |
| **L4 — Audit Log** | All operations recorded to a local SQLite database; tamper-proof, exportable |

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
1. Ask where to install (default: `~/clawguard-py`)
2. Create a Python venv and install dependencies
3. Copy config templates to `~/.clawguard/`
4. Install the OpenClaw plugin to `~/.clawguard/openclaw-plugin/`
5. Install the OpenClaw config transform tool

**Requirements:** Python 3.9+, Node.js 18+, Git, [OpenClaw](https://openclaw.ai)

---

## Usage

### Enable ClawGuard

```bash
~/clawguard-py/bin/enable-clawguard.sh
```

This will:
- Start the ClawGuard daemon (via `nohup`, logs to `~/.clawguard/daemon.log`)
- Back up your current `openclaw.json` as `openclaw_guardback.json`
- Patch your OpenClaw config to enable the plugin and block native tools
- Install the ClawGuard skill into `~/.openclaw/skills/`
- Restart the OpenClaw gateway

### Disable ClawGuard

```bash
~/clawguard-py/bin/disable-clawguard.sh
```

This will:
- Remove the ClawGuard skill from `~/.openclaw/skills/`
- Stop the daemon
- Restore your original `openclaw.json` from backup
- Restart the OpenClaw gateway

### Dashboard

Once running, open: **http://127.0.0.1:19821**

The dashboard provides:
- Real-time operation timeline
- Pending approval queue (approve/deny supervised operations)
- Audit log with export
- One-click Panic (emergency block all operations)

---

## Configuration

### `~/.clawguard/config.yaml`

```yaml
policy:
  mode: supervised     # strict | supervised | permissive
  approval_timeout: 60 # seconds to wait for human approval
```

| Mode | Behaviour |
|------|-----------|
| `strict` | Violations are immediately blocked |
| `supervised` | Violations are paused and queued for human approval |
| `permissive` | Violations are logged only (no blocking) |

### `~/.clawguard/rules.yaml`

Define file path allowlists/blocklists, command patterns, and network domain controls. See [`config/rules.yaml`](config/rules.yaml) for the full template.

---

## Security Tools (for agents)

When ClawGuard is active, the agent uses `cg_*` tools instead of native tools:

| `cg_*` Tool | Replaces | Protection |
|-------------|----------|------------|
| `cg_execute_command` | `exec` / `process` | Command blacklist + output sanitization |
| `cg_read_file` | `read` | Sensitive path blocking + content sanitization |
| `cg_write_file` | `write` / `edit` | Path access control + write sanitization |
| `cg_list_directory` | `read` (dir) | Directory access control |
| `cg_http_request` | network tools | Domain allowlist + exfiltration prevention |
| `cg_status` | — | View engine status and audit stats |
| `cg_panic` | — | 🚨 Emergency block all operations |
| `cg_resume` | — | Resume after panic |

---

## Project Structure

```
ClawGuard/
├── install.sh                  # One-step installer
├── main.py                     # Daemon entry point
├── requirements.txt
├── clawguard/                  # Python daemon
│   ├── api.py                  # FastAPI REST + SSE server
│   ├── approval.py             # Human-in-the-loop approval queue
│   ├── audit.py                # SQLite audit logger
│   ├── rules.py                # Rule engine (allow/deny/approve)
│   ├── sanitizer.py            # Bidirectional I/O sanitizer
│   ├── normalizer.py           # Input normalizer
│   ├── panic.py                # Emergency panic/resume
│   ├── skill_check.py          # Skill allowlist checker
│   ├── cli.py                  # CLI interface
│   └── dashboard/              # Web dashboard (HTML/JS/CSS)
├── config/                     # Config templates
│   ├── config.yaml
│   └── rules.yaml
├── openclaw-plugin/            # OpenClaw plugin
│   ├── index.js                # Plugin entry point
│   ├── openclaw.plugin.json    # Plugin manifest
│   └── SKILL.md                # Agent skill definition
├── bin/
│   ├── enable-clawguard.sh     # Enable + start
│   ├── disable-clawguard.sh    # Disable + restore
│   └── clawguard-shell         # Shell wrapper
├── tests/
│   ├── test_*.py               # Unit tests
│   └── transform.js            # OpenClaw config transform tool
└── docs/
    ├── USER_GUIDE.md
    ├── QUICK_START.md
    ├── SECURITY_ANALYSIS.md
    └── CLAWGUARD_TRANSFORM.md
```

---

## Citation

If you use ClawGuard in your research, please cite:

```bibtex
@misc{clawguard2026,
  title  = {A Runtime Security Framework for Tool-Augmented LLM Agents Against Indirect Prompt Injection},
  author = {Wei Zhao et al.},
  year   = {2026},
  eprint = {2604.11790},
  archivePrefix = {arXiv},
  primaryClass  = {cs.CR},
  url    = {https://arxiv.org/abs/2604.11790}
}
```

---

## License

MIT — see [LICENSE](LICENSE).
