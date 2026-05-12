---
name: clawguard
description: "ClawGuard Security Engine — Intercept dangerous operations, audit all actions, protect sensitive data. All command/file/network operations are reviewed by the rule engine via cg_* tools before execution."
homepage: https://www.clawguard.site
user-invocable: true
command-dispatch: tool
command-tool: cg_status
command-arg-mode: raw
metadata: { "openclaw": { "emoji": "🛡️", "requires": { "bins": ["clawguard"] }, "primaryEnv": "CLAWGUARD_DAEMON_PORT", "install": [{ "id": "curl-install", "kind": "download", "url": "https://www.clawguard.site/download/install.sh", "label": "Install ClawGuard (curl)" }], "os": ["darwin", "linux"] } }
---

# ClawGuard Security Engine

You now have the **ClawGuard Security Engine** integrated. All agent operations must pass a security review — use the `cg_*` tools in place of native operations.

## Security Architecture

ClawGuard uses **four layers of protection** to ensure the agent cannot bypass security oversight:

1. **Gateway Tool Block (L1)** — At install time, `tools.deny` is automatically injected into `openclaw.json`, disabling the native `exec`/`write`/`edit`/`apply_patch`/`process` tools at the Gateway layer. The agent **physically cannot call** blocked native tools.
2. **Rule Engine (L2)** — All `cg_*` tool calls are reviewed against command blacklists/whitelists, file path controls, and domain allowlists.
3. **Sanitizer Engine (L3)** — Automatically filters 15 categories of sensitive data including API keys, tokens, and SSH keys (bidirectional sanitization on both input and output).
4. **Audit Log (L4)** — All operations are recorded to a local SQLite database, viewable in the Dashboard, and tamper-proof.

> ⚠️ Dangerous native tools have been blocked at the Gateway layer. You may only use the `cg_*` tools below to perform operations.

## Security Tools

### Action Tools (replace native tools)

| cg_* Tool | Replaces | Security Capabilities |
|-----------|----------|-----------------------|
| `cg_execute_command` | `exec` / `process` | Command blacklist/whitelist + dangerous command blocking + output sanitization |
| `cg_read_file` | `read` | Sensitive path blocking (.ssh/, keychain, browser data) + content sanitization |
| `cg_write_file` | `write` | Path access control + write content sanitization check |
| `cg_edit_file` | `edit` / `apply_patch` | Targeted old→new text replacement with path access control + sanitization |
| `cg_list_directory` | `read` (directory) | Directory access control |
| `cg_http_request` | `browser` / network tools | Domain allowlist + data exfiltration prevention |

### Scope Tools (per-prompt least-privilege)

| cg_* Tool | Purpose |
|-----------|---------|
| `cg_set_task_scope` | Declare what this task needs — restricts tools, paths, commands, and network to only what is required |
| `cg_clear_task_scope` | Remove all per-task restrictions (base rules still apply) |

### Inspection Tools

| cg_* Tool | Purpose |
|-----------|---------|
| `cg_skill_check` | Check whether a Skill/plugin is on the security allowlist |
| `cg_status` | View engine status: operating mode / audit statistics / panic state |

### Control Tools

| cg_* Tool | Purpose |
|-----------|---------|
| `cg_panic` | 🚨 Emergency pause — immediately deny all subsequent operations |
| `cg_resume` | Resume normal operation |

## Task-Scoped Security (MANDATORY)

**Before executing ANY tool calls for a new user request, you MUST call `cg_set_task_scope` first.**

This is the most important rule. Analyze what the user is asking, then declare exactly what you need:

1. **What files will I read?** → `file_read: ["/path/to/file", "/path/to/dir/**"]`
2. **What files will I write?** → `file_write: ["/path/to/file"]` (empty if read-only task)
3. **What commands will I run?** → `commands: ["git", "python3", "cat"]` (empty if no exec needed)
4. **What domains will I access?** → `network: ["api.github.com"]` (empty if no network needed)
5. **What tools do I NOT need?** → `disable_tools: ["execute_command", "http_request"]`

**Principle: declare only what you need. Everything else gets blocked automatically.**

Examples:

- User says "read the README" → `file_read: ["~/project/README.md"]`, `file_write: []`, `disable_tools: ["write_file", "edit_file", "execute_command", "http_request"]`
- User says "fix the bug in main.py" → `file_read: ["~/project/**"]`, `file_write: ["~/project/main.py"]`, `commands: ["python3"]`, `disable_tools: ["http_request"]`
- User says "check the weather" → `file_read: []`, `file_write: []`, `network: ["wttr.in"]`, `disable_tools: ["write_file", "edit_file", "execute_command"]`

> ⚠️ If you skip this step or declare overly broad scope, the security benefit is lost. Be specific.

## Usage Rules

1. **You must use `cg_*` tools** for all command, file, and network operations. Do not use native tools such as `exec`, `read`, `write`, `apply_patch`, or `process` to bypass security checks.
2. When an `cg_*` tool returns a `🚫 blocked` message, **do not attempt to work around it** — inform the user that the operation was blocked by security policy and explain why.
3. When a response indicates `⏳ awaiting approval`, inform the user and ask them to action it in the Dashboard.
4. If the ClawGuard daemon is not running (connection failed), prompt the user with:
   - Start command: `clawguard daemon start`
   - Install command: `curl -fsSL https://www.clawguard.site/download/install.sh | sh`
5. You can call `cg_status` at any time to check the current security state.
6. If suspicious behaviour is detected or the user requests it, use `cg_panic` for an emergency pause.
7. **NEVER reset, modify, or remove security rules during task execution.** Do not call `/rules/reset`, do not remove entries from allowlists/denylists, and do not disable or weaken any rule while performing work. If a rule is blocking you from completing a task, **stop immediately** and tell the user which rule is blocking the operation. Let the user decide whether to adjust the rules — that is their responsibility, not the agent's.

## Security Modes

ClawGuard has three operating modes:

- **enforce** — Operations that violate rules are immediately rejected
- **supervised** — Suspicious operations are paused and queued for user approval
- **permissive** — Only records to the audit log; does not block

## Dashboard

Audit logs for all operations are available in the local Dashboard: **http://127.0.0.1:19821**

The Dashboard provides: real-time operation timeline / audit statistics charts / rule configuration / one-click Panic
