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
| `cg_write_file` | `write` / `edit` / `apply_patch` | Path access control + write content sanitization check |
| `cg_list_directory` | `read` (directory) | Directory access control |
| `cg_http_request` | `browser` / network tools | Domain allowlist + data exfiltration prevention |

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

## Usage Rules

1. **You must use `cg_*` tools** for all command, file, and network operations. Do not use native tools such as `exec`, `read`, `write`, `apply_patch`, or `process` to bypass security checks.
2. When an `cg_*` tool returns a `🚫 blocked` message, **do not attempt to work around it** — inform the user that the operation was blocked by security policy and explain why.
3. When a response indicates `⏳ awaiting approval`, inform the user and ask them to action it in the Dashboard.
4. If the ClawGuard daemon is not running (connection failed), prompt the user with:
   - Start command: `clawguard daemon start`
   - Install command: `curl -fsSL https://www.clawguard.site/download/install.sh | sh`
5. You can call `cg_status` at any time to check the current security state.
6. If suspicious behaviour is detected or the user requests it, use `cg_panic` for an emergency pause.

## Security Modes

ClawGuard has three operating modes:

- **enforce** — Operations that violate rules are immediately rejected
- **supervised** — Suspicious operations are paused and queued for user approval
- **permissive** — Only records to the audit log; does not block

## Dashboard

Audit logs for all operations are available in the local Dashboard: **http://127.0.0.1:19821**

The Dashboard provides: real-time operation timeline / audit statistics charts / rule configuration / one-click Panic
