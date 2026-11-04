# ClawGuard 2026.11.3

This release rebuilds the GitHub distribution around a standalone, local
ClawGuard API gateway. Docker is not required.

## Highlights

- One cross-platform deployment script for ClawGuard.
- No Agent runtime is installed automatically.
- Select the ClawGuard action adapter with `--agent`.
- Select Responses, Chat Completions, or Anthropic Messages with `--protocol`.
- Route an existing Codex or OpenClaw installation through
  `http://127.0.0.1:19822/v1`.
- Keep provider credentials with the Agent or provide them to ClawGuard through
  its environment.
- Preserve the shared policy engine, Task Scope, approval queue, audit store,
  Skill Inspector, and output sanitization.

## Deploy ClawGuard only

```bash
python deploy.py --agent codex --protocol responses
python deploy.py --agent openclaw --protocol chat-completions
python deploy.py --agent openclaw --protocol responses
```

Codex and OpenClaw must be installed and managed separately. See
[`README.md`](README.md) for provider configuration and switching instructions.
