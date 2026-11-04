# 🛡️ ClawGuard

**A Runtime Security Framework for Tool-Augmented LLM Agents Against Indirect Prompt Injection**

[![arXiv](https://img.shields.io/badge/arXiv-2604.11790-b31b1b.svg)](https://arxiv.org/abs/2604.11790)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

> **ClawGuard enforces a user-confirmed rule set at every tool-call boundary, transforming unreliable alignment-dependent defense into a deterministic, auditable mechanism that intercepts adversarial tool calls before any real-world effect is produced.**

ClawGuard implements that guarantee as an Agent-agnostic API gateway: it runs
locally between an Agent and its model provider, inspects every tool-call
boundary, and makes security decisions independently of the Agent's plugin
system. Because the integration point is the provider API rather than a
specific Agent SDK, the same policy engine can protect Codex, OpenClaw, or a
future framework through a small action adapter.

Accordingly, this repository deploys **ClawGuard only**. It does not install,
configure, or manage the Agent runtime; users install Codex, OpenClaw, or their
preferred framework separately, then point that Agent's provider URL at
ClawGuard.

## Architecture

```text
Existing Agent runtime                 ClawGuard                     Model provider
┌────────────────────┐        ┌──────────────────────────┐        ┌──────────────────┐
│ Codex              │        │ API Gateway :19822       │        │ OpenAI-compatible│
│ OpenClaw           │───────>│ action adapter           │───────>│ provider API     │
│ another framework  │        │ policy + approvals       │        │                  │
└────────────────────┘        │ audit + sanitization     │        └──────────────────┘
                              └──────────────────────────┘
```

There are deliberately **two different base URLs**. The Agent-facing URL points
to ClawGuard, while ClawGuard's upstream URL points to the real model provider:

| Configuration | Where it is set | Example | Purpose |
|---|---|---|---|
| Agent provider base URL | Codex or OpenClaw configuration | `http://127.0.0.1:19822/v1` | Sends Agent traffic into ClawGuard |
| ClawGuard upstream base URL | `~/.clawguard/config.yaml` | `https://api.deepseek.com` | Sends accepted traffic to the real LLM provider |
| Agent model | Codex or OpenClaw configuration | `deepseek-v4-pro` | Selects the provider model to request |
| Agent API key | Agent configuration or environment | `CODEX_GATEWAY_API_KEY` | Authenticates the request forwarded to the provider |

The API key and model belong to the Agent/provider configuration. ClawGuard does
not select a model: it forwards the requested `model` value and, by default,
forwards the Agent's `Authorization` header. ClawGuard only needs its own
outbound provider URL and matching wire protocol.

ClawGuard separates the Agent runtime from the security engine:

| Layer | Responsibility |
|---|---|
| Agent adapter | Maps native tool names and argument shapes into canonical actions |
| Protocol adapter | Parses Responses, Chat Completions, or Anthropic Messages |
| Policy engine | Evaluates command, file, network, and Skill permissions |
| Task Scope | Narrows permissions to the current user request |
| Approval queue | Pauses operations that require human review |
| Audit store | Records decisions in Agent-isolated databases |
| Sanitizer | Removes detected secrets from model output |

The Agent-specific integration point is the **action adapter**. If a new
framework uses a supported wire protocol, such as the OpenAI Responses API,
migration normally requires only:

1. Add or select the action adapter for that framework's tool-call format.
2. Point the framework's provider `base_url` at ClawGuard.
3. Select the matching `upstream_format`.

The rule engine, approval system, audit schema, and sanitizer remain shared.
ClawGuard does not translate between wire protocols. The Agent and gateway must
use the same configured protocol, and one gateway process serves one Agent
adapter/protocol combination at a time.

## Request flow

1. ClawGuard checks client authentication, Panic state, and protocol match.
2. It extracts tools from the current request and records a schema digest.
3. It creates a Task Scope for the latest user turn.
4. It forwards the original provider payload.
5. It parses every tool call in the response before execution.
6. It applies base policy intersected with Task Scope.
7. It allows, denies, requests approval, or returns bounded feedback.
8. It records the decision in the configured Agent audit store.

Unparseable or unknown calls fail closed. Task Scope may narrow access but
cannot override a base deny rule.

## Requirements

- Python 3.10 or newer
- Network access to your model provider
- An existing supported Agent installation, configured separately

No Docker installation is required.

## Deploy ClawGuard

### 1. Download or clone this repository

```bash
git clone https://github.com/Claw-Guard/ClawGuard.git
cd ClawGuard
```

### 2. Start the gateway

For Codex using the Responses API:

```bash
python deploy.py \
  --agent codex \
  --protocol responses \
  --upstream-url https://api.deepseek.com
```

For OpenClaw using Chat Completions:

```bash
python deploy.py \
  --agent openclaw \
  --protocol chat-completions \
  --upstream-url https://api.deepseek.com
```

For OpenClaw using Responses:

```bash
python deploy.py \
  --agent openclaw \
  --protocol responses \
  --upstream-url https://api.deepseek.com
```

`deploy.py` performs only the ClawGuard deployment:

- creates a local `.venv`;
- installs ClawGuard and its Python dependencies;
- initializes `~/.clawguard/config.yaml` and `rules.yaml`;
- configures the selected Agent adapter and provider protocol;
- starts ClawGuard in the background;
- waits for `http://127.0.0.1:19822/status`.

It does not install or launch Codex or OpenClaw. The `--agent` argument selects
ClawGuard's interpretation layer; it does not install that Agent.

The provider URL must be the API origin that ClawGuard forwards to, not the
local ClawGuard URL. Include `/v1` if your provider requires it.

### Change ClawGuard's provider URL

ClawGuard's outbound API URL is stored separately from the Agent configuration:

```yaml
gateway:
  host: 127.0.0.1
  port: 19822
  agent: codex
  upstream_base_url: https://api.deepseek.com
  upstream_format: openai_response
  enable_responses_api: true
  forward_client_authorization: true
```

`gateway.upstream_base_url` is the real LLM provider address. It is not the URL
that Codex or OpenClaw should call. To change it with the deployment script:

```bash
python deploy.py \
  --agent codex \
  --protocol responses \
  --upstream-url https://api.openai.com/v1 \
  --restart
```

If `--upstream-url` is omitted, `deploy.py` preserves the current configured
value. For a first deployment it defaults to
`https://api.deepseek.com`.

The same setting can be changed manually in `~/.clawguard/config.yaml`, followed
by a restart:

```bash
python deploy.py --agent codex --protocol responses --restart
```

The Agent's provider URL must remain local:

```text
Agent -> http://127.0.0.1:19822/v1 -> ClawGuard
ClawGuard -> https://api.openai.com/v1 -> provider
```

Use `upstream_format: openai_response` for Codex Responses,
`openai_chat_completion` for OpenClaw Chat Completions, and the corresponding
`--protocol` value when using `deploy.py`.

### 3. Check or stop ClawGuard

```bash
python deploy.py --status
python deploy.py --stop
```

Configuration and runtime state are stored under:

```text
~/.clawguard/
```

Use `--foreground` to keep the gateway attached to the terminal:

```bash
python deploy.py --agent codex --protocol responses --foreground
```

Use `--restart` after changing ClawGuard settings:

```bash
python deploy.py --agent openclaw --protocol chat-completions --restart
```

Use `--reset-config` to restore the distributed configuration and rules.

### Provider credentials

By default ClawGuard forwards the Agent's provider authorization header, so the
existing Agent can continue using its own API key. If ClawGuard should hold the
upstream credential instead, set `CLAWGUARD_UPSTREAM_API_KEY` in the environment
before starting the gateway.

Provider keys are never written into the repository. Keep the generated
`~/.clawguard` directory and request logs private.

## Connect Codex

Install Codex separately. Then edit its configuration, normally at
`~/.codex/config.toml`:

```toml
model = "deepseek-v4-pro"
model_provider = "clawguard"

[model_providers.clawguard]
name = "ClawGuard"
base_url = "http://127.0.0.1:19822/v1"
wire_api = "responses"
env_key = "CODEX_GATEWAY_API_KEY"
requires_openai_auth = false
```

In this configuration:

- `model` is the exact model name supported by the upstream provider.
- `base_url` points to ClawGuard, not to the provider.
- `env_key` names the environment variable that contains your provider API key.
- `wire_api = "responses"` must match ClawGuard's `openai_response` format.

Set the API key in the environment before starting Codex. For example:

```bash
export CODEX_GATEWAY_API_KEY="<your-provider-api-key>"
```

On PowerShell:

```powershell
$env:CODEX_GATEWAY_API_KEY = "<your-provider-api-key>"
```

Then point ClawGuard at the real provider URL:

```bash
python deploy.py \
  --agent codex \
  --protocol responses \
  --upstream-url https://api.deepseek.com
```

The resulting chain is:

```text
Codex model=deepseek-v4-pro
  -> base_url=http://127.0.0.1:19822/v1
  -> ClawGuard agent=codex, format=openai_response
  -> upstream_base_url=https://api.deepseek.com
```

Change `model` and `--upstream-url` together when switching to a different
provider/model family. ClawGuard neither renames nor substitutes the model.

### Switch Codex back to the provider API

Change `model_provider` and add a direct provider:

```toml
model_provider = "deepseek-direct"

[model_providers.deepseek-direct]
name = "DeepSeek direct"
base_url = "https://api.deepseek.com"
wire_api = "responses"
env_key = "DEEPSEEK_API_KEY"
requires_openai_auth = false
```

Traffic now bypasses ClawGuard. Restore the `clawguard` provider entry to route
Codex through the gateway again.

## Connect OpenClaw

Install OpenClaw separately. OpenClaw may use either Chat Completions or
Responses.

### OpenClaw with Chat Completions

First select the model OpenClaw should request and keep its provider pointed at
ClawGuard. The relevant OpenClaw fields are:

```text
agents.defaults.model.primary = deepseek-clawguard/deepseek-v4-pro
models.providers.deepseek-clawguard.baseUrl = http://127.0.0.1:19822/v1
models.providers.deepseek-clawguard.apiKey = <your-provider-api-key>
models.providers.deepseek-clawguard.api = openai-completions
```

Then start ClawGuard with its own upstream provider URL:

```bash
python deploy.py \
  --agent openclaw \
  --protocol chat-completions \
  --upstream-url https://api.deepseek.com
```

In `~/.openclaw/openclaw.json`, the provider object should contain:

```json
{
  "baseUrl": "http://127.0.0.1:19822/v1",
  "apiKey": "<your-provider-api-key>",
  "api": "openai-completions"
}
```

### OpenClaw with Responses

Select the same or another provider-supported model in OpenClaw, then start
ClawGuard with the Responses protocol and the real provider URL:

```bash
python deploy.py \
  --agent openclaw \
  --protocol responses \
  --upstream-url https://api.deepseek.com
```

Set the provider to:

```json
{
  "baseUrl": "http://127.0.0.1:19822/v1",
  "apiKey": "<your-provider-api-key>",
  "api": "openai-responses"
}
```

Restart OpenClaw after changing its provider configuration.

The resulting chain is:

```text
OpenClaw model=<provider-supported-model>
  -> baseUrl=http://127.0.0.1:19822/v1
  -> ClawGuard agent=openclaw, protocol=chat-completions|responses
  -> upstream_base_url=<real provider API URL>
```

The model remains an Agent/provider setting. ClawGuard forwards the selected
model name unchanged.

### Switch OpenClaw back to the provider API

Point the provider directly at the model provider:

```json
{
  "baseUrl": "https://api.deepseek.com",
  "apiKey": "<your-provider-api-key>",
  "api": "openai-completions"
}
```

OpenClaw then bypasses ClawGuard. Restore the local ClawGuard URL to re-enable
policy inspection.

## Extending to another Agent

Implement the integration in the action-adapter layer:

- map native tool names to canonical tool names;
- parse function, custom, and free-form tool calls;
- normalize arguments into `CanonicalToolCall`;
- select an existing wire protocol when possible;
- add regression tests for new envelopes and edge cases.

The policy and approval engine should not need Agent-specific changes when the
new framework can be represented by the existing canonical action model.

## Security model

- Base deny rules cannot be widened by Task Scope.
- Unknown tools and unparsed calls fail closed.
- File paths are resolved before deny/allow decisions.
- Network checks use URL hostnames and reject private/metadata endpoints.
- Skill bundles are bounded, content-addressed, and inspected before loading.
- Approval timeout defaults to deny.
- Audit databases and logs are isolated by Agent adapter.
- Panic mode rejects model traffic immediately.

ClawGuard is not an operating-system sandbox. It only protects traffic that
passes through its local API endpoint. Use OS isolation, network controls, and
secret management in addition to ClawGuard.

## Development

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest -q
```

On Windows, activate the environment with:

```powershell
.\.venv\Scripts\Activate.ps1
```

The detailed security design is in
[`CLAWGUARD_ARCHITECTURE_AND_SECURITY.md`](CLAWGUARD_ARCHITECTURE_AND_SECURITY.md).
