# ClawGuard 架构与安全设计

本文档对应 2026-11-03 的 ClawGuard 实现，适用于同一容器内包含
OpenClaw 和 Codex CLI 的发布镜像。

## 1. ClawGuard 的定位

ClawGuard 是一个位于 Agent 与模型厂商之间的透明 LLM API Gateway。它不通过
Agent Hook 介入，也不要求 Agent 安装 ClawGuard 专用工具。Agent 仍然使用自己的
Provider 配置，只把 `baseUrl` 指向：

```text
http://127.0.0.1:19822/v1
```

推荐部署下，Codex 请求 `/v1/responses`，OpenClaw 根据配置请求
`/v1/chat/completions` 或 `/v1/responses`。ClawGuard 检查请求中的工具定义和模型
返回的工具调用，然后决定放行、拒绝、要求模型重新规划，或进入人工审批。

ClawGuard 不是 Hook，不是插件，也不是工具代理。它只处理经过它的 API 流量。
Agent 如果被配置为绕过 ClawGuard 直接访问厂商，ClawGuard 无法观察到这部分流量。

## 2. 核心安全不变量

实现以以下不变量为约束：

1. 一个环境中只运行一个 ClawGuard Gateway。
2. Agent 集成方式是修改 Provider API URL；不使用 Agent Hook。
3. ClawGuard 未启动时，Agent 请求应直接失败，不能回退到厂商或第二个网关。
4. 普通请求的 `messages`、`input`、`tools`、`tool_choice` 和 conversation
   history 原样转发，不做 wire-protocol 转换。
5. ClawGuard 只允许为内部判断构造克隆上下文：
   - Task Scope planner；
   - Skill Judge；
   - 最多三轮 Task Scope 策略反思。
6. 客户端提交的 `set_task_scope` schema 可以继续留在原请求中，但不能进入可执行
   工具注册表；如果模型调用它，ClawGuard 直接拒绝。
7. ClawGuard 不执行模型工具调用。它只在把模型响应交还给 Agent 之前审查调用。
8. 基础规则中的 hard deny 永远不能被 Task Scope 扩大覆盖。
9. 无法解析、无法识别或 Scope 建立失败时必须 fail closed。
10. OpenClaw、Codex、Claude 的审计、日志、审批历史和 Skill 判定数据库默认隔离。

## 3. 运行拓扑

```text
┌──────────────────────────────────────────────────────────────┐
│ Local ClawGuard process                                      │
│                                                              │
│  Codex CLI ── /v1/responses ───────┐                         │
│                                    │                         │
│  OpenClaw ── /v1/chat/completions ─┼──> ClawGuard :19822     │
│           └─ /v1/responses ────────┘          │              │
│                                                │              │
│                                      provider API            │
│                                      e.g. DeepSeek            │
│                                                              │
│  OpenClaw Gateway :18789                                     │
│  supervisord controls ClawGuard and OpenClaw                 │
└──────────────────────────────────────────────────────────────┘
```

关键组件：

- FastAPI Gateway：`clawguard/gateway.py`
- 基础规则引擎：`clawguard/rules.py`
- Responses 协议适配：`clawguard/responses.py`
- Anthropic Messages 适配：`clawguard/anthropic.py`
- Agent 工具别名与 Skill 根目录：`clawguard/agent_adapters.py`
- Skill 内容审查：`clawguard/skill_inspector.py`
- 审计数据库：`clawguard/audit.py`
- 审批队列：`clawguard/approval.py`
- 普通配置：`~/.clawguard/config.yaml`
- 基础策略：`~/.clawguard/rules.yaml`

## 4. Agent 与协议是两个独立维度

`gateway.agent` 决定 Agent 的工具名称语义和 Skill 根目录：

```yaml
gateway:
  agent: codex | openclaw | claude
```

`gateway.upstream_format` 决定 wire protocol：

```yaml
gateway:
  upstream_format: openai_response | openai_chat_completion | anthropic_message
```

两者必须分开理解。例如：

| Agent | 推荐请求端点 | `upstream_format` | `enable_responses_api` |
|---|---|---|---|
| Codex | `/v1/responses` | `openai_response` | `true` |
| OpenClaw Chat | `/v1/chat/completions` | `openai_chat_completion` | 可为 `false` |
| OpenClaw Responses | `/v1/responses` | `openai_response` | `true` |

入站协议与 `upstream_format` 不一致时，ClawGuard 返回
`protocol_mismatch`。它不尝试在 Chat Completions 和 Responses 之间转换。

## 5. 请求生命周期

### 5.1 入口与认证

Gateway 提供：

- `POST /v1/chat/completions`
- `POST /v1/responses`
- `POST /v1/messages`
- `GET /v1/models`
- `GET /v1/models/{model_id}`
- Dashboard 和本地控制接口

如果配置了 `gateway.client_api_key`，请求必须携带对应 Bearer token。发布 compose
默认不设置客户端密钥，依赖本机端口绑定和 Provider 凭据转发。

### 5.2 Panic 与协议检查

任何 LLM 请求到达后先检查 Panic 状态。Panic 开启时，所有模型调用返回协议对应的
拒绝响应。

随后检查入站端点是否匹配 `upstream_format`。不匹配直接返回 400，不修改请求。

### 5.3 工具注册表提取

ClawGuard 从当前请求的 `tools`、旧式 `functions` 和 Responses `custom` 工具中
提取函数名称与 schema：

- Chat Completions 常见形式：

  ```json
  {"type":"function","function":{"name":"exec","parameters":{}}}
  ```

- Responses 常见形式：

  ```json
  {"type":"function","name":"exec_command","parameters":{}}
  ```

- Codex 的 free-form 工具可以是：

  ```json
  {"type":"custom","name":"apply_patch"}
  ```

OpenClaw、Codex、Claude 的 provider-native 工具会被保留在普通请求中。ClawGuard
只把能识别的 function/custom tool 放入策略注册表；如果厂商返回一个无法识别的
native call，它仍会进入策略判断并按 `unknown_tool_action` 处理。

### 5.4 Agent 工具名规范化

Codex 的别名映射包括：

| Codex/兼容名称 | 统一策略名称 |
|---|---|
| `bash`、`exec_command`、`shell` | `exec` |
| `view_image` | `read` |
| `webfetch` | `web_fetch` |
| `websearch` | `web_search` |
| `apply_patch` | `apply_patch` |

原始请求中的工具名不会因此被改写；规范化只用于 ClawGuard 内部策略判断。

### 5.5 工具目录摘要与漂移检测

每个 session 会保存当前工具目录的 schema digest。若同一轮对话中工具目录变化：

- 记录 `tool_registry_changed`；
- 不静默创建第二份 Task Scope；
- 用新目录重新约束已保存 Scope 的 allowlist；
- 确保已经消失的工具不会继续被授权。

### 5.6 会话识别

Session ID 按以下顺序获取：

1. `x-openclaw-session-key`
2. `x-openclaw-session-id`
3. `x-client-request-id`
4. `session_id`
5. `x-session-affinity`
6. payload 中的 `user`
7. `gateway-anonymous`

每个 session 的 Scope 状态和策略转换有独立锁，避免并发请求相互覆盖权限。

### 5.7 内部脱敏副本

ClawGuard 会为审计和内部 planner 生成脱敏副本，但发往上游的普通请求仍使用原始
payload。也就是说：

- conversation history 不因发现 secret 而被删除或改写；
- Task Scope planner 只接收脱敏后的最新用户任务；
- request log 保存的是脱敏副本；
- 模型正常输出可按 `output_sanitization` 规则脱敏。

### 5.8 Task Scope 建立

只有存在工具注册表时才自动建立 Task Scope。Planner：

- 只接收固定 policy system prompt；
- 只接收最新一个实质用户消息；
- 不接收旧 assistant 消息、旧工具结果或其他历史；
- 只能从当前请求注册的工具名中选择；
- 必须调用内部工具 `set_task_scope`。

Planner 可使用 Chat Completions、Responses 或 Anthropic wire shape，但使用的是
当前 `upstream_format` 对应的原生 payload，不经过错误协议的转换。

同一 user turn 的后续 tool round-trip 不会重复规划权限。新用户 turn 会清除旧
Scope 并重新规划。

### 5.9 原样发送普通请求

Scope 建立完成后，ClawGuard 将原始客户端 payload 发往配置的 upstream path：

- Responses -> `/v1/responses`
- Chat Completions -> `/v1/chat/completions`
- Anthropic -> `/v1/messages`

普通请求中的完整 conversation history、工具定义和客户端 tool choice 不会被
内部 planner 视图替换。

### 5.10 检查上游响应

ClawGuard 解析上游响应中的全部工具调用，再逐个执行策略判断。只有没有拒绝调用时
才把响应返回给 Agent。

上游 HTTP 错误保留其状态和正文；planner 错误会额外附带阶段、状态、Content-Type
和有界错误正文。网络异常与超时返回 502，不会无限等待。

### 5.11 策略反思

只有可恢复的 Task Scope 拒绝会进入反思，例如：

- 工具不在当前 Scope allowlist；
- 工具被 Scope 禁用；
- 路径或目标不在 Scope；
- 工具参数无法解析；
- 选用未注册的替代工具名。

ClawGuard 会在内部克隆的请求中追加英文 tool feedback，要求模型换用已经允许的
工具。最多允许三个 provider response，其中最多两次反馈重试。

以下情况不进入反思：

- 基础 hard deny；
- 危险 shell、解释器或磁盘操作；
- 非 Scope 引起的策略拒绝；
- 无法安全向模型解释的调用。

## 6. Conversation History 与工具调用解析

### 6.1 OpenClaw Chat Completions

请求中的对话历史位于 `messages[]`。ClawGuard 用该字段：

- 统计 user turn；
- 找最新实质用户消息；
- 建立 session 与审计摘要；
- 对响应中的 tool call 执行策略。

工具 schema 位于 `tools[].function`。模型非流式调用主要从：

```text
choices[].message.tool_calls[]
choices[].message.function_call
```

提取。流式调用从：

```text
choices[].delta.tool_calls[]
choices[].delta.function_call
```

按 `index` 聚合参数片段。

OpenClaw 有时通过 `tool_search`、`tool_call` 暴露工具桥。ClawGuard 会把已知只读的
`web_fetch`、`web_search` 加入内部策略注册表，但不修改发给 OpenClaw 的 schema。

### 6.2 OpenClaw Synthetic Context

OpenClaw 会在 user role 中附加时间戳、Conversation Info、Runtime banner 和内建
runtime-status 消息。它们不是用户授权来源。

ClawGuard 在内部 planner 前会移除：

- `[Tue 2026-... GMT+8]` 时间戳前缀；
- `Conversation info: ⟦openclaw:ctx⟧` 块；
- queued message banner；
- `Runtime: name=...`、`Continue the current task...` 等 transport framing；
- `OPENCLAW_INTERNAL_CONTEXT` 状态消息。

原始请求中的这些文本不会被删除；清理只作用于 Scope planner 的用户消息视图。

### 6.3 Codex Responses

Responses 请求使用 `input`，而不是 Chat 的 `messages`。ClawGuard 将 `input`
投影为内部 message view：

- 普通 message item -> `system/developer/user/assistant` message；
- `function_call_output` -> `tool` message；
- `function_call` -> assistant 的规范 tool call；
- 字符串 input -> 一个 user message。

该投影只用于 session、审计和 planner，不会被作为 Responses payload 发往上游。

Responses 工具 schema 使用扁平结构：

```json
{"type":"function","name":"read","parameters":{}}
```

Codex 的 `apply_patch` 常见为：

```json
{"type":"custom","name":"apply_patch"}
```

非流式响应从 `output[]` 提取：

- `function_call`：参数在 `arguments`；
- `custom_tool_call`：free-form 输入在 `input`；
- provider `*_call`：作为 native call 继续审查。

流式响应从以下事件聚合：

- `response.output_item.added`
- `response.output_item.done`
- `response.function_call_arguments.delta`
- `response.function_call_arguments.done`
- `response.custom_tool_call_input.delta`
- `response.custom_tool_call_input.done`

### 6.4 流式安全

ClawGuard 会缓冲上游 SSE，在完整拼接 tool arguments 后执行策略检查，再将清洗后的
SSE 返回给 Agent。这样 secret 可以被跨 chunk 检测，工具参数也不会在尚未审查时
交给 Agent。

代价是客户端会承担完整上游响应生成时间，ClawGuard 不是逐 token 透明转发器。

### 6.5 Generic `tool_call` Envelope

部分 OpenAI-compatible provider 返回：

```json
{
  "name": "tool_call",
  "arguments": {
    "id": "web_fetch",
    "args": {"url": "https://example.com"}
  }
}
```

ClawGuard 会将外层 `tool_call` 展开为真正执行的 `web_fetch` 再判断，同时保留
wrapper 名称用于 Scope 兼容。否则只审查不会真正执行的 envelope 会形成绕过。

### 6.6 无法解析的调用

- 没有函数名的调用 -> deny；
- 参数不是 JSON object -> 拒绝，可能作为可恢复参数错误反馈；
- 不在请求注册表中的工具 -> `unknown_tool_action`，默认 deny；
- 已注册但没有可分类参数的 opaque 工具 -> `unclassified_tool_action`，默认 approve；
- 客户端伪造的 `set_task_scope` -> 永远 deny。

## 7. ClawGuard 自身安全系统

### 7.1 基础规则与 Task Scope 的交集

基础规则来自 `rules.yaml`，Task Scope 只能进一步收窄权限。组合语义是严格交集：

- 基础 deny 是最终 deny；
- 基础 approve 仍是人工审批，不因 Scope allow 而自动放行；
- 基础 allow 仍需要 Scope 覆盖具体目标；
- Scope 没有声明的路径、命令或域名不放行。

### 7.2 命令规则

命令策略支持：

- blacklist hard deny；
- whitelist allow；
- supervised approval；
- unknown command 默认 approval；
- shell pipeline、重定向、替换和复合命令的分解检查。

危险边界包括：

- 递归删除根目录或 home；
- 磁盘和分区操作；
- fork bomb、资源耗尽；
- 下载内容直接管道到 shell/interpreter；
- 反向 shell、持久化、凭据读取；
- `python`/`pypy` 运行时；
- `find -exec`、`-delete`、`-fprint*`；
- `perl`、`ruby`、`node` 等 inline code 执行；
- shell expansion、命令替换、无法解析的复杂语法。

### 7.3 文件规则

文件路径会：

1. 展开 `~` 和环境变量；
2. 解析符号链接；
3. 检查 dangling symlink；
4. 先检查 deny path；
5. 再检查敏感文件；
6. 再检查 allowed path；
7. 最后与 Task Scope 做交集。

检查使用真实路径边界，避免 `/workspace_evil` 被误认为 `/workspace` 的子路径。
默认 deny 包括 SSH、云凭据、浏览器 profile、邮件、密码管理器、ClawGuard 内部目录
和 OpenClaw 配置文件。

### 7.4 网络规则

网络检查基于 URL hostname，而不是 netloc：

- 非 HTTP/HTTPS 协议直接拒绝；
- 云 metadata endpoint 直接拒绝；
- 私网、loopback、link-local 地址直接拒绝；
- deny domain 优先；
- allow domain 次之；
- 未声明域名按 `network_rules.default_action`；
- Task Scope 还要精确包含目标 host。

URL path 不构成权限边界；声明的是 host。

### 7.5 Capability Adapter

ClawGuard 不要求模型永远只发单一 `curl`。它把可证明安全的单命令或只读 pipeline
映射到 capability：

| 安全操作 | Capability |
|---|---|
| `cat`、`head`、`grep` 等普通本地读取 | `file_read` |
| `wget -qO- URL` | `network_read` |
| `curl -s URL \| grep ... \| head` | `network_read` |
| `wget -O path URL` | `network_read + file_write` |
| `cp`、`mv` | `file_read + file_write` |

适配只适用于：

- `exec` 工具本身已经被 Scope 允许；
- 命令可被安全解析；
- 没有 shell expansion 或未声明重定向；
- 文件目标、host 和基础规则都通过。

`curl -d`、上传、POST body、未知命令、Python、inline interpreter 和
`find -exec` 不会通过 capability 自动放行。

### 7.6 Policy Mode

`supervised`：

- allow 放行；
- deny 拒绝；
- approve 进入审批；
- Task Scope 仍在最前尝试三轮合规替代方案。

`strict`：

- approval 转为 deny；
- 适合无人值守环境。

`permissive`：

- approval 不阻塞；
- **不会**把 hard deny 改成 allow。

### 7.7 Skill Inspector

Skill 被视为不受信任的代码与指令。ClawGuard 在 Skill install、load、create 和 call
路径上识别 Skill intent。

审查过程：

1. 定位并限制 bundle；
2. 读取 `SKILL.md` 和声明文件；
3. 计算内容 hash；
4. 检查 bundle 完整性、文件数、单文件和总大小；
5. 将 Skill 内容作为不可信 user content 交给 Judge；
6. Judge 返回安全结论、风险级别、能力和理由；
7. 将 verdict 与 content hash 一起缓存。

安全属性：

- Skill 内容不会进入 Judge 的 authoritative system prompt；
- 文件变化导致 hash 改变，必须重新审查；
- Judge 不可用、超时或输出无效时 fail closed；
- Active Skill 在后续调用时重新核对；
- 人工 override 需要同源请求和明确理由；
- 全局 Skill 元数据可枚举，但普通 `SKILL.md` body 仍受审查。

Codex 默认 Skill 根目录：

```text
/home/node/.codex/skills
/home/node/.agents/skills
/etc/codex/skills
```

OpenClaw 默认 Skill 根目录：

```text
/home/node/.openclaw/workspace/skills
/home/node/.openclaw/skills
```

### 7.8 人工审批

审批队列将请求持久化到 Agent 独立的 `approval_history.db`。进程重启时，上次未解决
的 pending 请求会标为 interrupted。

默认：

```yaml
policy:
  approval_timeout: 60
  timeout_action: deny
```

审批内容包括工具名、规则原因、规则类型和最多 8192 字符的脱敏参数。超时默认 deny。

### 7.9 Panic

Panic 是全局紧急关闭路径：

- `POST /panic` 进入 Panic；
- `POST /resume` 恢复；
- `GET /panic/status` 查询；
- `GET /panic/sse` 推送状态。

Panic 开启时，模型 API 请求在工具执行前直接拒绝。

### 7.10 输出脱敏

输入脱敏用于审计和内部 planner，不改变普通上游 payload。输出侧可在非流式和流式
响应中识别跨 chunk 的 secret 并替换。输出脱敏是数据泄露防线，不代替权限控制。

### 7.11 Panic、认证和协议拒绝的优先级

网关执行顺序是：

1. 客户端认证；
2. Panic；
3. 协议匹配；
4. 工具目录审计；
5. Task Scope；
6. 普通模型请求；
7. 工具调用策略；
8. Skill Judge 和人工审批；
9. 输出脱敏和返回。

## 8. 审计和数据隔离

`gateway.data_dir: null` 时自动使用：

```text
~/.clawguard/agents/codex
~/.clawguard/agents/openclaw
~/.clawguard/agents/claude
```

每个 Agent 目录包含：

```text
audit.db
approval_history.db
skill_inspector.db
logs/
```

共享文件：

```text
~/.clawguard/config.yaml
~/.clawguard/rules.yaml
```

审计记录包含：

- LLM request；
- LLM response；
- model tool call；
- requested/final action；
- rule type；
- capability；
- target；
- tool arguments SHA-256 前缀；
- Skill 审查明细；
- approval 决议。

默认保留期为 90 天。`request_logging: true` 时还会保存脱敏后的请求 JSON/TXT。

注意：Task Scope 调试日志额外保存原始未脱敏用户消息，用于排查
input-sanitization 差异。因此 `~/.clawguard/agents/<agent>/logs/scope-*.json` 应按
敏感日志保护，不应对外分发。

## 9. 失败语义

| 情况 | 结果 |
|---|---|
| ClawGuard 未启动 | Agent 连接失败，不回退 |
| 入站/上游协议不匹配 | HTTP 400 `protocol_mismatch` |
| Responses 未开启 | HTTP 501 |
| Scope planner 上游 4xx/5xx | HTTP 502，带 stage、状态和正文 |
| Scope planner 网络错误/超时 | HTTP 502，带异常类型 |
| Scope 声明无效 | HTTP 502，带具体校验原因 |
| 普通上游 4xx/5xx | 原状态码和原错误正文 |
| 不可恢复工具调用 | 协议对应的策略拒绝 |
| 可恢复 Task Scope 拒绝 | 最多三次 provider attempt |
| Skill Judge 失败 | Skill 不可用，fail closed |
| 人工审批超时 | 默认 deny |
| Panic | all model calls denied |

## 10. 安全边界与限制

ClawGuard 是 API 边界防护层，不是操作系统沙箱。

- 它只能看到经过 Gateway 的模型 API 和模型响应。
- 它不拦截 Agent 在模型调用之外自行启动的后台进程。
- 它不保证 Agent 的内部插件不会绕过 Provider 配置。
- 它不能修复模型厂商自身的 502。
- 它不转换 wire protocol。
- 一个 Gateway 在同一时刻只对应一个 `agent` 和一种 `upstream_format`。
- 流式响应会先完整缓冲再审查，增加延迟。
- Task Scope 是模型声明的窄权限，不是管理员签名；因此必须与基础 deny、
  capability adapter 和目标检查共同使用。
- 发布镜像默认使用 DeepSeek，但架构本身支持其他 OpenAI-compatible provider。

生产部署还应结合：

- 容器非 root 执行；
- dropped Linux capabilities；
- `no-new-privileges`；
- 只读根文件系统或最小可写卷；
- 出站网络策略；
- Provider key 轮换；
- 日志访问控制；
- 定期测试 Scope 和 Skill Judge 故障关闭。

## 11. 配置参考

Codex/Responses：

```yaml
gateway:
  agent: codex
  upstream_format: openai_response
  enable_responses_api: true
  upstream_base_url: https://api.deepseek.com
  forward_client_authorization: true
  unknown_tool_action: deny
  unclassified_tool_action: approve
  policy_mode: supervised
```

OpenClaw/Chat Completions：

```yaml
gateway:
  agent: openclaw
  upstream_format: openai_chat_completion
  enable_responses_api: false
  upstream_base_url: https://api.deepseek.com
```

关键环境变量：

| 变量 | 作用 |
|---|---|
| `CLAWGUARD_AGENT` | 覆盖 Agent adapter |
| `CLAWGUARD_UPSTREAM_FORMAT` | 覆盖 wire protocol |
| `CLAWGUARD_ENABLE_RESPONSES_API` | 开启 Responses 入口 |
| `CLAWGUARD_UPSTREAM_BASE_URL` | Provider base URL |
| `CLAWGUARD_UPSTREAM_API_KEY` | Gateway 使用的 Provider key |
| `CLAWGUARD_FORWARD_CLIENT_AUTHORIZATION` | 透传 Agent Provider key |
| `CLAWGUARD_REQUEST_LOGGING` | 保存请求调试日志 |
| `CODEX_GATEWAY_API_KEY` | Codex CLI 发给 ClawGuard 的 key |
| `OPENCLAW_PROVIDER_API_KEY` | 首次启动写入 OpenClaw provider 的 key |

## 12. 验证状态

当前代码回归测试：

```text
148 passed
```

最近一次 40 项双 Agent 任务复跑：

| Agent / protocol | PASS | PARTIAL | FAIL | Total |
|---|---:|---:|---:|---:|
| OpenClaw / Chat Completions | 12 | 8 | 0 | 20 |
| Codex / Responses | 13 | 1 | 6 | 20 |
| Combined | 25 | 9 | 6 | 40 |

该次复跑产生 45 个 Scope planner 日志，HTTP 415 为 0，HTTP 502 为 0。

详细任务结果见：

```text
UTILITY_RUN_REPORT_2026-11-03.md
```

## 13. 源码索引

| 功能 | 主要位置 |
|---|---|
| Gateway 路由和请求流程 | `clawguard/gateway.py` |
| Chat/Responses 工具调用提取 | `clawguard/gateway.py`、`clawguard/responses.py` |
| Agent 工具名语义 | `clawguard/agent_adapters.py` |
| 规范工具调用对象 | `clawguard/tool_protocol.py` |
| 基础命令/文件/网络规则 | `clawguard/rules.py` |
| Task Scope planner | `_scope_planning_payload`、`proxy_json` |
| Capability adapter | `_safe_command_capability_adapter` |
| Skill Inspector | `clawguard/skill_inspector.py` |
| 审批 | `clawguard/approval.py` |
| 审计 | `clawguard/audit.py` |
| 内部协议请求 | `clawguard/internal_requests.py` |
