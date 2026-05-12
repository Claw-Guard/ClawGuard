/**
 * ClawGuard Plugin for OpenClaw
 *
 * Integrates the ClawGuard security engine into OpenClaw, proxying all tool calls:
 * - execute_command → executed after review by the ClawGuard rule engine
 * - read_file / write_file → path allowlist/blocklist + sensitive data sanitization
 * - list_directory → directory access control
 * - http_request → domain allowlist filtering
 * - skill_check → Skill allowlist validation
 *
 * All operations are recorded to the ClawGuard audit log. Dashboard: http://127.0.0.1:19821
 *
 * Plugin spec reference: https://docs.openclaw.ai/tools/plugin
 * Agent Tools reference: https://docs.openclaw.ai/plugins/agent-tools
 */

import http from "http";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

// --- Default config (can be overridden by openclaw.plugin.json configSchema) ---
const DEFAULT_CONFIG = {
  daemonHost: "127.0.0.1",
  daemonPort: 19821,
  healthCheckInterval: 30,
  autoReconnect: true,
};

// --- Plugin state ---
let pluginConfig = { ...DEFAULT_CONFIG };
let daemonConnected = false;
let healthCheckTimer = null;

// --- HTTP helper ---
function agRequest(method, path, body, customTimeout) {
  return new Promise((resolve, reject) => {
    const opts = {
      hostname: pluginConfig.daemonHost,
      port: pluginConfig.daemonPort,
      path,
      method,
      timeout: customTimeout || (method === "GET" ? 5000 : 15000),
    };

    if (body) {
      opts.headers = {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(JSON.stringify(body)),
      };
    }

    const req = http.request(opts, (res) => {
      let chunks = "";
      res.on("data", (c) => (chunks += c));
      res.on("end", () => {
        try {
          const data = JSON.parse(chunks);
          // HTTP 4xx/5xx treated as business errors
          if (res.statusCode >= 400) {
            resolve({ error: data.error || data.message || `HTTP ${res.statusCode}`, _status: res.statusCode });
          } else {
            resolve(data);
          }
        } catch {
          resolve({ raw: chunks, _status: res.statusCode });
        }
      });
    });
    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("ClawGuard daemon connection timed out"));
    });
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

function agGet(path) {
  return agRequest("GET", path);
}
function agPost(path, body) {
  return agRequest("POST", path, body);
}

// --- ClawGuard tool proxy ---
async function callTool(toolName, params) {
  // Blocking call — daemon holds connection open until approved/denied/timeout (max 60s)
  // No approval_required intermediate state; result is always final.
  return await agRequest("POST", "/api/tool/call", { tool: toolName, input: params }, 70000);
}

// --- Daemon health check ---
async function checkDaemonHealth(logger) {
  try {
    const status = await agGet("/api/status");
    if (status.version) {
      if (!daemonConnected) {
        daemonConnected = true;
        if (logger) logger.info(`[ClawGuard] daemon connected v${status.version} mode=${status.mode}`);
      }
      return true;
    }
  } catch {
    if (daemonConnected) {
      daemonConnected = false;
      if (logger) logger.warn("[ClawGuard] daemon connection lost");
    }
  }
  return false;
}

// --- Unified result formatter ---
function formatResult(res) {
  if (res.error) {
    return {
      content: [{ type: "text", text: `🚫 ClawGuard blocked: ${res.error}` }],
      isError: true,
    };
  }
  const text = res.result || res.output || res.content || JSON.stringify(res, null, 2);
  return { content: [{ type: "text", text }] };
}

function formatError(e) {
  return {
    content: [{
      type: "text",
      text: `⚠️ ClawGuard daemon not responding: ${e.message}\n` +
            `  Start command: clawguard daemon start\n` +
            `  Install command: curl -fsSL https://www.clawguard.site/download/install.sh | sh`,
    }],
    isError: true,
  };
}

// ====================================================
// Plugin entry point — OpenClaw 2026.x compatible
// ====================================================
export default definePluginEntry({
  id: "clawguard",
  name: "ClawGuard",
  description: "ClawGuard Security Engine OpenClaw Plugin — Intercept dangerous operations, audit all actions, protect sensitive data",
  register(api) {
    // --- Load plugin config ---
    if (api.config) {
      pluginConfig = { ...DEFAULT_CONFIG, ...api.config };
    }
    const logger = api.logger || null;

    // --- Register background health check service ---
    api.registerService({
      id: "clawguard-health",
      start: () => {
        if (logger) logger.info("[ClawGuard] Health check service started");
        checkDaemonHealth(logger);
        healthCheckTimer = setInterval(
          () => checkDaemonHealth(logger),
          (pluginConfig.healthCheckInterval || 30) * 1000
        );
      },
      stop: () => {
        if (healthCheckTimer) {
          clearInterval(healthCheckTimer);
          healthCheckTimer = null;
        }
        if (logger) logger.info("[ClawGuard] Health check service stopped");
      },
    });

    // --- Register Gateway RPC methods ---
    api.registerGatewayMethod("clawguard.status", async ({ respond }) => {
      try {
        const status = await agGet("/api/status");
        respond(true, { connected: true, ...status });
      } catch (e) {
        respond(false, { connected: false, error: e.message });
      }
    });

    api.registerGatewayMethod("clawguard.health", async ({ respond }) => {
      respond(true, { connected: daemonConnected, config: pluginConfig });
    });

    // ============================================
    // Action tools — replace native exec/read/write
    // ============================================

    // Tool: cg_execute_command — replaces exec / process
    api.registerTool({
      name: "cg_execute_command",
      description:
        "Execute a shell command through the ClawGuard security engine. Commands are reviewed by the rule engine; dangerous commands are automatically blocked and output is sanitized of sensitive information. Replaces the native exec tool.",
      parameters: {
        type: "object",
        properties: {
          command: { type: "string", description: "Shell command to execute" },
          cwd: { type: "string", description: "Working directory (optional)" },
          timeout: { type: "integer", description: "Timeout in seconds, default 30", default: 30 },
        },
        required: ["command"],
      },
      async execute(_id, params) {
        try {
          const res = await callTool("execute_command", {
            command: params.command,
            cwd: params.cwd || "",
            timeout: params.timeout || 30,
          });
          return formatResult(res);
        } catch (e) {
          return formatError(e);
        }
      },
    });

    // Tool: cg_read_file — replaces read
    api.registerTool({
      name: "cg_read_file",
      description:
        "Read a file through the ClawGuard security engine. Sensitive paths (~/.ssh, /etc/shadow, browser data, etc.) are automatically blocked, and file contents are sanitized to filter API keys, tokens, and SSH keys. Replaces the native read tool.",
      parameters: {
        type: "object",
        properties: {
          path: { type: "string", description: "Absolute file path or path starting with ~" },
          offset: { type: "integer", description: "Starting line number (1-indexed)" },
          limit: { type: "integer", description: "Number of lines to read" },
        },
        required: ["path"],
      },
      async execute(_id, params) {
        try {
          const input = { path: params.path };
          if (params.offset) input.offset = params.offset;
          if (params.limit) input.limit = params.limit;
          const res = await callTool("read_file", input);
          return formatResult(res);
        } catch (e) {
          return formatError(e);
        }
      },
    });

    // Tool: cg_write_file — replaces write
    api.registerTool({
      name: "cg_write_file",
      description:
        "Write a file through the ClawGuard security engine. Sensitive paths are automatically blocked and written content is scanned by the sanitizer to prevent leaking secrets. Replaces the native write tool. For targeted edits to an existing file, use cg_edit_file instead.",
      parameters: {
        type: "object",
        properties: {
          path: { type: "string", description: "Absolute file path" },
          content: { type: "string", description: "File content" },
        },
        required: ["path", "content"],
      },
      async execute(_id, params) {
        try {
          const res = await callTool("write_file", {
            path: params.path,
            content: params.content,
          });
          if (!res.error && !res.pending) {
            return { content: [{ type: "text", text: res.result || `✅ File written: ${params.path}` }] };
          }
          return formatResult(res);
        } catch (e) {
          return formatError(e);
        }
      },
    });

    // Tool: cg_edit_file — replaces edit / apply_patch
    api.registerTool({
      name: "cg_edit_file",
      description:
        "Make precise targeted edits to an existing file through the ClawGuard security engine. Each edit specifies an oldText (must match exactly once in the file) and a newText replacement. Replaces the native edit / apply_patch tools.",
      parameters: {
        type: "object",
        properties: {
          path: { type: "string", description: "Absolute file path or path starting with ~" },
          edits: {
            type: "array",
            description: "One or more targeted replacements. Each oldText must be unique and non-overlapping in the file.",
            items: {
              type: "object",
              properties: {
                oldText: { type: "string", description: "Exact text to replace (must match exactly once in the file)" },
                newText: { type: "string", description: "Replacement text" },
              },
              required: ["oldText", "newText"],
            },
          },
        },
        required: ["path", "edits"],
      },
      async execute(_id, params) {
        try {
          const res = await callTool("edit_file", {
            path: params.path,
            edits: params.edits,
          });
          if (!res.error) {
            return { content: [{ type: "text", text: res.result || `✅ Edits applied: ${params.path}` }] };
          }
          return formatResult(res);
        } catch (e) {
          return formatError(e);
        }
      },
    });

    // Tool: cg_list_directory — replaces read (directory)
    api.registerTool({
      name: "cg_list_directory",
      description:
        "List directory contents through the ClawGuard security engine. Protected by path access control; sensitive directories are automatically blocked.",
      parameters: {
        type: "object",
        properties: {
          path: { type: "string", description: "Directory path" },
        },
        required: ["path"],
      },
      async execute(_id, params) {
        try {
          const res = await callTool("list_directory", { path: params.path });
          return formatResult(res);
        } catch (e) {
          return formatError(e);
        }
      },
    });

    // Tool: cg_http_request — replaces web_fetch / browser / network tools
    api.registerTool({
      name: "cg_http_request",
      description:
        "Fetch a URL through the ClawGuard security engine. Only allowlisted domains are permitted. HTML responses are automatically converted to readable markdown or plain text (similar to web_fetch). Replaces native network tools.",
      parameters: {
        type: "object",
        properties: {
          url: { type: "string", description: "HTTP or HTTPS URL to fetch" },
          method: { type: "string", enum: ["GET", "POST", "PUT", "DELETE"], description: "HTTP method (default: GET)", default: "GET" },
          extract_mode: {
            type: "string",
            enum: ["markdown", "text", "raw"],
            description: "Extraction mode for HTML responses: \"markdown\" (default, HTML→markdown), \"text\" (strip all tags), \"raw\" (raw response body)",
            default: "markdown",
          },
          max_chars: { type: "integer", description: "Maximum characters to return (truncates when exceeded). Minimum: 100.", minimum: 100 },
          headers: { type: "object", description: "Additional request headers" },
          body: { type: "string", description: "Request body (for POST/PUT)" },
        },
        required: ["url"],
      },
      async execute(_id, params) {
        try {
          const res = await callTool("http_request", {
            method: params.method || "GET",
            url: params.url,
            extract_mode: params.extract_mode || "markdown",
            max_chars: params.max_chars,
            headers: params.headers,
            body: params.body,
          });
          return formatResult(res);
        } catch (e) {
          return formatError(e);
        }
      },
    });

    // ============================================
    // Scope tools — per-prompt least-privilege
    // ============================================

    // Tool: cg_set_task_scope
    api.registerTool({
      name: "cg_set_task_scope",
      description:
        "Declare what this task needs BEFORE executing any other tools. " +
        "Sets per-prompt least-privilege restrictions: only the declared file paths, commands, network domains, and tools will be allowed. " +
        "Everything not declared is blocked. Call this once at the start of every new user request. " +
        "Base security rules (rules.yaml) always apply on top \u2014 task scope can only further restrict, never override base denials.",
      parameters: {
        type: "object",
        properties: {
          task_description: {
            type: "string",
            description: "Brief description of what the user asked (for audit trail)",
          },
          file_read: {
            type: "array",
            items: { type: "string" },
            description: "File/directory paths this task needs to READ. Supports globs (~/project/**). Empty array = no reads allowed.",
          },
          file_write: {
            type: "array",
            items: { type: "string" },
            description: "File/directory paths this task needs to WRITE. Empty array = no writes allowed.",
          },
          commands: {
            type: "array",
            items: { type: "string" },
            description: "Command prefixes this task needs to execute (e.g. ['git', 'python3', 'cat']). Empty array = no commands allowed.",
          },
          network: {
            type: "array",
            items: { type: "string" },
            description: "Network domains this task needs to access (e.g. ['api.github.com']). Empty array = no network allowed.",
          },
          disable_tools: {
            type: "array",
            items: {
              type: "string",
              enum: ["execute_command", "read_file", "write_file", "edit_file", "list_directory", "http_request"],
            },
            description: "Tools to completely disable for this task. Use this for tools you definitely don't need.",
          },
        },
        required: ["task_description"],
      },
      async execute(_id, params) {
        try {
          const res = await callTool("set_task_scope", {
            task_description: params.task_description,
            file_read: params.file_read || [],
            file_write: params.file_write || [],
            commands: params.commands || [],
            network: params.network || [],
            disable_tools: params.disable_tools || [],
          });
          return formatResult(res);
        } catch (e) {
          return formatError(e);
        }
      },
    });

    // Tool: cg_clear_task_scope
    api.registerTool({
      name: "cg_clear_task_scope",
      description:
        "Clear the current task scope, removing all per-task restrictions. Base security rules (rules.yaml) still apply. " +
        "Use this when a task is complete or if scope is too restrictive.",
      parameters: { type: "object", properties: {} },
      async execute() {
        try {
          const res = await callTool("clear_task_scope", {});
          return formatResult(res);
        } catch (e) {
          return formatError(e);
        }
      },
    });

    // ============================================
    // Inspection tools
    // ============================================

    // Tool: cg_skill_check
    api.registerTool({
      name: "cg_skill_check",
      description:
        "Check whether a specified Skill/plugin is on the ClawGuard security allowlist. Skills that are not on the allowlist will be flagged as untrusted.",
      parameters: {
        type: "object",
        properties: {
          identifier: { type: "string", description: "Skill identifier, e.g. @anthropic/claude-code" },
          name: { type: "string", description: "Skill name (optional)" },
        },
        required: ["identifier"],
      },
      async execute(_id, params) {
        try {
          const res = await callTool("skill_check", {
            identifier: params.identifier,
            name: params.name || "",
          });
          if (res.error) {
            return {
              content: [{ type: "text", text: `🚫 Skill failed security check: ${res.error}` }],
              isError: true,
            };
          }
          return { content: [{ type: "text", text: res.result || `✅ Skill ${params.identifier} is on the allowlist` }] };
        } catch (e) {
          return formatError(e);
        }
      },
    });

    // Tool: cg_status
    api.registerTool({
      name: "cg_status",
      description:
        "View ClawGuard security engine status: version, operating mode, audit statistics, and panic state. Users can call this at any time for a security overview.",
      parameters: { type: "object", properties: {} },
      async execute() {
        try {
          const status = await agGet("/api/status");
          const modeLabel = { enforce: "Enforce (block)", supervised: "Supervised (approval)", permissive: "Permissive (log only)" };
          const lines = [
            `🛡️ ClawGuard Security Engine`,
            ``,
            `  Version:  v${status.version}`,
            `  Mode:     ${modeLabel[status.mode] || status.mode}`,
            `  Status:   ${status.panic ? "🔴 Paused (Panic)" : "🟢 Running normally"}`,
            `  PID:      ${status.pid || "-"}`,
            ``,
            `  📊 Audit Statistics`,
            `  Total ops:  ${status.audit_total || 0}`,
            `  Blocked:    ${status.audit_denied || 0}`,
            ``,
            `  🔗 Dashboard: http://${pluginConfig.daemonHost}:${pluginConfig.daemonPort}`,
          ];
          return { content: [{ type: "text", text: lines.join("\n") }] };
        } catch (e) {
          return {
            content: [{
              type: "text",
              text: `⚠️ ClawGuard daemon is not running\n\n` +
                    `  Start: clawguard daemon start\n` +
                    `  Install: curl -fsSL https://www.clawguard.site/download/install.sh | sh\n` +
                    `  Docs: https://www.clawguard.site`,
            }],
            isError: true,
          };
        }
      },
    });

    // ============================================
    // Control tools
    // ============================================

    // Tool: cg_panic
    api.registerTool({
      name: "cg_panic",
      description:
        "🚨 Emergency pause ClawGuard — immediately deny all subsequent agent operations. Use when anomalous or suspicious behaviour is detected.",
      parameters: { type: "object", properties: {} },
      async execute() {
        try {
          await agPost("/panic", {});
          return {
            content: [{ type: "text", text: "🔴 ClawGuard emergency paused. All subsequent operations will be blocked.\n   To resume: call cg_resume or use the Dashboard." }],
          };
        } catch (e) {
          return {
            content: [{ type: "text", text: `⚠️ Panic operation failed: ${e.message}` }],
            isError: true,
          };
        }
      },
    });

    // Tool: cg_resume
    api.registerTool({
      name: "cg_resume",
      description:
        "Resume normal ClawGuard operation, lifting the emergency panic state.",
      parameters: { type: "object", properties: {} },
      async execute() {
        try {
          await agPost("/resume", {});
          const status = await agGet("/api/status");
          const modeLabel = { enforce: "Enforce (block)", supervised: "Supervised (approval)", permissive: "Permissive (log only)" };
          return {
            content: [{
              type: "text",
              text: `🟢 ClawGuard resumed normal operation\n   Current mode: ${modeLabel[status.mode] || status.mode}`,
            }],
          };
        } catch (e) {
          return {
            content: [{ type: "text", text: `⚠️ Resume operation failed: ${e.message}` }],
            isError: true,
          };
        }
      },
    });

    // --- Plugin startup log ---
    if (logger) {
      logger.info(`[ClawGuard] Plugin loaded — daemon=${pluginConfig.daemonHost}:${pluginConfig.daemonPort}`);
    }
  },
});
