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
// Plugin entry point
// OpenClaw plugin standard interface: export default function(api)
// Reference: https://docs.openclaw.ai/plugins/agent-tools
// ====================================================
export default function (api) {
  // --- Load plugin config ---
  if (api.config) {
    pluginConfig = { ...DEFAULT_CONFIG, ...api.config };
  }
  const logger = api.logger || null;

  // --- Register background health check service ---
  // Reference: https://docs.openclaw.ai/tools/plugin#register-background-services
  if (api.registerService) {
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
  }

  // --- Register Gateway RPC methods ---
  // Allows other plugins or external callers to query ClawGuard status
  // Reference: https://docs.openclaw.ai/tools/plugin#register-gateway-rpc-methods
  if (api.registerGatewayMethod) {
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
  }

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

  // Tool: cg_write_file — replaces write / edit / apply_patch
  api.registerTool({
    name: "cg_write_file",
    description:
      "Write a file through the ClawGuard security engine. Sensitive paths are automatically blocked and written content is scanned by the sanitizer to prevent leaking secrets. Replaces the native write / edit / apply_patch tools.",
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

  // Tool: cg_http_request — replaces browser / network tools
  api.registerTool({
    name: "cg_http_request",
    description:
      "Make an HTTP request through the ClawGuard security engine. Only allowlisted domains are permitted; unauthorized external requests are automatically blocked to prevent data exfiltration. Replaces native network tools.",
    parameters: {
      type: "object",
      properties: {
        method: { type: "string", enum: ["GET", "POST", "PUT", "DELETE"], description: "HTTP method" },
        url: { type: "string", description: "Request URL" },
        headers: { type: "object", description: "Request headers" },
        body: { type: "string", description: "Request body" },
      },
      required: ["method", "url"],
    },
    async execute(_id, params) {
      try {
        const res = await callTool("http_request", {
          method: params.method,
          url: params.url,
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
        await agPost("/api/panic", {});
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
        await agPost("/api/resume", {});
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
};
