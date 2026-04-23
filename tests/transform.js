#!/usr/bin/env node
/**
 * transform.js — Apply ClawGuard configuration to any openclaw.json
 *
 * Usage:
 *   node transform.js [input_path] [output_path]
 *
 * Defaults:
 *   input:  ~/.openclaw/openclaw.json
 *   output: <same dir as input>/openclaw.clawguard.json
 *
 * This script is non-destructive: it never overwrites the input file.
 */

import { readFileSync, writeFileSync } from "fs";
import { resolve, dirname, join } from "path";
import { homedir } from "os";

// ── Arg parsing ──────────────────────────────────────────────────────────────

const inputPath  = resolve(process.argv[2] ?? join(homedir(), ".openclaw/openclaw.json"));
const outputPath = resolve(process.argv[3] ?? join(dirname(inputPath), "openclaw.clawguard.json"));

if (inputPath === outputPath) {
  console.error("ERROR: input and output paths are the same — refusing to overwrite.");
  process.exit(1);
}

// ── Load input ───────────────────────────────────────────────────────────────

let config;
try {
  config = JSON.parse(readFileSync(inputPath, "utf8"));
} catch (e) {
  console.error(`ERROR: Could not read/parse ${inputPath}: ${e.message}`);
  process.exit(1);
}

// Deep-clone so we can safely mutate
const out = JSON.parse(JSON.stringify(config));

// ── Transform functions ───────────────────────────────────────────────────────

/**
 * 1. plugins — add ClawGuard plugin registration
 */
function applyPlugins(cfg) {
  cfg.plugins = {
    enabled: true,
    entries: {
      clawguard: { enabled: true },
    },
    installs: {
      clawguard: {
        installPath: `${homedir()}/.clawguard/openclaw-plugin`,
        installedAt: new Date().toISOString(),
        source: "path",
        sourcePath: `${homedir()}/.clawguard/openclaw-plugin`,
        version: "1.6.0",
      },
    },
    load: {
      paths: [`${homedir()}/.clawguard/openclaw-plugin`],
    },
  };
}

/**
 * 2. skills — add clawguard entry, preserve existing fields
 */
function applySkills(cfg) {
  if (!cfg.skills) cfg.skills = {};
  if (!cfg.skills.entries) cfg.skills.entries = {};
  cfg.skills.entries.clawguard = { enabled: true };
}

/**
 * 3. tools — add alsoAllow, remove native exec config
 */
function applyTools(cfg) {
  if (!cfg.tools) cfg.tools = {};
  // Allow clawguard tools
  if (!cfg.tools.alsoAllow) cfg.tools.alsoAllow = [];
  if (!cfg.tools.alsoAllow.includes("clawguard")) {
    cfg.tools.alsoAllow.push("clawguard");
  }
  // Remove native exec config (exec is being blocked)
  delete cfg.tools.exec;
}

/**
 * 4. agents — update defaults + add main agent tool block
 */
function applyAgents(cfg) {
  if (!cfg.agents) cfg.agents = {};

  // 4a. defaults
  const d = cfg.agents.defaults || {};

  // Upgrade model primary to -cc variant if it's the plain autodl model
  if (d.model?.primary === "autodl/claude-sonnet-4-6") {
    d.model.primary = "autodl/claude-sonnet-4-6-cc";
  }

  // Upgrade models entry
  if (d.models?.["anthropic/claude-sonnet-4-6"] !== undefined) {
    d.models["anthropic/claude-sonnet-4-6"] = {
      params: { cacheRetention: "short" },
    };
  }

  // Add ClawGuard-recommended defaults
  d.compaction    = { mode: "safeguard" };
  d.contextPruning = { mode: "cache-ttl", ttl: "1h" };
  d.heartbeat     = { every: "30m" };

  // Remove superseded llm.idleTimeoutSeconds
  delete d.llm;

  cfg.agents.defaults = d;

  // 4b. agents.list — ensure main agent blocks native tools
  if (!cfg.agents.list) cfg.agents.list = [];

  const mainIdx = cfg.agents.list.findIndex((a) => a.id === "main");
  const mainAgent = mainIdx >= 0 ? cfg.agents.list[mainIdx] : { id: "main" };

  if (!mainAgent.tools) mainAgent.tools = {};

  // alsoAllow clawguard
  if (!mainAgent.tools.alsoAllow) mainAgent.tools.alsoAllow = [];
  if (!mainAgent.tools.alsoAllow.includes("clawguard")) {
    mainAgent.tools.alsoAllow.push("clawguard");
  }

  // deny native tools
  const nativeDeny = ["exec", "write", "edit", "apply_patch", "process"];
  if (!mainAgent.tools.deny) mainAgent.tools.deny = [];
  for (const t of nativeDeny) {
    if (!mainAgent.tools.deny.includes(t)) {
      mainAgent.tools.deny.push(t);
    }
  }

  if (mainIdx >= 0) {
    cfg.agents.list[mainIdx] = mainAgent;
  } else {
    cfg.agents.list.push(mainAgent);
  }
}

/**
 * 5. meta — update lastTouchedAt
 */
function applyMeta(cfg) {
  if (!cfg.meta) cfg.meta = {};
  cfg.meta.lastTouchedAt = new Date().toISOString();
}

// ── Apply all transforms ──────────────────────────────────────────────────────

applyPlugins(out);
applySkills(out);
applyTools(out);
applyAgents(out);
applyMeta(out);

// ── Write output ─────────────────────────────────────────────────────────────

writeFileSync(outputPath, JSON.stringify(out, null, 2) + "\n", "utf8");
console.log(`✅ Transformed config written to: ${outputPath}`);
console.log(`   Input:  ${inputPath}`);
console.log(`   Output: ${outputPath}`);
console.log();
console.log("Review the output, then apply with:");
console.log(`  cp ${outputPath} ${inputPath}`);
console.log("  openclaw gateway restart");
