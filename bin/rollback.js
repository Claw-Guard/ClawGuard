#!/usr/bin/env node
/**
 * rollback.js — Remove ClawGuard-specific configuration from openclaw.json
 *
 * Usage:
 *   node rollback.js [input_path] [output_path]
 *
 * Defaults:
 *   input:  ~/.openclaw/openclaw.json
 *   output: <same dir as input>/openclaw.rolled-back.json
 *
 * This script is non-destructive: it never overwrites the input file.
 * It only removes what transform.js added — everything else stays untouched.
 */

import { readFileSync, writeFileSync } from "fs";
import { resolve, dirname, join } from "path";
import { homedir } from "os";

// ── Arg parsing ──────────────────────────────────────────────────────────────

const inputPath  = resolve(process.argv[2] ?? join(homedir(), ".openclaw/openclaw.json"));
const outputPath = resolve(process.argv[3] ?? join(dirname(inputPath), "openclaw.rolled-back.json"));

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

// ── Native tools that ClawGuard denies ───────────────────────────────────────

const CLAWGUARD_DENIED_TOOLS = [
  "exec", "read", "write", "edit", "apply_patch", "process", "web_fetch", "browser", "web_search"
];

// ── Rollback functions ───────────────────────────────────────────────────────

/**
 * 1. plugins — remove clawguard entries only
 */
function rollbackPlugins(cfg) {
  if (!cfg.plugins) return;

  // Remove clawguard from entries
  if (cfg.plugins.entries) {
    delete cfg.plugins.entries.clawguard;
    if (Object.keys(cfg.plugins.entries).length === 0) {
      delete cfg.plugins.entries;
    }
  }

  // Remove clawguard from installs
  if (cfg.plugins.installs) {
    delete cfg.plugins.installs.clawguard;
    if (Object.keys(cfg.plugins.installs).length === 0) {
      delete cfg.plugins.installs;
    }
  }

  // Remove clawguard load path
  if (cfg.plugins.load?.paths) {
    const clawguardPath = `${homedir()}/.clawguard/openclaw-plugin`;
    cfg.plugins.load.paths = cfg.plugins.load.paths.filter(
      (p) => p !== clawguardPath
    );
    if (cfg.plugins.load.paths.length === 0) {
      delete cfg.plugins.load;
    }
  }

  // If plugins section is now empty (no other plugins), remove it
  const remaining = Object.keys(cfg.plugins).filter((k) => k !== "enabled");
  if (remaining.length === 0) {
    delete cfg.plugins;
  }
}

/**
 * 2. skills — remove clawguard entry only
 */
function rollbackSkills(cfg) {
  if (!cfg.skills?.entries) return;

  delete cfg.skills.entries.clawguard;

  if (Object.keys(cfg.skills.entries).length === 0) {
    delete cfg.skills.entries;
  }
  if (cfg.skills && Object.keys(cfg.skills).length === 0) {
    delete cfg.skills;
  }
}

/**
 * 3. tools — remove "clawguard" from alsoAllow
 */
function rollbackTools(cfg) {
  if (!cfg.tools?.alsoAllow) return;

  cfg.tools.alsoAllow = cfg.tools.alsoAllow.filter((t) => t !== "clawguard");
  if (cfg.tools.alsoAllow.length === 0) {
    delete cfg.tools.alsoAllow;
  }
}

/**
 * 4. agents — remove clawguard deny/allow from main agent
 */
function rollbackAgents(cfg) {
  if (!cfg.agents?.list) return;

  const mainIdx = cfg.agents.list.findIndex((a) => a.id === "main");
  if (mainIdx < 0) return;

  const mainAgent = cfg.agents.list[mainIdx];
  if (!mainAgent.tools) return;

  // Remove "clawguard" from alsoAllow
  if (mainAgent.tools.alsoAllow) {
    mainAgent.tools.alsoAllow = mainAgent.tools.alsoAllow.filter(
      (t) => t !== "clawguard"
    );
    if (mainAgent.tools.alsoAllow.length === 0) {
      delete mainAgent.tools.alsoAllow;
    }
  }

  // Remove only the native tools that ClawGuard added to deny
  if (mainAgent.tools.deny) {
    mainAgent.tools.deny = mainAgent.tools.deny.filter(
      (t) => !CLAWGUARD_DENIED_TOOLS.includes(t)
    );
    if (mainAgent.tools.deny.length === 0) {
      delete mainAgent.tools.deny;
    }
  }

  // Clean up empty tools object
  if (Object.keys(mainAgent.tools).length === 0) {
    delete mainAgent.tools;
  }

  cfg.agents.list[mainIdx] = mainAgent;
}

/**
 * 5. meta — update lastTouchedAt
 */
function rollbackMeta(cfg) {
  if (!cfg.meta) cfg.meta = {};
  cfg.meta.lastTouchedAt = new Date().toISOString();
}

// ── Apply all rollbacks ──────────────────────────────────────────────────────

rollbackPlugins(out);
rollbackSkills(out);
rollbackTools(out);
rollbackAgents(out);
rollbackMeta(out);

// ── Write output ─────────────────────────────────────────────────────────────

writeFileSync(outputPath, JSON.stringify(out, null, 2) + "\n", "utf8");
console.log(`✅ Rolled back config written to: ${outputPath}`);
console.log(`   Input:  ${inputPath}`);
console.log(`   Output: ${outputPath}`);
console.log();
console.log("Review the output, then apply with:");
console.log(`  cp ${outputPath} ${inputPath}`);
console.log("  openclaw gateway restart");
