#!/bin/bash
# disable-clawguard.sh — Stop ClawGuard daemon and restore OpenClaw to original config
#
# Steps:
#   1. Remove ~/.openclaw/skills/ folder
#   2. Stop the nohup daemon process
#   3. Use rollback.js to remove ClawGuard config from openclaw.json
#   4. Restart OpenClaw gateway

set -e

CLAWGUARD_DIR="/home/amadeus/clawguard-py"  # patched by install.sh
OPENCLAW_DIR="$HOME/.openclaw"
OPENCLAW_JSON="$OPENCLAW_DIR/openclaw.json"
BACKUP_JSON="$OPENCLAW_DIR/openclaw_guardback.json"
SKILLS_DIR="$OPENCLAW_DIR/skills"
ROLLBACK_SCRIPT="$CLAWGUARD_DIR/bin/rollback.js"
ROLLED_BACK_JSON="$OPENCLAW_DIR/openclaw.rolled-back.json"
PID_FILE="$HOME/.clawguard/daemon.pid"
LOG_FILE="$HOME/.clawguard/daemon.log"

echo "🛡️  Disabling ClawGuard..."
echo ""

# ── Step 1: Remove skills folder ──────────────────────────────────────────────

echo "[1/4] Removing ClawGuard skill..."

if [ -d "$SKILLS_DIR" ]; then
    rm -rf "$SKILLS_DIR"
    echo "  ✅ Removed $SKILLS_DIR"
else
    echo "  ℹ️  Skills folder not found — skipping"
fi

echo ""

# ── Step 2: Stop daemon ───────────────────────────────────────────────────────

echo "[2/4] Stopping ClawGuard daemon..."

if [ -f "$PID_FILE" ]; then
    DAEMON_PID=$(cat "$PID_FILE")
    if kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill "$DAEMON_PID"
        sleep 1
        if kill -0 "$DAEMON_PID" 2>/dev/null; then
            echo "  ⚠️  Process didn't stop — force killing..."
            kill -9 "$DAEMON_PID" 2>/dev/null || true
        fi
        echo "  ✅ Daemon stopped (PID $DAEMON_PID)"
    else
        echo "  ℹ️  Daemon not running (stale PID $DAEMON_PID)"
    fi
    rm -f "$PID_FILE"
else
    # Fallback: try to find and kill by process name
    PIDS=$(pgrep -f "clawguard.cli daemon start" 2>/dev/null || true)
    if [ -n "$PIDS" ]; then
        echo "  ⚠️  No PID file — killing by process name..."
        kill $PIDS 2>/dev/null || true
        echo "  ✅ Daemon stopped"
    else
        echo "  ℹ️  No daemon process found — skipping"
    fi
fi

echo ""

# ── Step 3: Rollback ClawGuard config ─────────────────────────────────────────

echo "[3/4] Rolling back ClawGuard config from openclaw.json..."

if [ ! -f "$ROLLBACK_SCRIPT" ]; then
    echo "  ⚠️  rollback.js not found at $ROLLBACK_SCRIPT"
    echo "     Falling back to backup restore method..."
    
    if [ ! -f "$BACKUP_JSON" ]; then
        echo "  ❌ Backup not found at $BACKUP_JSON — cannot restore"
        echo "     You will need to manually restore openclaw.json"
        exit 1
    fi
    
    cp "$BACKUP_JSON" "$OPENCLAW_JSON"
    echo "  ✅ Restored $BACKUP_JSON → $OPENCLAW_JSON"
else
    # Use rollback.js to surgically remove ClawGuard config
    node "$ROLLBACK_SCRIPT" "$OPENCLAW_JSON" "$ROLLED_BACK_JSON"
    cp "$ROLLED_BACK_JSON" "$OPENCLAW_JSON"
    echo "  ✅ ClawGuard config removed from openclaw.json"
    
    # Keep backup for safety
    if [ -f "$BACKUP_JSON" ]; then
        echo "  ℹ️  Backup preserved at: $BACKUP_JSON"
    fi
fi

echo ""

# ── Step 4: Restart OpenClaw gateway ─────────────────────────────────────────

echo "[4/4] Restarting OpenClaw gateway..."

openclaw gateway restart
echo "  ✅ Gateway restarted"
echo ""

# ── Done ──────────────────────────────────────────────────────────────────────

echo "=================================================="
echo "✅ ClawGuard disabled successfully!"
echo "=================================================="
echo ""
echo "  OpenClaw config rolled back (ClawGuard entries removed)"
echo "  Backup preserved at: $BACKUP_JSON"
echo "  Daemon log preserved at: $LOG_FILE"
echo ""
echo "To re-enable ClawGuard, run: $(dirname "$0")/enable-clawguard.sh"
