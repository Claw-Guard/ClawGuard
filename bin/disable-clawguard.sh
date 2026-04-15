#!/bin/bash
# disable-clawguard.sh — Stop ClawGuard daemon and restore OpenClaw to original config
#
# Steps:
#   1. Remove ~/.openclaw/skills/ folder
#   2. Stop the nohup daemon process
#   3. Restore openclaw_guardback.json as openclaw.json
#   4. Restart OpenClaw gateway

set -e

OPENCLAW_DIR="$HOME/.openclaw"
OPENCLAW_JSON="$OPENCLAW_DIR/openclaw.json"
BACKUP_JSON="$OPENCLAW_DIR/openclaw_guardback.json"
SKILLS_DIR="$OPENCLAW_DIR/skills"
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

# ── Step 3: Restore backup config ────────────────────────────────────────────

echo "[3/4] Restoring openclaw.json from backup..."

if [ ! -f "$BACKUP_JSON" ]; then
    echo "  ❌ Backup not found at $BACKUP_JSON — cannot restore"
    echo "     You will need to manually restore openclaw.json"
    exit 1
fi

cp "$BACKUP_JSON" "$OPENCLAW_JSON"
echo "  ✅ Restored $BACKUP_JSON → $OPENCLAW_JSON"
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
echo "  OpenClaw restored to original config"
echo "  Backup preserved at: $BACKUP_JSON"
echo "  Daemon log preserved at: $LOG_FILE"
echo ""
echo "To re-enable ClawGuard, run: $(dirname "$0")/enable-clawguard.sh"
