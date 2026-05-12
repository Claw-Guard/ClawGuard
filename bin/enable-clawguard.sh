#!/bin/bash
# enable-clawguard.sh — Start ClawGuard daemon and activate ClawGuard in OpenClaw
#
# Steps:
#   1. Activate venv and start the ClawGuard daemon with nohup
#   2. Backup current openclaw.json as openclaw_guardback.json
#   3. Apply ClawGuard config via transform.js
#   4. Copy SKILL.md into ~/.openclaw/skills/clawguard/
#   5. Restart OpenClaw gateway

set -e

CLAWGUARD_DIR="/home/amadeus/clawguard-py"  # patched by install.sh
VENV="$CLAWGUARD_DIR/venv/bin/activate"
OPENCLAW_DIR="$HOME/.openclaw"
OPENCLAW_JSON="$OPENCLAW_DIR/openclaw.json"
BACKUP_JSON="$OPENCLAW_DIR/openclaw_guardback.json"
SKILLS_DIR="$OPENCLAW_DIR/skills"
SKILL_DEST_DIR="$SKILLS_DIR/clawguard"
INSTALLED_PLUGIN_DIR="$HOME/.clawguard/openclaw-plugin"
SKILL_SRC="$INSTALLED_PLUGIN_DIR/SKILL.md"
TRANSFORM_SCRIPT="$CLAWGUARD_DIR/bin/transform.js"
TRANSFORMED_JSON="$OPENCLAW_DIR/openclaw.clawguard.json"
LOG_FILE="$HOME/.clawguard/daemon.log"
PID_FILE="$HOME/.clawguard/daemon.pid"

echo "🛡️  Enabling ClawGuard..."
echo ""

# ── Preflight checks ──────────────────────────────────────────────────────────

if [ ! -f "$VENV" ]; then
    echo "❌ venv not found at $CLAWGUARD_DIR/venv — please run: python3 -m venv venv && venv/bin/pip install -r requirements.txt"
    exit 1
fi

if [ ! -f "$SKILL_SRC" ]; then
    echo "❌ SKILL.md not found at $SKILL_SRC"
    exit 1
fi

if [ ! -f "$TRANSFORM_SCRIPT" ]; then
    echo "❌ transform.js not found at $TRANSFORM_SCRIPT"
    exit 1
fi

if [ ! -f "$OPENCLAW_JSON" ]; then
    echo "❌ openclaw.json not found at $OPENCLAW_JSON"
    exit 1
fi

# ── Step 1: Start daemon with nohup ──────────────────────────────────────────

echo "[1/5] Starting ClawGuard daemon..."

# Check if already running
if [ -f "$PID_FILE" ]; then
    EXISTING_PID=$(cat "$PID_FILE")
    if kill -0 "$EXISTING_PID" 2>/dev/null; then
        echo "  ℹ️  Daemon already running (PID $EXISTING_PID) — skipping start"
    else
        echo "  ⚠️  Stale PID file found — removing and restarting"
        rm -f "$PID_FILE"
    fi
fi

if [ ! -f "$PID_FILE" ]; then
    mkdir -p "$HOME/.clawguard"
    cd "$CLAWGUARD_DIR"
    source "$VENV"

    nohup venv/bin/python -m clawguard.cli daemon start > "$LOG_FILE" 2>&1 &
    DAEMON_PID=$!
    echo "$DAEMON_PID" > "$PID_FILE"

    # Wait briefly and confirm it started
    sleep 2
    if kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "  ✅ Daemon started (PID $DAEMON_PID, log: $LOG_FILE)"
    else
        echo "  ❌ Daemon failed to start — check logs: $LOG_FILE"
        cat "$LOG_FILE" | tail -20
        exit 1
    fi
fi

echo ""

# ── Step 2: Backup openclaw.json ──────────────────────────────────────────────

echo "[2/5] Backing up openclaw.json..."

if [ -f "$BACKUP_JSON" ]; then
    echo "  ⚠️  Backup already exists at $BACKUP_JSON — overwriting"
fi

cp "$OPENCLAW_JSON" "$BACKUP_JSON"
echo "  ✅ Backup saved to $BACKUP_JSON"
echo ""

# ── Step 3: Apply ClawGuard config transform ──────────────────────────────────

echo "[3/5] Applying ClawGuard config transform..."

node "$TRANSFORM_SCRIPT" "$OPENCLAW_JSON" "$TRANSFORMED_JSON"
cp "$TRANSFORMED_JSON" "$OPENCLAW_JSON"
echo "  ✅ openclaw.json updated"
echo ""

# ── Step 4: Install SKILL.md ──────────────────────────────────────────────────

echo "[4/5] Installing ClawGuard skill..."

mkdir -p "$SKILL_DEST_DIR"
cp "$SKILL_SRC" "$SKILL_DEST_DIR/SKILL.md"
echo "  ✅ SKILL.md copied to $SKILL_DEST_DIR/SKILL.md"
echo ""

# ── Step 5: Restart OpenClaw gateway ─────────────────────────────────────────

echo "[5/5] Restarting OpenClaw gateway..."

openclaw gateway restart
echo "  ✅ Gateway restarted"
echo ""

# ── Done ──────────────────────────────────────────────────────────────────────

echo "=================================================="
echo "✅ ClawGuard enabled successfully!"
echo "=================================================="
echo ""
echo "  Daemon PID:  $(cat $PID_FILE)"
echo "  Daemon log:  $LOG_FILE"
echo "  Dashboard:   http://127.0.0.1:19821"
echo "  Backup:      $BACKUP_JSON"
echo ""
echo "To disable ClawGuard, run: $(dirname "$0")/disable-clawguard.sh"
