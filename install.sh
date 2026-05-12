#!/usr/bin/env bash
# install.sh — ClawGuard installer
#
# Usage (one-liner):
#   curl -fsSL https://raw.githubusercontent.com/Claw-Guard/ClawGuard/main/install.sh | bash
#
# Usage (manual, from inside a cloned repo):
#   bash install.sh
#   bash install.sh [install_dir]   # explicit destination override
#
# Behaviour:
#   - One-liner (piped from curl): asks where to install, clones repo there
#   - Manual (run from repo dir):  uses the existing repo as-is, skips clone
#   - Explicit arg:                clones/updates to the given directory
#
# Setup steps:
#   1. Clone repo (skipped when running from an existing repo)
#   2. Create Python venv and install dependencies
#   3. Copy config templates to ~/.clawguard/ (if not already present)
#   4. Install the OpenClaw plugin to ~/.clawguard/openclaw-plugin/
#   5. Make bin scripts executable
#   6. Print next steps

set -e

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}  ℹ${NC}  $*"; }
success() { echo -e "${GREEN}  ✅${NC} $*"; }
warn()    { echo -e "${YELLOW}  ⚠️${NC}  $*"; }
error()   { echo -e "${RED}  ❌${NC} $*"; exit 1; }

REPO_URL="https://github.com/Claw-Guard/ClawGuard.git"
DEFAULT_INSTALL_DIR="$HOME/clawguard-py"

echo ""
echo "  🛡️  ClawGuard Installer"
echo "  ─────────────────────────────────────────────"
echo ""

# ── Step 0: Detect run mode and resolve install directory ─────────────────────
#
# Three cases:
#   A) curl ... | bash        → BASH_SOURCE[0] is empty/"-", no repo on disk → clone
#   B) bash install.sh        → running from inside the cloned repo → use repo dir
#   C) bash install.sh <dir>  → explicit override → clone/update to <dir>

# Detect if we're already running from inside a cloned repo
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo "")"
IS_IN_REPO=false
if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/requirements.txt" ] && [ -d "$SCRIPT_DIR/.git" ]; then
    IS_IN_REPO=true
fi

if [ -n "$1" ]; then
    # Case C: explicit path argument — always clone/update there
    INSTALL_DIR="${1/#\~/$HOME}"
    NEED_CLONE=true
elif [ "$IS_IN_REPO" = true ]; then
    # Case B: running from inside an existing repo — use it as-is
    INSTALL_DIR="$SCRIPT_DIR"
    NEED_CLONE=false
    info "Detected existing repo at $INSTALL_DIR — skipping clone"
else
    # Case A: one-liner or run outside any repo — ask where to install
    echo -e "  ${CYAN}Where would you like to install ClawGuard?${NC}"
    echo -e "  Press Enter to use the default: ${YELLOW}$DEFAULT_INSTALL_DIR${NC}"
    echo -n "  > "
    read -r USER_DIR </dev/tty 2>/dev/null || USER_DIR=""
    INSTALL_DIR="${USER_DIR:-$DEFAULT_INSTALL_DIR}"
    INSTALL_DIR="${INSTALL_DIR/#\~/$HOME}"
    NEED_CLONE=true
fi

echo ""
info "Install directory: $INSTALL_DIR"
echo ""

# ── Preflight checks ──────────────────────────────────────────────────────────

command -v python3 >/dev/null 2>&1 || error "python3 is required but not installed."
command -v git     >/dev/null 2>&1 || error "git is required but not installed."
command -v node    >/dev/null 2>&1 || error "node is required but not installed (needed for transform.js)."

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
info "Python version: $PYTHON_VERSION"

# ── Detect OpenClaw version ───────────────────────────────────────────────────

OPENCLAW_VERSION=""
PLUGIN_VARIANT="legacy"

if command -v openclaw >/dev/null 2>&1; then
    OPENCLAW_VERSION=$(openclaw --version 2>&1 | head -1 | grep -oP '\d{4}\.\d+\.\d+' || echo "")

    if [ -n "$OPENCLAW_VERSION" ]; then
        info "Detected OpenClaw version: $OPENCLAW_VERSION"

        # >= 2026.5.7 uses v5 plugin API; anything older uses legacy
        if [ "$(printf '%s\n' "2026.5.7" "$OPENCLAW_VERSION" | sort -V | head -n1)" = "2026.5.7" ]; then
            PLUGIN_VARIANT="v5"
            info "Using v5 plugin variant (OpenClaw >= 2026.5.7)"
        else
            PLUGIN_VARIANT="legacy"
            info "Using legacy plugin variant (OpenClaw < 2026.5.7)"
        fi
    else
        warn "Could not parse OpenClaw version — defaulting to legacy variant"
    fi
else
    warn "OpenClaw not found in PATH — defaulting to legacy variant"
fi

echo ""

# ── Step 1: Clone or skip ─────────────────────────────────────────────────────

echo "[1/6] Repository..."

if [ "$NEED_CLONE" = false ]; then
    success "Using existing repo at $INSTALL_DIR (clone skipped)"
else
    if [ -d "$INSTALL_DIR/.git" ]; then
        warn "Directory already exists — pulling latest changes"
        git -C "$INSTALL_DIR" pull
    else
        git clone "$REPO_URL" "$INSTALL_DIR"
    fi
    success "Repository ready at $INSTALL_DIR"
fi
echo ""

# ── Step 2: Create venv and install dependencies ──────────────────────────────

echo "[2/6] Setting up Python virtual environment..."

cd "$INSTALL_DIR"
python3 -m venv venv
venv/bin/pip install --upgrade pip --quiet
venv/bin/pip install -r requirements.txt --quiet

success "venv created and dependencies installed"
echo ""

# ── Step 3: Copy config templates to ~/.clawguard/ ───────────────────────────

echo "[3/6] Setting up ~/.clawguard config directory..."

mkdir -p "$HOME/.clawguard"

if [ ! -f "$HOME/.clawguard/config.yaml" ]; then
    cp "$INSTALL_DIR/config/config.yaml" "$HOME/.clawguard/config.yaml"
    success "config.yaml installed to ~/.clawguard/"
else
    warn "~/.clawguard/config.yaml already exists — skipping (not overwritten)"
fi

if [ ! -f "$HOME/.clawguard/rules.yaml" ]; then
    cp "$INSTALL_DIR/config/rules.yaml" "$HOME/.clawguard/rules.yaml"
    success "rules.yaml installed to ~/.clawguard/"
else
    warn "~/.clawguard/rules.yaml already exists — skipping (not overwritten)"
fi

echo ""

# ── Step 4: Install OpenClaw plugin ──────────────────────────────────────────

echo "[4/6] Installing OpenClaw plugin ($PLUGIN_VARIANT)..."

PLUGIN_SOURCE="$INSTALL_DIR/openclaw-plugin/$PLUGIN_VARIANT"
PLUGIN_DEST="$HOME/.clawguard/openclaw-plugin"
mkdir -p "$PLUGIN_DEST"
cp "$PLUGIN_SOURCE/index.js" "$PLUGIN_DEST/index.js"
cp "$PLUGIN_SOURCE/SKILL.md" "$PLUGIN_DEST/SKILL.md"
cp "$PLUGIN_SOURCE/openclaw.plugin.json" "$PLUGIN_DEST/openclaw.plugin.json"
cp "$PLUGIN_SOURCE/package.json" "$PLUGIN_DEST/package.json"
success "Plugin installed to $PLUGIN_DEST ($PLUGIN_VARIANT variant)"
echo ""

# ── Step 5: Make bin scripts executable ──────────────────────────────────────

echo "[5/5] Making scripts executable..."

chmod +x "$INSTALL_DIR/bin/enable-clawguard.sh"
chmod +x "$INSTALL_DIR/bin/disable-clawguard.sh"
chmod +x "$INSTALL_DIR/bin/clawguard-shell"

# Patch CLAWGUARD_DIR in enable/disable scripts to match the chosen install dir
sed -i "s|CLAWGUARD_DIR=.*  # patched by install.sh|CLAWGUARD_DIR=\"$INSTALL_DIR\"  # patched by install.sh|" \
    "$INSTALL_DIR/bin/enable-clawguard.sh" \
    "$INSTALL_DIR/bin/disable-clawguard.sh" 2>/dev/null || true

success "Scripts ready"
echo ""

# ── Done ─────────────────────────────────────────────────────────────────────

echo "  ══════════════════════════════════════════════"
echo -e "  ${GREEN}🛡️  ClawGuard installed successfully!${NC}"
echo "  ══════════════════════════════════════════════"
echo ""
echo "  Plugin variant: $PLUGIN_VARIANT (OpenClaw $OPENCLAW_VERSION)"
echo "  Install dir:  $INSTALL_DIR"
echo "  Config:       ~/.clawguard/config.yaml"
echo "  Rules:        ~/.clawguard/rules.yaml"
echo "  Plugin:       ~/.clawguard/openclaw-plugin/"
echo "  Dashboard:    http://127.0.0.1:19821 (after start)"
echo ""
echo -e "  ${YELLOW}Next steps:${NC}"
echo ""
echo "  1. Enable ClawGuard (starts daemon + patches OpenClaw config):"
echo -e "     ${CYAN}$INSTALL_DIR/bin/enable-clawguard.sh${NC}"
echo ""
echo "  2. To disable ClawGuard and restore original config:"
echo -e "     ${CYAN}$INSTALL_DIR/bin/disable-clawguard.sh${NC}"
echo ""
