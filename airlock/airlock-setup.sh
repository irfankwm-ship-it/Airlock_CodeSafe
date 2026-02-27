#!/usr/bin/env bash
# airlock-setup.sh — First-time setup wizard for Airlock
# Creates state directories, detects credentials, sets up signing key
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=airlock.conf
source "$SCRIPT_DIR/airlock.conf"

# ── Colors ────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; }
ask()   { echo -en "${BOLD}$*${NC} "; }

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║              Airlock — First-Time Setup                 ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Step 1: Check prerequisites ──────────────────────────────────────
echo -e "${BOLD}Step 1: Checking prerequisites${NC}"
echo ""

MISSING=0

if command -v docker &>/dev/null; then
    ok "Docker found: $(docker --version | head -1)"
else
    fail "Docker not found. Install Docker: https://docs.docker.com/get-docker/"
    MISSING=1
fi

if command -v sudo &>/dev/null; then
    ok "sudo found"
else
    fail "sudo not found. Airlock needs sudo for nsenter/iptables."
    MISSING=1
fi

if command -v dig &>/dev/null; then
    ok "dig found"
else
    warn "dig not found. Install dnsutils: sudo apt install dnsutils"
    warn "Airlock uses dig for DNS resolution during launch."
    MISSING=1
fi

if command -v ssh-keygen &>/dev/null; then
    ok "ssh-keygen found"
else
    fail "ssh-keygen not found. Install openssh-client."
    MISSING=1
fi

if command -v jq &>/dev/null; then
    ok "jq found"
else
    warn "jq not found (optional). Install: sudo apt install jq"
fi

if [ "$MISSING" -eq 1 ]; then
    echo ""
    warn "Some prerequisites are missing. Fix them before launching Airlock."
    echo ""
fi

# ── Step 2: Detect or ask for credentials ────────────────────────────
echo ""
echo -e "${BOLD}Step 2: Claude Code credentials${NC}"
echo ""

CRED_PATH="${AIRLOCK_CREDENTIALS_HOST}"

if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
    ok "ANTHROPIC_API_KEY is set in environment"
    echo "  Airlock will pass this to the container. No credentials file needed."
elif [ -f "$CRED_PATH" ]; then
    ok "Credentials found at $CRED_PATH"
else
    warn "No authentication found"
    echo ""
    echo "  Airlock supports two auth methods:"
    echo ""
    echo "  Option A — OAuth credentials (Claude Max subscription):"
    echo "    npm install -g @anthropic-ai/claude-code"
    echo "    claude          # complete the login flow"
    echo "    # Creates ~/.claude/.credentials.json automatically"
    echo ""
    echo "  Option B — API key:"
    echo "    export ANTHROPIC_API_KEY=\"sk-ant-...\""
    echo "    # Set this before running airlock-launch.sh"
    echo ""
    ask "Enter custom credentials path, or press Enter to skip:"
    read -r custom_cred
    if [ -n "$custom_cred" ] && [ -f "$custom_cred" ]; then
        CRED_PATH="$custom_cred"
        ok "Using credentials at $CRED_PATH"
        echo ""
        echo "  To make this permanent, set in your environment:"
        echo "    export AIRLOCK_CREDENTIALS_HOST=\"$CRED_PATH\""
    elif [ -n "$custom_cred" ]; then
        warn "File not found: $custom_cred — skipping."
    fi
fi

# ── Step 3: Detect or generate signing key ───────────────────────────
echo ""
echo -e "${BOLD}Step 3: Ed25519 signing key${NC}"
echo ""

KEY_PATH="${AIRLOCK_SIGNING_KEY}"

if [ -f "$KEY_PATH" ]; then
    ok "Signing key found at $KEY_PATH"
elif [ -f "$HOME/.ssh/id_ed25519" ]; then
    KEY_PATH="$HOME/.ssh/id_ed25519"
    ok "Signing key found at $KEY_PATH"
else
    warn "No Ed25519 key found at $KEY_PATH"
    echo ""
    ask "Generate a new Ed25519 key for Airlock signing? [Y/n]:"
    read -r gen_key
    if [ "${gen_key,,}" != "n" ]; then
        mkdir -p "$HOME/.ssh"
        ssh-keygen -t ed25519 -C "airlock-signing" -f "$HOME/.ssh/id_ed25519"
        KEY_PATH="$HOME/.ssh/id_ed25519"
        ok "Key generated at $KEY_PATH"
    else
        warn "Skipping key generation. You'll need a key before extracting changes."
    fi
fi

# ── Step 4: Create state directories ─────────────────────────────────
echo ""
echo -e "${BOLD}Step 4: Creating state directories${NC}"
echo ""

for dir in \
    "$AIRLOCK_STATE_DIR" \
    "$AIRLOCK_IMAGE_HASH_DIR" \
    "$AIRLOCK_SESSION_DIR" \
    "$AIRLOCK_ALLOWLISTS_DIR" \
    "$AIRLOCK_STATE_DIR/enhancements"; do
    if [ -d "$dir" ]; then
        ok "Exists: $dir"
    else
        mkdir -p "$dir"
        ok "Created: $dir"
    fi
done

# ── Step 5: Set up allowed_signers ───────────────────────────────────
echo ""
echo -e "${BOLD}Step 5: Setting up allowed_signers${NC}"
echo ""

SIGNERS_FILE="$AIRLOCK_ALLOWED_SIGNERS"

if [ -f "$SIGNERS_FILE" ]; then
    ok "allowed_signers already exists at $SIGNERS_FILE"
elif [ -f "${KEY_PATH}.pub" ]; then
    echo "airlock-user $(cat "${KEY_PATH}.pub")" > "$SIGNERS_FILE"
    ok "Created $SIGNERS_FILE with your public key"
else
    warn "No public key found at ${KEY_PATH}.pub — skipping allowed_signers setup."
    warn "Create it manually after generating your key:"
    echo "  echo \"airlock-user \$(cat ${KEY_PATH}.pub)\" > $SIGNERS_FILE"
fi

# ── Step 6: Optionally build example image ───────────────────────────
echo ""
echo -e "${BOLD}Step 6: Build an image${NC}"
echo ""

if command -v docker &>/dev/null; then
    ask "Build the example image now? This takes a few minutes. [y/N]:"
    read -r build_now
    if [ "${build_now,,}" = "y" ]; then
        echo ""
        info "Building airlock-example:latest from Dockerfile.example..."
        echo ""
        "$SCRIPT_DIR/airlock-build.sh" Dockerfile.example airlock-example:latest
    else
        echo "  Skipping. Build later with:"
        echo "    cd $SCRIPT_DIR"
        echo "    ./airlock-build.sh Dockerfile.example airlock-example:latest"
        echo ""
        echo "  Or build the full dev image:"
        echo "    ./airlock-build.sh Dockerfile.base airlock-base:latest"
    fi
else
    warn "Docker not available — skipping image build."
fi

# ── Summary ──────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║                  Setup Complete                         ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  Quick start:"
echo ""
echo "    # Build an image (if you haven't already)"
echo "    cd $SCRIPT_DIR"
echo "    ./airlock-build.sh Dockerfile.base airlock-base:latest"
echo ""
echo "    # Launch a session"
echo "    ./airlock-launch.sh airlock-base:latest ~/projects/my-app"
echo ""
echo "    # When done, extract changes"
echo "    ./airlock-extract.sh airlock-<session-id>"
echo ""
echo "  For full documentation, see:"
echo "    README.md       — Overview and quick reference"
echo "    QUICKSTART.md   — 5-minute walkthrough"
echo "    USER-MANUAL.md  — Complete operational guide"
echo ""
