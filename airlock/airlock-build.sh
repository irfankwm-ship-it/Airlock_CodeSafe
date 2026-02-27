#!/usr/bin/env bash
# airlock-build.sh — Build Airlock image, store hash, verify contract
# Decoupled from launch — build any image, launch any image.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=airlock.conf
source "$SCRIPT_DIR/airlock.conf"

# ── Usage ──────────────────────────────────────────────────────────────
usage() {
    echo "Usage: $0 <dockerfile> <image-name> [--verify-only]"
    echo ""
    echo "  Build:   $0 Dockerfile.base airlock-base:latest"
    echo "  Verify:  $0 _ airlock-base:latest --verify-only"
    echo ""
    echo "  --verify-only  Re-verify an existing image's contract without rebuilding."
    echo "                 Dockerfile arg is ignored (use _ as placeholder)."
    exit 1
}

[ $# -lt 2 ] && usage

DOCKERFILE="$1"
IMAGE_NAME="$2"
VERIFY_ONLY=false

if [ "${3:-}" = "--verify-only" ]; then
    VERIFY_ONLY=true
fi

# Sanitize image name for use as filename (replace : and / with -)
HASH_FILENAME="${IMAGE_NAME//[:\/]/-}.hash"
HASH_FILE="$AIRLOCK_IMAGE_HASH_DIR/$HASH_FILENAME"

# ── Ensure state directories exist ────────────────────────────────────
mkdir -p "$AIRLOCK_STATE_DIR" "$AIRLOCK_IMAGE_HASH_DIR"

# ── Build (unless --verify-only) ──────────────────────────────────────
if [ "$VERIFY_ONLY" = false ]; then
    if [ ! -f "$SCRIPT_DIR/$DOCKERFILE" ]; then
        echo "ERROR: $SCRIPT_DIR/$DOCKERFILE not found" >&2
        exit 1
    fi

    echo "==> Building image $IMAGE_NAME from $DOCKERFILE (--no-cache)"
    docker build \
        --no-cache \
        -t "$IMAGE_NAME" \
        -f "$SCRIPT_DIR/$DOCKERFILE" \
        "$SCRIPT_DIR"
else
    echo "==> Verify-only mode for $IMAGE_NAME"
    if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
        echo "ERROR: image '$IMAGE_NAME' not found" >&2
        exit 1
    fi
fi

# ── Store image hash ──────────────────────────────────────────────────
IMAGE_HASH=$(docker inspect --format='{{.Id}}' "$IMAGE_NAME")
echo "$IMAGE_HASH" > "$HASH_FILE"
echo "==> Image hash stored: $HASH_FILE"
echo "    $IMAGE_HASH"

# ── Contract verification ─────────────────────────────────────────────
echo "==> Verifying image contract..."

ERRORS=0

# Check 1: entrypoint.sh exists
if ! docker run --rm --entrypoint="" "$IMAGE_NAME" test -f /usr/local/bin/entrypoint.sh; then
    echo "  FAIL: /usr/local/bin/entrypoint.sh not found" >&2
    ERRORS=$((ERRORS + 1))
else
    echo "  OK: entrypoint.sh exists"
fi

# Check 2: user claude exists with UID 1000
CLAUDE_UID=$(docker run --rm --entrypoint="" "$IMAGE_NAME" id -u claude 2>/dev/null || echo "missing")
if [ "$CLAUDE_UID" != "1000" ]; then
    echo "  FAIL: user claude UID is '$CLAUDE_UID', expected 1000" >&2
    ERRORS=$((ERRORS + 1))
else
    echo "  OK: user claude (UID 1000)"
fi

# Check 3: /workspace/project exists
if ! docker run --rm --entrypoint="" "$IMAGE_NAME" test -d /workspace/project; then
    echo "  FAIL: /workspace/project not found" >&2
    ERRORS=$((ERRORS + 1))
else
    echo "  OK: /workspace/project exists"
fi

# Check 4: claude binary on PATH
if ! docker run --rm --entrypoint="" "$IMAGE_NAME" which claude >/dev/null 2>&1; then
    echo "  FAIL: 'claude' not found on PATH" >&2
    ERRORS=$((ERRORS + 1))
else
    echo "  OK: claude binary on PATH"
fi

# ── Allowed signers check ─────────────────────────────────────────────
if [ ! -f "$AIRLOCK_ALLOWED_SIGNERS" ]; then
    echo ""
    echo "WARNING: allowed_signers not found at $AIRLOCK_ALLOWED_SIGNERS"
    echo "  Run: mkdir -p ~/.airlock && echo \"airlock-user \$(cat ~/.ssh/id_ed25519.pub)\" > ~/.airlock/allowed_signers"
fi

# ── Result ─────────────────────────────────────────────────────────────
echo ""
if [ "$ERRORS" -gt 0 ]; then
    echo "FAILED: $ERRORS contract check(s) failed" >&2
    exit 1
fi

if [ "$VERIFY_ONLY" = true ]; then
    echo "==> Verification complete. All contract checks passed."
else
    echo "==> Build complete. All contract checks passed."
fi
echo "    Image: $IMAGE_NAME"
echo "    Hash:  $IMAGE_HASH"
echo "    File:  $HASH_FILE"
