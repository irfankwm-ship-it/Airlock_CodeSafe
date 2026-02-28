#!/usr/bin/env bash
# airlock-extract.sh — Human-gated extraction pipeline (phases 6-7)
# Extracts changes from a container, applies security checks, signs and syncs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=airlock.conf
source "$SCRIPT_DIR/airlock.conf"

usage() {
    echo "Usage: $0 <container-name>"
    exit 1
}

[ $# -lt 1 ] && usage

CONTAINER_NAME="$1"

# ── Validate container ─────────────────────────────────────────────────
if ! docker inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
    echo "ERROR: container '$CONTAINER_NAME' not found" >&2
    exit 1
fi

SESSION_ID=$(docker inspect --format='{{index .Config.Labels "airlock.session"}}' "$CONTAINER_NAME" 2>/dev/null || echo "")
PROJECT_PATH=$(docker inspect --format='{{index .Config.Labels "airlock.project"}}' "$CONTAINER_NAME" 2>/dev/null || echo "")

if [ -z "$SESSION_ID" ] || [ -z "$PROJECT_PATH" ]; then
    echo "ERROR: container '$CONTAINER_NAME' is not an airlock container (missing labels)" >&2
    exit 1
fi

SESSION_LOG_DIR="$AIRLOCK_SESSION_DIR/$SESSION_ID"
mkdir -p "$SESSION_LOG_DIR"

# Find the staged directory from bind mounts
STAGED_DIR=$(docker inspect --format='{{range .Mounts}}{{if eq .Destination "/workspace/project"}}{{.Source}}{{end}}{{end}}' "$CONTAINER_NAME")

if [ -z "$STAGED_DIR" ] || [ ! -d "$STAGED_DIR" ]; then
    echo "ERROR: cannot find staged directory for container" >&2
    exit 1
fi

echo "════════════════════════════════════════════════════════════════════"
echo "  Airlock Extraction: $SESSION_ID"
echo "  Container:          $CONTAINER_NAME"
echo "  Project:            $PROJECT_PATH"
echo "  Staged dir:         $STAGED_DIR"
echo "════════════════════════════════════════════════════════════════════"
echo ""

# ── Detect container state ────────────────────────────────────────────
CONTAINER_RUNNING=$(docker inspect --format='{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null || echo "false")
CONTAINER_PAUSED=$(docker inspect --format='{{.State.Paused}}' "$CONTAINER_NAME" 2>/dev/null || echo "false")
CONTAINER_STATUS=$(docker inspect --format='{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null || echo "unknown")

if [ "$CONTAINER_STATUS" = "exited" ]; then
    echo "  NOTE: Container already exited. TOCTOU pause not possible,"
    echo "        but staged files are on the host bind mount and immutable."
    echo ""
    CONTAINER_EXITED=true
elif [ "$CONTAINER_PAUSED" = "true" ]; then
    echo "  Container already paused."
    CONTAINER_EXITED=false
elif [ "$CONTAINER_RUNNING" = "true" ]; then
    CONTAINER_EXITED=false
else
    echo "  Container state: $CONTAINER_STATUS"
    CONTAINER_EXITED=true
fi

# ══════════════════════════════════════════════════════════════════════
# PHASE 6A: Capture audit logs
# ══════════════════════════════════════════════════════════════════════
echo "==> Phase 6A: Capturing audit logs"

# docker logs works on exited containers
docker logs "$CONTAINER_NAME" 2>&1 | cat -v > "$SESSION_LOG_DIR/docker-logs.txt" || true

# docker exec only works on running containers
if [ "$CONTAINER_EXITED" = false ] && [ "$CONTAINER_PAUSED" != "true" ]; then
    docker exec "$CONTAINER_NAME" cat /tmp/audit.log 2>/dev/null | cat -v > "$SESSION_LOG_DIR/audit.txt" || true
else
    echo "  Skipping audit.log capture (container not running)."
fi
echo "  Logs saved to $SESSION_LOG_DIR"

# ══════════════════════════════════════════════════════════════════════
# PHASE 6B: Pause container (TOCTOU protection)
# ══════════════════════════════════════════════════════════════════════
echo ""
echo "==> Phase 6B: Pausing container"

if [ "$CONTAINER_EXITED" = true ]; then
    echo "  Skipped (container already exited — no process can modify staged files)."
elif [ "$CONTAINER_PAUSED" = "true" ]; then
    echo "  Already paused."
else
    docker pause "$CONTAINER_NAME"
    echo "  Container paused."
fi

# From here we read files from the host-side bind mount (no docker exec on paused container)

# ══════════════════════════════════════════════════════════════════════
# PHASE 6C: Security checks on staged files
# ══════════════════════════════════════════════════════════════════════
echo ""
echo "==> Phase 6C: Security checks"

ABORT=0

# --- Symlink check ---
echo "  Checking for symlinks..."
SYMLINKS=$(find "$STAGED_DIR" -type l 2>/dev/null || true)
if [ -n "$SYMLINKS" ]; then
    echo "  ABORT: symlinks detected:" >&2
    echo "$SYMLINKS" | sed 's/^/    /' >&2
    echo "  Symlinks may point outside staged dir — possible escape attempt." >&2
    ABORT=1
fi

# --- ANSI escape check ---
echo "  Checking for ANSI escape sequences..."
ANSI_FILES=$(grep -rlP '\x1b' "$STAGED_DIR" 2>/dev/null || true)
if [ -n "$ANSI_FILES" ]; then
    echo "  ABORT: ANSI escape sequences found in:" >&2
    echo "$ANSI_FILES" | sed 's/^/    /' >&2
    echo "  May be terminal injection. Inspect manually." >&2
    ABORT=1
fi

if [ "$ABORT" -gt 0 ]; then
    echo ""
    echo "Extraction aborted due to security checks."
    if [ "$CONTAINER_EXITED" = true ]; then
        echo "  Destroy: docker rm -f $CONTAINER_NAME"
    else
        echo "  Container remains paused."
        echo "  Unpause: docker unpause $CONTAINER_NAME"
        echo "  Destroy: docker rm -f $CONTAINER_NAME"
    fi
    exit 1
fi

# ══════════════════════════════════════════════════════════════════════
# PHASE 6D: Hash-lock staged files
# ══════════════════════════════════════════════════════════════════════
echo ""
echo "==> Phase 6D: Computing file hashes"

HASH_FILE="$SESSION_LOG_DIR/staged-hashes.txt"
find "$STAGED_DIR" -type f -print0 | sort -z | xargs -0 sha256sum > "$HASH_FILE"
OVERALL_HASH=$(sha256sum "$HASH_FILE" | awk '{print $1}')
echo "  Overall hash: $OVERALL_HASH"

# ══════════════════════════════════════════════════════════════════════
# PHASE 6E: Generate diff
# ══════════════════════════════════════════════════════════════════════
echo ""
echo "==> Phase 6E: Generating diff"

DIFF_FILE="$SESSION_LOG_DIR/changes.diff"
diff -ruN "$PROJECT_PATH" "$STAGED_DIR" 2>/dev/null | cat -v > "$DIFF_FILE" || true

DIFF_LINES=$(wc -l < "$DIFF_FILE")
echo "  Diff: $DIFF_LINES lines → $DIFF_FILE"
if [ "$DIFF_LINES" -gt 500 ]; then
    echo "  WARNING: large diff ($DIFF_LINES lines). Review carefully."
fi

# --- New file detection (G7 enhancement) ---
echo "  Checking for new files..."
NEW_FILES=""
while IFS= read -r staged_file; do
    REL_PATH="${staged_file#"$STAGED_DIR"/}"
    if [ ! -e "$PROJECT_PATH/$REL_PATH" ]; then
        NEW_FILES="$NEW_FILES  NEW: $REL_PATH"$'\n'
    fi
done < <(find "$STAGED_DIR" -type f)

if [ -n "$NEW_FILES" ]; then
    echo "  New files not in original project:"
    echo "$NEW_FILES" | sed 's/^/  /'
fi

# ══════════════════════════════════════════════════════════════════════
# PHASE 6F: Automated scanning (trip wire, NOT shield)
# ══════════════════════════════════════════════════════════════════════
echo ""
echo "==> Phase 6F: Automated scan (catches OBVIOUS issues only — manual review is primary defense)"

SCAN_FINDINGS=""

# API key patterns
for pattern in 'sk-ant-[a-zA-Z0-9]' 'AKIA[0-9A-Z]{16}' 'ghp_[a-zA-Z0-9]{36}' 'gho_[a-zA-Z0-9]'; do
    MATCHES=$(grep -rlP "$pattern" "$STAGED_DIR" 2>/dev/null || true)
    if [ -n "$MATCHES" ]; then
        SCAN_FINDINGS="${SCAN_FINDINGS}  SECRET PATTERN ($pattern): $MATCHES"$'\n'
    fi
done

# Private key material
MATCHES=$(grep -rl 'BEGIN.*PRIVATE KEY' "$STAGED_DIR" 2>/dev/null || true)
if [ -n "$MATCHES" ]; then
    SCAN_FINDINGS="${SCAN_FINDINGS}  PRIVATE KEY: $MATCHES"$'\n'
fi

# Network imports in Python
MATCHES=$(grep -rlP '^\s*(import|from)\s+(urllib|requests|socket|http\b|aiohttp|httpx)' "$STAGED_DIR" --include='*.py' 2>/dev/null || true)
if [ -n "$MATCHES" ]; then
    SCAN_FINDINGS="${SCAN_FINDINGS}  PYTHON NETWORK IMPORT: $MATCHES"$'\n'
fi

# Network calls in JS/TS
MATCHES=$(grep -rlP "(require\s*\(\s*['\"](?:http|https|net|dgram|dns)['\"]|fetch\s*\(|XMLHttpRequest)" "$STAGED_DIR" --include='*.js' --include='*.ts' --include='*.jsx' --include='*.tsx' 2>/dev/null || true)
if [ -n "$MATCHES" ]; then
    SCAN_FINDINGS="${SCAN_FINDINGS}  JS/TS NETWORK CALL: $MATCHES"$'\n'
fi

# Dynamic execution
MATCHES=$(grep -rlP '(__import__|(?<!\w)exec\s*\(|(?<!\w)eval\s*\(|subprocess\.|os\.system\s*\()' "$STAGED_DIR" --include='*.py' 2>/dev/null || true)
if [ -n "$MATCHES" ]; then
    SCAN_FINDINGS="${SCAN_FINDINGS}  PYTHON DYNAMIC EXEC: $MATCHES"$'\n'
fi

if [ -n "$SCAN_FINDINGS" ]; then
    echo "  FINDINGS (review required):"
    echo "$SCAN_FINDINGS"
else
    echo "  No obvious issues found."
fi

# ── AST analysis on Python files (best effort) ────────────────────────
echo ""
echo "  AST analysis on Python files..."
PYTHON_FILES=$(find "$STAGED_DIR" -name '*.py' -type f 2>/dev/null || true)
if [ -n "$PYTHON_FILES" ]; then
    AST_SCRIPT=$(cat << 'PYEOF'
import ast, sys, os

dangerous = {
    'exec': 'dynamic execution',
    'eval': 'dynamic execution',
    '__import__': 'dynamic import',
    'getattr': 'dynamic attribute access',
    'compile': 'code compilation',
}

for fpath in sys.argv[1:]:
    try:
        with open(fpath) as f:
            tree = ast.parse(f.read(), filename=fpath)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = None
                if isinstance(node.func, ast.Name):
                    name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    name = node.func.attr
                if name and name in dangerous:
                    rel = os.path.relpath(fpath)
                    print(f"  AST: {dangerous[name]} — {name}() at {rel}:{node.lineno}")
    except (SyntaxError, UnicodeDecodeError):
        pass
PYEOF
    )
    # shellcheck disable=SC2086
    echo "$PYTHON_FILES" | xargs python3 -c "$AST_SCRIPT" 2>/dev/null || echo "  AST analysis: skipped (python3 not available or error)"
else
    echo "  No Python files to analyze."
fi

# Save scan results
{
    echo "=== Automated Scan Results ==="
    echo "Date: $(date -Iseconds)"
    echo "Session: $SESSION_ID"
    echo ""
    if [ -n "$SCAN_FINDINGS" ]; then
        echo "$SCAN_FINDINGS"
    else
        echo "No findings."
    fi
} > "$SESSION_LOG_DIR/scan-results.txt"

# ══════════════════════════════════════════════════════════════════════
# PHASE 7A: Human review
# ══════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "  HUMAN REVIEW REQUIRED"
echo ""
echo "  Diff file:     $DIFF_FILE"
echo "  Diff lines:    $DIFF_LINES"
echo "  Overall hash:  $OVERALL_HASH"
echo "  Scan results:  $SESSION_LOG_DIR/scan-results.txt"
echo ""
echo "  Open diff:     less $DIFF_FILE"
echo "  Open in editor: \${EDITOR:-vim} $DIFF_FILE"
echo "════════════════════════════════════════════════════════════════════"
echo ""
read -rp "Have you reviewed the diff? Type 'approve' to sign and sync: " REVIEW_RESPONSE

if [ "$REVIEW_RESPONSE" != "approve" ]; then
    echo "Extraction cancelled by reviewer."
    if [ "$CONTAINER_EXITED" = true ]; then
        echo "  Destroy: docker rm -f $CONTAINER_NAME"
    else
        echo "  Container remains paused. To resume: docker unpause $CONTAINER_NAME"
    fi
    exit 1
fi

# ══════════════════════════════════════════════════════════════════════
# PHASE 7B: Ed25519 signature (requires passphrase — human in loop)
# ══════════════════════════════════════════════════════════════════════
echo ""
echo "==> Phase 7B: Signing with Ed25519 key"

SIGNATURE_FILE="$SESSION_LOG_DIR/changes.diff.sig"
SIGN_NAMESPACE="airlock-approval"

# Sign the diff (will prompt for passphrase)
ssh-keygen -Y sign \
    -f "$AIRLOCK_SIGNING_KEY" \
    -n "$SIGN_NAMESPACE" \
    "$DIFF_FILE"

# ssh-keygen creates <file>.sig
if [ -f "${DIFF_FILE}.sig" ]; then
    mv "${DIFF_FILE}.sig" "$SIGNATURE_FILE"
fi

# Verify signature
if ! ssh-keygen -Y verify \
    -f "$AIRLOCK_ALLOWED_SIGNERS" \
    -I "airlock-user" \
    -n "$SIGN_NAMESPACE" \
    -s "$SIGNATURE_FILE" \
    < "$DIFF_FILE"; then
    echo "ERROR: signature verification failed!" >&2
    exit 1
fi
echo "  Signature verified."

# ══════════════════════════════════════════════════════════════════════
# PHASE 7C: TOCTOU final check
# ══════════════════════════════════════════════════════════════════════
echo ""
echo "==> Phase 7C: TOCTOU hash verification"

HASH_FILE_RECHECK="$SESSION_LOG_DIR/staged-hashes-recheck.txt"
find "$STAGED_DIR" -type f -print0 | sort -z | xargs -0 sha256sum > "$HASH_FILE_RECHECK"
RECHECK_HASH=$(sha256sum "$HASH_FILE_RECHECK" | awk '{print $1}')

if [ "$OVERALL_HASH" != "$RECHECK_HASH" ]; then
    echo "ABORT: hash mismatch detected!" >&2
    echo "  Pre-review:  $OVERALL_HASH" >&2
    echo "  Post-review: $RECHECK_HASH" >&2
    echo "  Staged files were modified during review. DO NOT sync." >&2
    exit 1
fi
echo "  Hash verified: unchanged since review."

# ══════════════════════════════════════════════════════════════════════
# PHASE 7D: Diff-only sync
# ══════════════════════════════════════════════════════════════════════
echo ""
echo "==> Phase 7D: Syncing changes to project"

SYNCED=0

# Parse diff to find changed/new files, sync only those
# Diff headers look like: diff -ruN /original/path/file /staged/path/file
while IFS= read -r diff_line; do
    # Extract the staged-side path from "diff -ruN <original> <staged>"
    STAGED_FILE=$(echo "$diff_line" | awk '{print $4}')
    if [ -z "$STAGED_FILE" ] || [ ! -f "$STAGED_FILE" ]; then
        continue
    fi

    REL_PATH="${STAGED_FILE#"$STAGED_DIR"/}"
    DEST="$PROJECT_PATH/$REL_PATH"
    DEST_DIR=$(dirname "$DEST")

    mkdir -p "$DEST_DIR"
    cp -a "$STAGED_FILE" "$DEST"
    SYNCED=$((SYNCED + 1))
    echo "  Synced: $REL_PATH"
done < <(grep '^diff -ruN ' "$DIFF_FILE" || true)

# Fallback: if diff parsing found nothing, compare per-file hashes
if [ "$SYNCED" -eq 0 ] && [ "$DIFF_LINES" -gt 0 ]; then
    echo "  Diff parsing found no files. Falling back to per-file hash comparison."
    while IFS= read -r staged_file; do
        REL_PATH="${staged_file#"$STAGED_DIR"/}"
        ORIGINAL="$PROJECT_PATH/$REL_PATH"

        if [ ! -f "$ORIGINAL" ]; then
            # New file
            DEST_DIR=$(dirname "$ORIGINAL")
            mkdir -p "$DEST_DIR"
            cp -a "$staged_file" "$ORIGINAL"
            SYNCED=$((SYNCED + 1))
            echo "  Synced (new): $REL_PATH"
        else
            STAGED_HASH=$(sha256sum "$staged_file" | awk '{print $1}')
            ORIG_HASH=$(sha256sum "$ORIGINAL" | awk '{print $1}')
            if [ "$STAGED_HASH" != "$ORIG_HASH" ]; then
                cp -a "$staged_file" "$ORIGINAL"
                SYNCED=$((SYNCED + 1))
                echo "  Synced (modified): $REL_PATH"
            fi
        fi
    done < <(find "$STAGED_DIR" -type f)
fi

echo "  $SYNCED file(s) synced. No host files deleted."

# ══════════════════════════════════════════════════════════════════════
# PHASE 7E: Cleanup
# ══════════════════════════════════════════════════════════════════════
echo ""
echo "==> Phase 7E: Cleanup"

# Find and kill watchdog
WATCHDOG_PID=""
if [ -f "$SESSION_LOG_DIR/session.env" ]; then
    WATCHDOG_PID=$(grep '^WATCHDOG_PID=' "$SESSION_LOG_DIR/session.env" | cut -d= -f2 || true)
fi
if [ -n "$WATCHDOG_PID" ] && kill -0 "$WATCHDOG_PID" 2>/dev/null; then
    kill "$WATCHDOG_PID" 2>/dev/null || true
    echo "  Watchdog killed (PID: $WATCHDOG_PID)"
fi

# Destroy container
NETWORK_NAME=$(docker inspect --format='{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$CONTAINER_NAME" 2>/dev/null | tr ' ' '\n' | grep "^${AIRLOCK_CONTAINER_PREFIX}-net-" | head -1 || true)
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
echo "  Container destroyed."

# Destroy network
if [ -n "$NETWORK_NAME" ]; then
    docker network rm "$NETWORK_NAME" 2>/dev/null || true
    echo "  Network $NETWORK_NAME destroyed."
fi

# Clean staged files
rm -rf "$STAGED_DIR"
echo "  Staged files cleaned."

# Archive session completion
echo "COMPLETED=$(date -Iseconds)" >> "$SESSION_LOG_DIR/session.env"
echo "SYNCED_FILES=$SYNCED" >> "$SESSION_LOG_DIR/session.env"

# Purge old sessions
if [ -d "$AIRLOCK_SESSION_DIR" ]; then
    find "$AIRLOCK_SESSION_DIR" -maxdepth 1 -type d -mtime "+$AIRLOCK_LOG_RETENTION_DAYS" -exec rm -rf {} + 2>/dev/null || true
fi

echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "  Extraction complete."
echo "  Session:       $SESSION_ID"
echo "  Files synced:  $SYNCED"
echo "  Signature:     $SIGNATURE_FILE"
echo "  Diff:          $DIFF_FILE"
echo "  Session logs:  $SESSION_LOG_DIR"
echo "════════════════════════════════════════════════════════════════════"
