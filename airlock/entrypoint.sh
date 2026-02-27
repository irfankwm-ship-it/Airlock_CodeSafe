#!/usr/bin/env bash
# entrypoint.sh — Airlock container entrypoint (the image contract)
#
# Contract:
#   1. Auth via credentials file OR ANTHROPIC_API_KEY env var
#   2. If credentials file present, entrypoint symlinks into /home/claude/.claude/
#   3. Touch /tmp/.key-loaded as readiness signal
#   4. exec claude --dangerously-skip-permissions with any extra args
set -euo pipefail

CRED_MOUNT="/run/credentials/.credentials.json"
CRED_TARGET="/home/claude/.claude/.credentials.json"

# /home/claude is tmpfs — create dir structure
mkdir -p /home/claude/.claude

if [ -f "$CRED_MOUNT" ]; then
    # OAuth credentials file mode
    ln -sf "$CRED_MOUNT" "$CRED_TARGET"
    echo "Auth: credentials file"
elif [ -n "${ANTHROPIC_API_KEY:-}" ]; then
    # API key mode — Claude Code reads ANTHROPIC_API_KEY from env directly
    echo "Auth: API key"
else
    echo "FATAL: no authentication found." >&2
    echo "  Either mount credentials at $CRED_MOUNT" >&2
    echo "  or set ANTHROPIC_API_KEY environment variable." >&2
    exit 1
fi

# Copy approved enhancements from read-only mounts into tmpfs .claude/
# Enhancements are mounted at /opt/enhancements/<name>/ (read-only)
if [ -d /opt/enhancements ]; then
    for enhance_dir in /opt/enhancements/*/; do
        [ ! -d "$enhance_dir" ] && continue
        enhance_name=$(basename "$enhance_dir")
        echo "Loading enhancement: $enhance_name"

        # Copy Claude Code config dirs (commands, hooks, skills, agents, etc.)
        for subdir in commands hooks skills agents; do
            src="$enhance_dir/.claude/$subdir"
            if [ -d "$src" ]; then
                mkdir -p "/home/claude/.claude/$subdir"
                cp -r "$src"/* "/home/claude/.claude/$subdir/" 2>/dev/null || true
            fi
            # Also check top-level subdir (some enhancements use this layout)
            src="$enhance_dir/$subdir"
            if [ -d "$src" ]; then
                mkdir -p "/home/claude/.claude/$subdir"
                cp -r "$src"/* "/home/claude/.claude/$subdir/" 2>/dev/null || true
            fi
        done

        # Copy plugin config if present
        if [ -d "$enhance_dir/.claude-plugin" ]; then
            mkdir -p "/home/claude/.claude/plugins/$enhance_name"
            cp -r "$enhance_dir/.claude-plugin"/* "/home/claude/.claude/plugins/$enhance_name/" 2>/dev/null || true
        fi

        # Copy CLAUDE.md content (append to existing)
        if [ -f "$enhance_dir/CLAUDE.md" ]; then
            echo "" >> /home/claude/.claude/CLAUDE.md
            echo "# === Enhancement: $enhance_name ===" >> /home/claude/.claude/CLAUDE.md
            cat "$enhance_dir/CLAUDE.md" >> /home/claude/.claude/CLAUDE.md
        fi

        # Copy any data/lib dirs the enhancement needs (read-only source preserved)
        for datadir in data lib src; do
            if [ -d "$enhance_dir/$datadir" ]; then
                mkdir -p "/home/claude/.claude/enhancement-data/$enhance_name/$datadir"
                cp -r "$enhance_dir/$datadir"/* "/home/claude/.claude/enhancement-data/$enhance_name/$datadir/" 2>/dev/null || true
            fi
        done
    done
    echo "Enhancements loaded: $(ls /opt/enhancements/ 2>/dev/null | tr '\n' ' ')"
fi

# Readiness signal for launch script (credentials + enhancements loaded)
touch /tmp/.key-loaded

# Wait for network to be ready (launch script signals this after firewall + connect)
# The container starts with --network none; the host applies firewall rules then
# connects the network and touches /tmp/.network-ready via docker exec.
echo "Waiting for network..."
WAIT=0
while [ ! -f /tmp/.network-ready ] && [ "$WAIT" -lt 120 ]; do
    sleep 1
    WAIT=$((WAIT + 1))
done

if [ ! -f /tmp/.network-ready ]; then
    echo "FATAL: network readiness signal not received after 120s" >&2
    exit 1
fi

echo "Network ready. Starting Claude Code..."
exec claude --dangerously-skip-permissions "$@"
