#!/usr/bin/env bash
# airlock-kill.sh — Emergency kill switch for airlock sessions
# Destroys container(s), network(s), and watchdog(s). Does NOT extract or sync.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=airlock.conf
source "$SCRIPT_DIR/airlock.conf"

usage() {
    echo "Usage: $0 [container-name | --all] [--purge]"
    echo ""
    echo "  Kill one:     $0 airlock-20260227-101500-12345"
    echo "  Kill all:     $0 --all"
    echo "  List:         $0 --list"
    echo "  Scorched earth: $0 --all --purge  (destroys session logs too)"
    exit 1
}

[ $# -lt 1 ] && usage

# Check for --purge flag
PURGE=false
for arg in "$@"; do
    if [ "$arg" = "--purge" ]; then
        PURGE=true
    fi
done

# ── List mode ──────────────────────────────────────────────────────────
if [ "$1" = "--list" ]; then
    echo "Running airlock sessions:"
    docker ps --filter "name=^${AIRLOCK_CONTAINER_PREFIX}-" --format 'table {{.Names}}\t{{.Status}}\t{{.Label "airlock.project"}}' 2>/dev/null || echo "  (none)"
    exit 0
fi

# ── Determine targets ─────────────────────────────────────────────────
if [ "$1" = "--all" ]; then
    CONTAINERS=$(docker ps -a --filter "name=^${AIRLOCK_CONTAINER_PREFIX}-" --format '{{.Names}}' 2>/dev/null || true)
    if [ -z "$CONTAINERS" ]; then
        echo "No airlock containers found."
        exit 0
    fi
    echo "Killing ALL airlock sessions:"
    echo "$CONTAINERS" | sed 's/^/  /'
else
    CONTAINERS="$1"
fi

# ── Kill each container ───────────────────────────────────────────────
for CONTAINER_NAME in $CONTAINERS; do
    echo ""
    echo "==> Killing $CONTAINER_NAME"

    # Read session metadata if available
    SESSION_ID=$(docker inspect --format='{{index .Config.Labels "airlock.session"}}' "$CONTAINER_NAME" 2>/dev/null || echo "")
    SESSION_LOG_DIR="$AIRLOCK_SESSION_DIR/$SESSION_ID"

    # Kill watchdog if we know its PID
    if [ -n "$SESSION_ID" ] && [ -f "$SESSION_LOG_DIR/session.env" ]; then
        WATCHDOG_PID=$(grep '^WATCHDOG_PID=' "$SESSION_LOG_DIR/session.env" | cut -d= -f2 || true)
        if [ -n "$WATCHDOG_PID" ] && kill -0 "$WATCHDOG_PID" 2>/dev/null; then
            kill "$WATCHDOG_PID" 2>/dev/null || true
            echo "  Watchdog killed (PID: $WATCHDOG_PID)"
        fi
    fi

    # Find and destroy associated network
    NETWORK_NAME=$(docker inspect --format='{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$CONTAINER_NAME" 2>/dev/null | tr ' ' '\n' | grep "^${AIRLOCK_CONTAINER_PREFIX}-net-" | head -1 || true)

    # Destroy container
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    echo "  Container destroyed."

    # Destroy network
    if [ -n "$NETWORK_NAME" ]; then
        docker network rm "$NETWORK_NAME" 2>/dev/null || true
        echo "  Network $NETWORK_NAME destroyed."
    fi

    # Clean staged dir
    if [ -n "$SESSION_ID" ] && [ -f "$SESSION_LOG_DIR/session.env" ]; then
        STAGED_DIR=$(grep '^STAGED_DIR=' "$SESSION_LOG_DIR/session.env" | cut -d= -f2 || true)
        if [ -n "$STAGED_DIR" ] && [ -d "$STAGED_DIR" ]; then
            rm -rf "$STAGED_DIR"
            echo "  Staged files cleaned."
        fi

        if [ "$PURGE" = true ]; then
            rm -rf "$SESSION_LOG_DIR"
            echo "  Session logs purged."
        else
            echo "KILLED=$(date -Iseconds)" >> "$SESSION_LOG_DIR/session.env"
            echo "  Session logs preserved at $SESSION_LOG_DIR"
        fi
    fi

    echo "  Done."
done

echo ""
if [ "$PURGE" = true ]; then
    echo "Kill + purge complete. All session data destroyed. No files were synced."
else
    echo "Kill complete. Session logs preserved for forensics. No files were synced."
fi
