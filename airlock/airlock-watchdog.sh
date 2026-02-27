#!/usr/bin/env bash
# airlock-watchdog.sh — Host-side session monitor with anomaly detection
# Runs OUTSIDE the container. Nothing inside can stop or influence it.
#
# Detection signals (all read from host side):
#   1. Memory usage exceeding threshold % of limit
#   2. PID count exceeding threshold % of limit
#   3. Blocked outbound connections (iptables LOG → dmesg)
#   4. File creation burst in staged directory
#
# Strikes accumulate. A clean check decays one strike.
# Auto-kill at AIRLOCK_MAX_STRIKES.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=airlock.conf
source "$SCRIPT_DIR/airlock.conf"

usage() {
    echo "Usage: $0 <container-name> <staged-dir> <session-log-dir>"
    exit 1
}

[ $# -lt 3 ] && usage

CONTAINER_NAME="$1"
STAGED_DIR="$2"
SESSION_LOG_DIR="$3"
ANOMALY_LOG="$SESSION_LOG_DIR/anomaly.log"

ELAPSED=0
CHECKPOINT_NUM=0
CHECK_INTERVAL=60
STRIKES=0
PREV_FILE_COUNT=0
LAST_DMESG_TIME=""

# Initialize file count baseline
PREV_FILE_COUNT=$(find "$STAGED_DIR" -type f 2>/dev/null | wc -l)

log() {
    local msg
    msg="[watchdog $(date '+%H:%M:%S')] $1"
    echo "$msg"
    echo "$msg" >> "$ANOMALY_LOG"
}

strike() {
    STRIKES=$((STRIKES + 1))
    log "STRIKE $STRIKES/$AIRLOCK_MAX_STRIKES: $1"
}

# ── Anomaly: Memory ───────────────────────────────────────────────────
check_memory() {
    # docker stats returns MiB used / limit
    local stats
    stats=$(docker stats --no-stream --format '{{.MemUsage}}' "$CONTAINER_NAME" 2>/dev/null || echo "")
    [ -z "$stats" ] && return

    # Parse "123.4MiB / 4GiB" → extract used and limit in MiB
    local used_raw limit_raw
    used_raw=$(echo "$stats" | awk -F'/' '{print $1}' | xargs)
    limit_raw=$(echo "$stats" | awk -F'/' '{print $2}' | xargs)

    local used_mib limit_mib
    used_mib=$(normalize_to_mib "$used_raw")
    limit_mib=$(normalize_to_mib "$limit_raw")

    if [ "$limit_mib" -gt 0 ] 2>/dev/null; then
        local pct=$((used_mib * 100 / limit_mib))
        if [ "$pct" -ge "$AIRLOCK_ANOMALY_MEM_PCT" ]; then
            strike "Memory at ${pct}% (${used_raw} / ${limit_raw}, threshold: ${AIRLOCK_ANOMALY_MEM_PCT}%)"
            return 1
        fi
    fi
    return 0
}

# ── Anomaly: PIDs ─────────────────────────────────────────────────────
check_pids() {
    local pids
    pids=$(docker stats --no-stream --format '{{.PIDs}}' "$CONTAINER_NAME" 2>/dev/null || echo "0")
    pids="${pids//[^0-9]/}"
    [ -z "$pids" ] && return

    local threshold=$((AIRLOCK_PIDS_LIMIT * AIRLOCK_ANOMALY_PID_PCT / 100))
    if [ "$pids" -ge "$threshold" ]; then
        strike "PID count at $pids (limit: $AIRLOCK_PIDS_LIMIT, threshold: ${AIRLOCK_ANOMALY_PID_PCT}%=$threshold)"
        return 1
    fi
    return 0
}

# ── Anomaly: Blocked connections (dmesg) ──────────────────────────────
check_blocked_connections() {
    local blocked_count
    if [ -n "$LAST_DMESG_TIME" ]; then
        blocked_count=$(sudo dmesg --since "$LAST_DMESG_TIME" 2>/dev/null \
            | grep -c "$AIRLOCK_FW_LOG_PREFIX" || true)
    else
        # First check — count all since container start
        blocked_count=$(sudo dmesg -T 2>/dev/null \
            | grep -c "$AIRLOCK_FW_LOG_PREFIX" || true)
    fi
    LAST_DMESG_TIME="$(date '+%Y-%m-%d %H:%M:%S')"

    if [ "$blocked_count" -ge "$AIRLOCK_ANOMALY_BLOCKED_CONNS" ]; then
        # Log the actual blocked destinations for forensics
        sudo dmesg --since "$(date -d "-${CHECK_INTERVAL} seconds" '+%Y-%m-%d %H:%M:%S')" 2>/dev/null \
            | grep "$AIRLOCK_FW_LOG_PREFIX" | tail -5 >> "$ANOMALY_LOG" 2>/dev/null || true
        strike "Blocked connections: $blocked_count in last ${CHECK_INTERVAL}s (threshold: $AIRLOCK_ANOMALY_BLOCKED_CONNS)"
        return 1
    fi
    return 0
}

# ── Anomaly: File burst ───────────────────────────────────────────────
check_file_burst() {
    local current_count
    current_count=$(find "$STAGED_DIR" -type f 2>/dev/null | wc -l)
    local delta=$((current_count - PREV_FILE_COUNT))
    PREV_FILE_COUNT="$current_count"

    # Only flag positive bursts (creation, not deletion)
    if [ "$delta" -ge "$AIRLOCK_ANOMALY_FILE_BURST" ]; then
        strike "File burst: $delta new files in last ${CHECK_INTERVAL}s (threshold: $AIRLOCK_ANOMALY_FILE_BURST)"
        return 1
    fi
    return 0
}

# ── Helper: normalize memory strings to MiB ───────────────────────────
normalize_to_mib() {
    local raw="$1"
    local num unit
    num=$(echo "$raw" | grep -oP '[0-9]+\.?[0-9]*')
    unit=$(echo "$raw" | grep -oP '[A-Za-z]+')

    # Truncate to integer
    num="${num%%.*}"
    [ -z "$num" ] && echo "0" && return

    case "$unit" in
        KiB|kB)  echo $((num / 1024)) ;;
        MiB|MB)  echo "$num" ;;
        GiB|GB)  echo $((num * 1024)) ;;
        TiB|TB)  echo $((num * 1024 * 1024)) ;;
        *)       echo "$num" ;;
    esac
}

# ══════════════════════════════════════════════════════════════════════
# Main loop
# ══════════════════════════════════════════════════════════════════════
log "Monitoring $CONTAINER_NAME"
log "  Timeout: ${AIRLOCK_SESSION_TIMEOUT}s | Checkpoint: ${AIRLOCK_CHECKPOINT_INTERVAL}s"
log "  Anomaly thresholds: mem>${AIRLOCK_ANOMALY_MEM_PCT}% pids>${AIRLOCK_ANOMALY_PID_PCT}% blocked>${AIRLOCK_ANOMALY_BLOCKED_CONNS}/check files>${AIRLOCK_ANOMALY_FILE_BURST}/check"
log "  Auto-kill at $AIRLOCK_MAX_STRIKES strikes"

while true; do
    sleep "$CHECK_INTERVAL"
    ELAPSED=$((ELAPSED + CHECK_INTERVAL))

    # ── Is container still running? ───────────────────────────────────
    if ! docker inspect --format='{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null | grep -q true; then
        log "Container stopped on its own. Exiting."
        break
    fi

    # ── Session timeout ───────────────────────────────────────────────
    if [ "$ELAPSED" -ge "$AIRLOCK_SESSION_TIMEOUT" ]; then
        log "SESSION TIMEOUT reached (${AIRLOCK_SESSION_TIMEOUT}s). Killing container."
        docker kill "$CONTAINER_NAME" 2>/dev/null || true
        echo "TIMEOUT" > "$SESSION_LOG_DIR/exit-reason"
        break
    fi

    # ── Anomaly detection ─────────────────────────────────────────────
    ANOMALY_THIS_ROUND=0

    check_memory       || ANOMALY_THIS_ROUND=1
    check_pids         || ANOMALY_THIS_ROUND=1
    check_blocked_connections || ANOMALY_THIS_ROUND=1
    check_file_burst   || ANOMALY_THIS_ROUND=1

    # Clean round decays one strike (self-healing for transient spikes)
    if [ "$ANOMALY_THIS_ROUND" -eq 0 ] && [ "$STRIKES" -gt 0 ]; then
        STRIKES=$((STRIKES - 1))
        log "Clean check. Strikes decayed to $STRIKES/$AIRLOCK_MAX_STRIKES"
    fi

    # ── Auto-kill on max strikes ──────────────────────────────────────
    if [ "$STRIKES" -ge "$AIRLOCK_MAX_STRIKES" ]; then
        log "MAX STRIKES REACHED ($STRIKES). KILLING CONTAINER."

        # Capture final forensics before kill
        docker stats --no-stream "$CONTAINER_NAME" >> "$ANOMALY_LOG" 2>/dev/null || true
        docker logs --tail 50 "$CONTAINER_NAME" >> "$SESSION_LOG_DIR/final-logs.txt" 2>&1 || true
        sudo dmesg -T 2>/dev/null | grep "$AIRLOCK_FW_LOG_PREFIX" | tail -20 >> "$ANOMALY_LOG" 2>/dev/null || true

        docker kill "$CONTAINER_NAME" 2>/dev/null || true
        echo "ANOMALY_KILL: ${STRIKES} strikes" > "$SESSION_LOG_DIR/exit-reason"
        break
    fi

    # ── Periodic checkpoint ───────────────────────────────────────────
    SINCE_CHECKPOINT=$((ELAPSED % AIRLOCK_CHECKPOINT_INTERVAL))
    if [ "$SINCE_CHECKPOINT" -lt "$CHECK_INTERVAL" ]; then
        CHECKPOINT_NUM=$((CHECKPOINT_NUM + 1))
        CHECKPOINT_DIR="$SESSION_LOG_DIR/checkpoint-$CHECKPOINT_NUM"
        mkdir -p "$CHECKPOINT_DIR"

        # Snapshot workspace file listing
        find "$STAGED_DIR" -type f -printf '%T@ %s %p\n' 2>/dev/null | sort -rn > "$CHECKPOINT_DIR/files.txt" || true

        # Capture container logs (incremental)
        docker logs --since "${AIRLOCK_CHECKPOINT_INTERVAL}s" "$CONTAINER_NAME" > "$CHECKPOINT_DIR/docker-logs.txt" 2>&1 || true

        # Capture audit log if it exists
        docker exec "$CONTAINER_NAME" cat /tmp/audit.log 2>/dev/null | cat -v > "$CHECKPOINT_DIR/audit.txt" || true

        # Snapshot resource usage
        docker stats --no-stream "$CONTAINER_NAME" > "$CHECKPOINT_DIR/resources.txt" 2>/dev/null || true

        log "Checkpoint $CHECKPOINT_NUM saved (strikes: $STRIKES/$AIRLOCK_MAX_STRIKES, elapsed: ${ELAPSED}s)"
    fi
done

log "Exiting."
