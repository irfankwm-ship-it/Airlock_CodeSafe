#!/usr/bin/env bash
# airlock-launch.sh — Main orchestration: phases 0-4
# Launches a hardened, network-isolated Docker container for Claude Code
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=airlock.conf
source "$SCRIPT_DIR/airlock.conf"

usage() {
    echo "Usage: $0 <image-name> <project-path>"
    echo ""
    echo "  Example: $0 airlock-base:latest ~/projects/my-app"
    echo ""
    echo "  The image must have been built and verified with airlock-build.sh first."
    exit 1
}

[ $# -lt 2 ] && usage

AIRLOCK_IMAGE="$1"
PROJECT_PATH="$(realpath "$2")"
SESSION_ID="$(date +%Y%m%d-%H%M%S)-$$"
CONTAINER_NAME="${AIRLOCK_CONTAINER_PREFIX}-${SESSION_ID}"
NETWORK_NAME="${AIRLOCK_CONTAINER_PREFIX}-net-${SESSION_ID}"
SESSION_LOG_DIR="$AIRLOCK_SESSION_DIR/$SESSION_ID"
STAGED_DIR=$(mktemp -d "/tmp/airlock-staged-${SESSION_ID}.XXXXXX")

# Cleanup on failure
cleanup_on_error() {
    echo "==> Cleaning up after error..."
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
    docker network rm "$NETWORK_NAME" 2>/dev/null || true
    rm -rf "$STAGED_DIR"
}
trap cleanup_on_error ERR

# ══════════════════════════════════════════════════════════════════════
# PHASE 0: Pre-flight checks
# ══════════════════════════════════════════════════════════════════════
echo "==> Phase 0: Pre-flight checks"

# Check concurrent sessions
RUNNING=$(docker ps --filter "name=^${AIRLOCK_CONTAINER_PREFIX}-" --format '{{.Names}}' | wc -l)
if [ "$RUNNING" -ge "$AIRLOCK_MAX_CONCURRENT" ]; then
    echo "ERROR: $RUNNING airlock session(s) already running (max: $AIRLOCK_MAX_CONCURRENT)" >&2
    echo "  Running: $(docker ps --filter "name=^${AIRLOCK_CONTAINER_PREFIX}-" --format '{{.Names}}')" >&2
    exit 1
fi

# Verify Docker image exists
if ! docker image inspect "$AIRLOCK_IMAGE" >/dev/null 2>&1; then
    echo "ERROR: image '$AIRLOCK_IMAGE' not found. Run airlock-build.sh first." >&2
    exit 1
fi

# Verify image hash (per-image hash file)
HASH_FILENAME="${AIRLOCK_IMAGE//[:\/]/-}.hash"
HASH_FILE="$AIRLOCK_IMAGE_HASH_DIR/$HASH_FILENAME"
if [ ! -f "$HASH_FILE" ]; then
    echo "ERROR: no stored hash for '$AIRLOCK_IMAGE' at $HASH_FILE" >&2
    echo "  Run: ./airlock-build.sh <dockerfile> $AIRLOCK_IMAGE" >&2
    exit 1
fi

STORED_HASH=$(cat "$HASH_FILE")
CURRENT_HASH=$(docker inspect --format='{{.Id}}' "$AIRLOCK_IMAGE")
if [ "$STORED_HASH" != "$CURRENT_HASH" ]; then
    echo "ERROR: image hash mismatch — possible tampering!" >&2
    echo "  Stored:  $STORED_HASH" >&2
    echo "  Current: $CURRENT_HASH" >&2
    echo "  Rebuild with airlock-build.sh to update hash." >&2
    exit 1
fi
echo "  Image hash verified: ${CURRENT_HASH:0:20}..."

# Verify credentials (file or API key)
if [ -n "$AIRLOCK_API_KEY" ]; then
    echo "  Auth mode: API key (ANTHROPIC_API_KEY)"
    AIRLOCK_AUTH_MODE="api_key"
elif [ -f "$AIRLOCK_CREDENTIALS_HOST" ]; then
    echo "  Auth mode: OAuth credentials file"
    AIRLOCK_AUTH_MODE="credentials_file"
else
    echo "ERROR: no authentication found." >&2
    echo "  Either set ANTHROPIC_API_KEY or ensure credentials exist at:" >&2
    echo "  $AIRLOCK_CREDENTIALS_HOST" >&2
    echo "  Run './airlock-setup.sh' for help." >&2
    exit 1
fi

# Multi-DNS resolve Anthropic IPs
echo "  Resolving Anthropic API IPs..."
ANTHROPIC_IPS=""
for domain in $AIRLOCK_API_DOMAINS; do
    for dns in $AIRLOCK_DNS_SERVERS; do
        RESOLVED=$(dig +short "$domain" @"$dns" A 2>/dev/null | grep -E '^[0-9]+\.' || true)
        if [ -n "$RESOLVED" ]; then
            ANTHROPIC_IPS="$ANTHROPIC_IPS $RESOLVED"
        fi
    done
done

# Deduplicate
ANTHROPIC_IPS=$(echo "$ANTHROPIC_IPS" | tr ' ' '\n' | sort -u | grep -v '^$' | tr '\n' ' ')
ANTHROPIC_IPS="${ANTHROPIC_IPS% }"

if [ -z "$ANTHROPIC_IPS" ]; then
    echo "ERROR: could not resolve any IPs for $AIRLOCK_API_DOMAINS" >&2
    exit 1
fi

IP_COUNT=$(echo "$ANTHROPIC_IPS" | wc -w)
echo "  Resolved $IP_COUNT unique Anthropic IP(s): $ANTHROPIC_IPS"

# Verify project path
if [ ! -d "$PROJECT_PATH" ]; then
    echo "ERROR: project path '$PROJECT_PATH' does not exist" >&2
    exit 1
fi

# Create session log directory
mkdir -p "$SESSION_LOG_DIR"

# Create dedicated internal Docker network
echo "  Creating network $NETWORK_NAME"
# Not --internal: iptables firewall is the access control layer.
# --internal would block all external traffic including allowed Anthropic IPs.
docker network create "$NETWORK_NAME" >/dev/null

echo "  Pre-flight passed."

# ══════════════════════════════════════════════════════════════════════
# PHASE 1: Sanitize project
# ══════════════════════════════════════════════════════════════════════
echo ""
echo "==> Phase 1: Sanitizing project"
"$SCRIPT_DIR/airlock-sanitize.sh" "$PROJECT_PATH" "$STAGED_DIR"

# ══════════════════════════════════════════════════════════════════════
# PHASE 2: Launch container (--network none)
# ══════════════════════════════════════════════════════════════════════
echo ""
echo "==> Phase 2: Launching container (network none)"

# Build --add-host flags for Anthropic IPs
ADD_HOST_FLAGS=""
for domain in $AIRLOCK_API_DOMAINS; do
    for ip in $ANTHROPIC_IPS; do
        ADD_HOST_FLAGS="$ADD_HOST_FLAGS --add-host $domain:$ip"
    done
done

# Optional test port
PORT_FLAGS=""
if [ -n "${TEST_PORT:-}" ]; then
    PORT_FLAGS="-p 127.0.0.1:${TEST_PORT}:${TEST_PORT}"
fi

# Discover approved enhancements
ENHANCE_DIR="$AIRLOCK_STATE_DIR/enhancements"
ENHANCE_FLAGS=""
ENHANCE_NAMES=""
if [ -d "$ENHANCE_DIR" ]; then
    for meta in "$ENHANCE_DIR"/*/metadata.env; do
        [ ! -f "$meta" ] && continue
        status=$(grep '^STATUS=' "$meta" | cut -d= -f2)
        name=$(grep '^NAME=' "$meta" | cut -d= -f2)
        stored_hash=$(grep '^HASH=' "$meta" | cut -d= -f2)

        if [ "$status" = "approved" ] && [ -n "$stored_hash" ]; then
            repo_dir="$ENHANCE_DIR/$name/repo"
            # Tamper check
            current_hash=$(find "$repo_dir" -type f -not -path '*/.git/*' -exec sha256sum {} \; | sort | sha256sum | cut -d' ' -f1)
            if [ "$current_hash" != "$stored_hash" ]; then
                echo "  WARNING: Enhancement '$name' hash mismatch — SKIPPING (possible tampering)" >&2
                continue
            fi
            ENHANCE_FLAGS="$ENHANCE_FLAGS -v $repo_dir:/opt/enhancements/$name:ro"
            if [ -n "$ENHANCE_NAMES" ]; then
                ENHANCE_NAMES="$ENHANCE_NAMES,$name"
            else
                ENHANCE_NAMES="$name"
            fi
            echo "  Enhancement loaded: $name"
        fi
    done
fi

# Build auth flags based on mode
AUTH_FLAGS=""
AUTH_ENV_FLAGS=""
if [ "$AIRLOCK_AUTH_MODE" = "credentials_file" ]; then
    AUTH_FLAGS="-v $AIRLOCK_CREDENTIALS_HOST:$AIRLOCK_CREDENTIALS_MOUNT:ro"
    AUTH_ENV_FLAGS="-e ANTHROPIC_AUTH_TOKEN_FILE=$AIRLOCK_CREDENTIALS_CONTAINER"
elif [ "$AIRLOCK_AUTH_MODE" = "api_key" ]; then
    AUTH_ENV_FLAGS="-e ANTHROPIC_API_KEY=$AIRLOCK_API_KEY"
fi

# shellcheck disable=SC2086
docker run -dit \
    --name "$CONTAINER_NAME" \
    --network none \
    --user 1000:1000 \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --security-opt "seccomp=$AIRLOCK_SECCOMP_PROFILE" \
    --security-opt apparmor=docker-default \
    --read-only \
    --tmpfs "/tmp:rw,nosuid,size=$AIRLOCK_TMPFS_TMP_SIZE,uid=1000,gid=1000" \
    --tmpfs "/home/claude:rw,exec,size=$AIRLOCK_TMPFS_HOME_SIZE,uid=1000,gid=1000" \
    --sysctl net.ipv6.conf.all.disable_ipv6=1 \
    --memory="$AIRLOCK_MEMORY" \
    --pids-limit="$AIRLOCK_PIDS_LIMIT" \
    --cpus="$AIRLOCK_CPUS" \
    --ulimit "nofile=$AIRLOCK_NOFILE:$AIRLOCK_NOFILE" \
    --dns 0.0.0.0 \
    $ADD_HOST_FLAGS \
    -v "$STAGED_DIR:/workspace/project:rw" \
    $AUTH_FLAGS \
    $ENHANCE_FLAGS \
    $PORT_FLAGS \
    $AUTH_ENV_FLAGS \
    -e "AIRLOCK_AI_COMMAND=$AIRLOCK_AI_COMMAND" \
    -e "AIRLOCK_ENHANCEMENTS=$ENHANCE_NAMES" \
    --label "airlock.session=$SESSION_ID" \
    --label "airlock.project=$PROJECT_PATH" \
    "$AIRLOCK_IMAGE" >/dev/null

CONTAINER_ID=$(docker inspect --format='{{.Id}}' "$CONTAINER_NAME")
CONTAINER_PID=$(docker inspect --format='{{.State.Pid}}' "$CONTAINER_NAME")
echo "  Container: $CONTAINER_NAME (PID: $CONTAINER_PID)"

# ══════════════════════════════════════════════════════════════════════
# PHASE 3: Apply firewall (host-side via nsenter)
# ══════════════════════════════════════════════════════════════════════
echo ""
echo "==> Phase 3: Applying firewall rules"

# IPv4 rules
sudo nsenter -t "$CONTAINER_PID" -n iptables -P OUTPUT DROP
sudo nsenter -t "$CONTAINER_PID" -n iptables -A OUTPUT -o lo -j ACCEPT
sudo nsenter -t "$CONTAINER_PID" -n iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

for ip in $ANTHROPIC_IPS; do
    sudo nsenter -t "$CONTAINER_PID" -n iptables -A OUTPUT -d "$ip" -p tcp --dport "$AIRLOCK_API_PORT" -j ACCEPT
done

# LOG blocked attempts before DROP (anomaly detection feed)
sudo nsenter -t "$CONTAINER_PID" -n iptables -A OUTPUT -j LOG \
    --log-prefix "$AIRLOCK_FW_LOG_PREFIX" --log-level 4 --log-uid

# IPv6: LOG then block everything except loopback
sudo nsenter -t "$CONTAINER_PID" -n ip6tables -P OUTPUT DROP
sudo nsenter -t "$CONTAINER_PID" -n ip6tables -A OUTPUT -o lo -j ACCEPT
sudo nsenter -t "$CONTAINER_PID" -n ip6tables -A OUTPUT -j LOG \
    --log-prefix "$AIRLOCK_FW_LOG_PREFIX" --log-level 4 --log-uid

# Verify rule count
IPV4_RULES=$(sudo nsenter -t "$CONTAINER_PID" -n iptables -L OUTPUT -n | grep -c -v '^Chain\|^target' || true)
IPV6_RULES=$(sudo nsenter -t "$CONTAINER_PID" -n ip6tables -L OUTPUT -n | grep -c -v '^Chain\|^target' || true)
EXPECTED_IPV4=$((3 + IP_COUNT))  # loopback + ESTABLISHED + per-IP + LOG
echo "  IPv4 OUTPUT rules: $IPV4_RULES (expected: $EXPECTED_IPV4)"
echo "  IPv6 OUTPUT rules: $IPV6_RULES (expected: 2)"  # loopback + LOG

if [ "$IPV4_RULES" -ne "$EXPECTED_IPV4" ]; then
    echo "WARNING: IPv4 rule count mismatch!" >&2
fi

echo "  Firewall applied."

# ══════════════════════════════════════════════════════════════════════
# PHASE 4: Connect network + signal readiness
# ══════════════════════════════════════════════════════════════════════
echo ""
echo "==> Phase 4: Waiting for container readiness, then connecting network"

# Wait for key-loaded signal (entrypoint has set up credentials + enhancements)
echo "  Waiting for container setup (/tmp/.key-loaded)..."
WAITED=0
while [ "$WAITED" -lt "$AIRLOCK_KEY_LOAD_TIMEOUT" ]; do
    if docker exec "$CONTAINER_NAME" test -f /tmp/.key-loaded 2>/dev/null; then
        echo "  Container setup complete."
        break
    fi
    sleep 1
    WAITED=$((WAITED + 1))
done

if [ "$WAITED" -ge "$AIRLOCK_KEY_LOAD_TIMEOUT" ]; then
    echo "ERROR: container setup signal not received after ${AIRLOCK_KEY_LOAD_TIMEOUT}s" >&2
    echo "  Check: docker logs $CONTAINER_NAME" >&2
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
    docker network rm "$NETWORK_NAME" 2>/dev/null || true
    exit 1
fi

# Disconnect from 'none' then connect to internal network (firewall already active — G2 timing fix)
docker network disconnect none "$CONTAINER_NAME"
docker network connect "$NETWORK_NAME" "$CONTAINER_NAME"
echo "  Network connected (firewall was active before connect)"

# Signal the entrypoint that network is ready — Claude Code can now start
docker exec "$CONTAINER_NAME" touch /tmp/.network-ready
echo "  Network readiness signaled to container"

# Start watchdog in background
"$SCRIPT_DIR/airlock-watchdog.sh" "$CONTAINER_NAME" "$STAGED_DIR" "$SESSION_LOG_DIR" &
WATCHDOG_PID=$!
echo "  Watchdog started (PID: $WATCHDOG_PID)"

# Save session metadata
cat > "$SESSION_LOG_DIR/session.env" << EOF
SESSION_ID=$SESSION_ID
CONTAINER_NAME=$CONTAINER_NAME
CONTAINER_ID=$CONTAINER_ID
CONTAINER_PID=$CONTAINER_PID
NETWORK_NAME=$NETWORK_NAME
PROJECT_PATH=$PROJECT_PATH
STAGED_DIR=$STAGED_DIR
WATCHDOG_PID=$WATCHDOG_PID
IMAGE_NAME=$AIRLOCK_IMAGE
IMAGE_HASH=$CURRENT_HASH
ANTHROPIC_IPS=$ANTHROPIC_IPS
ENHANCEMENTS=$ENHANCE_NAMES
STARTED=$(date -Iseconds)
EOF

# Disable ERR trap — we launched successfully
trap - ERR

clear
echo ""
echo "  ┌──────────────────────────────────────────────────────────────┐"
echo "  │                                                              │"
echo "  │                    AIRLOCK ACTIVE                            │"
echo "  │                                                              │"
echo "  │  Session:   $SESSION_ID"
echo "  │  Image:     $AIRLOCK_IMAGE"
echo "  │  Project:   $(basename "$PROJECT_PATH")"
if [ -n "$ENHANCE_NAMES" ]; then
echo "  │  Enhance:   ${ENHANCE_NAMES//,/ + }"
fi
echo "  │                                                              │"
echo "  │  Firewall:  Anthropic API only (TCP 443)                     │"
echo "  │  Seccomp:   Whitelist-only (185 syscalls)                    │"
echo "  │  Filesystem: Read-only rootfs + tmpfs                        │"
echo "  │  Watchdog:  PID $WATCHDOG_PID (timeout: ${AIRLOCK_SESSION_TIMEOUT}s)             │"
echo "  │                                                              │"
echo "  │  When done: Ctrl+C or let Claude exit naturally              │"
echo "  │  Then run:  ./airlock-extract.sh $CONTAINER_NAME"
echo "  │                                                              │"
echo "  └──────────────────────────────────────────────────────────────┘"
echo ""

# ══════════════════════════════════════════════════════════════════════
# PHASE 5: Attach to Claude session
# ══════════════════════════════════════════════════════════════════════
docker attach "$CONTAINER_NAME"

# ── Post-session ──────────────────────────────────────────────────────
# We get here when Claude exits or user detaches
echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "  Airlock session ended: $SESSION_ID"
echo ""

# Check if container is still running (user may have detached vs Claude exiting)
if docker inspect --format='{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null | grep -q true; then
    echo "  Container still running (you detached)."
    echo "  Re-attach:  docker attach $CONTAINER_NAME"
    echo "  Extract:    ./airlock-extract.sh $CONTAINER_NAME"
    echo "  Kill:       ./airlock-kill.sh $CONTAINER_NAME"
else
    echo "  Claude session exited."
    echo "  Extract changes: ./airlock-extract.sh $CONTAINER_NAME"
fi
echo "════════════════════════════════════════════════════════════════════"
