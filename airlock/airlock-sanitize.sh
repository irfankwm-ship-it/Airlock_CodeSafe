#!/usr/bin/env bash
# airlock-sanitize.sh — Phase 1: allowlist-based project copy + secret scanning
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=airlock.conf
source "$SCRIPT_DIR/airlock.conf"

usage() {
    echo "Usage: $0 <project-path> <output-dir>"
    exit 1
}

[ $# -lt 2 ] && usage

PROJECT_PATH="$1"
OUTPUT_DIR="$2"

if [ ! -d "$PROJECT_PATH" ]; then
    echo "ERROR: project path '$PROJECT_PATH' does not exist" >&2
    exit 1
fi

PROJECT_NAME="$(basename "$PROJECT_PATH")"
ALLOWLIST_FILE="$AIRLOCK_ALLOWLISTS_DIR/$PROJECT_NAME.allowlist"

# ── Prepare output ─────────────────────────────────────────────────────
mkdir -p "$OUTPUT_DIR"

# ── Build rsync filter rules ──────────────────────────────────────────
FILTER_FILE=$(mktemp)
trap 'rm -f "$FILTER_FILE"' EXIT

# Always strip these regardless of allowlist
cat > "$FILTER_FILE" << 'STRIP'
- .git/
- .git
- .env
- .env.*
- *.pem
- *.key
- *.p12
- *.pfx
- .ssh/
- .gnupg/
- .bash_history
- .zsh_history
- .python_history
- .node_repl_history
- .npmrc
- .pypirc
- .docker/
- node_modules/
- __pycache__/
- .vscode/
- .idea/
- .DS_Store
- *.swp
- *.swo
STRIP

if [ -f "$ALLOWLIST_FILE" ]; then
    echo "==> Using project allowlist: $ALLOWLIST_FILE"
    # Add allowlist includes, then deny everything else
    while IFS= read -r pattern || [ -n "$pattern" ]; do
        # Skip comments and blank lines
        [[ "$pattern" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${pattern// /}" ]] && continue
        echo "+ $pattern" >> "$FILTER_FILE"
    done < "$ALLOWLIST_FILE"
    echo "- *" >> "$FILTER_FILE"
else
    echo "==> No allowlist found, using default extensions"
    # Default: common source file extensions
    cat >> "$FILTER_FILE" << 'DEFAULT'
+ */
+ *.py
+ *.js
+ *.ts
+ *.tsx
+ *.jsx
+ *.json
+ *.yaml
+ *.yml
+ *.toml
+ *.cfg
+ *.ini
+ *.sh
+ *.bash
+ *.md
+ *.txt
+ *.rst
+ *.html
+ *.css
+ *.scss
+ *.sql
+ *.go
+ *.rs
+ *.java
+ *.c
+ *.h
+ *.cpp
+ *.hpp
+ *.rb
+ *.php
+ *.swift
+ *.kt
+ *.scala
+ *.r
+ *.R
+ *.ipynb
+ *.xml
+ *.proto
+ *.graphql
+ *.tf
+ *.hcl
+ Makefile
+ Dockerfile
+ Dockerfile.*
+ docker-compose*.yml
+ Cargo.toml
+ Cargo.lock
+ package.json
+ package-lock.json
+ requirements.txt
+ pyproject.toml
+ setup.py
+ setup.cfg
+ go.mod
+ go.sum
+ Gemfile
+ Gemfile.lock
+ tsconfig*.json
+ .eslintrc*
+ .prettierrc*
+ .gitignore
- *
DEFAULT
fi

# ── Copy via rsync ─────────────────────────────────────────────────────
echo "==> Copying sanitized project to $OUTPUT_DIR"
rsync -a --filter="merge $FILTER_FILE" "$PROJECT_PATH/" "$OUTPUT_DIR/"

# ── Secret scanning ───────────────────────────────────────────────────
echo "==> Scanning for residual secrets..."

CRITICAL_PATTERNS=(
    'sk-ant-[a-zA-Z0-9]'
    'AKIA[0-9A-Z]{16}'
    'ghp_[a-zA-Z0-9]{36}'
    'gho_[a-zA-Z0-9]{36}'
    'github_pat_[a-zA-Z0-9]'
    'xox[bpors]-[a-zA-Z0-9]'
    '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'
    '-----BEGIN PGP PRIVATE KEY BLOCK-----'
)

WARN_PATTERNS=(
    'api[_-]?key\s*[:=]\s*["\x27][a-zA-Z0-9]'
    'password\s*[:=]\s*["\x27][^\x27"]{8,}'
    'secret\s*[:=]\s*["\x27][a-zA-Z0-9]'
    'token\s*[:=]\s*["\x27][a-zA-Z0-9]'
)

FOUND_CRITICAL=0
FOUND_WARN=0

for pattern in "${CRITICAL_PATTERNS[@]}"; do
    MATCHES=$(grep -rlP "$pattern" "$OUTPUT_DIR" 2>/dev/null || true)
    if [ -n "$MATCHES" ]; then
        echo "  CRITICAL: pattern '$pattern' found in:" >&2
        echo "$MATCHES" | sed 's/^/    /' >&2
        FOUND_CRITICAL=$((FOUND_CRITICAL + 1))
    fi
done

for pattern in "${WARN_PATTERNS[@]}"; do
    MATCHES=$(grep -rlPi "$pattern" "$OUTPUT_DIR" 2>/dev/null || true)
    if [ -n "$MATCHES" ]; then
        echo "  WARNING: pattern '$pattern' found in:" >&2
        echo "$MATCHES" | sed 's/^/    /' >&2
        FOUND_WARN=$((FOUND_WARN + 1))
    fi
done

# ── Fix ownership ─────────────────────────────────────────────────────
chown -R 1000:1000 "$OUTPUT_DIR"

# ── Result ─────────────────────────────────────────────────────────────
FILE_COUNT=$(find "$OUTPUT_DIR" -type f | wc -l)
echo "==> Sanitized: $FILE_COUNT files copied"

if [ "$FOUND_CRITICAL" -gt 0 ]; then
    echo "ABORT: $FOUND_CRITICAL critical secret pattern(s) found. Fix source project." >&2
    exit 1
fi

if [ "$FOUND_WARN" -gt 0 ]; then
    echo "WARNING: $FOUND_WARN low-confidence pattern(s) found. Review before proceeding."
fi

echo "==> Sanitization complete."
