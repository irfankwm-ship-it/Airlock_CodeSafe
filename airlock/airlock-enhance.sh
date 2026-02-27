#!/usr/bin/env bash
# airlock-enhance.sh — Clone, quarantine, scan, and approve Claude enhancements
# Safe pipeline: nothing enters airlock without human review and explicit approval.
#
# Workflow:
#   1. clone   — git clone into quarantine, run automated scan
#   2. review  — human reads the code (manual step)
#   3. approve — mark as safe, record hash for tamper detection
#   4. list    — show all enhancements and their status
#   5. revoke  — remove approval (re-review needed)
#   6. remove  — delete an enhancement entirely
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=airlock.conf
source "$SCRIPT_DIR/airlock.conf"

ENHANCE_DIR="$AIRLOCK_STATE_DIR/enhancements"
mkdir -p "$ENHANCE_DIR"

usage() {
    echo "Usage: $0 <command> [args]"
    echo ""
    echo "Commands:"
    echo "  clone <github-url> [name]   Clone an enhancement into quarantine"
    echo "  scan <name>                 Re-run security scan on an enhancement"
    echo "  approve <name>              Mark enhancement as reviewed and approved"
    echo "  revoke <name>               Revoke approval (requires re-review)"
    echo "  remove <name>               Delete an enhancement entirely"
    echo "  list                        Show all enhancements and status"
    echo "  inspect <name>              Show file tree and scan results"
    echo ""
    echo "Example:"
    echo "  $0 clone https://github.com/obra/superpowers"
    echo "  # ... read the code ..."
    echo "  $0 approve superpowers"
    echo "  ./airlock-launch.sh airlock-base:latest ~/projects/my-app"
    exit 1
}

[ $# -lt 1 ] && usage

# ── Security scan ─────────────────────────────────────────────────────
# Automated scan is a TRIP WIRE, not a shield. It catches obvious issues.
# Human review is the primary defense.
scan_enhancement() {
    local name="$1"
    local dir="$ENHANCE_DIR/$name/repo"
    local scan_file="$ENHANCE_DIR/$name/scan-report.txt"

    echo "==> Scanning $name for security concerns..."
    echo "Scan report for: $name" > "$scan_file"
    echo "Date: $(date -Iseconds)" >> "$scan_file"
    echo "Directory: $dir" >> "$scan_file"
    echo "========================================" >> "$scan_file"

    local findings=0

    # 1. Executable files (hooks, scripts)
    echo "" >> "$scan_file"
    echo "--- Executable files ---" >> "$scan_file"
    local exec_files
    exec_files=$(find "$dir" -type f \( -executable -o -name "*.sh" -o -name "*.py" -o -name "*.js" -o -name "*.ts" \) 2>/dev/null | head -50 || true)
    if [ -n "$exec_files" ]; then
        echo "$exec_files" >> "$scan_file"
        exec_count=$(echo "$exec_files" | wc -l)
        echo "  Found $exec_count executable/script files"
        findings=$((findings + 1))
    else
        echo "  (none)" >> "$scan_file"
    fi

    # 2. Hook files (these run automatically)
    echo "" >> "$scan_file"
    echo "--- Hook files (auto-execute on events) ---" >> "$scan_file"
    local hook_files
    hook_files=$(find "$dir" -type f \( -name "hooks.json" -o -path "*/hooks/*" \) 2>/dev/null | head -20 || true)
    if [ -n "$hook_files" ]; then
        echo "!! ATTENTION: Hooks run automatically during Claude Code sessions !!" >> "$scan_file"
        echo "$hook_files" >> "$scan_file"
        # Show hook content
        for hf in $hook_files; do
            echo "" >> "$scan_file"
            echo "  Content of $hf:" >> "$scan_file"
            cat -v "$hf" >> "$scan_file" 2>/dev/null || true
        done
        echo "  Found hook files — these execute automatically!"
        findings=$((findings + 1))
    else
        echo "  (none)" >> "$scan_file"
    fi

    # 3. Network-related code
    echo "" >> "$scan_file"
    echo "--- Network calls in code ---" >> "$scan_file"
    local net_patterns="fetch\(|XMLHttpRequest|require.*http|require.*net|urllib|requests\.\(get\|post\)|aiohttp|socket\.connect|curl|wget|npm.*install|npx "
    local net_hits
    net_hits=$(grep -rlP "$net_patterns" "$dir" --include="*.js" --include="*.ts" --include="*.py" --include="*.sh" 2>/dev/null | head -20 || true)
    if [ -n "$net_hits" ]; then
        echo "!! Files containing network calls:" >> "$scan_file"
        echo "$net_hits" >> "$scan_file"
        for nf in $net_hits; do
            echo "" >> "$scan_file"
            echo "  In $nf:" >> "$scan_file"
            grep -nP "$net_patterns" "$nf" 2>/dev/null | head -10 >> "$scan_file" || true
        done
        echo "  Found network call patterns in code!"
        findings=$((findings + 1))
    else
        echo "  (none)" >> "$scan_file"
    fi

    # 4. Dynamic code execution
    echo "" >> "$scan_file"
    echo "--- Dynamic code execution ---" >> "$scan_file"
    local exec_patterns="eval\(|exec\(|__import__|subprocess|os\.system|os\.popen|child_process|spawn\(|Function\("
    local exec_hits
    exec_hits=$(grep -rlP "$exec_patterns" "$dir" --include="*.js" --include="*.ts" --include="*.py" 2>/dev/null | head -20 || true)
    if [ -n "$exec_hits" ]; then
        echo "!! Files with dynamic execution:" >> "$scan_file"
        echo "$exec_hits" >> "$scan_file"
        for ef in $exec_hits; do
            echo "" >> "$scan_file"
            echo "  In $ef:" >> "$scan_file"
            grep -nP "$exec_patterns" "$ef" 2>/dev/null | head -10 >> "$scan_file" || true
        done
        echo "  Found dynamic execution patterns!"
        findings=$((findings + 1))
    else
        echo "  (none)" >> "$scan_file"
    fi

    # 5. Symlinks (potential escape vector in sandboxed mount)
    echo "" >> "$scan_file"
    echo "--- Symlinks ---" >> "$scan_file"
    local symlinks
    symlinks=$(find "$dir" -type l 2>/dev/null | head -20 || true)
    if [ -n "$symlinks" ]; then
        echo "Symlinks found (verify targets are within repo):" >> "$scan_file"
        for sl in $symlinks; do
            target=$(readlink -f "$sl" 2>/dev/null || echo "BROKEN")
            echo "  $sl -> $target" >> "$scan_file"
        done
        echo "  Found symlinks — verify targets are safe"
        findings=$((findings + 1))
    else
        echo "  (none)" >> "$scan_file"
    fi

    # 6. Secret-looking patterns
    echo "" >> "$scan_file"
    echo "--- Potential secrets ---" >> "$scan_file"
    local secret_patterns="sk-ant-|AKIA[0-9A-Z]|ghp_[a-zA-Z0-9]|BEGIN.*PRIVATE KEY|password\s*=\s*['\"][^'\"]+['\"]"
    local secret_hits
    secret_hits=$(grep -rlP "$secret_patterns" "$dir" 2>/dev/null | grep -v '\.git/' | head -10 || true)
    if [ -n "$secret_hits" ]; then
        echo "!! Potential secrets found:" >> "$scan_file"
        echo "$secret_hits" >> "$scan_file"
        echo "  WARNING: Potential secrets found in enhancement!"
        findings=$((findings + 1))
    else
        echo "  (none)" >> "$scan_file"
    fi

    # 7. File type summary
    echo "" >> "$scan_file"
    echo "--- File type summary ---" >> "$scan_file"
    find "$dir" -type f -not -path '*/.git/*' | sed 's/.*\.//' | sort | uniq -c | sort -rn | head -20 >> "$scan_file" 2>/dev/null || true

    # 8. Total file count and size
    local file_count
    file_count=$(find "$dir" -type f -not -path '*/.git/*' | wc -l)
    local total_size
    total_size=$(du -sh "$dir" --exclude='.git' 2>/dev/null | cut -f1)
    echo "" >> "$scan_file"
    echo "--- Summary ---" >> "$scan_file"
    echo "Total files (excl .git): $file_count" >> "$scan_file"
    echo "Total size (excl .git): $total_size" >> "$scan_file"
    echo "Findings: $findings categories flagged" >> "$scan_file"

    echo "" >> "$scan_file"
    if [ "$findings" -gt 0 ]; then
        echo "VERDICT: $findings concern(s) flagged. REVIEW BEFORE APPROVING." >> "$scan_file"
        echo ""
        echo "  Scan complete: $findings concern(s) flagged."
        echo "  Review report: cat $scan_file"
    else
        echo "VERDICT: No automated concerns found. Still review manually." >> "$scan_file"
        echo ""
        echo "  Scan complete: no automated concerns found."
    fi

    echo "  Full report: $scan_file"
}

# ── Clone command ─────────────────────────────────────────────────────
cmd_clone() {
    local url="${1:-}"
    [ -z "$url" ] && { echo "ERROR: provide a GitHub URL" >&2; usage; }

    # Derive name from URL
    local name="${2:-$(basename "$url" .git)}"
    local dest="$ENHANCE_DIR/$name"

    if [ -d "$dest" ]; then
        echo "ERROR: enhancement '$name' already exists at $dest" >&2
        echo "  Remove first: $0 remove $name" >&2
        exit 1
    fi

    echo "==> Cloning $url into quarantine as '$name'"
    mkdir -p "$dest"

    # Clone with depth 1 (we don't need history)
    git clone --depth 1 "$url" "$dest/repo"

    # Record metadata
    cat > "$dest/metadata.env" << EOF
NAME=$name
URL=$url
CLONED=$(date -Iseconds)
STATUS=quarantined
APPROVED=
HASH=
EOF

    echo "  Cloned to: $dest/repo"
    echo ""

    # Auto-scan
    scan_enhancement "$name"

    echo ""
    echo "  Next steps:"
    echo "    1. Review the code:     ls $dest/repo"
    echo "    2. Read scan report:    cat $dest/scan-report.txt"
    echo "    3. When satisfied:      $0 approve $name"
}

# ── Approve command ───────────────────────────────────────────────────
cmd_approve() {
    local name="${1:-}"
    [ -z "$name" ] && { echo "ERROR: provide enhancement name" >&2; usage; }

    local dest="$ENHANCE_DIR/$name"
    [ ! -d "$dest/repo" ] && { echo "ERROR: enhancement '$name' not found" >&2; exit 1; }

    # Check scan report exists
    if [ ! -f "$dest/scan-report.txt" ]; then
        echo "  No scan report found. Running scan first..."
        scan_enhancement "$name"
    fi

    local hash

    echo "==> Approving enhancement: $name"
    echo ""
    echo "  By approving, you confirm:"
    echo "    - You have reviewed the code in $dest/repo"
    echo "    - You have read the scan report at $dest/scan-report.txt"
    echo "    - You accept any hooks, scripts, and executable code"
    echo ""
    read -rp "  Type 'approve' to confirm: " confirm
    if [ "$confirm" != "approve" ]; then
        echo "  Cancelled."
        exit 1
    fi

    # Resolve symlinks to prevent escape from mount (BEFORE hashing)
    echo "  Resolving symlinks..."
    find "$dest/repo" -type l | while read -r link; do
        target=$(readlink -f "$link")
        # Check if target is within the repo
        if [[ "$target" != "$dest/repo"* ]]; then
            echo "  WARNING: Removing external symlink: $link -> $target"
            rm "$link"
        else
            # Replace symlink with copy of target (handle both files and dirs)
            rm "$link"
            if [ -d "$target" ]; then
                cp -r "$target" "$link"
            else
                cp "$target" "$link"
            fi
        fi
    done

    # Compute hash AFTER symlink resolution (so hash matches final state)
    hash=$(find "$dest/repo" -type f -not -path '*/.git/*' -exec sha256sum {} \; | sort | sha256sum | cut -d' ' -f1)
    echo "  Content hash: $hash"

    # Update metadata
    sed -i "s/^STATUS=.*/STATUS=approved/" "$dest/metadata.env"
    sed -i "s/^APPROVED=.*/APPROVED=$(date -Iseconds)/" "$dest/metadata.env"
    sed -i "s/^HASH=.*/HASH=$hash/" "$dest/metadata.env"

    echo ""
    echo "  Enhancement '$name' APPROVED."
    echo "  It will be available in your next airlock session."
}

# ── Revoke command ────────────────────────────────────────────────────
cmd_revoke() {
    local name="${1:-}"
    [ -z "$name" ] && { echo "ERROR: provide enhancement name" >&2; usage; }

    local dest="$ENHANCE_DIR/$name"
    [ ! -d "$dest" ] && { echo "ERROR: enhancement '$name' not found" >&2; exit 1; }

    sed -i "s/^STATUS=.*/STATUS=quarantined/" "$dest/metadata.env"
    sed -i "s/^APPROVED=.*/APPROVED=/" "$dest/metadata.env"
    sed -i "s/^HASH=.*/HASH=/" "$dest/metadata.env"

    echo "  Approval revoked for '$name'. Re-review and re-approve to use."
}

# ── Remove command ────────────────────────────────────────────────────
cmd_remove() {
    local name="${1:-}"
    [ -z "$name" ] && { echo "ERROR: provide enhancement name" >&2; usage; }

    local dest="$ENHANCE_DIR/$name"
    [ ! -d "$dest" ] && { echo "ERROR: enhancement '$name' not found" >&2; exit 1; }

    read -rp "  Remove '$name' entirely? (yes/no): " confirm
    if [ "$confirm" = "yes" ]; then
        rm -rf "$dest"
        echo "  Enhancement '$name' removed."
    else
        echo "  Cancelled."
    fi
}

# ── List command ──────────────────────────────────────────────────────
cmd_list() {
    echo "Airlock Enhancements:"
    echo ""

    local found=false
    for meta in "$ENHANCE_DIR"/*/metadata.env; do
        [ ! -f "$meta" ] && continue
        found=true

        local name url status approved hash
        name=$(grep '^NAME=' "$meta" | cut -d= -f2)
        url=$(grep '^URL=' "$meta" | cut -d= -f2)
        status=$(grep '^STATUS=' "$meta" | cut -d= -f2)
        approved=$(grep '^APPROVED=' "$meta" | cut -d= -f2)
        hash=$(grep '^HASH=' "$meta" | cut -d= -f2)

        # Tamper check for approved enhancements
        local tamper_note=""
        if [ "$status" = "approved" ] && [ -n "$hash" ]; then
            current_hash=$(find "$ENHANCE_DIR/$name/repo" -type f -not -path '*/.git/*' -exec sha256sum {} \; | sort | sha256sum | cut -d' ' -f1)
            if [ "$current_hash" != "$hash" ]; then
                tamper_note=" !! HASH MISMATCH — TAMPERED !!"
                # Auto-revoke
                sed -i "s/^STATUS=.*/STATUS=tampered/" "$meta"
                status="tampered"
            fi
        fi

        if [ "$status" = "approved" ]; then
            printf "  [APPROVED]    %-25s %s\n" "$name" "$url"
            [ -n "$approved" ] && printf "                Approved: %s\n" "$approved"
        elif [ "$status" = "tampered" ]; then
            printf "  [TAMPERED!]   %-25s %s\n" "$name" "$url"
            printf "                %s\n" "$tamper_note"
        else
            printf "  [QUARANTINED] %-25s %s\n" "$name" "$url"
        fi
    done

    if [ "$found" = false ]; then
        echo "  (none)"
        echo ""
        echo "  Get started: $0 clone https://github.com/obra/superpowers"
    fi
}

# ── Inspect command ───────────────────────────────────────────────────
cmd_inspect() {
    local name="${1:-}"
    [ -z "$name" ] && { echo "ERROR: provide enhancement name" >&2; usage; }

    local dest="$ENHANCE_DIR/$name"
    [ ! -d "$dest/repo" ] && { echo "ERROR: enhancement '$name' not found" >&2; exit 1; }

    echo "==> Enhancement: $name"
    echo ""

    if [ -f "$dest/metadata.env" ]; then
        echo "--- Metadata ---"
        cat "$dest/metadata.env"
        echo ""
    fi

    echo "--- File tree (excl .git) ---"
    find "$dest/repo" -not -path '*/.git/*' -not -path '*/.git' | head -80 | sed "s|$dest/repo/||" | sort
    echo ""

    if [ -f "$dest/scan-report.txt" ]; then
        echo "--- Scan Report ---"
        cat "$dest/scan-report.txt"
    else
        echo "  No scan report. Run: $0 scan $name"
    fi
}

# ── Scan command ──────────────────────────────────────────────────────
cmd_scan() {
    local name="${1:-}"
    [ -z "$name" ] && { echo "ERROR: provide enhancement name" >&2; usage; }

    local dest="$ENHANCE_DIR/$name"
    [ ! -d "$dest/repo" ] && { echo "ERROR: enhancement '$name' not found" >&2; exit 1; }

    scan_enhancement "$name"
}

# ── Route commands ────────────────────────────────────────────────────
case "${1:-}" in
    clone)   shift; cmd_clone "$@" ;;
    scan)    shift; cmd_scan "$@" ;;
    approve) shift; cmd_approve "$@" ;;
    revoke)  shift; cmd_revoke "$@" ;;
    remove)  shift; cmd_remove "$@" ;;
    list)    cmd_list ;;
    inspect) shift; cmd_inspect "$@" ;;
    *)       usage ;;
esac
