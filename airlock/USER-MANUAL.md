# Airlock User Manual

## 1. What is Airlock

Airlock is a security wrapper that runs AI coding agents (Claude Code, Aider, Codex, etc.) inside a locked-down Docker container. Your project files go in, the AI works on them in isolation with no internet access except configured API endpoints, and nothing comes back out until you personally review and approve every change. Think of it as a clean room for AI-assisted coding.

## 2. Prerequisites

Before you begin, make sure you have the following:

- **Docker** installed and working. Verify with:

  ```
  docker run --rm hello-world
  ```

- **An Ed25519 SSH key** at `~/.ssh/id_ed25519`. This is used to cryptographically sign approved extractions. Generate one if you do not have it:

  ```
  ssh-keygen -t ed25519 -C "airlock"
  ```

- **Authentication** — one of the following:

  - **OAuth credentials file** at `~/.claude/.credentials.json`. This file comes from authenticating Claude Code with a Max subscription. If the file does not exist, install Claude Code on the host, run `claude`, and complete the login flow.

  - **API key** via environment variable. Set `ANTHROPIC_API_KEY` (or the appropriate key for your AI provider) before launching. When an API key is set, no credentials file is needed.

- **sudo access**. Airlock uses `sudo nsenter` and `sudo iptables` to apply firewall rules inside the container's network namespace. You will be prompted for your password during launch.

## 3. First-Time Setup

### 3.1 Create state directories

Airlock stores image hashes, session logs, and allowlists under `~/.airlock/`. Create the directory structure:

```
mkdir -p ~/.airlock/hashes
mkdir -p ~/.airlock/sessions
mkdir -p ~/.airlock/allowlists
```

### 3.2 Set up allowed_signers for extraction signing

The extraction pipeline verifies your SSH signature against an `allowed_signers` file. Create it:

```
echo "airlock-user $(cat ~/.ssh/id_ed25519.pub)" > ~/.airlock/allowed_signers
```

This tells the verification step to trust your public key under the identity `airlock-user`.

### 3.3 Build your first image

```
cd /path/to/airlock
./airlock-build.sh Dockerfile.base airlock-base:latest
```

This does three things:

1. Builds the Docker image from the specified Dockerfile (with `--no-cache` for reproducibility).
2. Stores the image hash in `~/.airlock/hashes/airlock-base-latest.hash`.
3. Runs contract verification to confirm the image has the correct user, directories, entrypoint, and Claude binary.

You should see output ending with:

```
==> Build complete. All contract checks passed.
    Image: airlock-base:latest
    Hash:  sha256:abc123...
```

If any contract check fails, the build aborts with an error.

## 4. Building Images

### 4.1 Standard build

```
./airlock-build.sh <dockerfile> <image-name>
```

Example:

```
./airlock-build.sh Dockerfile.base airlock-base:latest
```

The Dockerfile must be in the Airlock directory (where the scripts live). The build always uses `--no-cache`.

### 4.2 Verify-only mode

To re-verify an existing image without rebuilding it:

```
./airlock-build.sh _ airlock-base:latest --verify-only
```

The first argument (Dockerfile) is ignored in this mode -- use `_` as a placeholder. This is useful for auditing images you built in the past.

### 4.3 Creating custom Dockerfiles

Your Dockerfile must satisfy the **image contract**. All five points are mandatory:

1. A user named `claude` exists with UID 1000.
2. The directory `/workspace/project` exists and is owned by `claude`.
3. `entrypoint.sh` is copied to `/usr/local/bin/entrypoint.sh` and set as the `ENTRYPOINT`.
4. The entrypoint touches `/tmp/.key-loaded` as a readiness signal.
5. The entrypoint execs `$AIRLOCK_AI_COMMAND` (default: `claude --dangerously-skip-permissions`).

See `Dockerfile.example` for a minimal template. See `Dockerfile.base` for a batteries-included dev image with Python, Node.js, dev tools, and bash audit logging.

Authentication is never baked into the image. Credentials are bind-mounted or passed via environment variables at runtime.

## 5. Launching a Session

### 5.1 Command

```
./airlock-launch.sh <image-name> <project-path>
```

Example:

```
./airlock-launch.sh airlock-base:latest ~/projects/my-app
```

### 5.2 What happens during launch

The launch script runs through five phases:

**Phase 0 -- Pre-flight checks.** Verifies the image exists, its hash matches the stored hash, authentication is present (credentials file or API key), configured API domains resolve, the project path exists, and the concurrent session limit has not been reached. Creates an internal Docker network.

**Phase 1 -- Sanitize project.** Copies your project into a temporary staging directory. Strips secrets (`.env`, `.pem`, `.key`, etc.), removes non-essential files (`.git/`, `node_modules/`, `__pycache__/`), and runs pattern-based secret scanning. If a critical secret pattern is found (API keys, private keys), the launch aborts.

**Phase 2 -- Launch container.** Starts the container with `--network none` (no network at all), a read-only root filesystem, tmpfs for `/tmp` and `/home/claude`, all capabilities dropped, a seccomp whitelist, AppArmor, resource limits (memory, CPU, PID, file descriptor limits), and IPv6 disabled.

**Phase 3 -- Apply firewall.** Uses `sudo nsenter` to inject iptables rules into the container's network namespace. The OUTPUT chain default policy is DROP. Only TCP 443 to resolved API domain IPs (configured in `AIRLOCK_API_DOMAINS`) is allowed. All other outbound traffic is logged and dropped.

**Phase 4 -- Connect network and wait.** Connects the container to the internal Docker network (firewall is already active at this point). Waits for the readiness signal (`/tmp/.key-loaded`). Starts the watchdog process. Saves session metadata.

### 5.3 The AIRLOCK ACTIVE banner

After all phases complete, the screen clears and you see:

```
  +--------------------------------------------------------------+
  |                                                                |
  |                    AIRLOCK ACTIVE                              |
  |                                                                |
  |  Session:   20260227-143000-12345                              |
  |  Image:     airlock-base:latest                               |
  |  Project:   my-app                                             |
  |                                                                |
  |  Firewall:  Configured API domains only (TCP 443)               |
  |  Seccomp:   Whitelist-only (185 syscalls)                      |
  |  Filesystem: Read-only rootfs + tmpfs                          |
  |  Watchdog:  PID 54321 (timeout: 14400s)                        |
  |                                                                |
  |  When done: Ctrl+C or let Claude exit naturally                |
  |  Then run:  ./airlock-extract.sh airlock-20260227-143000-12345 |
  |                                                                |
  +--------------------------------------------------------------+
```

You are now attached to the AI session inside the container.

## 6. Working Inside Airlock

### 6.1 What works

- The AI coding tool operates normally. You interact with it exactly as you would on the host.
- Your project files are available at `/workspace/project` inside the container.
- The AI can read, edit, create, and delete files within the project.
- Tools installed in the image (git, python3, ripgrep, etc.) are available.

### 6.2 What does not work

- **No internet access** except configured API domains on TCP 443. All other outbound connections are dropped and logged.
- **No access to the host filesystem** beyond the mounted project staging directory and read-only credentials.
- **No privilege escalation.** All Linux capabilities are dropped, `no-new-privileges` is set, and a seccomp whitelist blocks unauthorized syscalls.
- **Changes stay inside the container.** Nothing is synced back to your real project until you explicitly extract and approve.

### 6.3 Ending a session

When you are done, either:

- Let Claude exit naturally (type `/exit` or similar).
- Press `Ctrl+C` to stop Claude.
- Detach from the container with `Ctrl+P, Ctrl+Q` (the container keeps running).

After the session ends, the script prints instructions for extraction.

## 7. Extracting Changes

Extraction is the gate between the sandbox and your real files. Nothing leaves the container without your review and cryptographic signature.

### 7.1 Run the extraction script

```
./airlock-extract.sh airlock-<session-id>
```

The container name is printed in the AIRLOCK ACTIVE banner and in the post-session output. Example:

```
./airlock-extract.sh airlock-20260227-143000-12345
```

### 7.2 What happens during extraction

**Phase 6A -- Capture audit logs.** Saves container logs and bash history.

**Phase 6B -- Pause container.** Freezes the container so no further changes can be made during review (TOCTOU protection).

**Phase 6C -- Security checks.** Scans staged files for symlinks (possible escape) and ANSI escape sequences (possible terminal injection). If either is found, extraction aborts.

**Phase 6D -- Hash-lock.** Computes SHA-256 hashes of all staged files and records the overall hash.

**Phase 6E -- Generate diff.** Produces a unified diff between your original project and the staged (modified) files. The diff is saved to the session log directory. New files are listed separately.

**Phase 6F -- Automated scan.** Runs pattern matching for secrets, private keys, network imports (Python, JS/TS), and dynamic execution patterns. Runs AST analysis on Python files. These are trip wires, not guarantees -- your manual review is the primary defense.

### 7.3 Reviewing the diff

The script pauses and displays:

```
  HUMAN REVIEW REQUIRED

  Diff file:     ~/.airlock/sessions/<id>/changes.diff
  Diff lines:    42
  Overall hash:  a1b2c3...

  Open diff:     less ~/.airlock/sessions/<id>/changes.diff
  Open in editor: vim ~/.airlock/sessions/<id>/changes.diff
```

Open a second terminal and review the diff. Read every line. When satisfied, return to the extraction terminal and type `approve`.

If you type anything other than `approve`, extraction is cancelled. The container remains paused. You can unpause it with `docker unpause <container-name>` or destroy it.

### 7.4 Signing with your SSH key

After you type `approve`, the script signs the diff file with your Ed25519 key:

```
ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n airlock-approval changes.diff
```

You will be prompted for your SSH key passphrase. This creates a cryptographic proof that you, specifically, approved these changes.

The signature is then verified against your `allowed_signers` file. If verification fails, extraction aborts.

### 7.5 Final TOCTOU check and sync

The script re-hashes all staged files. If any hash changed since the review (the container was paused, so this should not happen), extraction aborts.

Only changed and new files are synced to your real project directory. No files are deleted from the host. The container, network, watchdog, and staging directory are cleaned up.

## 8. Emergency: Killing a Session

If something goes wrong, you need to kill the session from **outside** the container. You cannot run `airlock-kill.sh` from inside the container.

### 8.1 Detach first

If you are attached to the container, detach with:

```
Ctrl+P, Ctrl+Q
```

Or open a second terminal.

### 8.2 List running sessions

```
./airlock-kill.sh --list
```

This shows all running airlock containers with their status and project.

### 8.3 Kill a specific session

```
./airlock-kill.sh airlock-<session-id>
```

Example:

```
./airlock-kill.sh airlock-20260227-143000-12345
```

This destroys the container, its network, and the watchdog. Staged files are removed. Session logs are preserved for forensics. No files are synced to your project.

### 8.4 Kill all sessions

```
./airlock-kill.sh --all
```

### 8.5 Scorched earth

```
./airlock-kill.sh --all --purge
```

This kills all sessions AND deletes all session logs. Use this only when you want to destroy all evidence of past sessions.

## 9. Command Reference

| Command | What it does | Example | When to use |
|---------|-------------|---------|-------------|
| `./airlock-build.sh <dockerfile> <image>` | Build an image and verify its contract | `./airlock-build.sh Dockerfile.base airlock-base:latest` | Before your first launch, or after changing a Dockerfile |
| `./airlock-build.sh _ <image> --verify-only` | Re-verify an existing image without rebuilding | `./airlock-build.sh _ airlock-base:latest --verify-only` | Auditing an image you built previously |
| `./airlock-launch.sh <image> <project>` | Launch a sandboxed AI session | `./airlock-launch.sh airlock-base:latest ~/projects/my-app` | Starting work on a project |
| `./airlock-extract.sh <container>` | Review, sign, and sync changes back to your project | `./airlock-extract.sh airlock-20260227-143000-12345` | After a session ends, to get your changes out |
| `./airlock-kill.sh <container>` | Emergency kill a specific session | `./airlock-kill.sh airlock-20260227-143000-12345` | Something is wrong, abort immediately |
| `./airlock-kill.sh --list` | List all running airlock sessions | `./airlock-kill.sh --list` | Finding the container name to kill or extract |
| `./airlock-kill.sh --all` | Kill all running sessions | `./airlock-kill.sh --all` | Nuclear option |
| `./airlock-kill.sh --all --purge` | Kill all sessions and delete all logs | `./airlock-kill.sh --all --purge` | Complete cleanup, destroy all forensic data |
| `./airlock-sanitize.sh <project> <output>` | Copy a project with secret stripping (called by launch) | `./airlock-sanitize.sh ~/projects/my-app /tmp/staged` | Normally not called directly; used internally by launch |
| `./airlock-watchdog.sh <container> <staged> <logdir>` | Monitor a session for anomalies (called by launch) | (started automatically) | Never called directly; runs as a background process |

## 10. Configuration Reference

All settings are in `airlock.conf`. Every airlock script sources this file. No secrets are stored here -- credentials are referenced by path only.

### Paths

| Variable | Default | Description |
|----------|---------|-------------|
| `AIRLOCK_BASE_DIR` | `$HOME/airlock` | Root directory containing airlock scripts |
| `AIRLOCK_STATE_DIR` | `$HOME/.airlock` | State directory for hashes, sessions, allowlists |
| `AIRLOCK_SESSION_DIR` | `$HOME/.airlock/sessions` | Per-session log storage |
| `AIRLOCK_IMAGE_HASH_DIR` | `$HOME/.airlock/hashes` | Stored image hashes (one file per image) |
| `AIRLOCK_ALLOWLISTS_DIR` | `$HOME/.airlock/allowlists` | Per-project file allowlists |

### Resource Limits

| Variable | Default | Description |
|----------|---------|-------------|
| `AIRLOCK_MEMORY` | `4g` | Container memory limit |
| `AIRLOCK_CPUS` | `2` | CPU core limit |
| `AIRLOCK_PIDS_LIMIT` | `256` | Maximum number of processes inside the container |
| `AIRLOCK_NOFILE` | `1024` | Maximum open file descriptors |
| `AIRLOCK_TMPFS_TMP_SIZE` | `2g` | Size of tmpfs mounted at `/tmp` |
| `AIRLOCK_TMPFS_HOME_SIZE` | `1g` | Size of tmpfs mounted at `/home/claude` |

### Timeouts

| Variable | Default | Description |
|----------|---------|-------------|
| `AIRLOCK_SESSION_TIMEOUT` | `14400` (4 hours) | Maximum session duration in seconds; watchdog kills the container after this |
| `AIRLOCK_CHECKPOINT_INTERVAL` | `300` (5 minutes) | How often the watchdog takes a snapshot of container state |
| `AIRLOCK_KEY_LOAD_TIMEOUT` | `10` | Seconds to wait for the readiness signal before aborting launch |

### Network

| Variable | Default | Description |
|----------|---------|-------------|
| `AIRLOCK_DNS_SERVERS` | `1.1.1.1 8.8.8.8 9.9.9.9` | DNS servers used to resolve the API domain during pre-flight |
| `AIRLOCK_API_DOMAINS` | `api.anthropic.com` | Domains allowed through the firewall |
| `AIRLOCK_API_PORT` | `443` | Destination port allowed through the firewall |

### Security

| Variable | Default | Description |
|----------|---------|-------------|
| `AIRLOCK_SIGNING_KEY` | `$HOME/.ssh/id_ed25519` | Ed25519 private key used to sign approved extractions |
| `AIRLOCK_ALLOWED_SIGNERS` | `$HOME/.airlock/allowed_signers` | SSH allowed_signers file for signature verification |
| `AIRLOCK_SECCOMP_PROFILE` | `$HOME/airlock/seccomp-profile.json` | Seccomp whitelist profile applied to the container |

### Credentials and Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `AIRLOCK_CREDENTIALS_HOST` | `$HOME/.claude/.credentials.json` | Host path to OAuth credentials file (Option A) |
| `AIRLOCK_API_KEY` | (unset) | Set via `ANTHROPIC_API_KEY` env var (Option B). When set, credentials file is not required. |
| `AIRLOCK_CREDENTIALS_MOUNT` | `/run/credentials/.credentials.json` | Mount point inside the container (outside tmpfs) |
| `AIRLOCK_CREDENTIALS_CONTAINER` | `/home/claude/.claude/.credentials.json` | Where the entrypoint symlinks credentials to |

### Sessions

| Variable | Default | Description |
|----------|---------|-------------|
| `AIRLOCK_MAX_CONCURRENT` | `2` | Maximum number of simultaneous airlock sessions |
| `AIRLOCK_LOG_RETENTION_DAYS` | `30` | Session logs older than this are purged during extraction cleanup |
| `AIRLOCK_CONTAINER_PREFIX` | `airlock` | Prefix for container and network names |

### Anomaly Detection

| Variable | Default | Description |
|----------|---------|-------------|
| `AIRLOCK_MAX_STRIKES` | `5` | Strikes before auto-kill; a clean check decays one strike |
| `AIRLOCK_ANOMALY_MEM_PCT` | `90` | Memory usage percent that triggers a strike |
| `AIRLOCK_ANOMALY_PID_PCT` | `80` | PID usage percent that triggers a strike |
| `AIRLOCK_ANOMALY_BLOCKED_CONNS` | `20` | Blocked outbound connections per check interval that trigger a strike |
| `AIRLOCK_ANOMALY_FILE_BURST` | `200` | New files per check interval that trigger a strike |
| `AIRLOCK_FW_LOG_PREFIX` | `AIRLOCK-BLOCKED:` | Prefix in iptables LOG rules; used to parse dmesg for blocked connections |

### AI Command

| Variable | Default | Description |
|----------|---------|-------------|
| `AIRLOCK_AI_COMMAND` | `claude --dangerously-skip-permissions` | Command the entrypoint execs inside the container. Override for other AI tools (e.g., `aider --yes`). The binary must be installed in the image. |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `TEST_PORT` | (unset) | Uncomment and set to forward a port (e.g., `8080`) on localhost for testing |

## 11. Troubleshooting

### "sudo: a password is required"

Airlock needs sudo for `nsenter` and `iptables`. Run the launch script from an interactive terminal where you can enter your password. If you are running from a script or cron, configure passwordless sudo for the specific commands or run interactively.

### "image hash mismatch"

The image on disk does not match the hash stored during the last build. This can happen if someone rebuilt the image outside of airlock, or if you pulled a new version. Fix it by rebuilding:

```
./airlock-build.sh Dockerfile.base airlock-base:latest
```

### "no authentication found"

Neither a credentials file nor an API key was detected. Fix with one of:

**Option A — OAuth credentials** (Claude Code):
```
npm install -g @anthropic-ai/claude-code
claude
```
Complete the login flow. This creates `~/.claude/.credentials.json` automatically.

**Option B — API key:**
```
export ANTHROPIC_API_KEY="sk-ant-..."
./airlock-launch.sh airlock-base:latest ~/projects/my-app
```

### "readiness signal not received"

The container started but the entrypoint did not create `/tmp/.key-loaded` within the timeout (default: 10 seconds). Debug with:

```
docker logs airlock-<session-id>
```

Common causes: credentials file is malformed, the entrypoint script was not copied correctly, or the image does not satisfy the contract. Re-run `./airlock-build.sh` with `--verify-only` to check.

### Container killed by watchdog

The watchdog auto-kills the container after `AIRLOCK_SESSION_TIMEOUT` seconds (default: 4 hours) or after `AIRLOCK_MAX_STRIKES` anomaly strikes. Check the anomaly log:

```
cat ~/.airlock/sessions/<session-id>/anomaly.log
```

If timeout is the issue, increase `AIRLOCK_SESSION_TIMEOUT` in `airlock.conf`. If anomaly strikes are the issue, check what triggered them -- high memory, too many processes, blocked connections, or file creation bursts.

### Seccomp violations

If Claude or its tools crash with "operation not permitted" errors, a required syscall may be blocked by the seccomp profile. Check the kernel log:

```
dmesg | grep seccomp
```

The output shows which syscall was blocked and by which PID. If the syscall is legitimate, add it to `seccomp-profile.json` and rebuild the image.

### Extraction aborted: symlinks detected

The automated security check found symlinks in the staged directory. Symlinks can point outside the sandbox. Inspect them manually:

```
find /tmp/airlock-staged-<id>* -type l -ls
```

If they are safe, this is a limitation of the automated check. You can destroy the container and manually copy the files you need.

### Extraction aborted: ANSI escape sequences

Files containing raw ANSI escape codes (e.g., `\x1b[...`) were detected. These can be used for terminal injection attacks. Inspect the flagged files manually. If the escapes are benign (e.g., in test fixtures), this is a false positive. Destroy the container and manually copy the files.

## 12. Project Allowlists

By default, the sanitization step copies common source file types (`.py`, `.js`, `.ts`, `.json`, `.yaml`, etc.) and excludes secrets and junk. For finer control, create a per-project allowlist.

### 12.1 Creating an allowlist

Create a file at `~/.airlock/allowlists/<project-name>.allowlist`, where `<project-name>` matches the basename of your project directory. For a project at `~/projects/my-app`, create:

```
~/.airlock/allowlists/my-app.allowlist
```

### 12.2 Allowlist format

The file contains rsync filter patterns, one per line. Lines starting with `#` are comments. Blank lines are ignored. Only files matching these patterns will be included; everything else is excluded.

Example allowlist:

```
# Include Python source and configs
src/***
tests/***
*.py
pyproject.toml
setup.cfg

# Include documentation
docs/***
README.md

# Include specific config files
.flake8
mypy.ini
```

The dangerous file patterns (`.env`, `.pem`, `.key`, `.ssh/`, etc.) are always stripped regardless of your allowlist.

### 12.3 When no allowlist exists

If no allowlist file is found for the project, the sanitizer uses a built-in default list that includes common source code extensions (Python, JavaScript, TypeScript, Go, Rust, Java, C/C++, Ruby, PHP, etc.) and common config files (Dockerfile, Makefile, package.json, requirements.txt, etc.).

## 13. Tips

- **Always have a second terminal ready.** You cannot run `airlock-kill.sh` from inside the container. Before launching a session, open a second terminal window. If anything goes wrong, use it to run the kill switch.

- **Review diffs carefully.** The automated scanner in Phase 6F is a trip wire, not a shield. It catches obvious patterns like leaked API keys and known dangerous function calls. It does not catch sophisticated attacks. Read every line of the diff yourself.

- **Use --verify-only to audit old images.** If you have not rebuilt in a while, run `./airlock-build.sh _ airlock-base:latest --verify-only` to confirm the image still passes all contract checks and the stored hash still matches.

- **Keep sessions short.** The default timeout is 4 hours. Shorter sessions mean smaller diffs, which are easier to review. If you have a large task, break it into smaller sessions.

- **Check the anomaly log after each session.** Even if nothing went wrong, `~/.airlock/sessions/<id>/anomaly.log` tells you what the watchdog observed. Unusual patterns in blocked connections or resource usage are worth investigating.

- **One project per session.** Each launch is tied to one project directory. Do not try to work on multiple projects in one session.

- **Credentials are read-only.** If using OAuth, the credentials file is bind-mounted read-only. The AI cannot modify it, and it is mounted at `/run/credentials/` which is separate from the tmpfs at `/home/claude`. If using an API key, it is passed as an environment variable.

- **Rebuild after updating your AI tool.** If you update the AI tool (e.g., `@anthropic-ai/claude-code` npm package), you need to rebuild your image to get the new version inside the container:

  ```
  ./airlock-build.sh Dockerfile.base airlock-base:latest
  ```

- **Session logs are your audit trail.** Each session creates a directory under `~/.airlock/sessions/` containing docker logs, anomaly logs, checkpoints, diffs, signatures, and scan results. These are retained for 30 days by default (configurable via `AIRLOCK_LOG_RETENTION_DAYS`).
