# Airlock

A hardened Docker sandbox for running AI coding agents in a sealed, network-isolated container. The AI gets full autonomy inside the box. Nothing leaves without human review and cryptographic approval.

Designed for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) with `--dangerously-skip-permissions`, but works with any AI coding tool (Aider, Codex, etc.) via the configurable `AIRLOCK_AI_COMMAND`.

## Quick Start

```bash
# 1. Run the setup wizard
cd airlock/
./airlock-setup.sh

# 2. Build the base image
./airlock-build.sh Dockerfile.base airlock-base:latest

# 3. Launch a session
./airlock-launch.sh airlock-base:latest ~/projects/my-app

# 4. Work with Claude (you're attached to the session)

# 5. When done, extract changes
./airlock-extract.sh airlock-<session-id>

# 6. Emergency kill (from a second terminal)
./airlock-kill.sh airlock-<session-id>
```

For a detailed walkthrough, see [QUICKSTART.md](QUICKSTART.md).

## Image Contract

Any Docker image used with Airlock must satisfy these 5 points:

| # | Requirement |
|---|-------------|
| 1 | User `claude` exists with UID 1000 |
| 2 | `/workspace/project` directory exists, owned by `claude` |
| 3 | `entrypoint.sh` copied to `/usr/local/bin/` and set as `ENTRYPOINT` |
| 4 | Entrypoint touches `/tmp/.key-loaded` as readiness signal |
| 5 | Entrypoint execs `$AIRLOCK_AI_COMMAND` (default: `claude --dangerously-skip-permissions`) |

Authentication is handled via mounted credentials or environment variables at runtime, not baked into the image. See `Dockerfile.example` for a minimal template and `Dockerfile.base` for a batteries-included dev environment.

## Security Architecture

### 8 Defense Layers

| Layer | Implementation |
|-------|---------------|
| Network isolation | `--network none` at launch, iptables whitelist for configured API domains only |
| Read-only filesystem | `--read-only` rootfs, tmpfs for `/tmp` and `/home/claude` |
| Capability dropping | `--cap-drop ALL`, `no-new-privileges` |
| Syscall filtering | Whitelist-only seccomp profile (~155 allowed syscalls) |
| AppArmor | `docker-default` mandatory access control |
| Resource limits | Memory, PID, CPU, and file descriptor caps |
| IPv6 disabled | Entire stack disabled to prevent rule bypass |
| DNS blocked | `--dns 0.0.0.0` with pre-resolved `--add-host` entries |

### Extraction Pipeline

Changes never flow back automatically. The extraction process:

1. **Pause** the container (TOCTOU protection)
2. **Scan** for symlinks, ANSI escapes, secrets, dangerous patterns
3. **Hash-lock** all staged files (SHA-256)
4. **Generate diff** for human review
5. **Human reviews** every line of the diff
6. **Ed25519 signature** (passphrase-protected key = human present)
7. **TOCTOU recheck** (verify nothing changed since review)
8. **Diff-only sync** (only reviewed files copied, no host files deleted)

### Anomaly Detection

A host-side watchdog monitors every session — invisible and unstoppable from inside the container:

- Memory usage, PID count, blocked connections, file creation bursts
- Strike system with decay (5 strikes = auto-kill)
- Periodic checkpoints for forensic breadcrumbs
- Hard session timeout (default: 4 hours)

## Authentication

Airlock supports two auth methods:

**Option A — OAuth credentials file** (Claude Max subscription):
```bash
# Authenticate on the host first
claude    # complete login flow → creates ~/.claude/.credentials.json
# Airlock mounts it into the container automatically
```

**Option B — API key** (any provider):
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
./airlock-launch.sh airlock-base:latest ~/projects/my-app
```

When `ANTHROPIC_API_KEY` is set, no credentials file is needed.

## Configuration

All settings in `airlock.conf`. Key options support environment variable overrides:

| Variable | Default | Override Env Var |
|----------|---------|-----------------|
| `AIRLOCK_AI_COMMAND` | `claude --dangerously-skip-permissions` | `AIRLOCK_AI_COMMAND` |
| `AIRLOCK_API_DOMAINS` | `api.anthropic.com platform.claude.com` | Edit `airlock.conf` |
| `AIRLOCK_CREDENTIALS_HOST` | `~/.claude/.credentials.json` | `AIRLOCK_CREDENTIALS_HOST` |
| `AIRLOCK_API_KEY` | (unset) | `ANTHROPIC_API_KEY` |
| `AIRLOCK_SIGNING_KEY` | `~/.ssh/id_ed25519` | `AIRLOCK_SIGNING_KEY` |
| `AIRLOCK_SECCOMP_PROFILE` | `<install-dir>/seccomp-profile.json` | `AIRLOCK_SECCOMP_PROFILE` |
| `AIRLOCK_BASE_DIR` | Auto-detected from conf location | `AIRLOCK_BASE_DIR` |
| `AIRLOCK_MEMORY` | `4g` | Edit `airlock.conf` |
| `AIRLOCK_SESSION_TIMEOUT` | `14400` (4h) | Edit `airlock.conf` |

See `airlock.conf` for the complete list with descriptions.

## Using Other AI Tools

Airlock defaults to Claude Code but works with any AI coding tool:

```bash
# Example: Aider with OpenAI
export AIRLOCK_AI_COMMAND="aider --yes"
export ANTHROPIC_API_KEY=""  # clear if set
# Edit airlock.conf: AIRLOCK_API_DOMAINS="api.openai.com"
# Build an image with aider installed instead of claude
./airlock-build.sh Dockerfile.custom airlock-aider:latest
./airlock-launch.sh airlock-aider:latest ~/projects/my-app
```

To use a different AI tool, you need to:
1. Set `AIRLOCK_AI_COMMAND` to the command to exec inside the container
2. Update `AIRLOCK_API_DOMAINS` in `airlock.conf` to your provider's API domain
3. Build an image with your AI tool installed (the tool's binary must be on PATH)
4. Pass the appropriate auth (env var or credentials file)

See `airlock.conf` for the complete list with descriptions.

## Enhancement System

Airlock supports loading pre-approved enhancements (custom commands, hooks, skills, CLAUDE.md instructions) into the container at launch time. Enhancements are:

1. Ingested and verified with `airlock-enhance.sh`
2. Stored in `~/.airlock/enhancements/`
3. Mounted read-only into the container
4. Loaded by the entrypoint into Claude's config

See [USER-MANUAL.md](USER-MANUAL.md) for details.

## Documentation

| File | Content |
|------|---------|
| [QUICKSTART.md](QUICKSTART.md) | 5-minute getting started guide |
| [USER-MANUAL.md](USER-MANUAL.md) | Complete operational guide |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Technical reference and design decisions |
| [SECURITY.md](SECURITY.md) | Threat model and security design |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute |

## Command Reference

| Command | Purpose |
|---------|---------|
| `./airlock-setup.sh` | First-time setup wizard |
| `./airlock-build.sh <dockerfile> <image>` | Build + verify image |
| `./airlock-launch.sh <image> <project>` | Launch sandboxed session |
| `./airlock-extract.sh <container>` | Review + sign + sync changes |
| `./airlock-kill.sh <container>` | Emergency kill |
| `./airlock-kill.sh --list` | List running sessions |
| `./airlock-enhance.sh <source>` | Ingest an enhancement |

## License

[MIT](../LICENSE)
