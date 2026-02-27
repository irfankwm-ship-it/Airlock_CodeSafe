# Airlock Quickstart

Get from zero to a sandboxed AI coding session in 5 minutes.

## Prerequisites

- **Docker** installed and running (`docker run --rm hello-world` should work)
- **sudo access** (needed for network firewall rules)
- **Authentication** — one of:
  - **OAuth credentials** (`~/.claude/.credentials.json`) — run `claude` on the host and complete the login flow
  - **API key** — `export ANTHROPIC_API_KEY="sk-ant-..."` in your shell

## Step 1: Run the Setup Wizard

```bash
cd airlock/
./airlock-setup.sh
```

The wizard will:
- Check that Docker, sudo, dig, and ssh-keygen are available
- Detect your authentication (OAuth credentials file or `ANTHROPIC_API_KEY`)
- Generate an Ed25519 signing key if you don't have one
- Create the `~/.airlock/` state directories
- Set up the `allowed_signers` file for extraction signing

## Step 2: Build an Image

Build the batteries-included dev image:

```bash
./airlock-build.sh Dockerfile.base airlock-base:latest
```

This takes a few minutes on first build. It installs Python 3.12, Node.js 22, Claude Code, linters, formatters, and common dev tools.

For a minimal image (just Node.js + Claude Code), use `Dockerfile.example` instead.

The build script verifies the image satisfies the [5-point contract](README.md#image-contract) and stores its hash for tamper detection.

## Step 3: Launch a Session

```bash
./airlock-launch.sh airlock-base:latest ~/projects/my-app
```

Replace `~/projects/my-app` with the path to your project.

The launch script:
1. Sanitizes your project (strips secrets, `.git/`, `node_modules/`, etc.)
2. Starts a hardened container with no network
3. Injects firewall rules (configured API domains only)
4. Connects the network and waits for readiness
5. Starts a watchdog and attaches you to the AI session

You'll see the **AIRLOCK ACTIVE** banner with session details, then the AI's interface.

## Step 4: Work Inside the Sandbox

You're now inside a sandboxed session. The AI has full autonomy within the container but:
- Can only reach the configured API endpoints (all other network traffic is dropped)
- Cannot access your host filesystem
- Cannot escalate privileges
- Is monitored by a host-side watchdog

Work normally. When done, press `Ctrl+C` or let the AI exit naturally.

## Step 5: Extract Changes

After the session ends, the script prints the container name. Extract your changes:

```bash
./airlock-extract.sh airlock-<session-id>
```

The extraction pipeline:
1. Pauses the container
2. Runs automated security scans
3. Generates a diff for your review
4. Waits for you to type `approve` after reading the diff
5. Signs the approved changes with your SSH key
6. Syncs only the changed files back to your project

**Read the diff carefully.** The automated scanner is a trip wire, not a shield.

## Step 6: Emergency Kill (If Needed)

If something goes wrong, open a second terminal and kill the session:

```bash
# List running sessions
./airlock-kill.sh --list

# Kill a specific session
./airlock-kill.sh airlock-<session-id>

# Kill all sessions
./airlock-kill.sh --all
```

The kill switch runs on the host — the container cannot prevent or delay it.

## Using a Different AI Tool

Airlock defaults to Claude Code but supports any AI coding tool:

```bash
export AIRLOCK_AI_COMMAND="aider --yes"
# Edit airlock.conf: AIRLOCK_API_DOMAINS="api.openai.com"
# Build an image with your tool installed
./airlock-build.sh Dockerfile.custom airlock-custom:latest
./airlock-launch.sh airlock-custom:latest ~/projects/my-app
```

See the [README](README.md#using-other-ai-tools) for full details.

## Next Steps

- Read [USER-MANUAL.md](USER-MANUAL.md) for the complete operational guide
- Read [SECURITY.md](SECURITY.md) to understand the threat model
- Create [per-project allowlists](USER-MANUAL.md#12-project-allowlists) for fine-grained file control
- Build custom images with your preferred tools (just satisfy the 5-point contract)
