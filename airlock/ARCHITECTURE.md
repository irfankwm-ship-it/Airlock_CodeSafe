# Airlock Architecture

Technical reference for the Airlock sandboxed execution system.

Last updated: 2026-02-27

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Security Model](#2-security-model)
3. [Phase Architecture](#3-phase-architecture)
4. [Anomaly Detection](#4-anomaly-detection)
5. [Image Contract](#5-image-contract)
6. [Data Flow Diagram](#6-data-flow-diagram)
7. [Trust Boundaries](#7-trust-boundaries)
8. [Kill Chain](#8-kill-chain)
9. [File Reference](#9-file-reference)
10. [Known Limitations and Trade-offs](#10-known-limitations-and-trade-offs)

---

## 1. System Overview

Airlock is a hardened sandbox for running AI coding agents inside Docker
containers. It is designed for Claude Code but supports any AI tool via
the configurable `AIRLOCK_AI_COMMAND`. The core principle:

> The AI gets full autonomy inside a sealed box. Nothing leaves without
> human review and cryptographic approval.

The AI operates with full permissions inside the container (e.g., Claude
Code with `--dangerously-skip-permissions`), meaning it can read, write,
and execute anything within the sandbox. But the sandbox is hermetically
sealed: the network is firewalled to configured API domains only (TCP
443), the filesystem is read-only except for tmpfs mounts, syscalls are
filtered to a whitelist, and all Linux capabilities are dropped.

When the session ends, output does not flow back to the host automatically.
Instead, the container is paused, its files are security-scanned, a diff
is generated for human review, and only after the human signs the diff
with an Ed25519 key are the changed files synced back. A TOCTOU recheck
ensures nothing changed between review and sync.

Airlock is not a single script. It is a phased pipeline of seven scripts
plus a configuration file, a seccomp profile, and an entrypoint, each
responsible for a specific stage of the lifecycle.

---

## 2. Security Model

Airlock uses layered defense. No single layer is the complete defense;
they overlap so that a bypass of one layer is contained by the next.

### 2.1 Container Isolation (Namespaces and Cgroups)

Docker provides PID, network, mount, UTS, and IPC namespace isolation.
The container process cannot see host processes, host filesystem, or host
network interfaces. Cgroups enforce resource limits (see 2.6).

### 2.2 Network Firewall

The container starts with `--network none` (Phase 2). A dedicated
internal Docker network is created per session. Before the network is
connected, host-side iptables rules are injected into the container's
network namespace via `nsenter` (Phase 3). This eliminates any timing
window where the container has unfiltered network access.

Firewall rules:

- **Default OUTPUT policy**: DROP
- **Allowed**: Loopback, ESTABLISHED/RELATED (return traffic), and
  explicit per-IP rules for resolved `AIRLOCK_API_DOMAINS` IPs on TCP 443
- **IPv6**: OUTPUT policy DROP, loopback only
- **DNS**: Blocked. `--dns 0.0.0.0` prevents DNS resolution from inside.
  API hostnames are injected via `--add-host` flags using IPs
  resolved at launch time from multiple DNS servers (1.1.1.1, 8.8.8.8,
  9.9.9.9).
- **Logging**: All blocked packets are logged with `iptables -j LOG`
  using the prefix `AIRLOCK-BLOCKED:` before the final DROP. This feeds
  the anomaly detection system via dmesg.

### 2.3 Syscall Filtering (Seccomp)

A custom seccomp profile (`seccomp-profile.json`) uses a whitelist-only
approach:

- **Default action**: `SCMP_ACT_ERRNO` (return error code 1 for any
  unlisted syscall)
- **Architecture**: x86_64 (with x86 and x32 sub-architectures)
- **Allowed syscalls**: ~155 syscalls organized into categories:
  - File I/O (open, read, write, stat, rename, mkdir, symlink, etc.)
  - File descriptors and polling (dup, fcntl, epoll, inotify, etc.)
  - Directory listing (getdents, getdents64)
  - Memory management (mmap, mprotect, munmap, brk, mremap, etc.)
  - Process lifecycle (clone, fork, execve, exit, wait4, etc.)
  - Process info (getpid, getuid, prctl, sched_*, prlimit64, etc.)
  - Signals (kill, tgkill, rt_sigaction, rt_sigprocmask, etc.)
  - Networking (socket, connect, bind, listen, send, recv, etc.)
  - Pipe and I/O (pipe, splice, sendfile, ioctl, etc.)
  - Time (clock_gettime, nanosleep, timer_*, etc.)
  - Random (getrandom)
  - System info (uname, sysinfo, statfs)
  - Runtime support (futex, rseq, umask)

Notably absent: `mount`, `umount`, `ptrace`, `reboot`, `kexec_load`,
`init_module`, `finit_module`, `bpf`, `perf_event_open`, `userfaultfd`,
`keyctl`, `request_key`, `add_key`, `pivot_root`, `chroot`,
`unshare`, `setns`, and all other dangerous syscalls.

### 2.4 Capability Dropping

```
--cap-drop ALL
--security-opt no-new-privileges
```

All 41 Linux capabilities are dropped. `no-new-privileges` prevents any
process inside the container from gaining new privileges through setuid
binaries, capability bits, or other escalation vectors.

### 2.5 Filesystem Hardening

- **Read-only root filesystem**: `--read-only` flag. The container cannot
  write to any part of the image filesystem.
- **tmpfs for /tmp**: `rw,nosuid,size=2g,uid=1000,gid=1000`. Writable
  scratch space, size-capped, owned by claude user.
- **tmpfs for /home/claude**: `rw,exec,size=1g,uid=1000,gid=1000`.
  The home directory is ephemeral and rebuilt each session. The `exec`
  flag is needed because Claude Code's Node.js runtime may write and
  execute from here.
- **Credentials via /run/credentials** (OAuth mode): The host credentials
  file is bind-mounted read-only at `/run/credentials/.credentials.json`.
  The entrypoint symlinks it into `/home/claude/.claude/` on the tmpfs.
  This keeps credentials outside the writable tmpfs and read-only.
  Alternatively, API key auth passes `ANTHROPIC_API_KEY` as an env var
  (no file mount needed).
- **Project files via /workspace/project**: The sanitized staged
  directory is bind-mounted read-write so the AI can modify project files.

### 2.6 Resource Limits

| Resource         | Limit   | Config Key              |
|------------------|---------|-------------------------|
| Memory           | 4 GB    | `AIRLOCK_MEMORY`        |
| PIDs             | 256     | `AIRLOCK_PIDS_LIMIT`    |
| CPUs             | 2       | `AIRLOCK_CPUS`          |
| Open files       | 1024    | `AIRLOCK_NOFILE`        |
| /tmp size        | 2 GB    | `AIRLOCK_TMPFS_TMP_SIZE`|
| /home/claude size| 1 GB    | `AIRLOCK_TMPFS_HOME_SIZE`|

### 2.7 AppArmor

The `docker-default` AppArmor profile is applied via
`--security-opt apparmor=docker-default`. This provides mandatory access
control on top of the other layers.

### 2.8 IPv6 Disabled

```
--sysctl net.ipv6.conf.all.disable_ipv6=1
```

IPv6 is disabled at the kernel level inside the container, with a
corresponding ip6tables DROP policy as a belt-and-suspenders measure.

---

## 3. Phase Architecture

Airlock operates in seven numbered phases across three scripts
(launch, extract, kill).

### Phase 0: Pre-flight (`airlock-launch.sh`)

Checks performed before any container is created:

1. **Concurrent session check** -- counts running `airlock-*` containers
   and aborts if the count meets or exceeds `AIRLOCK_MAX_CONCURRENT` (2).
2. **Image existence** -- verifies the Docker image is present locally.
3. **Image hash verification** -- compares the current image ID against
   the stored hash in `~/.airlock/hashes/<image-name>.hash`. Mismatch
   aborts with a tampering warning.
4. **Auth check** -- verifies either a credentials file exists or
   `ANTHROPIC_API_KEY` is set.
5. **DNS resolution** -- resolves `AIRLOCK_API_DOMAINS` using three DNS
   servers (1.1.1.1, 8.8.8.8, 9.9.9.9), deduplicates the IPs.
6. **Project path validation** -- confirms the project directory exists.
7. **Session directory creation** -- creates `~/.airlock/sessions/<id>/`.
8. **Network creation** -- creates a per-session internal Docker network
   (`airlock-net-<session-id>`).

### Phase 1: Sanitization (`airlock-sanitize.sh`)

Copies the host project into a temporary staged directory with two
layers of filtering:

1. **Hardcoded strip list** -- Always removes: `.git/`, `.env`, `*.pem`,
   `*.key`, `*.p12`, `*.pfx`, `.ssh/`, `.gnupg/`, shell histories,
   `.npmrc`, `.pypirc`, `.docker/`, `node_modules/`, `__pycache__/`,
   IDE configs, `.DS_Store`, swap files.

2. **Allowlist or default extensions** -- If a project-specific allowlist
   exists at `~/.airlock/allowlists/<project>.allowlist`, only those
   patterns are included. Otherwise, a default list of ~50 common source
   file extensions is used. Either way, everything not explicitly included
   is excluded (`- *`).

3. **Secret scanning** -- Scans the staged output for critical patterns
   (Anthropic API keys, AWS keys, GitHub tokens, Slack tokens, private
   key headers) and warning patterns (generic `api_key=`, `password=`,
   `secret=`, `token=` assignments). Critical matches abort. Warnings
   are printed but do not block.

4. **Ownership fix** -- All staged files are chowned to 1000:1000
   (the claude user inside the container).

### Phase 2: Container Launch (`airlock-launch.sh`)

The container is started with `docker run -d` and the full hardening
flag set:

- `--network none` (no network at all yet)
- `--user 1000:1000`
- `--cap-drop ALL`
- `--security-opt no-new-privileges`
- `--security-opt seccomp=<profile>`
- `--security-opt apparmor=docker-default`
- `--read-only`
- tmpfs mounts for `/tmp` and `/home/claude`
- `--sysctl net.ipv6.conf.all.disable_ipv6=1`
- Memory, PID, CPU, and file descriptor limits
- `--dns 0.0.0.0` (blocks DNS)
- `--add-host` entries for pre-resolved Anthropic IPs
- Bind mounts for staged project (rw) and credentials (ro)
- Session labels for metadata tracking

### Phase 3: Firewall (`airlock-launch.sh`)

Firewall rules are injected from the host into the container's network
namespace using `sudo nsenter -t <PID> -n iptables`. This is a
host-side operation -- the container process cannot interfere.

Rules installed:

```
IPv4:
  OUTPUT policy DROP
  ACCEPT on loopback
  ACCEPT ESTABLISHED,RELATED
  ACCEPT dst <each-api-domain-ip> tcp dport 443
  LOG prefix "AIRLOCK-BLOCKED:" level 4

IPv6:
  OUTPUT policy DROP
  ACCEPT on loopback
  LOG prefix "AIRLOCK-BLOCKED:" level 4
```

Rule count is verified programmatically after installation.

### Phase 4: Network Connect + Readiness (`airlock-launch.sh`)

The per-session Docker network is connected to the container only after
the firewall rules are in place. This is the critical ordering that
eliminates the timing window:

```
Phase 2: Container starts with --network none    (no network)
Phase 3: Firewall rules injected via nsenter      (rules ready)
Phase 4: docker network connect                   (network live, rules active)
```

The script then polls for the readiness signal (`/tmp/.key-loaded`),
which the entrypoint touches after symlinking credentials into place.
Timeout is configurable (default 10 seconds).

The watchdog is started as a background process. Session metadata is
saved to `session.env`.

### Phase 5: Attach (`airlock-launch.sh`)

`docker attach` connects the user's terminal to the Claude session
inside the container. Claude is already running (started by the
entrypoint). The user interacts with Claude normally.

When Claude exits or the user detaches (Ctrl+P, Ctrl+Q), control
returns to the launch script, which prints post-session instructions.

### Phase 6: Extraction Security Checks (`airlock-extract.sh`)

Triggered manually by the user after the session. Sub-phases:

- **6A -- Audit log capture**: Docker logs and bash audit log
  (`/tmp/audit.log`) are saved to the session directory, piped through
  `cat -v` to neutralize any ANSI sequences.

- **6B -- Container pause**: `docker pause` freezes all processes in the
  container. From this point, the container cannot modify files. This is
  the TOCTOU anchor -- all subsequent reads are against a frozen
  filesystem.

- **6C -- Security checks**:
  - **Symlink check**: `find -type l` on the staged directory. Any
    symlinks are flagged as potential escape attempts (a symlink could
    point outside the staged dir). Aborts extraction.
  - **ANSI escape check**: `grep -rlP '\x1b'` on staged files. ANSI
    sequences in source files may be terminal injection attempts
    (crafting malicious display during `less` or `cat` review). Aborts
    extraction.

- **6D -- Hash-lock**: Computes SHA-256 of every file in the staged
  directory, then computes a SHA-256 of the hash manifest itself. This
  overall hash becomes the integrity anchor for the TOCTOU recheck.

- **6E -- Diff generation**: `diff -ruN` between the original project
  and the staged directory. Output is piped through `cat -v`. New files
  (present in staged but not original) are listed separately. Large
  diffs (>500 lines) trigger a warning.

- **6F -- Automated scanning**: Pattern-based and AST-based analysis.
  Explicitly described as a "trip wire, NOT shield" -- it catches obvious
  issues but is not the primary defense (human review is).
  - **Secret patterns**: Anthropic keys, AWS keys, GitHub tokens, private
    key headers.
  - **Network imports**: Python (`urllib`, `requests`, `socket`, `http`,
    `aiohttp`, `httpx`) and JS/TS (`http`, `https`, `net`, `dgram`,
    `dns`, `fetch`, `XMLHttpRequest`).
  - **Dynamic execution**: Python `exec()`, `eval()`, `subprocess`,
    `os.system()`, `__import__()`.
  - **AST analysis**: Python files are parsed with `ast.parse()` to
    detect calls to `exec`, `eval`, `__import__`, `getattr`, `compile`
    with line numbers. Best-effort; skipped if python3 is unavailable.

### Phase 7: Human-Gated Sync (`airlock-extract.sh`)

- **7A -- Human review**: The diff file path, line count, overall hash,
  and scan results are presented. The user is prompted to type `approve`.
  Any other input cancels extraction. The container remains paused.

- **7B -- Ed25519 signature**: `ssh-keygen -Y sign` signs the diff file
  with the user's Ed25519 key (configured in `AIRLOCK_SIGNING_KEY`).
  This requires the key passphrase, ensuring a human is present. The
  signature is immediately verified against `allowed_signers`.

- **7C -- TOCTOU recheck**: The staged file hashes are recomputed and
  compared against the hash from Phase 6D. If they differ, extraction
  aborts. Since the container is paused, a mismatch here would indicate
  either a bug or external tampering.

- **7D -- Diff-only sync**: Only files that appear in the diff are
  copied to the original project. Files are never deleted from the host.
  If diff parsing yields no files, a fallback compares per-file SHA-256
  hashes to find modified and new files.

- **7E -- Cleanup**: Watchdog process is killed. Container is destroyed
  (`docker rm -f`). Per-session network is removed. Staged directory is
  deleted. Session metadata is updated with completion timestamp and
  sync count. Old session logs beyond the retention period (30 days)
  are purged.

---

## 4. Anomaly Detection

The watchdog (`airlock-watchdog.sh`) runs on the host as a background
process. It is started by the launch script and cannot be stopped,
influenced, or even detected from inside the container.

### 4.1 Detection Signals

All four signals are read from the host side:

| Signal              | Source                  | Threshold            |
|---------------------|-------------------------|----------------------|
| Memory usage        | `docker stats`          | >90% of limit        |
| PID count           | `docker stats`          | >80% of limit (204+) |
| Blocked connections | `dmesg` + LOG prefix    | >20 per check        |
| File creation burst | `find` on staged dir    | >200 new files/check |

### 4.2 Strike System

- Each anomaly detection adds one strike.
- A completely clean check round decays one strike (self-healing for
  transient spikes).
- At 5 strikes (`AIRLOCK_MAX_STRIKES`), the container is automatically
  killed.
- Multiple anomalies in a single round accumulate independently (e.g.,
  high memory + blocked connections = 2 strikes in one round).

### 4.3 Auto-Kill

When max strikes are reached:

1. Final forensics are captured (docker stats, last 50 log lines, recent
   dmesg entries matching the firewall prefix).
2. `docker kill` terminates the container immediately.
3. Exit reason is recorded as `ANOMALY_KILL: N strikes`.

### 4.4 Session Timeout

Independent of the strike system, the watchdog enforces a hard session
timeout (default 4 hours / 14400 seconds). When reached, the container
is killed and exit reason is recorded as `TIMEOUT`.

### 4.5 Checkpoints

Every 5 minutes (`AIRLOCK_CHECKPOINT_INTERVAL`), the watchdog saves:

- Workspace file listing with timestamps and sizes
- Incremental Docker logs
- Bash audit log from inside the container
- Resource usage snapshot
- Current strike count

These checkpoints provide forensic breadcrumbs even if the session ends
abnormally.

### 4.6 Host-Side Guarantee

The watchdog runs as a regular host process (started by the launch
script with `&`). From inside the container:

- The watchdog PID is not visible (PID namespace isolation).
- The watchdog cannot be signaled (it is outside the container).
- The dmesg log cannot be cleared (the container has no capabilities).
- The docker stats API cannot be blocked (it is a host-side query).
- The staged directory is a bind mount; the host sees the true
  filesystem state regardless of any mount tricks inside.

---

## 5. Image Contract

Any Docker image used with Airlock must satisfy a 5-point contract,
verified by `airlock-build.sh`:

| #  | Requirement                                      | Verification                          |
|----|--------------------------------------------------|---------------------------------------|
| 1  | `/usr/local/bin/entrypoint.sh` exists            | `docker run --entrypoint="" test -f`  |
| 2  | User `claude` exists with UID 1000              | `docker run --entrypoint="" id -u`    |
| 3  | `/workspace/project` directory exists            | `docker run --entrypoint="" test -d`  |
| 4  | AI binary on PATH (`$AIRLOCK_AI_COMMAND` first word) | `docker run --entrypoint="" which`    |
| 5  | Entrypoint touches `/tmp/.key-loaded` then execs `$AIRLOCK_AI_COMMAND` | Convention (not statically verified)  |

### 5.1 Decoupled Build/Launch Model

Image building and session launching are fully decoupled:

- `airlock-build.sh` accepts any Dockerfile and image name. It builds
  the image with `--no-cache`, stores the image hash, and runs contract
  verification.
- `airlock-launch.sh` accepts any image name and project path. It
  verifies the stored hash matches the current image before proceeding.

This means different projects can use different images (e.g., one with
Python tooling, one with Rust tooling), and images can be rebuilt
independently of sessions.

### 5.2 Per-Image Hash Verification

Image hashes are stored in `~/.airlock/hashes/` with filenames derived
from the image name (colons and slashes replaced with dashes). At launch
time, the stored hash is compared against `docker inspect --format={{.Id}}`.
A mismatch aborts with a tampering warning.

The `--verify-only` flag allows re-verifying an existing image's
contract without rebuilding.

---

## 6. Data Flow Diagram

```
HOST                                    CONTAINER
====                                    =========

~/projects/my-app/
        |
        | Phase 1: airlock-sanitize.sh
        | (allowlist copy, strip secrets, chown 1000)
        v
/tmp/airlock-staged-<id>.XXXXXX/
        |
        | Phase 2: docker run (bind mount --rw)
        |          --network none
        v
                               /workspace/project/  <-- Claude works here
                                        |
                                        | Claude reads, writes, creates,
                                        | deletes files freely
                                        |
                               /workspace/project/  (modified)
        |
        | Phase 6B: docker pause (freeze all processes)
        v
/tmp/airlock-staged-<id>.XXXXXX/  (frozen on host)
        |
        | Phase 6C: Symlink check, ANSI check
        | Phase 6D: SHA-256 hash-lock
        | Phase 6E: diff -ruN against original
        | Phase 6F: Secret scan, network import scan, AST analysis
        v
~/.airlock/sessions/<id>/changes.diff
        |
        | Phase 7A: Human reads diff
        | Phase 7B: ssh-keygen -Y sign (Ed25519 + passphrase)
        | Phase 7C: TOCTOU hash recheck
        v
        | Phase 7D: diff-only sync (cp changed files only)
        v
~/projects/my-app/  (updated)


PARALLEL (host-side):

airlock-watchdog.sh
        |
        +-- docker stats -------> memory, PIDs
        +-- dmesg --------------> blocked connections
        +-- find staged-dir ----> file burst
        |
        +-- strike/decay logic
        +-- auto-kill at threshold
        +-- periodic checkpoints to ~/.airlock/sessions/<id>/
```

---

## 7. Trust Boundaries

### Trusted

- **The host OS and kernel** -- Airlock assumes the host is not
  compromised. All enforcement (namespaces, cgroups, seccomp, iptables,
  AppArmor) is kernel-level.
- **Docker daemon** -- Assumed to correctly enforce isolation primitives.
- **The Airlock scripts themselves** -- They run as the host user (with
  sudo for nsenter/iptables). They are not inside the container.
- **The human reviewer** -- The final gate. Automated scans are "trip
  wires" only. The human reading the diff and signing with their
  passphrase-protected key is the primary defense against malicious
  output.
- **The Ed25519 signing key** -- Assumed to be passphrase-protected
  and not accessible from inside the container.
- **Configured API endpoints** -- The allowed network destinations
  (`AIRLOCK_API_DOMAINS`). Airlock assumes these are not adversarial.

### Untrusted

- **Everything inside the container** -- The AI agent, any code it writes,
  any processes it spawns, any files it creates. All of it is
  treated as potentially adversarial output.
- **The staged directory contents after a session** -- Treated as
  untrusted until reviewed and signed.
- **Network traffic from inside** -- Only whitelisted destinations are
  reachable. Everything else is dropped and logged.

### Boundary Crossings

| Crossing                     | Direction       | Gate                        |
|------------------------------|-----------------|-----------------------------|
| Project files into container | Host -> Container| Sanitization (Phase 1)      |
| Credentials into container   | Host -> Container| Read-only bind mount        |
| API traffic                  | Container -> Net | Firewall whitelist (Phase 3)|
| Modified files out           | Container -> Host| Pause + scan + review + sign (Phases 6-7) |
| Monitoring telemetry         | Container -> Host| Host-side read only (watchdog) |

---

## 8. Kill Chain

The kill switch (`airlock-kill.sh`) provides immediate, unconditional
container destruction. The container cannot prevent, delay, or
circumvent it.

### 8.1 What the Kill Does

1. Reads session metadata from container labels.
2. Kills the watchdog process (host-side `kill`).
3. Discovers and destroys the per-session Docker network.
4. Force-removes the container (`docker rm -f`).
5. Deletes the staged directory.
6. Optionally purges session logs (`--purge`).

### 8.2 What the Container Cannot Do to Prevent It

- **Cannot hide from `docker ps`** -- The container prefix is
  deterministic (`airlock-*`). Renaming is not possible from inside.
- **Cannot prevent `docker rm -f`** -- This sends SIGKILL via the
  Docker daemon, which operates outside the container's PID namespace.
  SIGKILL cannot be caught or blocked.
- **Cannot prevent `docker pause`** -- Pause uses the cgroup freezer,
  a kernel mechanism outside the container's control.
- **Cannot modify iptables rules** -- Rules are in the container's
  network namespace but applied via `nsenter` from the host. The
  container has no capabilities (`CAP_NET_ADMIN` is dropped).
- **Cannot escape the network namespace** -- `unshare` and `setns` are
  not in the seccomp whitelist.
- **Cannot kill the watchdog** -- The watchdog PID is in the host PID
  namespace, invisible and unreachable from inside.
- **Cannot write to the kill script** -- The root filesystem is
  read-only, and the kill script is on the host, not in the container.

### 8.3 Kill Modes

| Mode                    | Command                          | Effect                        |
|-------------------------|----------------------------------|-------------------------------|
| Kill one session        | `airlock-kill.sh <name>`         | Destroy container + network   |
| Kill all sessions       | `airlock-kill.sh --all`          | Destroy all airlock containers|
| Scorched earth          | `airlock-kill.sh --all --purge`  | Above + delete all session logs|
| List sessions           | `airlock-kill.sh --list`         | Show running airlock sessions |

In all kill modes, no files are synced to the host project. The staged
directory is deleted. This is a hard abort with no data extraction.

---

## 9. File Reference

| File                     | Role                                                    | Phases        |
|--------------------------|---------------------------------------------------------|---------------|
| `airlock.conf`           | Central configuration. Sourced by all scripts. Paths, limits, thresholds, credentials references (no secrets). | All |
| `entrypoint.sh`          | Container entrypoint. Sets up auth, signals readiness, execs `$AIRLOCK_AI_COMMAND`. | 2, 4 |
| `seccomp-profile.json`   | Syscall whitelist. ~155 allowed syscalls, everything else ERRNO. | 2 |
| `airlock-build.sh`       | Builds Docker image, stores hash, verifies 5-point contract. | Pre-launch |
| `airlock-sanitize.sh`    | Allowlist-based project copy + secret scanning.         | 1 |
| `airlock-launch.sh`      | Main orchestrator. Pre-flight, container launch, firewall, network connect, watchdog start, attach. | 0-5 |
| `airlock-watchdog.sh`    | Host-side anomaly detection. Memory, PIDs, blocked connections, file bursts. Strike system with decay and auto-kill. | 4 (start), runs during 5 |
| `airlock-extract.sh`     | Extraction pipeline. Pause, security checks, hash-lock, diff, automated scan, AST analysis, human review, sign, TOCTOU recheck, diff-only sync, cleanup. | 6-7 |
| `airlock-kill.sh`        | Emergency kill switch. Destroys container, network, watchdog, staged files. Optional log purge. | Any time |
| `Dockerfile.example`     | Minimal reference Dockerfile satisfying the image contract. | Build time |
| `Dockerfile.base`        | Full dev image (Node.js, Python, linters, formatters, audit logging). | Build time |

### Runtime Directories

| Path                              | Purpose                                           |
|-----------------------------------|---------------------------------------------------|
| `~/.airlock/`                     | State root                                        |
| `~/.airlock/hashes/`             | Per-image hash files                              |
| `~/.airlock/sessions/<id>/`      | Per-session logs, diffs, signatures, checkpoints  |
| `~/.airlock/allowlists/`         | Per-project file allowlists                       |
| `/tmp/airlock-staged-<id>.XXXXXX`| Temporary staged project directory (deleted on cleanup) |

---

## 10. Known Limitations and Trade-offs

### What Airlock Does NOT Protect Against

1. **Compromised host or kernel** -- If the host kernel has a container
   escape vulnerability, Airlock cannot prevent it. Airlock relies on
   kernel enforcement of namespaces, cgroups, seccomp, and iptables.

2. **Compromised Docker daemon** -- If the Docker daemon itself is
   exploited, all bets are off. Airlock does not use rootless Docker or
   gVisor/Kata containers.

3. **Side-channel attacks** -- Timing attacks, cache-based side channels,
   or speculative execution attacks from inside the container are not
   mitigated.

4. **Covert channels via the API** -- The AI can communicate freely with
   its configured API endpoints. If the API were compromised or if the AI
   encoded data in its API requests, that traffic is allowed through the
   firewall. Airlock trusts the configured API domains.

5. **Steganographic output** -- The AI could embed hidden information in
   code that looks benign (e.g., variable names encoding data, specific
   whitespace patterns, algorithmic backdoors). The automated scan
   catches obvious patterns but cannot detect semantic-level hiding.
   This is why human review is the primary defense.

6. **Human reviewer error** -- If the reviewer approves a malicious diff
   without reading it carefully, the signed files will be synced. The
   Ed25519 signature is a non-repudiation mechanism, not a content
   verification mechanism.

7. **Denial of service within the container** -- The AI can exhaust
   resources up to the configured limits (4 GB RAM, 256 PIDs, 2 CPUs).
   The watchdog will detect and kill if thresholds are exceeded, but
   the resources are consumed until then.

8. **File deletion on the host** -- Airlock never deletes host project
   files during sync. If Claude deletes a file inside the container,
   that deletion is not propagated. This is a safety choice but means
   the human must handle deletions manually.

9. **Pre-existing secrets in source files** -- If the host project
   contains secrets that pass through the sanitization filter (e.g., a
   secret embedded in a `.py` file that matches the allowlist), those
   secrets are visible inside the container. The secret scanner catches
   common patterns but is not exhaustive.

10. **No VM-level isolation** -- Airlock uses Docker (container-level
    isolation), not virtual machines. The attack surface includes the
    shared kernel. For higher-assurance isolation, a VM or
    microVM layer (Firecracker, gVisor) would be needed.

### Design Trade-offs

- **DNS is blocked entirely** -- API domain IPs are resolved once at
  launch time and injected via `--add-host`. If the provider rotates
  IPs during a session, the container loses connectivity. This is
  accepted as preferable to allowing DNS resolution, which could be
  used for data exfiltration.

- **Seccomp whitelist includes `socket` and `connect`** -- These are
  needed for API communication. The firewall is the enforcement
  layer for network destinations, not seccomp. A compromised seccomp
  would still face the iptables rules.

- **`exec` flag on /home/claude tmpfs** -- Needed for Node.js runtime
  behavior. This is a relaxation from ideal (noexec on all tmpfs) but
  is contained by the seccomp profile and capability drops.

- **Max 2 concurrent sessions** -- Limits resource consumption and
  reduces the monitoring surface. Configurable but intentionally low
  by default.

- **4-hour session timeout** -- Hard kill after 4 hours regardless of
  activity. Prevents abandoned sessions from running indefinitely.
  Configurable in `airlock.conf`.
