# Airlock Security

Threat model, defense layers, trust boundaries, and known limitations.

## What Airlock Defends Against

Airlock assumes Claude Code may attempt any of the following when running with `--dangerously-skip-permissions`:

| Threat | Defense |
|--------|---------|
| **Data exfiltration via network** | iptables firewall allows only Anthropic API on TCP 443. All other traffic is dropped and logged. |
| **Container escape via syscalls** | Whitelist-only seccomp profile (~155 syscalls). Dangerous syscalls (`ptrace`, `mount`, `unshare`, `setns`, `bpf`, etc.) are blocked. |
| **Privilege escalation** | All 41 Linux capabilities dropped. `no-new-privileges` set. Non-root user (UID 1000). |
| **DNS-based exfiltration** | `--dns 0.0.0.0` blocks all DNS. Anthropic IPs pre-resolved and injected via `--add-host`. |
| **IPv6 firewall bypass** | IPv6 disabled at kernel level + ip6tables DROP policy. |
| **Terminal injection via ANSI escapes** | Extraction pipeline scans for raw ANSI escape sequences in output files. |
| **Symlink escape** | Extraction pipeline scans for symlinks in staged files. |
| **File modification after review** | Container paused during review. TOCTOU hash recheck before sync. |
| **Automated approval** | Ed25519 signature with passphrase-protected key requires human presence. |
| **Resource exhaustion** | Memory, PID, CPU, and file descriptor limits. Host-side watchdog with strike system. |

## 8 Defense Layers

### 1. Network Isolation

The container starts with `--network none` (zero network access). A per-session Docker network is created, but only connected after iptables rules are injected via `sudo nsenter` from the host. This eliminates any timing window where the container has unfiltered access.

**Firewall rules:**
- IPv4 OUTPUT default: DROP
- Allowed: loopback, ESTABLISHED/RELATED, Anthropic API IPs on TCP 443
- All blocked packets logged with `AIRLOCK-BLOCKED:` prefix
- IPv6 OUTPUT default: DROP (loopback only)

### 2. Filesystem Hardening

- Read-only root filesystem (`--read-only`)
- tmpfs for `/tmp` (2 GB, nosuid) and `/home/claude` (1 GB, exec needed for Node.js)
- Credentials mounted read-only at `/run/credentials/` (outside tmpfs)
- Project files bind-mounted from a sanitized staging copy

### 3. Capability Dropping

`--cap-drop ALL` removes all 41 Linux capabilities. `--security-opt no-new-privileges` prevents gaining capabilities through setuid, setgid, or file capabilities.

### 4. Syscall Filtering

A custom seccomp profile uses `SCMP_ACT_ERRNO` (deny by default) with ~155 explicitly allowed syscalls. Notably blocked: `mount`, `umount`, `ptrace`, `reboot`, `kexec_load`, `init_module`, `bpf`, `perf_event_open`, `userfaultfd`, `keyctl`, `pivot_root`, `chroot`, `unshare`, `setns`.

### 5. AppArmor

The `docker-default` AppArmor profile provides mandatory access control on top of discretionary controls.

### 6. Resource Limits

| Resource | Default Limit |
|----------|--------------|
| Memory | 4 GB |
| PIDs | 256 |
| CPUs | 2 |
| Open files | 1024 |
| /tmp | 2 GB |
| /home/claude | 1 GB |

### 7. Anomaly Detection (Watchdog)

A host-side process monitors the container. It cannot be seen, stopped, or influenced from inside:

- **Memory**: Strike if >90% of limit
- **PIDs**: Strike if >80% of limit
- **Blocked connections**: Strike if >20 per check interval
- **File bursts**: Strike if >200 new files per check interval
- Clean checks decay one strike (self-healing for transient spikes)
- 5 strikes = automatic container kill
- Hard timeout at 4 hours (configurable)

### 8. Input Sanitization

Before project files enter the container, the sanitizer:
- Strips `.env`, `*.pem`, `*.key`, `.ssh/`, `.gnupg/`, `.git/`, `node_modules/`
- Applies allowlist filtering (per-project or default extension list)
- Scans for critical secret patterns (API keys, private keys, tokens)
- Aborts on critical matches

## Extraction Pipeline

The extraction pipeline is the gate between the sandbox and your real files. It is deliberately slow and manual.

1. **Audit capture**: Container logs and bash history saved
2. **Container pause**: `docker pause` freezes all processes (TOCTOU anchor)
3. **Symlink check**: Any symlinks abort extraction
4. **ANSI escape check**: Raw escape sequences abort extraction
5. **Hash-lock**: SHA-256 of all staged files recorded
6. **Diff generation**: `diff -ruN` between original and staged, piped through `cat -v`
7. **Automated scan**: Secret patterns, network imports, dynamic execution, Python AST analysis
8. **Human review**: You read the diff; type `approve` to proceed
9. **Ed25519 signature**: `ssh-keygen -Y sign` with your passphrase-protected key
10. **Signature verification**: Checked against `allowed_signers`
11. **TOCTOU recheck**: Re-hash and compare (container still paused)
12. **Diff-only sync**: Only changed files copied to host; no deletions

## Trust Boundaries

### Trusted

- **Host OS and kernel** — all enforcement is kernel-level
- **Docker daemon** — assumed to correctly enforce isolation
- **Airlock scripts** — run on the host, not inside the container
- **Human reviewer** — the primary defense against malicious output
- **Ed25519 signing key** — passphrase-protected, not accessible from container
- **Anthropic API** — the sole allowed network destination

### Untrusted

- **Everything inside the container** — Claude, its code, its processes, its files
- **Staged directory after a session** — untrusted until reviewed and signed
- **All network traffic from inside** — only whitelisted destinations reachable

## Known Limitations

1. **Not VM-level isolation.** Airlock uses Docker (shared kernel). A kernel-level container escape vulnerability would bypass all defenses. For higher assurance, layer a VM or microVM (Firecracker, gVisor) underneath.

2. **Covert channels via the API.** Claude communicates freely with the Anthropic API. Data could be encoded in API requests. Airlock trusts the API endpoint.

3. **Steganographic output.** Claude could embed hidden information in code that looks benign (variable names, whitespace patterns, algorithmic backdoors). Automated scans catch obvious patterns but not semantic-level hiding. Human review is the defense.

4. **Reviewer error.** If you approve a malicious diff without reading it, the signed files are synced. The signature is non-repudiation, not content verification.

5. **Side-channel attacks.** Timing, cache, and speculative execution attacks from inside the container are not mitigated.

6. **DNS rotation.** Anthropic IPs are resolved once at launch. If they rotate during a session, connectivity is lost. This is accepted as preferable to allowing DNS.

7. **No file deletion propagation.** Files deleted inside the container are not deleted on the host. Deletions must be done manually.

8. **Pre-existing secrets in source.** Secrets embedded in source files (not `.env` etc.) may pass through sanitization if they don't match known patterns.

## Vulnerability Reporting

If you find a security vulnerability in Airlock, please report it responsibly:

1. **Do not** open a public issue for security vulnerabilities
2. Email details to the maintainers (see repository contact info)
3. Include steps to reproduce and potential impact
4. Allow reasonable time for a fix before public disclosure

We take all reports seriously and will respond promptly.
