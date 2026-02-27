# CodeSafe

Cybersecurity tools for vibe coders. Ship fast without shipping vulnerabilities.

CodeSafe is a collection of open-source tools that add security guardrails to AI-assisted development workflows. Each tool is standalone — use what you need.

## Tools

### [Airlock](airlock/)

A hardened Docker sandbox for running [Claude Code](https://docs.anthropic.com/en/docs/claude-code) with `--dangerously-skip-permissions`. Claude gets full autonomy inside a sealed container. Network access is limited to the Anthropic API only. Nothing comes back to your machine until you review every change and sign off with your SSH key.

**Use Airlock when:** You want Claude Code to work autonomously on your codebase but don't want to trust it with unrestricted access to your filesystem, network, and credentials.

[Get started with Airlock](airlock/QUICKSTART.md)

## Philosophy

1. **Defense in depth.** No single layer is the complete defense. They overlap so that a bypass of one is contained by the next.
2. **Human in the loop.** Automated scanners are trip wires, not shields. The human reviewer is the primary gate.
3. **Cryptographic non-repudiation.** Approvals are signed, not just clicked.
4. **Minimal trust.** Everything the AI produces is treated as untrusted output until reviewed.

## License

[MIT](LICENSE)
