# Contributing to Airlock

Thanks for your interest in improving Airlock. This document covers the basics of contributing.

## Getting Started

1. Fork the repository
2. Clone your fork
3. Run `./airlock-setup.sh` to set up your local environment
4. Make your changes
5. Test your changes (see below)
6. Submit a pull request

## What to Contribute

- Bug fixes
- Documentation improvements
- New Dockerfile templates (satisfying the 5-point image contract)
- Seccomp profile refinements
- Anomaly detection improvements
- Test cases and test automation

## Testing Your Changes

### Shell Scripts

All shell scripts should pass shellcheck:

```bash
shellcheck airlock-*.sh entrypoint.sh
```

### Image Contract

If you modify Dockerfiles or the build script, verify the image contract:

```bash
./airlock-build.sh Dockerfile.example airlock-example:latest
./airlock-build.sh _ airlock-example:latest --verify-only
```

### Full Cycle

For changes to the launch, watchdog, extraction, or kill scripts, test the full lifecycle:

1. Build an image
2. Launch a session with a test project
3. Make some changes inside
4. Extract and verify the diff
5. Kill a session and verify cleanup

## Code Style

- Shell scripts use `bash` with `set -euo pipefail`
- 4-space indentation
- Comments explain *why*, not *what*
- No hardcoded paths — everything goes through `airlock.conf`
- No secrets in code — credentials are referenced by path only

## Security Considerations

Airlock is a security tool. When contributing:

- Do not weaken any defense layer without explicit justification
- Do not add network access beyond the Anthropic API whitelist
- Do not relax seccomp, capability, or filesystem restrictions
- Do not bypass the human review gate in the extraction pipeline
- If you add a new syscall to the seccomp profile, document why it's needed
- If you add a new feature, consider its security implications

## Pull Request Process

1. Describe what your PR does and why
2. Reference any related issues
3. Ensure shellcheck passes
4. Test the affected workflow end-to-end if possible
5. Keep changes focused — one feature or fix per PR

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
