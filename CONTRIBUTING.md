# Contributing to ADscan

ADscan is built for Active Directory pentesters, red teamers, and CTF players. The highest-value contributions are reproducible bugs, lab notes, sanitized command output, docs fixes, and focused patches.

## Good Issues

When reporting a bug, include:

- ADscan version: `adscan version`
- Host OS and version
- Docker Engine and Compose versions
- Install method: `pipx`, `pip`, local `uv`, or Docker-only
- Command that failed
- Sanitized output, stack trace, or workspace path
- Lab or environment type, if safe to share

Do not include passwords, hashes, customer names, internal domains, public IPs, VPN configs, or screenshots containing client data.

## Pull Requests

Before opening a PR:

```bash
uv sync --extra dev
uv run ruff check adscan_core adscan_launcher adscan_internal
uv run pytest -m unit
```

Keep PRs small and tied to one behavior change. Include a short test note explaining what you ran and what environment you used.

## Security Reports

For vulnerabilities or sensitive findings, do not open a public issue. Email hello@adscanpro.com with a minimal reproduction and impact summary.
