# ADscan - Active Directory Pentesting CLI

ADscan is a Linux CLI for Active Directory pentesting, CTF labs, and internal audit workflows. It automates AD enumeration, BloodHound CE collection, Kerberoasting, AS-REP Roasting, ADCS checks, password spraying, credential dumping, attack-path execution, and evidence export from one terminal.

This PyPI package provides the `adscan` command as a lightweight Python launcher. The launcher is responsible for:
- pulling the ADscan Docker image (`adscan install`)
- running the ADscan CLI inside Docker (`adscan start`, `adscan ci`, and passthrough commands)

The full ADscan CLI implementation lives inside the Docker image.

## Requirements

- Linux host (x86_64)
- Docker Engine + Docker Compose plugin installed
- Permission to run Docker (root or user in the `docker` group)

## Quick Start

```bash
pipx install adscan
adscan install
adscan start
```

If you do not use `pipx`, install with `pip` in an isolated environment.

## Common Pentest Workflows

- Active Directory reconnaissance from DNS, LDAP, SMB, and Kerberos.
- BloodHound CE setup, collection, upload, and path analysis.
- Kerberoasting, AS-REP Roasting, ADCS checks, DCSync, SAM/LSA dumping, and credential workflows.
- HTB and VulnLab-style AD labs where you want repeatable attack chains.
- TXT/JSON exports for notes, reporting, and evidence handling.

## Documentation and Labs

- Documentation: https://adscanpro.com/docs
- Installation: https://adscanpro.com/docs/getting-started/installation
- HTB Forest walkthrough: https://adscanpro.com/docs/labs/htb/forest
- GitHub repository: https://github.com/ADscanPro/adscan
- Discord community: https://discord.com/invite/fXBR3P8H74

## Local development with `uv`

If you cloned this repository and want to run the launcher locally:

```bash
uv sync --extra dev
uv run adscan --help
uv run adscan version
```

Run lint/tests/build with `uv`:

```bash
uv run ruff check adscan_core adscan_launcher adscan_internal
uv run pytest -m unit
uv run python -m build
```