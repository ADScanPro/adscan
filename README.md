<div align="center">

<img width="740" height="198" alt="ADscan - Active Directory Pentesting Tool for Linux" src="https://github.com/user-attachments/assets/4902f205-d9bc-453e-b2ac-8c7d7fa2f329" />

# ADscan - Active Directory Pentesting Tool for Linux

[![PyPI version](https://img.shields.io/pypi/v/adscan.svg)](https://pypi.org/project/adscan/)
[![downloads](https://static.pepy.tech/badge/adscan)](https://pepy.tech/projects/adscan)
[![License: BSL 1.1](https://img.shields.io/badge/license-BSL%201.1-blue.svg)](https://github.com/ADscanPro/adscan/blob/main/LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://github.com/ADscanPro/adscan)
[![Discord](https://img.shields.io/discord/1355089867096199300?color=7289da&label=Discord&logo=discord&logoColor=white)](https://discord.com/invite/fXBR3P8H74)

**Free active directory pentesting tool for Linux. Replace your AD pentest toolchain with one CLI.**

ADscan is a free Linux CLI for pentesters, red teamers, and security consultants. It covers 103 Active Directory attack techniques in a single workflow: enumeration, Kerberoasting, AS-REP roasting, ADCS/ESC exploitation, DCSync, credential harvesting, and native attack-path analysis. No Windows required.

**[Docs](https://adscanpro.com/docs?utm_source=github&utm_medium=readme&utm_campaign=docs_cta)** | [Discord](https://discord.com/invite/fXBR3P8H74) | [Website](https://adscanpro.com)

</div>

---

## Table of Contents

- [Demo](#demo)
- [Quick Start](#quick-start)
- [ADscan vs Alternatives](#adscan-vs-alternatives)
- [Kerberoasting, ADCS and AD Attack Coverage](#kerberoasting-adcs-and-ad-attack-coverage)
- [Common Pentest Workflows](#common-pentest-workflows)
- [Usage Examples](#usage-examples)
- [Want the Full Client Report?](#want-the-full-client-report)
- [Requirements](#requirements)
- [FAQ](#faq)
- [Developer Setup](#developer-setup)
- [Contributing](#contributing)
- [License](#license)

---

## Demo

[![asciicast](https://asciinema.org/a/734180.svg)](https://asciinema.org/a/734180?autoplay=1)

_Auto-pwns **HTB Forest** in ~3 minutes_

---

## Quick Start

```bash
pipx install adscan
adscan install
adscan start
```

> Full installation guide at [adscanpro.com/docs](https://adscanpro.com/docs?utm_source=github&utm_medium=readme&utm_campaign=install_cta)

Once inside the shell, start an unauthenticated recon:

```
(ADscan) > start_unauth
```

This discovers domain controllers, SMB exposure, null sessions, and roastable accounts without credentials. From there, run `start_auth` with a domain user to enumerate LDAP, collect BloodHound data, and build the attack graph.

---

## ADscan vs Alternatives

Most AD pentesters use 5-8 separate tools. ADscan replaces the chain:

| | ADscan | NetExec/CrackMapExec | Certipy | Impacket | BloodHound CE |
|---|---|---|---|---|---|
| **Platform** | Linux | Linux/Win | Linux | Linux | Linux/Win |
| **AD enumeration** | Full | Partial | No | Partial | No |
| **Kerberoasting** | Yes | Yes | No | Yes | No |
| **ADCS ESC1-16** | Yes (auto) | No | Yes (manual) | No | No |
| **Attack paths** | Native graph | No | No | No | Yes |
| **DCSync** | Yes | Yes | No | Yes | No |
| **Single workflow** | Yes | No | No | No | No |
| **Compliance reports** | PRO tier | No | No | No | No |

ADscan is not a replacement for every tool in every scenario. It is the fastest path from credentials to a documented attack chain in a single terminal session.

---

## Kerberoasting, ADCS and AD Attack Coverage

ADscan covers 103 Active Directory attack techniques across the kill chain:

<table>
<tr>
<td width="50%">

### LITE (Free, Source Available)

**Everything a pentester could do manually, without the toolchain:**
- Three operation modes (automatic/semi-auto/manual)
- DNS, LDAP, SMB, Kerberos enumeration
- AS-REP Roasting and Kerberoasting
- Password spraying
- Native graph collection and attack-path analysis
- Credential harvesting (SAM, LSA, DCSync)
- ADCS detection and template enumeration
- GPP passwords and CVE enumeration
- Export to TXT/JSON
- Workspace and evidence management

</td>
<td width="50%">

### PRO

**What takes days manually, automated:**
- Algorithmic attack graph generation
- Auto-exploitation chains (unauthenticated to Domain Admin)
- ADCS ESC1-16 auto-exploitation
- MITRE-mapped Word/PDF reports
- Multi-domain trust spidering
- Advanced privilege escalation chains
- Priority enterprise support

[Full comparison](https://adscanpro.com/docs/lite-vs-pro) | [Get PRO beta free](https://adscanpro.com/pro?utm_source=github&utm_medium=readme&utm_campaign=pro_cta)

</td>
</tr>
</table>

---

## Common Pentest Workflows

- **CTF and lab auto-pwn:** reproduce HTB Forest, Active, and Cicada attack chains from the docs.
- **Unauthenticated AD recon:** discover domains, DNS, SMB exposure, null sessions, users, and roastable accounts.
- **Authenticated enumeration:** collect LDAP, SMB, Kerberos, ADCS, attack-graph data, and credential exposure.
- **Privilege escalation:** execute Kerberoasting, AS-REP Roasting, DCSync, GPP password, ADCS, and local credential workflows.
- **Evidence handling:** keep workspaces isolated and export findings to TXT/JSON for reports.

---

## Usage Examples

**Unauthenticated recon:**

```bash
adscan start
# Inside the ADscan shell:
start_unauth
```

Discovers domain controllers, DNS, SMB null sessions, and roastable accounts without credentials.

**Authenticated scan with BloodHound collection:**

```bash
# Inside the ADscan shell (after start_auth):
start_auth
```

Collects LDAP data, builds the attack graph, and identifies Kerberoasting targets, ADCS misconfigurations, and privilege escalation paths.

More walkthroughs:

- [HTB Forest auto-pwn](https://adscanpro.com/docs/labs/htb/forest?utm_source=github&utm_medium=readme&utm_campaign=ctf_forest)
- [HTB Active walkthrough](https://adscanpro.com/docs/labs/htb/active?utm_source=github&utm_medium=readme&utm_campaign=ctf_active)
- [HTB Cicada walkthrough](https://adscanpro.com/docs/labs/htb/cicada?utm_source=github&utm_medium=readme&utm_campaign=ctf_cicada)

---

## Want the Full Client Report?

ADscan LITE gives you enumeration, attack paths, and findings in the terminal. **ADscan PRO** generates four PDF deliverables in 90 seconds:

- **Executive Assessment Report** — risk narrative, attack chains, posture score for the CISO and board
- **MITRE Remediation Checklist** — ATT&CK-mapped action items filtered to your actual findings
- **AD Hardening Playbook** — 30-day remediation roadmap with effort and ownership
- **Coverage Matrix** — MITRE x ENS Alto / NIS2 / ISO 27001, audit-ready

Beta access is free for security consultants. [adscanpro.com/pro](https://adscanpro.com/pro?utm_source=github&utm_medium=readme&utm_campaign=pro_cta)

---

## Requirements

| | |
|---|---|
| **OS** | Linux (Debian/Ubuntu/Kali) |
| **Docker** | Docker Engine + Compose |
| **Privileges** | `docker` group or `sudo` |
| **Network** | Internet (pull images) + target network |

---

## FAQ

**Does ADscan work without a Windows machine?**
Yes. ADscan runs entirely on Linux inside Docker. No Windows VM, no RDP, no agent installation required. It connects to your target AD environment over the network using standard protocols (LDAP, SMB, Kerberos).

**Is ADscan safe to run in production Active Directory environments?**
ADscan LITE is read-only by default for enumeration. Exploitation steps (Kerberoasting, credential dumping, DCSync) require explicit operator confirmation. Run it in a test window with your client's written authorization. See the [security policy](SECURITY.md) for responsible use guidelines.

**How is ADscan different from BloodHound?**
BloodHound is a graph analysis tool that requires separate data collection (SharpHound or AzureHound). ADscan collects data, builds the attack graph, and executes the attack chain from one terminal. LITE includes native graph collection compatible with BloodHound CE. PRO adds algorithmic attack path auto-exploitation.

---

## Developer Setup

```bash
uv sync --extra dev
uv run adscan --help
uv run adscan version
```

Quality checks:

```bash
uv run ruff check adscan_core adscan_launcher adscan_internal
uv run pytest -m unit
```

---

## Contributing

Bug reports, lab reproductions, command-output samples, and focused pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the PR workflow and required checks.

Enterprise support: [hello@adscanpro.com](mailto:hello@adscanpro.com)

---

## License

Source available under the [Business Source License 1.1](LICENSE).

- Use freely for pentesting (personal or paid engagements)
- Read, modify, and redistribute the source code
- Cannot create a competing commercial product
- Converts to Apache 2.0 on 2029-02-01

---

<div align="center">

(c) 2024-2026 Yeray Martin Dominguez | [adscanpro.com](https://adscanpro.com)

</div>
