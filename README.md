<div align="center">

<img width="740" height="198" alt="adscan_wordmark_horizontal_transparent_cropped" src="https://github.com/user-attachments/assets/4902f205-d9bc-453e-b2ac-8c7d7fa2f329" />

# ADscan - Active Directory Pentesting CLI

[![Version](https://img.shields.io/badge/version-6.5.0--lite-blue.svg)](https://github.com/ADscanPro/adscan/releases)
[![downloads](https://static.pepy.tech/badge/adscan)](https://pepy.tech/projects/adscan)
[![License: BSL 1.1](https://img.shields.io/badge/license-BSL%201.1-blue.svg)](https://github.com/ADscanPro/adscan/blob/main/LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://github.com/ADscanPro/adscan)
[![Discord](https://img.shields.io/discord/1355089867096199300?color=7289da&label=Discord&logo=discord&logoColor=white)](https://discord.com/invite/fXBR3P8H74)

**Automate Active Directory pentesting. From DNS to Domain Admin.**

ADscan is a free Active Directory pentesting CLI for pentesters, red teamers, and CTF players who need fast AD enumeration, BloodHound collection, Kerberoasting, AS-REP Roasting, ADCS checks, password spraying, credential dumping, attack-path execution, and evidence export from one Linux terminal.

**[Docs](https://adscanpro.com/docs?utm_source=github&utm_medium=readme&utm_campaign=docs_cta)** | [Discord](https://discord.com/invite/fXBR3P8H74) | [Website](https://adscanpro.com)

</div>

---

## 🎬 Demo

[![asciicast](https://asciinema.org/a/734180.svg)](https://asciinema.org/a/734180?autoplay=1)

_Auto-pwns **HTB Forest** in ~3 minutes_

---

## 🚀 Quick Start

```bash
pipx install adscan
adscan install
adscan start
```

> **Full installation guide & docs** at [adscanpro.com/docs](https://adscanpro.com/docs?utm_source=github&utm_medium=readme&utm_campaign=install_cta)

## ⚡ Common Pentest Workflows

Use ADscan when you need to move quickly through internal Active Directory assessments:

- **CTF and lab auto-pwn:** reproduce HTB Forest, Active, and Cicada attack chains from the docs.
- **Unauthenticated AD recon:** discover domains, DNS, SMB exposure, null sessions, users, and roastable accounts.
- **Authenticated enumeration:** collect LDAP, SMB, Kerberos, ADCS, BloodHound CE data, and credential exposure.
- **Privilege escalation:** execute supported Kerberoasting, AS-REP Roasting, DCSync, GPP password, ADCS, and local credential workflows.
- **Evidence handling:** keep workspaces isolated and export findings to TXT/JSON for reports.

## 🧭 Usage Examples

```bash
adscan start
start_unauth
```

More walkthroughs:

- [HTB Forest auto-pwn](https://adscanpro.com/docs/labs/htb/forest?utm_source=github&utm_medium=readme&utm_campaign=ctf_forest)
- [HTB Active walkthrough](https://adscanpro.com/docs/labs/htb/active?utm_source=github&utm_medium=readme&utm_campaign=ctf_active)
- [HTB Cicada walkthrough](https://adscanpro.com/docs/labs/htb/cicada?utm_source=github&utm_medium=readme&utm_campaign=ctf_cicada)

## 🧪 Developer Setup (uv)

For local development in this repository:

```bash
uv sync --extra dev
uv run adscan --help
uv run adscan version
```

Quality checks:

```bash
uv run ruff check adscan_core adscan_launcher adscan_internal
uv run pytest -m unit
uv run python -m build
```

---

## ✨ Features

<table>
<tr>
<td width="50%">

### LITE (Free, Source Available)

**Everything a pentester could do manually, 10x faster:**
- ✅ Three operation modes (automatic/semi-auto/manual)
- ✅ DNS, LDAP, SMB, Kerberos enumeration
- ✅ AS-REP Roasting & Kerberoasting
- ✅ Password spraying
- ✅ BloodHound collection & analysis
- ✅ Credential harvesting (SAM, LSA, DCSync)
- ✅ ADCS detection & template enumeration
- ✅ GPP passwords & CVE enumeration
- ✅ Export to TXT/JSON
- ✅ Workspace & evidence management

</td>
<td width="50%">

### PRO

**What nobody can do manually in reasonable time:**
- 🎯 Algorithmic attack graph generation
- 🎯 Auto-exploitation chains (DNS to DA)
- 🎯 ADCS ESC1-13 auto-exploitation
- 🎯 MITRE-mapped Word/PDF reports
- 🎯 Multi-domain trust spidering
- 🎯 Advanced privilege escalation chains
- 🎯 Priority enterprise support

[Full comparison](https://adscanpro.com/docs/lite-vs-pro) | [Learn more](https://adscanpro.com?utm_source=github&utm_medium=readme&utm_campaign=pro_cta)

</td>
</tr>
</table>

---

## 📋 Requirements

| | |
|---|---|
| **OS** | Linux (Debian/Ubuntu/Kali) |
| **Docker** | Docker Engine + Compose |
| **Privileges** | `docker` group or `sudo` |
| **Network** | Internet (pull images) + target network |

---

## 📜 License

Source available under the [Business Source License 1.1](LICENSE).

- **Use freely** for pentesting (personal or paid engagements)
- **Read, modify, and redistribute** the source code
- **Cannot** create a competing commercial product
- **Converts to Apache 2.0** on 2029-02-01

---

## 💬 Community

<div align="center">

[![Discord](https://img.shields.io/badge/Discord-Join%20Community-7289da?style=for-the-badge&logo=discord&logoColor=white)](https://discord.com/invite/fXBR3P8H74)
[![GitHub Issues](https://img.shields.io/badge/GitHub-Report%20Bug-black?style=for-the-badge&logo=github)](https://github.com/ADscanPro/adscan/issues)

</div>

## 🤝 Contributing

Bug reports, lab reproductions, command-output samples, and focused pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and open an issue with your OS, Docker version, ADscan version, command, and sanitized output.

Enterprise support: [hello@adscanpro.com](mailto:hello@adscanpro.com)

---

<div align="center">

(c) 2024-2026 Yeray Martin Dominguez | [adscanpro.com](https://adscanpro.com)

</div>
