<div align="center">

<img width="800" alt="ADscan Logo" src="https://github.com/user-attachments/assets/77f3b465-faf6-4ea2-8838-9fcda31f993c" />

# ADscan

**Automated Active Directory Security Scanner**

[![Version](https://img.shields.io/badge/version-3.0.1--lite-blue.svg)](https://github.com/ADscanPro/adscan/releases)
[![License](https://img.shields.io/badge/license-EULA-red.svg)](https://github.com/ADscanPro/adscan/blob/main/LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://github.com/ADscanPro/adscan)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Discord](https://img.shields.io/discord/1355089867096199300?color=7289da&label=Discord&logo=discord&logoColor=white)](https://discord.com/invite/fXBR3P8H74)

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Documentation](https://adscanpro.com/docs) • [Discord](https://discord.com/invite/fXBR3P8H74)

</div>

---

## 🎯 Overview

**ADscan** is a professional pentesting tool that automates Active Directory reconnaissance, enumeration, and exploitation. It reduces AD assessment time from **hours to minutes** with an intelligent interactive CLI.

### Why ADscan?

- 🚀 **Auto-pwns retired HTB machines** (Forest, Active, Cicada)
- ⚡ **Shrinks AD recon from hours to minutes**
- 🎮 **Perfect for CTFs, labs, and jump-boxes** (100% CLI)
- 🔐 **Semi/automatic modes** for labs and production environments
- 📊 **BloodHound integration** with automated path analysis

> **Try ADscan PRO** — Request a 14-day free POV at [adscanpro.com](https://adscanpro.com/?utm_source=github&utm_medium=readme&utm_campaign=lite_cta) 🔥

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔓 LITE (Free)

- ✅ Interactive shell (autocomplete, history)
- ✅ Unauthenticated & authenticated scans
- ✅ Kerberos attacks (AS-REP, Kerberoast)
- ✅ BloodHound data collection
- ✅ Credential dumping (SAM, LSA, DCSync)
- ✅ Workspace & credential management
- ✅ Community Discord support

</td>
<td width="50%">

### 🔒 PRO (Coming Q4 2025)

- 🎯 Trust relationship auto-enum
- 🎫 ADCS ESC auto-exploit
- 📄 One-click Word/PDF reports
- ☁️ Cloud-accelerated hash cracking
- 🔍 Broad CVE/misconfig checks
- 🏢 Priority enterprise support
- 🚀 Advanced automation features

</td>
</tr>
</table>

---

## 📋 Requirements

| Requirement | Details |
|------------|---------|
| **OS** | Linux (Debian/Ubuntu/Kali and other Debian-based distros) |
| **Privileges** | Root access required |
| **Python** | 3.8+ (managed automatically with binary) |
| **Network** | Internet for installation, target network access |

---

## 🚀 Installation

### Option 1: pipx (Recommended)

```bash
pipx install adscan
```

### Option 2: pip

```bash
pip install adscan
```

### Option 3: Pre-built Binary

```bash
# Download latest release
wget https://github.com/ADscanPro/adscan/releases/latest/download/adscan
chmod +x adscan
sudo mv adscan /usr/local/bin/
```

### Install Dependencies

```bash
# Setup Python environment, tools, and wordlists
adscan install

# Verify installation
adscan check
```

**⚡ Ready to hack!** — Run `adscan start` and share your results with [#adscan](https://twitter.com/search?q=%23adscan) on X/Twitter.

---

## ⚡ Quick Start

### 1️⃣ Start ADscan

```bash
adscan start -v
```

### 2️⃣ Create Workspace

```bash
(ADscan) > workspace create my_audit
```

### 3️⃣ Configure Scan

```bash
(ADscan:my_audit) > set iface tun0
(ADscan:my_audit) > set auto False  # Semi-automatic (recommended)
```

### 4️⃣ Run Scan

**Unauthenticated:**
```bash
(ADscan:my_audit) > set hosts 192.168.1.0/24
(ADscan:my_audit) > start_unauth
```

**Authenticated:**
```bash
(ADscan:my_audit) > start_auth domain.local 10.10.10.1 username password
```

### 5️⃣ Follow Prompts

ADscan guides you through enumeration and exploitation automatically! 🎯

---

## 🎬 Interactive Demos

### Semi-Automatic Mode (`auto=False`)

[![asciicast](https://asciinema.org/a/GJqRmSw6dj7oxsSKDHVIWyZpZ.svg)](https://asciinema.org/a/GJqRmSw6dj7oxsSKDHVIWyZpZ)

### Automatic Mode (`auto=True`)

[![asciicast](https://asciinema.org/a/723117.svg)](https://asciinema.org/a/734180)

_Auto-pwns **HTB Forest** in ~3 minutes_ 🚀

---

## 🤖 CI/CD Mode

Run ADscan non-interactively for automated testing:

```bash
# Unauthenticated scan
adscan ci unauth --type ctf --interface tun0 --hosts 10.10.10.10

# Authenticated scan
adscan ci auth --type ctf --interface tun0 \
  --domain example.local --dc-ip 10.10.10.1 \
  --username user --password pass

# Keep workspace for debugging
adscan ci unauth --type ctf --interface tun0 --hosts 10.10.10.10 --keep-workspace
```

**Exit Codes:**
- `0`: Success with flags validated
- `1`: Scan failed
- `2`: Scan successful but flags invalid/missing

---

## 📚 Documentation

Comprehensive documentation available at **[adscanpro.com/docs](https://adscanpro.com/docs)**

- 📖 [Getting Started](https://adscanpro.com/docs/getting-started)
- 🔧 [Command Reference](https://adscanpro.com/docs/commands)
- 🎓 [CTF Walkthrough](https://adscanpro.com/docs/guides/ctf-walkthrough)

---

## 🏆 Tested On

| Provider | Machine | Status |
|----------|---------|--------|
| Hack The Box | Forest (Retired) | ✅ Auto-pwned in ~3min |
| Hack The Box | Active (Retired) | ✅ Auto-pwned |
| Hack The Box | Cicada (Retired) | ✅ Auto-pwned |

> **Contribute:** If you auto-pwn labs with ADscan, [open a PR](https://github.com/ADscanPro/adscan/pulls) to add them to the matrix!

---

## 🔒 Security & Privacy

- **Telemetry**: Opt-in by default (toggle with `set telemetry off`)
- **No sensitive data**: Only anonymized error data and feature usage
- **Local-first**: All data stored in `~/.adscan/workspaces/`
- **Open source LITE**: Transparent security tool

---

## 🗺️ Roadmap

| Quarter | Milestone |
|---------|-----------|
| **Q3 2025** | More ACL exploitation, pre-2k module, Kerberos unconstrained pathing |
| **Q4 2025** | **PRO release** — Trust enum, ADCS ESC, auto reports |
| **Q1 2026** | NTLM relay chain, SCCM module |
| **Q2 2026** | PwnDoc integration, cloud-accelerated cracking |

> Timelines are targets, not promises. Features may adjust based on feedback.

---

## 💬 Community & Support

<div align="center">

[![Discord](https://img.shields.io/badge/Discord-Join%20Community-7289da?style=for-the-badge&logo=discord&logoColor=white)](https://discord.com/invite/fXBR3P8H74)
[![GitHub](https://img.shields.io/badge/GitHub-Report%20Bug-black?style=for-the-badge&logo=github)](https://github.com/ADscanPro/adscan/issues)
[![Website](https://img.shields.io/badge/Website-adscanpro.com-blue?style=for-the-badge&logo=google-chrome&logoColor=white)](https://adscanpro.com)

</div>

**Need help?**
- 💬 Chat on [Discord](https://discord.com/invite/fXBR3P8H74)
- 🐛 Report bugs via [GitHub Issues](https://github.com/ADscanPro/adscan/issues)
- 📧 Enterprise support: [hello@adscanpro.com](mailto:hello@adscanpro.com)

---

## 🎓 Presented At

> **Announcement:** ADscan was presented at **Hackén 2025** cybersecurity conference.

---

## 📜 License

© 2025 Yeray Martín Domínguez — Released under custom EULA
ADscan LITE 3.0.1 | PRO edition: Q4 2025

---

<div align="center">

**⭐ Star this repo if ADscan helped you!** | **🔗 Share with [#adscan](https://twitter.com/search?q=%23adscan)**

Made with ❤️ for the pentesting community

</div>
