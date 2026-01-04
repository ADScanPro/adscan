# ADscan

<div align="center">

<img width="800" alt="ADscan Logo" src="https://github.com/user-attachments/assets/77f3b465-faf6-4ea2-8838-9fcda31f993c" />

[![Version](https://img.shields.io/badge/version-3.2.1--lite-blue.svg)](https://github.com/ADscanPro/adscan/releases)
[![downloads](https://static.pepy.tech/badge/adscan)](https://pepy.tech/projects/cai-adscan)
[![License](https://img.shields.io/badge/license-EULA-red.svg)](https://github.com/ADscanPro/adscan/blob/main/LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://github.com/ADscanPro/adscan)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Discord](https://img.shields.io/discord/1355089867096199300?color=7289da&label=Discord&logo=discord&logoColor=white)](https://discord.com/invite/fXBR3P8H74)

**[📚 Complete Documentation → adscanpro.com/docs](https://adscanpro.com/docs?utm_source=github&utm_medium=readme&utm_campaign=docs_cta)** • [Discord](https://discord.com/invite/fXBR3P8H74)

</div>

---

## 🎬 Demo

[![asciicast](https://asciinema.org/a/734180.svg)](https://asciinema.org/a/734180?autoplay=1)

_Auto-pwns **HTB Forest** in ~3 minutes_ 🚀

---

## 🎯 Overview

**ADscan** is an interactive CLI that automates and orchestrates Active Directory pentesting workflows. It helps teams ship internal AD engagements faster by reducing manual glue-work (tool handoffs, copy/paste, evidence collection, reporting).

### Operation Modes

- 🤖 **Automatic** (`auto=True`, labs/CTF): minimal prompts, fast flow
- 🤝 **Semi-automatic** (`auto=False`, internal/prod): prompts before risky actions
- 🎮 **Manual**: full operator control

### Why ADscan?

- 🚀 **Auto-pwns retired HTB machines** in minutes (Forest, Active, Cicada)
- ⚡ **Save time**: less glue-work, more repeatable workflows
- 🎮 **Built for pentesters**: CLI-first, designed for operators
- 🧾 **Evidence packaging**: workspace outputs + report templates

> **Try ADscan PRO** — Request a **FREE 30-Day POV (first 5 teams)** at [adscanpro.com](https://adscanpro.com/?utm_source=github&utm_medium=readme&utm_campaign=lite_cta)
>
> **🔥 30-Day POV — COMPLETELY FREE (First 5 Teams Only):**
> - **⚡ LIMITED**: Only **5 FREE POV slots** available
> - **Duration**: 1 internal AD pentest project
> - **Team**: Up to 5 pentesters
> - **Pricing**: **100% FREE** for first 5 teams (after that: €497 + VAT standard)
> - **Includes**:
>   - Modes: automatic / semi-automatic / manual
>   - 1:1 onboarding (60-90 min) + priority support
>   - MITRE-mapped report templates
> - **📊 In exchange**: Measured case study (baseline vs ADscan) + honest testimonial + detailed feedback
> - **Zero risk**: If it doesn't deliver results (≥1 credential OR ≥1 day saved), simply walk away—no strings attached

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔓 LITE (Free)

**Core capabilities:**
- ✅ Three operation modes (automatic/semi-automatic/manual)
- ✅ Unauthenticated & authenticated reconnaissance
- ✅ Kerberos exploitation (AS-REP, Kerberoast)
- ✅ BloodHound integration & analysis
- ✅ Credential harvesting (SAM, LSA, DCSync)
- ✅ Workspace & evidence management
- ✅ Community Discord support

</td>
<td width="50%">

### 🔒 PRO (Coming Q4 2025)

**Planned enhancements:**
- 🎯 Trust relationship autonomous enumeration
- 🎫 ADCS ESC auto-exploitation
- 📄 MITRE-mapped Word/PDF reports (auto-generated)
- ☁️ Cloud-accelerated hash cracking
- 🔍 CVE/misconfig autonomous scanning
- 🤖 Advanced automated attack chains
- 🏢 Priority enterprise support

</td>
</tr>
</table>

---

## 📋 Requirements

| Requirement | Details |
|------------|---------|
| **OS** | Linux (Debian/Ubuntu/Kali and other Debian-based distros) |
| **Docker** | Docker Engine + Compose (plugin or `docker-compose`) |
| **Privileges** | User must be able to run Docker (`docker` group or `sudo`) |
| **Python** | Not required for Docker mode (pipx wrapper only) |
| **Network** | Internet to pull images, target network access |

---

## 🚀 Quick Install

```bash
# Install via pipx (recommended)
pipx install adscan

# Install (pulls the latest ADscan image + BloodHound CE images)
adscan install

# Start ADscan
adscan start
```

### BloodHound CE Password

During `adscan install`, ADscan will try to ensure the BloodHound CE `admin`
password is set to a known value for a smooth first-time experience:

```bash
adscan install --bh-admin-password 'Adscan4thewin!'
```

If the automatic password change fails (for example because BloodHound CE isn’t
ready yet), ADscan prints the exact manual steps to finish it in the web UI.

### Legacy (Host) Installer

ADscan also includes a legacy host-based installer for environments where Docker is not available:

```bash
adscan install --legacy
```

> **📚 Complete installation guide, quick start, and full documentation → [adscanpro.com/docs](https://adscanpro.com/docs?utm_source=github&utm_medium=readme&utm_campaign=install_cta)**

---

## 🤖 CI/CD Mode

ADscan supports non-interactive mode for automated testing. 

> **📚 Complete CI/CD documentation and examples → [adscanpro.com/docs](https://adscanpro.com/docs?utm_source=github&utm_medium=readme&utm_campaign=cicd_cta)**

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
- **Local-first**: All data stored in `$ADSCAN_HOME/workspaces/` (default: `~/.adscan/workspaces/`)

---

## 📚 Documentation

**All documentation, guides, walkthroughs, and command references are available at:**

### **[→ adscanpro.com/docs](https://adscanpro.com/docs?utm_source=github&utm_medium=readme&utm_campaign=docs_section)**

Includes installation guides, quick start, complete command reference, CTF walkthroughs, lab guides, best practices, and more.

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
- 📚 **[Complete documentation → adscanpro.com/docs](https://adscanpro.com/docs?utm_source=github&utm_medium=readme&utm_campaign=support_cta)**

---

## 🎓 Presented At

> **Announcement:** ADscan was presented at **Hackén 2025** cybersecurity conference.

---

## 📜 License

© 2025 Yeray Martín Domínguez — Released under custom EULA
ADscan LITE 3.2.1 | PRO edition: Q4 2025

---

<div align="center">

**⭐ Star this repo if ADscan helped you!** | **🔗 Share with [#adscan](https://twitter.com/search?q=%23adscan)**

Made with ❤️ for the pentesting community

</div>
