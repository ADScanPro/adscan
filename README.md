# ADscan

<div align="center">

<img width="800" alt="ADscan Logo" src="https://github.com/user-attachments/assets/77f3b465-faf6-4ea2-8838-9fcda31f993c" />

[![Version](https://img.shields.io/badge/version-3.1.0--lite-blue.svg)](https://github.com/ADscanPro/adscan/releases)
[![downloads](https://static.pepy.tech/badge/adscan)](https://pepy.tech/projects/cai-adscan)
[![License](https://img.shields.io/badge/license-EULA-red.svg)](https://github.com/ADscanPro/adscan/blob/main/LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://github.com/ADscanPro/adscan)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Discord](https://img.shields.io/discord/1355089867096199300?color=7289da&label=Discord&logo=discord&logoColor=white)](https://discord.com/invite/fXBR3P8H74)

**[📚 Complete Documentation → adscanpro.com/docs](https://adscanpro.com/docs?utm_source=github&utm_medium=readme&utm_campaign=docs_cta)** • [Discord](https://discord.com/invite/fXBR3P8H74)

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

> **Try ADscan PRO** — Request a **30-day paid POV (Proof of Value)** at [adscanpro.com](https://adscanpro.com/?utm_source=github&utm_medium=readme&utm_campaign=lite_cta)
>
> POV details:
> - **Duration**: 30 days
> - **Launch pricing (beta)**: **€497 + VAT** (first **3–5 teams**: **€297 + VAT** in exchange for a case study + testimonial + detailed feedback)
> - **Guarantee**: **100% refund** if, after onboarding + an agreed baseline, you don't get at least one usable credential **or** ADscan doesn't save **≥1 full day** of work
> - **Limited exception**: up to **2 case-study POV slots** may be fee-waived for perfect-fit teams who agree to measure baseline vs ADscan and provide a case study

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

## 🚀 Quick Install

```bash
# Install via pipx (recommended)
pipx install adscan

# Install dependencies
adscan install

# Start ADscan
adscan start
```

> **📚 Complete installation guide, quick start, and full documentation → [adscanpro.com/docs](https://adscanpro.com/docs?utm_source=github&utm_medium=readme&utm_campaign=install_cta)**

---

## 🎬 Demo

[![asciicast](https://asciinema.org/a/734180.svg)](https://asciinema.org/a/734180?autoplay=1)

_Auto-pwns **HTB Forest** in ~3 minutes_ 🚀

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
- **Local-first**: All data stored in `~/.adscan/workspaces/`
- **Open source LITE**: Transparent security tool

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
ADscan LITE 3.1.0 | PRO edition: Q4 2025

---

<div align="center">

**⭐ Star this repo if ADscan helped you!** | **🔗 Share with [#adscan](https://twitter.com/search?q=%23adscan)**

Made with ❤️ for the pentesting community

</div>
