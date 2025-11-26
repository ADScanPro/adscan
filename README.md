<img width="1024" height="1024" alt="adscan_logo_horizontal_tagline" src="https://github.com/user-attachments/assets/77f3b465-faf6-4ea2-8838-9fcda31f993c" />

# ADscan

**ADscan** is a pentesting tool focused on automating collection, enumeration and common attack paths in **Active Directory**. It provides an interactive TUI with a wide range of commands to streamline internal audits and AD-focused pentests.

> **🔥 Why ADscan‑LITE?**  
> Shrinks AD recon/exploitation from **hours to minutes** – auto‑roots several retired HTB machines.  
> 100% CLI → perfect for CTFs, jump‑boxes and headless labs.  
> Seamless path to the coming **PRO** edition (target: late‑2025 / early‑2026).  
> 👉 **Request a 14‑day POV (free – no card):** [adscanpro.com](https://adscanpro.com/?utm_source=github&utm_medium=readme&utm_campaign=lite_cta)

---

> **Announcement:** ADscan was presented at the **Hackén 2025** cybersecurity conference.

## Table of Contents

- [Key Features](#key-features)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Running ADscan](#running-adscan)
- [Basic Usage Example](#basic-usage-example)
- [Interactive Demos](#interactive-demos)
- [Reporting Bugs](#reporting-bugs)
- [Roadmap](#roadmap)
- [Acknowledgements](#acknowledgements)

---

## Key Features

### Core engine (Lite & Pro foundation)

| Capability                                                                          |
| ----------------------------------------------------------------------------------- |
| Interactive shell (autocomplete, history)                                           |
| Colored, structured output (Rich)                                                   |
| Sequential unauth/auth scans (SMB · LDAP · RPC)                                     |
| Workspaces & credential persistence                                                 |
| Kerberos enumeration & roasting (AS‑REP / Kerberoast) + cracking helpers            |
| BloodHound collection helpers                                                       |
| (When available) credential dump / post‑ex primitives (SAM · LSA · DPAPI · DCSync)* |

> *Availability depends on license and safety prompts. Disruptive actions always require explicit confirmation.

### What LITE gives you today 🔓

|Feature|
|---|
|Auto‑pwn some HTB boxes|
|Semi‑automatic workflow prompts|
|Community support on Discord|

### What PRO adds (target: late‑2025 / early‑2026) 🔒

|Feature|
|---|
|Trust‑relationships auto‑enumeration|
|ADCS ESC auto‑exploit|
|One‑click **Word/PDF** report (MITRE/CVSS templated)|
|Cloud‑accelerated NTLM/TGS/AS‑REP cracking orchestration|
|Broad CVE/misconfig checks (LAPS, WinRM/RDP/SMB access, DA sessions, etc.)|

> **PRO activation** will be delivered as a simple license command when the edition ships.  
> Want early access for your consultancy? 👉 **Request a 14‑day POV**: [adscanpro.com](https://adscanpro.com/?utm_source=github&utm_medium=readme&utm_campaign=lite_cta)

---

## System Requirements

- **OS**: Linux (Debian/Ubuntu/Kali and other Debian‑based distros). Older versions supported.
    
- **Privileges**: Root access required for installation & full functionality (tooling installs, low‑level ops).
    
- **Dependencies**: Managed via `adscan install` (external tools + Python libs).
    

---

## Installation

1. **Install with pipx (recommended):**
    

```sh
pipx install adscan
```

Or using pip:

```sh
pip install adscan
```

Verify the CLI is available:

```sh
adscan --version
```

Alternatively, download a pre‑built binary from the [releases](https://github.com/ADscanPro/adscan/releases) page.

2. **Run the installer**
    

```sh
adscan install
```

This will:

- Set up the Python virtual environment.
    
- Install required Python packages.
    
- Download & configure external tools and wordlists.
    
- Launch BloodHound CE and configure the admin account automatically (`admin` / `Adscan4thewin!` by default).

3. **Verify installation**
    

```sh
adscan check
```

Performs checks and reports the status of dependencies and tools.

⚡ Ready to hack your first domain?  
Run `adscan start` and share your asciicast with #adscan on X/Twitter.

---

## Running ADscan

### Interactive Mode

The primary way to use ADscan is through the interactive TUI:

1. **Start the TUI**
    

```sh
adscan start
```

2. **Verbose mode (optional)**
    

```sh
adscan start -v
# or
adscan start --verbose
```

3. **Interactive prompt**
    

```text
(ADscan:your_workspace) >
```

4. **Getting help**
    

```sh
help                 # categories
help <command>       # command‑level help
```

### CI/CD Mode (Non-Interactive)

For automated testing and CI/CD pipelines, use the `ci` command:

```sh
# Unauthenticated scan
adscan ci unauth --type ctf --interface tun0 --hosts 10.10.10.10

# Authenticated scan
adscan ci auth --type ctf --interface tun0 --domain example.local --dc-ip 10.10.10.1 --username user --password pass

# Keep workspace after scan (useful for debugging)
adscan ci unauth --type ctf --interface tun0 --hosts 10.10.10.10 --keep-workspace
```

**CI Command Options:**
- `mode`: `auth` or `unauth` (required)
- `--type`, `-t`: Workspace type: `ctf` or `audit` (required)
- `--interface`, `-i`: Network interface to use (required)
- `--hosts`: CIDR range (required for `unauth` mode)
- `--domain`: Domain to scan (required for `auth` mode)
- `--dc-ip`: PDC IP for `auth` mode
- `--username`, `-u`: Username for `auth` mode
- `--password`, `-p`: Password for `auth` mode
- `--workspace`, `-w`: Optional workspace name (random if omitted)
- `--keep-workspace`: Keep the workspace after scan completion (do not delete auto-created workspace)
- `--verbose`, `-v`: Enable verbose mode

**Exit Codes:**
- `0`: Scan completed successfully with flags validated
- `1`: Scan failed
- `2`: Scan successful but flags invalid/missing

---

## Basic Usage Example

1. **Create/select a workspace**
    

```sh
(ADscan) > workspace create my_audit
(ADscan:my_audit) >
# or
(ADscan) > workspace select
```

2. **Configure network interface**
    

```sh
(ADscan:my_audit) > set iface eth0
```

3. **Choose automation level**
    

```sh
(ADscan:my_audit) > set auto False   # recommended for real audits
# set auto True   # faster for labs/CTFs
```

4. **Run scans**
    

- **Unauthenticated**
    

```sh
(ADscan:my_audit) > set hosts 192.168.1.0/24
(ADscan:my_audit) > start_unauth
```

- **Authenticated**
    

```sh
(ADscan:my_audit) > start_auth <domain> <pdc_ip> <username> <password_or_hash>
```

5. **Enumeration & exploitation**  
    Follow interactive prompts. Disruptive actions always prompt for confirmation, even in `auto=True`.
    

---

## Interactive Demos

### ⚙️ Semi-Automatic Mode (`auto=False`)

[![asciicast](https://asciinema.org/a/GJqRmSw6dj7oxsSKDHVIWyZpZ.svg)](https://asciinema.org/a/GJqRmSw6dj7oxsSKDHVIWyZpZ)

### ⚙️ Automatic Mode (`auto=True`)

[![asciicast](https://asciinema.org/a/723117.svg)](https://asciinema.org/a/734180)

_Auto‑pwns **Forest** (HTB retired) in ~3 minutes with ADscan‑LITE._  
Want trust‑enum, CVE, report and much more? 👉 **Request a 14‑day POV**: [adscanpro.com](https://adscanpro.com/?utm_source=github&utm_medium=readme&utm_campaign=lite_cta)

---

## Highlight: Modes & Data Handling

- **Automatic/Semi‑Automatic**: `auto=True` accelerates enumeration; `auto=False` provides more control for production networks.
    
- **Evidence & backups**: Credentials and progress are stored per‑workspace (JSON), making it easy to resume.
    
- **Service detection**: IPs are grouped by detected services (SMB, WinRM, LDAP, etc.) for next steps.
    
- **Safety**: Potentially disruptive operations are gated and require explicit confirmation.
    
- **Telemetry**: Opt‑in by default for the LITE build; toggle off anytime with `set telemetry off` (no sensitive payloads; used to improve speed & stability).
    

---

## Reporting Bugs

Open an issue in this repo or chat on **Discord**: [https://discord.com/invite/fXBR3P8H74](https://discord.com/invite/fXBR3P8H74)  
Your feedback shapes the PRO roadmap.

---

## Roadmap

|Quarter|Milestone|
|---|---|
|**Q3‑2025**|More ACL exploitation & pre‑2k module · Kerberos unconstrained pathing|
|**Q4‑2025**|**PRO** release target – trust enum, ADCS ESC exploit, auto Word/PDF report|
|**Q1‑2026**|NTLM relay chain · SCCM module|
|**Q2‑2026**|PwnDoc report integration · Cloud‑accelerated cracking for AS‑REP/Kerberoast|

> Timelines are targets, not promises; feature scope may adjust based on POV feedback.

---

## Compromise Coverage Lab Matrix

| Provider | Lab / Machine | Status |
| --- | --- | --- |
| Hack The Box | Active (retired) | ✅ |
| Hack The Box | Forest (retired) | ✅ |
| Hack The Box | Cicada (retired) | ✅ |

> Looking for contributions: if you maintain AD-centric labs (HTB, TryHackMe, VulnLab, custom GOAD snapshots) that ADscan compromises end-to-end, open an issue or PR with details so we can expand the matrix.
    
---

© 2025 Yeray Martín Domínguez – Released under EULA.  
ADscan 2.3.0‑lite · PRO edition target: late‑2025 / early‑2026.
