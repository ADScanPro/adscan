<img width="1024" height="1024" alt="adscan_logo_horizontal_tagline" src="https://github.com/user-attachments/assets/77f3b465-faf6-4ea2-8838-9fcda31f993c" />

# ADscan

**ADscan** is a pentesting tool focused on automating the collection and enumeration of information in **Active Directory**. It offers an interactive shell with a wide range of commands to streamline auditing and penetration testing processes in Windows/AD environments.


> **🔥 Why ADscan-LITE?**  
> Shrinks AD recon/exploitation from **hours to minutes** – auto-roots some retired HTB machines.  
> 100 % CLI → perfect for CTFs, jump-boxes and headless labs.
> Seamless path to the coming PRO edition (Q4-2025).
> 👉 **Reserve -50 % Founder price** → [wait-list](https://adscanpro.com/pro-waitlist)

---

> **Announcement:** ADscan was officially announced at the Hackén 2025 cybersecurity conference.

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

### Core engine (both Lite & Pro)
| Feature |
|---------|
| Advanced interactive shell (autocomplete, history) |
| Colored, structured output |
| Sequential unauth/auth scans (SMB · LDAP · RPC) |
| Workspace & credential persistence |
| Credential dump – SAM · LSA · DPAPI · DCSync |
| Auto AS-REP Roast & Kerberoast (includes preauth) enumeration & cracking |
| BloodHound integration |
| Shadow Creds / ACL path finding |
| Auto compromised user privilege escalation |

### What Lite gives you today   🔓
| Feature |
|---------|
| Auto-pwn some HTB boxes |
| Semi-automatic workflow prompts |
| Community support on Discord |

### What PRO adds in Q4-2025   🔒
| Feature |
|---------|
| Trust-relationships auto-enumeration |
| ADCS ESC auto-exploit |
| One-click Word/PDF report |
| Auto Cloud NTLM hash cracking |
| Auto CVE enumeration on DCs and all domain computers |
| Auto common pentest misconfiguration checks like LAPS, connection permissions (WinRM, RDP, SMB), Domain Admin sessions, etc.


> **PRO activation** will be delivered as a simple license command when the edition ships.  
> Lock the lifetime discount now → [Founder wait-list](https://adscanpro.com/pro-waitlist)

---

## System Requirements

- **Operating System**: Linux (Debian, Ubuntu, Kali Linux, and other Debian-based distributions, including older versions).
- **Privileges**: Root access is required for installation and full functionality (e.g., network operations, tool installation).
- **Dependencies**: All necessary external tools and Python libraries are managed and installed by the `install` command.

---

## Installation

1.  Install ADscan using pipx (recommended):

```sh
pipx install adscan
```
Or, using pip:
```sh
pip install adscan
```

After installation, verify that the `adscan` command is available:

```sh
adscan --version
```

Alternatively, download a pre-built binary from the [releases](https://github.com/ADscanPro/adscan/releases) page and place it in your `$PATH`.

2.  **Run the Installer**:
    ```sh
    adscan install
    ```
    This command will:
    - Set up the necessary Python virtual environment.
    - Install all required Python packages.
    - Download and configure external tools and wordlists.

3.  **Verify the Installation**:
    After the installation completes, you can check if all components are set up correctly:
    ```sh
    adscan check
    ```
    This command will perform a series of checks and report the status of dependencies and tools.

⚡ Ready to hack your first domain?
Run `adscan start` and share your asciicast with #adscan on Twitter.

---

## Running ADscan

1.  **Start the Tool**:
    To launch the interactive shell, run:
    ```sh
    adscan start
    ```

2.  **Verbose Mode (Optional)**:
    For more detailed output during startup and operations, use the `-v` or `--verbose` flag:
    ```sh
    adscan start -v
    # or
    adscan start --verbose
    ```

3.  **The Interactive Prompt**:
    Once started, you will see the ADscan prompt, which includes the current workspace:
    ```sh
    (ADscan:your_workspace) > 
    ```

4.  **Getting Help**:
    - For a list of all command categories:
      ```sh
      (ADscan:your_workspace) > help
      ```
    - For help on a specific category or command:
      ```sh
      (ADscan:your_workspace) > help <category_or_command>
      ```

---

## Basic Usage Example

1.  **Create or Select a Workspace**:
    Organize your audits by creating or selecting a workspace.
    ```sh
    (ADscan) > workspace create my_audit
    (ADscan:my_audit) > 
    ```
    Or select an existing one:
    ```sh
    (ADscan) > workspace select
    # (Follow prompts to choose a workspace)
    ```

2.  **Configure Network Interface**:
    Set the network interface for operations. Your IP will be automatically assigned to the `myip` variable.
    ```sh
    (ADscan:my_audit) > set iface eth0
    ```

3.  **Choose Automation Level**:
    - `set auto True`: More automation, fewer prompts (good for CTFs).
    - `set auto False`: Semi-automatic, more control (recommended for real audits).
    ```sh
    (ADscan:my_audit) > set auto False
    ```

4.  **Perform Scans**:
    - **Unauthenticated Scan** (if you don't have credentials yet):
      ```sh
      (ADscan:my_audit) > set hosts 192.168.1.0/24
      (ADscan:my_audit) > start_unauth
      ```

    - **Authenticated Scan** (if you have credentials):
      ```sh
      (ADscan:my_audit) > start_auth <domain_name> <username> <password_or_hash>
      ```

5.  **Enumeration and Exploitation**:
    The tool will guide you through enumeration options based on scan results. Specific commands are also available:
    ```sh
    (ADscan:my_audit) > dump_lsa <domain> <user> <password> <host> <islocal>
    (ADscan:my_audit) > kerberoast <domain>
    (ADscan:my_audit) > bloodhound_python <domain>
    ```
    Exploitation actions always require confirmation, even in automatic mode.

---

## Interactive Demos

### ⚙️ Semi-Automatic Mode (`auto=False`)

[![asciicast](https://asciinema.org/a/GJqRmSw6dj7oxsSKDHVIWyZpZ.svg)](https://asciinema.org/a/GJqRmSw6dj7oxsSKDHVIWyZpZ)

### ⚙️ Automatic Mode (`auto=True`)

[![asciicast](https://asciinema.org/a/GJqRmSw6dj7oxsSKDHVIWyZpZ.svg)](https://asciinema.org/a/723304)

_Auto-powns **Forest** (HTB retired) in < 1 min with ADscan-LITE._  
Want trust-enum & PDF report? 👉 [Join Founder wait-list](https://adscanpro.com/pro-waitlist)

---

## Highlighted Features

- **Automatic/Semi-Automatic Mode**: While `auto=True` speeds up scanning, it is recommended to use `auto=False` for more control in large networks. _Exploitation actions always require confirmation._
- **Data Backup**: Credentials and progress are automatically stored in JSON files within each workspace, making it easier to resume the audit after restarting the tool.
- **Service Detection**: Based on _nmap_, _netexec_, and other utilities, it groups IPs according to detected services (SMB, WinRM, LDAP, etc.) for subsequent exploitation.

---

## Reporting Bugs

If you encounter any bugs or unexpected errors while using ADscan, please open an issue in the “Issues” section of this GitHub repository or chat on our [Discord](https://discord.com/invite/fXBR3P8H74)

Your feedback shapes the roadmap to PRO.

---

## Roadmap

|Quarter|Milestone|
|---|---|
|**Q3-2025**| more ACL exploitation & pre2k module · Kerberos Unconstrained exploit|
|**Q4-2025**|**PRO launch** – trust enum, ADCS ESC exploit, auto Word/PDF report|
|**Q1-2026**|NTLM relay chain · SCCM module|
|**Q2-2026**|PwnDoc report integration · Hyper-Fast Cloud computing cracking for AS-REP and Kerberoast hashes|

---

## Acknowledgements

- **NetExec**: For its powerful assistance in SMB, WinRM, etc. enumeration.
- **BloodHound & bloodhound.py**: An essential tool for collecting and analyzing AD attack paths.
- **Impacket**: For its invaluable suite of Python classes for working with network protocols.
- **Rich**: For making the CLI beautiful and user-friendly.
- **Prompt Toolkit**: For the advanced interactive shell capabilities.
- **Certipy**: Highly useful for enumerating ADCS escalations.
- And all other open-source tools and libraries that make ADscan possible.

And thanks to the entire community of pentesters and researchers who have contributed knowledge and tools to the Active Directory ecosystem.

---

© 2025 Yeray Martín Domínguez – Released under EULA.
ADscan 2.0.0-lite · PRO edition arrives Q4-2025.
