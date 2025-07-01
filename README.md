<p align="center">
  <img src="https://github.com/user-attachments/assets/fc67100a-28d6-4276-b487-0254dbf32b27" 
       alt="logo" 
       width="400" 
       height="auto">
</p>

# ADscan

**ADscan** is a pentesting tool focused on automating the collection and enumeration of information in **Active Directory**. It offers an interactive shell with a wide range of commands to streamline auditing and penetration testing processes in Windows/AD environments.

---

> **Edition**: **LITE edition** of ADscan. This edition includes core domain enumeration, credential dumping, and vulnerability scanning. *Trust relationships enumeration and advanced modules are available in the upcoming PRO edition.*

> **Announcement:** ADscan was officially announced at the Hackén 2025 cybersecurity conference.

## Table of Contents

- [Key Features](#key-features)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Running ADscan](#running-adscan)
- [Basic Usage Example](#basic-usage-example)
- [Interactive Demos](#interactive-demos)
- [Reporting Bugs](#reporting-bugs)
- [Future Development (TODO)](#future-development-todo)
- [Acknowledgements](#acknowledgements)

---

## Key Features

- **Advanced Interactive Shell**: A powerful and user-friendly command-line interface built with, featuring:
    - Intelligent, context-aware command and argument autocompletion.
    - Persistent command history for easier recall and repetition of commands.
    - Enhanced navigation and editing capabilities.
- **Structured Output**:
    - Clear, colored, and well-formatted output for better readability.
    - Less verbose logging by default, with options for more detailed information.
    - Consistent and aesthetically pleasing user experience.
- **Sequential & Controlled Execution**: Operations are now primarily sequential, reducing network noise and providing more predictable behavior, especially in sensitive environments.
- **Unauthenticated Enumeration**: Supports SMB, LDAP, and Kerberos scans without credentials.
- **Authenticated Enumeration**: Allows authentication using a username and password (or NTLM hashes) to perform tasks such as:
    - Enumeration of domains, users, and groups.
    - Enumeration of Domain Controllers (DCs) and password policies.
    - **PRO only**: Trust relationships enumeration.
    - Credential dumping (SAM, LSA, DPAPI, DCSync, among others).
    - Exploitation of vulnerabilities and insecure configurations (Kerberoast, AS-REP Roasting, SMB misconfigurations, ADCS, delegations, etc.).
- **Cracking Module**: Integration with Hashcat and automated hash extraction for subsequent cracking.
- **Integrated BloodHound**: Runs BloodHound for advanced analysis of attack paths in AD.
- **Workspace Management**: Create, select, delete, and save different workspaces to organize auditing projects.
- **Credential Persistence**: Internally stores discovered or injected credentials for automatic reuse in various modules.

---

## System Requirements

- **Operating System**: Linux (Debian, Ubuntu, Kali Linux, and other Debian-based distributions, including older versions).
- **Privileges**: Root access is required for installation and full functionality (e.g., network operations, tool installation).
- **Dependencies**: All necessary external tools and Python libraries are managed and installed by the `install` command.

---

## Installation

Install ADscan using pipx (recommended):

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

---

## Running ADscan

> **Tip (Optional):** To avoid manually prefixing `sudo`, you can add the following alias to your shell RC (e.g., `~/.bashrc` or `~/.zshrc`):
>
> ```sh
> alias adscan='sudo -E $(which adscan)'
> ```

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
      Ensure your DNS (`/etc/resolv.conf`) is correctly configured or use `update_resolv_conf <domain> <dc_ip>` within the tool.

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

## 🎥 Interactive Demos

### ⚙️ Semi-Automatic Mode (`auto=False`)

[![asciicast](https://asciinema.org/a/GJqRmSw6dj7oxsSKDHVIWyZpZ.svg)](https://asciinema.org/a/GJqRmSw6dj7oxsSKDHVIWyZpZ)

> In this demo, the “Forest” machine from HackTheBox is solved using ADscan in semi-automatic mode, with user intervention at each key step.

---

## Highlighted Features

- **Automatic/Semi-Automatic Mode**: While `auto=True` speeds up scanning, it is recommended to use `auto=False` for more control in large networks. _Exploitation actions always require confirmation._
- **Data Backup**: Credentials and progress are automatically stored in JSON files within each workspace, making it easier to resume the audit after restarting the tool.
- **Service Detection**: Based on _nmap_, _netexec_, and other utilities, it groups IPs according to detected services (SMB, WinRM, LDAP, etc.) for subsequent exploitation.

---

## Reporting Bugs

If you encounter any bugs or unexpected errors while using ADscan, please open an issue in the “Issues” section of this GitHub repository.

Your feedback is very important for improving the tool.

---

## Future Development (TODO)

The following are planned improvements and features:

- **CVE Exploitation Expansion**: Add more specific CVE checks and exploitation modules (e.g., PrintNightmare variants, DropTheMic, etc.).
- **Enhanced Kerberos Attacks**: Deepen support for various delegation types (e.g., Unconstrained Delegation exploitation) and other Kerberos-based attacks.
- **Advanced ADCS Exploitation**: Incorporate more Active Directory Certificate Services escalation techniques.
- **Broader Enumeration**: Add modules for Pre-Windows 2000 (pre2k) compatibility enumeration and SCCM/MECM discovery and exploitation vectors.
- **NTLM Relay & Sniffing**: Integrate or improve NTLM relay attack capabilities and internal network sniffing features.
- **ACL & Security Descriptor Analysis**: More granular ACL analysis and exploitation paths.
- **Automated Reporting**: Generate comprehensive audit reports in multiple formats (JSON, HTML, Markdown).
- **Post-Exploitation Integration**: Better hooks or modules for common post-exploitation activities.
- **Visualizations**: Simple in-CLI visualizations for domain structure or trust relationships.
- **Configuration Hardening Checks**: Modules to identify common AD misconfigurations beyond direct vulnerabilities.

---

## Acknowledgements

- **NetExec**: For its powerful assistance in SMB, WinRM, etc. enumeration.
- **BloodHound & bloodhound.py**: An essential tool for collecting and analyzing AD attack paths.
- **Impacket**: For its invaluable suite of Python classes for working with network protocols.
- **Rich**: For making the CLI beautiful and user-friendly.
- **Prompt Toolkit**: For the advanced interactive shell capabilities.
- **Impacket**: For its collection of indispensable scripts (secretsdump, GetUserSPNs, etc.).
- **Certipy**: Highly useful for enumerating ADCS escalations.
- And all other open-source tools and libraries that make ADscan possible.

And thanks to the entire community of pentesters and researchers who have contributed knowledge and tools to the Active Directory ecosystem.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
