<p align="center">
  <img src="https://github.com/user-attachments/assets/fc67100a-28d6-4276-b487-0254dbf32b27" 
       alt="logo" 
       width="400" 
       height="auto">
</p>

# ADscan

**ADscan** is a pentesting tool focused on automating the collection and enumeration of information in **Active Directory**. It offers an interactive shell with a wide range of commands to streamline auditing and penetration testing processes in Windows/AD environments.

> **IMPORTANT:** This repository is private and is shared only with beta testers for internal testing. **The code is non-redistributable**; sharing or publishing any part of this project is not allowed, as it will eventually become a paid commercial tool.

---

## Table of Contents

- [Key Features](#key-features)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Running ADScan-CLI](#running-adscan-cli)
- [Basic Usage Example](#basic-usage-example)
- [Interactive Demos](#interactive-demos)
- [Reporting Bugs](#reporting-bugs)
- [Community](#community)
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
    - Enumeration of Domain Controllers (DCs), password policies, trust relationships, etc.
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

ADscan has a streamlined installation process handled by the tool itself.

1. **Generate Your Personal Access Token (PAT) on GitHub**  
    Since GitHub **no longer allows** password authentication for cloning private repositories, each user must generate their own **Personal Access Token (PAT)**. To do so:
    
    - Log in to your GitHub account.
    - Go to **Settings** > **Developer settings** > **Personal access tokens** > **Tokens (classic)** > **Generate new token**.
    - Select the necessary permissions (e.g., `repo`) and click **Generate token**.
    - Copy and save your token in a secure place. You will need it to download the program.

> **Optionally**, you can use SSH keys instead of a PAT if you prefer that configuration.

2. **Download the program**

    You can download the program from the **[releases](https://github.com/ADScan-Beta/adscan-cli/releases/tag/v2.0.0-beta)** section or, alternatively, if you have GitHub CLI installed, you can do it from the shell:

    ```sh
    sudo apt install gh
    gh auth login
    gh release download v2.0.0-beta --repo https://github.com/ADScan-Beta/adscan-cli
    mkdir adscan
    cd adscan
    chmod +x adscan-cli
    ```
    If using a PAT, enter your GitHub username and the PAT when prompted.

3.  **Run the Installer**:
    The old `setup.sh` script is no longer used. Installation is now handled directly by ADScan-CLI:
    ```sh
    sudo ./adscan-cli install
    ```
    This command will:
    - Set up the necessary Python virtual environment.
    - Install all required Python packages.
    - Download and configure external tools and wordlists.

> **Note:** If you previously installed ADScan-CLI using `setup.sh`, it is still **highly recommended** to run `sudo ./adscan-cli install` to ensure all components are correctly updated and configured for the new version.

4.  **Verify the Installation**:
    After the installation completes, you can check if all components are set up correctly:
    ```sh
    sudo ./adscan-cli check
    ```
    This command will perform a series of checks and report the status of dependencies and tools.

---

## Running ADscan

1.  **Start the Tool**:
    To launch the interactive shell, run:
    ```sh
    sudo ./adscan-cli start
    ```

2.  **Verbose Mode (Optional)**:
    For more detailed output during startup and operations, use the `-v` or `--verbose` flag:
    ```sh
    sudo ./adscan-cli start -v
    # or
    sudo ./adscan-cli start --verbose
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
      (ADScan:your_workspace) > help <category_or_command>
      ```

---

## Basic Usage Example

1.  **Create or Select a Workspace**:
    Organize your audits by creating or selecting a workspace.
    ```sh
    (ADScan) > workspace create my_audit
    (ADScan:my_audit) > 
    ```
    Or select an existing one:
    ```sh
    (ADScan) > workspace select
    # (Follow prompts to choose a workspace)
    ```

2.  **Configure Network Interface**:
    Set the network interface for operations. Your IP will be automatically assigned to the `myip` variable.
    ```sh
    (ADScan:my_audit) > set iface eth0
    ```

3.  **Choose Automation Level**:
    - `set auto True`: More automation, fewer prompts (good for CTFs).
    - `set auto False`: Semi-automatic, more control (recommended for real audits).
    ```sh
    (ADScan:my_audit) > set auto False
    ```

4.  **Perform Scans**:
    - **Unauthenticated Scan** (if you don't have credentials yet):
      ```sh
      (ADScan:my_audit) > set hosts 192.168.1.0/24
      (ADScan:my_audit) > start_unauth
      ```
      Ensure your DNS (`/etc/resolv.conf`) is correctly configured or use `update_resolv_conf <domain> <dc_ip>` within the tool.

    - **Authenticated Scan** (if you have credentials):
      ```sh
      (ADScan:my_audit) > start_auth <domain_name> <username> <password_or_hash>
      ```

5.  **Enumeration and Exploitation**:
    The tool will guide you through enumeration options based on scan results. Specific commands are also available:
    ```sh
    (ADScan:my_audit) > dump_lsa <domain> <user> <password> <host> <islocal>
    (ADScan:my_audit) > kerberoast <domain>
    (ADScan:my_audit) > bloodhound_python <domain>
    ```
    Exploitation actions always require confirmation, even in automatic mode.

---

## 🎥 Interactive Demos

### ⚙️ Semi-Automatic Mode (`auto=False`)

[![asciicast](https://asciinema.org/a/GJqRmSw6dj7oxsSKDHVIWyZpZ.svg)](https://asciinema.org/a/GJqRmSw6dj7oxsSKDHVIWyZpZ)

> In this demo, the “Forest” machine from HackTheBox is solved using ADScan-CLI in semi-automatic mode, with user intervention at each key step.

---

## Highlighted Features

- **Automatic/Semi-Automatic Mode**: While `auto=True` speeds up scanning, it is recommended to use `auto=False` for more control in large networks. _Exploitation actions always require confirmation._
- **Data Backup**: Credentials and progress are automatically stored in JSON files within each workspace, making it easier to resume the audit after restarting the tool.
- **Service Detection**: Based on _nmap_, _netexec_, and other utilities, it groups IPs according to detected services (SMB, WinRM, LDAP, etc.) for subsequent exploitation.

---

## Reporting Bugs

If you encounter any bugs or unexpected errors while using ADScan-CLI, please create an Issue in the “Issues” section of this GitHub repository.

Your feedback is very important for improving the tool during this beta phase.

---

## 🌐 Community

Join our **private Discord community** for official beta testers of ADScan-CLI!

📢 **Why join?**
- Direct communication with the development team.
- Ask questions, share feedback, and report bugs faster.
- Get notified of new releases, changelogs, and future updates.
- Participate in Q&As, upcoming workshops, and live testing sessions.

🔐 **How to join:**
- This server is **exclusive** to registered beta testers.
- Use the invite link: [Join ADScan Community on Discord](https://discord.com/invite/fXBR3P8H74)
- After joining, go to the `#beta-verification` channel and run `/verify your_email@example.com` (use the email you applied with).

📩 **Issues with verification?** Contact us at `hello@adscanpro.com` or message `Yeray | Founder of ADScan` on Discord directly.

Let’s build something awesome together. 💪

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

## Legal Disclaimer

This project is shared exclusively for **internal testing purposes**. **Redistribution** or publication in public environments is prohibited. Violation of these restrictions may have legal consequences. In the future, the tool will be released commercially under a paid license.

---

## License

- **Non-Redistributable Code**: The software and source code contained herein are the property of the author and/or designated collaborators. **Redistribution, unauthorized modification, or publication on third-party services is not allowed.**
