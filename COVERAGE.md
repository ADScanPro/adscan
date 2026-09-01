# ADscan — Active Directory Attack Coverage

Every technique below is implemented in ADscan and mapped to MITRE ATT&CK.

**How to read the Status column.** ADscan validates exposure — it proves whether a
path to compromise exists. It does not test your defensive stack, and it never
claims a security product blocked anything.

- **Executed** — ADscan runs the technique end to end and proves the outcome.
- **Detected** — ADscan identifies and maps the exposure but does not execute it.
- **Detected · not executed (safety)** — ADscan deliberately refuses to run it
  because it is destructive or disruptive to a production directory.
- **Observed (attack-path pivot)** — a condition ADscan observes and chains into
  an attack path rather than a standalone step it runs.

This page is generated from the product catalog by
`scripts/sync_technique_count.py`. Do not edit the table by hand; edit the
catalog and regenerate.

<!-- BEGIN GENERATED: technique-inventory -->

**104 techniques** across 15 categories · 71 executed end to end · AD CS ESC1–ESC17 · 79 reported finding types.

### ACL / ACE Abuse (18)

| Technique | What ADscan does | Status | MITRE ATT&CK |
|---|---|---|---|
| Add Member to Group | Add arbitrary members to target group | Executed | [T1098](https://attack.mitre.org/techniques/T1098/) |
| Add Self to Group | Self-add to controlled group under permissive ACL | Executed | [T1098](https://attack.mitre.org/techniques/T1098/) |
| All Extended Rights | Broad extended rights over directory object | Executed | [T1098](https://attack.mitre.org/techniques/T1098/) |
| Force Change Password | Reset target account password without current password | Executed | [T1098](https://attack.mitre.org/techniques/T1098/) |
| GenericAll | Full object control over target principal/object | Executed | [T1098](https://attack.mitre.org/techniques/T1098/) |
| GenericWrite | Write permissions over target object attributes | Executed | [T1098](https://attack.mitre.org/techniques/T1098/) |
| Object Ownership | Object ownership grants implicit GenericAll-equivalent rights | Executed | [T1222.001](https://attack.mitre.org/techniques/T1222/001/) |
| RODC Password Replication Policy Control | Modify the RODC password-replication policy on the RODC computer object | Observed (attack-path pivot) | [T1098](https://attack.mitre.org/techniques/T1098/) |
| Read LAPS Password | Read LAPS local administrator password | Executed | [T1555](https://attack.mitre.org/techniques/T1555/) |
| Read gMSA Password | Read gMSA managed password material | Executed | [T1555](https://attack.mitre.org/techniques/T1555/) |
| Shadow Credentials (Key Credential Link) | Write msDS-KeyCredentialLink to add shadow credentials | Executed | [T1649](https://attack.mitre.org/techniques/T1649/) |
| Sync LAPS Password | Read/replicate LAPS password material | Detected | [T1555](https://attack.mitre.org/techniques/T1555/) |
| Writable SMB Path | Theoretical write access to an SMB share/path that can host attack payloads | Observed (attack-path pivot) | [T1105](https://attack.mitre.org/techniques/T1105/) |
| Write Account Restrictions | Modify account-restriction property sets on the target user/computer object | Executed | [T1098](https://attack.mitre.org/techniques/T1098/) |
| Write Logon Script | Write the user's logon script path to attacker-controlled content | Executed | [T1098](https://attack.mitre.org/techniques/T1098/) |
| Write SPN | Set SPN to force kerberoastable ticket generation | Executed | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) |
| WriteDACL | Rewrite ACLs to grant further privileges | Executed | [T1222.001](https://attack.mitre.org/techniques/T1222/001/) |
| WriteOwner | Take ownership to unlock privilege escalation | Executed | [T1222.001](https://attack.mitre.org/techniques/T1222/001/) |
### AD CS — Certificate Services (17)

| Technique | What ADscan does | Status | MITRE ATT&CK |
|---|---|---|---|
| AD CS ESC1 | Enroll exploitable template and authenticate as target | Executed | [T1649](https://attack.mitre.org/techniques/T1649/) |
| AD CS ESC10 | ADCS ESC10 privilege escalation path | Detected | [T1649](https://attack.mitre.org/techniques/T1649/) |
| AD CS ESC11 | ADCS ESC11 privilege escalation path | Executed | [T1649](https://attack.mitre.org/techniques/T1649/) |
| AD CS ESC13 | ADCS ESC13 effective linked-group membership path | Executed | [T1649](https://attack.mitre.org/techniques/T1649/) |
| AD CS ESC14 | ADCS ESC14 privilege escalation path | Executed | [T1649](https://attack.mitre.org/techniques/T1649/) |
| AD CS ESC15 | ADCS ESC15 privilege escalation path | Executed | [T1649](https://attack.mitre.org/techniques/T1649/) |
| AD CS ESC16 | ADCS ESC16 privilege escalation path | Detected | [T1649](https://attack.mitre.org/techniques/T1649/) |
| AD CS ESC17 | ADCS ESC17 privilege escalation path | Detected | [T1557](https://attack.mitre.org/techniques/T1557/) |
| AD CS ESC2 | ADCS ESC2 privilege escalation path | Executed | [T1649](https://attack.mitre.org/techniques/T1649/) |
| AD CS ESC3 | Use enrollment agent cert to request impersonation certs | Executed | [T1649](https://attack.mitre.org/techniques/T1649/) |
| AD CS ESC4 | Modify template permissions/configuration for abuse | Executed | [T1649](https://attack.mitre.org/techniques/T1649/) |
| AD CS ESC5 — Vulnerable PKI Object Access Control | ADCS ESC5 privilege escalation path | Executed | [T1649](https://attack.mitre.org/techniques/T1649/) |
| AD CS ESC6 | ADCS ESC6 privilege escalation path | Executed | [T1649](https://attack.mitre.org/techniques/T1649/) |
| AD CS ESC7 | ADCS ESC7 privilege escalation path | Executed | [T1649](https://attack.mitre.org/techniques/T1649/) |
| AD CS ESC8 | ADCS ESC8 privilege escalation path | Executed | [T1649](https://attack.mitre.org/techniques/T1649/) |
| AD CS ESC9 | ADCS ESC9 privilege escalation path | Executed | [T1649](https://attack.mitre.org/techniques/T1649/) |
| Coerce and Relay NTLM to AD CS (ESC8) | Coerce NTLM authentication and relay it to ADCS endpoints | Executed | [T1187](https://attack.mitre.org/techniques/T1187/) |
### Authentication Coercion (3)

| Technique | What ADscan does | Status | MITRE ATT&CK |
|---|---|---|---|
| DFSCoerce | Coerce machine authentication via DFS endpoint behavior | Detected | [T1187](https://attack.mitre.org/techniques/T1187/) |
| PetitPotam | MS-EFSRPC coercion path (PetitPotam) | Detected | [T1187](https://attack.mitre.org/techniques/T1187/) |
| PrinterBug (MS-RPRN) | Spooler coercion path (PrinterBug) | Detected | [T1187](https://attack.mitre.org/techniques/T1187/) |
### Collection (1)

| Technique | What ADscan does | Status | MITRE ATT&CK |
|---|---|---|---|
| MSSQL OPENROWSET Bulk Read | SQL Server can read the raw content of any file the SQL Server service account can access on its host, without executing a single operating-system command. Any principal holding ADMINISTER BULK OPERATIONS — sysadmin, the bulkadmin fixed server role, an explicit grant, or a linked-server login mapping that lands on the same permission remotely — can pull configuration files, backup files, and scripts off the host and recover any credentials or connection strings stored in them. | Executed | [T1005](https://attack.mitre.org/techniques/T1005/) |
### Credential Access (15)

| Technique | What ADscan does | Status | MITRE ATT&CK |
|---|---|---|---|
| DCSync | Replicate AD secrets remotely from domain controller | Executed | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) |
| DPAPI Secret Extraction | Credential extraction from DPAPI-protected material | Executed | [T1555.004](https://attack.mitre.org/techniques/T1555/004/) |
| DS-Replication-Get-Changes | Partial replication right; combined with GetChangesAll enables DCSync | Detected | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) |
| DS-Replication-Get-Changes-All | Extended replication right; combined with GetChanges enables DCSync | Detected | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) |
| DS-Replication-Get-Changes-In-Filtered-Set | Replication right over filtered attribute set data | Detected | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) |
| Domain Password Reuse | Domain account credential reuse pivot through clustered shared secret material | Observed (attack-path pivot) | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) |
| LLMNR/NBT-NS Poisoning and NetNTLMv2 Recovery | Broadcast name-resolution poisoning to NetNTLMv2 capture and offline crack: an unauthenticated attacker on the same local network segment as the victim answers LLMNR, NBT-NS, and mDNS name-resolution requests with a rogue address, causing the victim to authenticate to the attacker. The captured NetNTLMv2 challenge/response is then cracked offline to recover the user's cleartext password, converting a wire capture into a usable domain credential without any prior access. | Executed | [T1557.001](https://attack.mitre.org/techniques/T1557/001/) |
| LSA Secrets Extraction | Credential extraction from LSA secrets | Executed | [T1003.004](https://attack.mitre.org/techniques/T1003/004/) |
| LSASS Credential Extraction | Credential extraction from LSASS memory | Executed | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) |
| Local-to-Domain Credential Reuse | Credential reuse pivot from local credential material to domain identity | Observed (attack-path pivot) | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) |
| MSSQL NetNTLMv2 Theft | A SQL sysadmin (or any user with EXECUTE rights on xp_dirtree / xp_fileexist) can force the SQL Server service account to authenticate to an attacker-controlled SMB share, capturing its NTLMv2 response hash. If the service account is a domain user, the hash can be cracked offline or relayed to authenticate as that account on other network resources. | Executed | [T1557.001](https://attack.mitre.org/techniques/T1557/001/) |
| RODC krbtgt Secret Extraction | Extract the per-RODC krbtgt secret from the compromised RODC | Executed | [T1003](https://attack.mitre.org/techniques/T1003/) |
| Readable Share | Principal has read access to a network SMB share | Executed | [T1039](https://attack.mitre.org/techniques/T1039/) |
| Shadow Credentials Present | Existing shadow credentials allow PKINIT authentication and NT hash retrieval | Executed | [T1606.002](https://attack.mitre.org/techniques/T1606/002/) |
| Timeroasting | Offline crack MS-SNTP challenge material from machine accounts | Executed | [T1110.002](https://attack.mitre.org/techniques/T1110/002/) |
### Delegation Abuse (4)

| Technique | What ADscan does | Status | MITRE ATT&CK |
|---|---|---|---|
| Coercion to TGT (Unconstrained Delegation) | Coerce a target into providing a usable TGT for delegation abuse | Detected | [T1187](https://attack.mitre.org/techniques/T1187/) |
| Constrained Delegation | Abuse AllowedToDelegate paths to impersonate users to delegated services | Executed | [T1558](https://attack.mitre.org/techniques/T1558/) |
| Resource-Based Constrained Delegation (inbound) | Resource-based constrained delegation attack path | Executed | [T1134.001](https://attack.mitre.org/techniques/T1134/001/) |
| SPN-Jacking | Compromise a computer by hijacking a delegated SPN: move the SPN the principal can delegate to onto the target computer, then abuse constrained delegation (S4U) with protocol transition to mint a service ticket against the target as a privileged user | Executed | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) |
### Execution (1)

| Technique | What ADscan does | Status | MITRE ATT&CK |
|---|---|---|---|
| xp_cmdshell Execution | The SQL Server service can execute operating-system commands on its host when a session holds sysadmin. Any principal that reaches sysadmin on the instance — a direct sysadmin login, or a linked-server login mapping that lands as a sysadmin login on the remote instance — can therefore run commands on the host as the SQL Server service account, a full host code-execution capability. | Executed | [T1059](https://attack.mitre.org/techniques/T1059/) |
### Initial Access (9)

| Technique | What ADscan does | Status | MITRE ATT&CK |
|---|---|---|---|
| Anonymous LDAP Bind | Anonymous LDAP bind entry vector | Detected | [T1087.002](https://attack.mitre.org/techniques/T1087/002/) |
| Blank Password | Blank-password entry vector | Executed | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |
| Credentials in User Description | Credentials recovered from LDAP user description fields | Detected | [T1087.002](https://attack.mitre.org/techniques/T1087/002/) |
| Group Policy Preferences Password | Credentials recovered from Group Policy Preferences artifacts | Detected | [T1552.006](https://attack.mitre.org/techniques/T1552/006/) |
| Password Spraying | Password spraying entry vector | Executed | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) |
| Password in File | Credentials discovered in host filesystem artifacts after service access | Detected | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) |
| Password in Share | Credentials discovered in SMB share content | Detected | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) |
| Pre-Windows 2000 Computer Account | Pre2k computer-account password entry vector | Executed | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) |
| Username as Password | Username-as-password entry vector | Executed | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) |
### Kerberos Attacks (4)

| Technique | What ADscan does | Status | MITRE ATT&CK |
|---|---|---|---|
| AS-REP Roasting | Offline crack AS-REP material from users without preauth | Executed | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) |
| Kerberoasting | Offline crack service ticket material for credential recovery | Executed | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) |
| Kerberos Key List (RODC) | Use the forged RODC golden ticket to request Key List data from a writable domain controller | Executed | [T1558](https://attack.mitre.org/techniques/T1558/) |
| RODC Golden Ticket | Forge a reusable RODC golden ticket from recovered per-RODC krbtgt material | Executed | [T1558.001](https://attack.mitre.org/techniques/T1558/001/) |
### Known CVEs (5)

| Technique | What ADscan does | Status | MITRE ATT&CK |
|---|---|---|---|
| MS14-068 / Kerberos PAC Forgery | MSEven coercion-style authentication trigger path | Detected | [T1187](https://attack.mitre.org/techniques/T1187/) |
| MS17-010 (EternalBlue) | EternalBlue SMBv1 remote code execution path | Detected | [T1210](https://attack.mitre.org/techniques/T1210/) |
| PrintNightmare | PrintNightmare privileged code execution path | Detected · not executed (safety) | [T1068](https://attack.mitre.org/techniques/T1068/) |
| Zerologon (CVE-2020-1472) | Netlogon cryptographic flaw exploitation path | Detected · not executed (safety) | [T1210](https://attack.mitre.org/techniques/T1210/) |
| noPac (CVE-2021-42278/42287) | NoPac domain takeover path | Detected · not executed (safety) | [T1068](https://attack.mitre.org/techniques/T1068/) |
### Lateral Movement (11)

| Technique | What ADscan does | Status | MITRE ATT&CK |
|---|---|---|---|
| DCOM Execution | Remote command execution capability over DCOM | Detected | [T1021.003](https://attack.mitre.org/techniques/T1021/003/) |
| Full Control Share | Principal has full control over a network SMB share | Executed | [T1570](https://attack.mitre.org/techniques/T1570/) |
| Guest Session | Guest SMB session accepted, enabling unauthenticated share access | Executed | [T1135](https://attack.mitre.org/techniques/T1135/) |
| Local Admin Password Reuse | Credential reuse pivot between hosts sharing local admin credentials | Observed (attack-path pivot) | [T1078.003](https://attack.mitre.org/techniques/T1078/003/) |
| Local Admin Rights | Administrative access from one principal to a host | Executed | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) |
| MSSQL Access | Authenticated access over MSSQL without confirmed sysadmin-level control | Executed | [T1078](https://attack.mitre.org/techniques/T1078/) |
| MSSQL Linked Server Lateral Movement | A SQL Server linked server relationship allows an attacker with sysadmin access on the source instance to execute arbitrary SQL on a second SQL Server instance (the linked target). This effectively extends the attack surface: each linked server hop can be chained with local privilege escalation (SeImpersonate or token theft) to achieve SYSTEM on additional hosts. | Observed (attack-path pivot) | [T1210](https://attack.mitre.org/techniques/T1210/) |
| MSSQL Sysadmin | Administrative access over MSSQL control surface | Executed | [T1078](https://attack.mitre.org/techniques/T1078/) |
| PowerShell Remoting Access | Remote command execution capability over WinRM/PowerShell | Executed | [T1021.006](https://attack.mitre.org/techniques/T1021/006/) |
| RDP Access | Interactive login capability via RDP | Executed | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) |
| Writable Share | Principal has write access to a network SMB share | Executed | [T1570](https://attack.mitre.org/techniques/T1570/) |
### NTLM Relay (3)

| Technique | What ADscan does | Status | MITRE ATT&CK |
|---|---|---|---|
| NetNTLMv1 Offline Recovery | NTLMv1 offline crack: a domain user coerces the victim computer, captures its NTLMv1 response, and cracks it offline to recover the victim's machine account NT hash. The most universal NTLMv1 avenue, independent of relay viability, LDAP signing, channel binding, ADCS, or DC count. | Detected | [T1187](https://attack.mitre.org/techniques/T1187/) |
| NetNTLMv1 Relay to RBCD | NTLMv1 coerce-and-relay to RBCD: a domain user coerces the victim computer, relays its NTLMv1 authentication to the DC, configures resource-based constrained delegation, and obtains local administrator access on the victim via S4U. | Executed | [T1187](https://attack.mitre.org/techniques/T1187/) |
| NetNTLMv1 Relay to Shadow Credentials | NTLMv1 coerce-and-relay to Shadow Credentials: a domain user coerces the victim computer, relays its NTLMv1 authentication to the DC, writes a key credential, and recovers the victim's machine NT hash via PKINIT. | Executed | [T1187](https://attack.mitre.org/techniques/T1187/) |
### NTLM Weaknesses (1)

| Technique | What ADscan does | Status | MITRE ATT&CK |
|---|---|---|---|
| NetNTLMv1 Enabled | NTLMv1 authentication enabled on the host (LmCompatibilityLevel < 3). The host's NTLMv1 response can be coerced and relayed or cracked to a machine NT hash. | Observed (attack-path pivot) | [T1556](https://attack.mitre.org/techniques/T1556/) |
### Privilege Escalation (11)

| Technique | What ADscan does | Status | MITRE ATT&CK |
|---|---|---|---|
| Backup Operators Escalation | Domain compromise via Backup Operators: remote registry hive extraction → DC machine account hash | Executed | [T1003.002](https://attack.mitre.org/techniques/T1003/002/) |
| DnsAdmins Abuse | Potential domain compromise path via DNSAdmins abuse | Detected · not executed (safety) | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) |
| MSSQL Login Impersonation | A low-privilege SQL login that has been granted IMPERSONATE rights on a higher-privileged login (e.g. 'sa') can assume that identity within the SQL Server session using EXECUTE AS LOGIN. This effectively grants sysadmin access, enabling xp_cmdshell execution, CLR assembly loading, and all other sysadmin capabilities, without knowing the target login's password. | Executed | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) |
| MSSQL SeImpersonate Escalation | The SQL Server service account's SeImpersonatePrivilege allows escalating to NT AUTHORITY\SYSTEM on the database server via a CLR stored procedure. No file is written to disk: the exploit assembly is loaded directly into SQL Server memory as a hexadecimal literal, bypassing AV write-time scanning. | Executed | [T1134.001](https://attack.mitre.org/techniques/T1134/001/) |
| MSSQL TRUSTWORTHY Database Escalation | A TRUSTWORTHY database owned by a sysadmin account allows any user with db_owner rights (or EXECUTE AS USER='dbo') to escalate to effective sysadmin server-wide. When EXECUTE AS USER impersonates the database owner context inside a TRUSTWORTHY database, SQL Server grants server-level permissions equivalent to the database owner's server role, giving sysadmin access to any db_owner in that database. | Executed | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) |
| MSSQL Token Theft Escalation | Even when SeImpersonatePrivilege has been removed from the SQL Server process token (a common hardening measure), the original service startup token stored in LSASS retains the privilege. A CLR stored procedure recovers this token via SMB loopback named pipe authentication (Forshaw shared logon session technique) and escalates to NT AUTHORITY\SYSTEM. This bypass is architectural. Removing the privilege from the process token is insufficient. | Executed | [T1134.001](https://attack.mitre.org/techniques/T1134/001/) |
| Print Operators Abuse | Potential escalation path unlocked by Print Operators membership | Detected | [T1547.006](https://attack.mitre.org/techniques/T1547/006/) |
| Privileged Group Control | Direct control achieved through membership in a terminal privileged group | Detected | [T1098](https://attack.mitre.org/techniques/T1098/) |
| Privileged Session Abuse | High-value user session observed on a non-Tier-0 computer that can be abused for scheduled-task impersonation | Executed | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) |
| RODC Credential Caching | Prepare RODC credential caching by modifying the RODC password-replication policy | Executed | [T1098](https://attack.mitre.org/techniques/T1098/) |
| Scheduled Task Execution | Impersonate a logged-on user by registering a scheduled task whose principal is that user's interactive logon session | Executed | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) |
### Trust Abuse (1)

| Technique | What ADscan does | Status | MITRE ATT&CK |
|---|---|---|---|
| Cross-Forest TGT Delegation | Escalate across a forest trust into the trusting forest by abusing cross-organization Kerberos TGT delegation: a forwardable ticket-granting ticket from the trusting forest is delegated across the trust boundary and can be captured from a compromised trusted forest | Executed | [T1558](https://attack.mitre.org/techniques/T1558/) |

<!-- END GENERATED: technique-inventory -->
