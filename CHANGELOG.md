# Changelog

All notable changes to ADscan are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

### Changed

### Fixed

### Removed

## [11.0.0] - 2026-08-03

### Added

- `generate_report` writes a free exposure report from your own scan, as a self-contained HTML file and as a paginated A4 PDF. It leads with the finding load, the paths to full domain compromise, and the techniques carrying the most paths. An audit-mode scan writes it without being asked. Compliance mapping, per-finding remediation and your own branding stay in PRO.
- ADscan executes AD CS ESC5 end to end: backing up the certification authority's private key, forging a certificate offline, and authenticating with it. It runs from the CA host's own machine account as well as from a recovered local-administrator password, and reports the copied key and the forged certificate as items only a CA key rotation can remediate.
- The report cover carries your client's logo beside the ADscan mark, in the free report and the paid one. Give `adscan deliver --client-logo` or `adscan ci --client-logo` a PNG, SVG or JPG, or pick one interactively; it is embedded in the document and reused on later runs. The platform offers the same choice when you create a scan.
- Both reports open the remediation plan with what the proven compromise obliges: reset krbtgt twice with replication completing in between, rotate the accounts whose secrets were recovered, revoke the certificate your CA issued during testing. The block appears only where the engagement reached those outcomes.
- Executing a collapsed attack path lets you choose which of the interchangeable accounts to target: several at once for a roast or a spray, one for a step that succeeds outright. An unattended run picks the strongest candidate without pausing.
- `writeup` saves the mechanical two thirds of a lab writeup while the evidence is still on disk: the ports, the directory contents, the chain as an editable mermaid diagram, every step with its outcome, timestamp and credential provenance, the flags, the dead ends. The analysis it is judged on is left as marked placeholders. Lab and CTF scans write it on their own; nothing is uploaded.
- Service accounts carrying an HTTP SPN are flagged as a Kerberos web-application relay and coercion surface, with native remediation guidance in the report and the platform.
- `COVERAGE.md` lists every Active Directory technique ADscan implements, each mapped to MITRE ATT&CK and marked as executed, detected, or declined for safety. It is generated from the product catalog, so it cannot drift from the tool.
- The Enterprise platform plots exposure across a workspace's scans and compares any two, listing the findings and attack paths that appeared, closed, or carried over.
- The optional end-of-session question now names the channels people actually arrive through and takes a free-text answer; a later session asks what kind of work you do. One question per session, and none on an unattended or air-gapped run.

### Changed

- Attack paths identical except for which account sits in the middle collapse into one finding that names and counts the interchangeable accounts. A 774-host audit produced a 200-page report dominated by fifty near-duplicate rows that were one decision. A cracked account keeps its proven status inside the collapsed row.
- Attack-path steps that already ran can be executed again from the step selector, labelled with their previous outcome and behind a confirmation that defaults to No. Reviewing which steps are runnable no longer prompts for an account on every step, and an unattended run never re-executes a proven step.
- Attack-path computation on large environments is much faster and finds the same paths. On a simulated 8,000-user domain, the step that works out who each path affects went from about 225 seconds to under two.
- The share credential hunt and the attack-path discovery phase show live progress. Both can run for hours behind nothing but an elapsed counter, which made the tool look frozen. Unattended runs print plain lines instead of a panel.
- The free exposure report is redrawn on the same design as the paid one, so it reads as the same product rather than a dashboard export. Its headline is labelled "Posture score" with "higher is safer" beside it, and attack-path steps lead with the plain-language technique and the object involved instead of a raw permission token.
- The certificate-authority key-theft technique is called AD CS ESC5 (Vulnerable PKI Object Access Control) throughout the CLI, the reports and the platform, replacing the older "GoldenCert" label.
- The `Scan complete` panel says what `deliver` will ask you and what it costs before you run it, and stays quiet after a scan that collected nothing.

### Fixed

- The free report records the findings behind the attack paths it prints. A free scan of a domain with exploitable certificate templates, noPac, PrintNightmare or readable LAPS recorded none of them, so the cover read `0 critical` beside paths exploited to full domain compromise. A proven step is also no longer dropped when its target was named by IP where the graph knew it by name, which could leave a chain ADscan had walked end to end reporting no attack paths at all.
- Findings name the objects they affect: the accounts, the hosts by name and address, the shares and files, the certificate templates and the issuing authority. Twenty-nine of them, among them noPac, shadow credentials and the LAPS coverage gap, named the domain instead. Both tiers resolve assets through one implementation, so they cannot disagree.
- A step granted through a group is executed by an account that is actually in that group, or not at all. ADscan had been falling back to whichever credential it captured first, and for local-admin, RDP, WinRM and SQL steps an unrelated account's own access to the host would make the step pass — so the report claimed the group grants access where nothing of the kind had been tested. A step whose source account you do not control is now locked, with the reason.
- Several findings that were never real are gone. `krbtgt`'s stock description read as a leaked password on every domain, and the remediation would have invalidated every Kerberos ticket in the domain. ESC13 was raised wherever a template carried an issuance policy, even with no group linked to it and so nothing to abuse. Group Managed Service Accounts were listed as roasting targets although their passwords are machine-managed. And text that merely resembles a password was called a confirmed disclosure before anything had tried it.
- A control the scan found clean is no longer also reported as an open weakness. An SMBv1 audit printing "No SMBv1 exposure detected" still produced a confirmed finding that travelled the whole deliverable; the obsolete-OS, stale-account and LDAP-signing audits had the same fault. A weakness two checks observe is reported once, at the higher severity, and all three documents state the same total.
- Directory replication is recorded as proof on the one permission it actually used. Marking every principal holding replication rights as having performed it turned one event into several and credited steps to accounts no credential was ever used for. That permission is still reported, as identified from configuration rather than demonstrated.
- An attack avenue closed by your own configuration is no longer also billed as a confirmed critical finding, and its path is view-only rather than offered for execution. One document credited the hardening in its attack-path section and charged for it twice in its findings list.
- The counts in a report reconcile with its own legend. The executive headline counted avenues the configuration already closes and routes ADscan had no surface to walk, reading 25 paths where 14 were actionable; chains with steps run against the live environment were filed under configuration analysis; and a domain reached over a trust and never enumerated was counted as scope, which now reads "1 assessed · 2 discovered". The end-of-scan panel quotes the report's figures instead of counting graph permutations.
- The compliance annexes carry the evidence the assessment produced and score it the way the rest of the report does. Seventeen findings reached no NIS2, DORA or ENS control, so all three printed "No major non-conformities identified" in a document that proved domain compromise on the same pages, and ten findings including all nine criticals carried one score in the findings and another in the annex. A score is called CVSS only where a published Base vector exists to recompute it from.
- The AD Control Coverage Report has something to attest after a credentialled scan: clean results were discarded rather than recorded, so it arrived empty on the most common engagement shape. It also lists the controls it found weak, and is left out of the kit when there is nothing to attest.
- A host that answers on one network interface and not another is reached on the one that works, chosen by probing the port the connection will use. A server advertising an internal-only address alongside a routable one could be reported offline and its attack path abandoned, on roughly one run in three. This covers the SQL Server chain through to SYSTEM.
- Recovered credentials are filed under the account and host they belong to. A machine account from an LSA dump was stored under the domain controller's name, a gMSA secret under the registry key naming the service, and a legacy LAPS password under the computer name, where it failed its own logon check and was discarded. A local credential is no longer handed to the next step as the domain account of the same name.
- A credential that cannot be verified is kept and reported as unverified rather than discarded as wrong, and every technique that reached an account is recorded with the Kerberos key material it carries. The first route used to claim the account and the rest were dropped, so on a domain enforcing AES the pass-the-key routes quietly stopped being available.
- An expired Kerberos ticket no longer kills an attack step. Every authenticated channel checks the ticket before it connects and re-mints it for the same account; a ticket whose privilege lives in the ticket itself is used exactly as issued.
- Switching domains could destroy a workspace's stored credentials: loading a domain's point-in-time snapshot emptied the credential store, and the next routine save wrote that empty store over the workspace file, losing every password, hash and ticket captured for the engagement.
- Session recordings uploaded to ADscan can no longer carry your client's domain name, a domain controller's hostname, your certificate authority's common name, IPv6 addresses, or key material split across a terminal line wrap. Recordings only leave your machine when telemetry is enabled, which is the default on the free and PRO tiers only.
- Leaving telemetry on no longer slows a scan: events were sent on the thread doing the work and waited for a reply, piling into minutes on a large environment, and now go in the background. `set telemetry off` is per-workspace again, `set telemetry off global` sets the operator-wide default, and `adscan start` accepts `--no-telemetry` and `--offline`. What is sent, and the scrubbing applied before it leaves your machine, are unchanged.
- Neither report issues an all-clear it cannot support. A workspace's first run reported that nothing had been changed on runs that created machine accounts, modified certificate templates and reset passwords. Where the record of those changes cannot be read, both documents now say so.
- A certificate your CA issues while ADscan proves an ADCS path is disclosed with its serial, request id, template, CA and expiry, and a native `certutil` procedure to revoke it — printed at the page's full width, since a 40-character serial broken across lines produced a failed revoke and a certificate that keeps authenticating as a domain administrator. Directory changes are named in plain English rather than internal identifiers.
- The remediation ranking decides what a client can actually change, per group membership and per permission holder rather than per technique. Built-in nesting that cannot be removed is excluded, routes the configuration already closes or that were never assessed no longer inflate a fix's count — 21 paths claimed where 12 are open — and priorities read "Certificate Mapping Abuse (ADCS ESC9)" instead of "Adcsesc9".
- The paid deliverable no longer prints internal engineering notes in the client's PDF, and the line about deliberately not executing a step to spare a production host is reserved for the steps ADscan genuinely refuses on safety grounds. Everything else states that it was identified from configuration and not exercised.
- The Privilege Blast Radius table matches the tier glossary six pages earlier, where DnsAdmins had been listed under "Tier 2: Standard" and Domain Admins under "Tier 0: Escalation-capable". The reports also render in the product's own typefaces and carry the ADscan mark on the cover, the ATT&CK matrix fits its page, the kill-chain page has no column of empty boxes, and the free report's PDF prints to the edge of the sheet.
- `writeup` builds its chain from the steps the run actually proved, in the order a reader follows them, keeps the failure history on a step that eventually worked, records what was changed in the directory from the rollback ledger, and runs on a workspace that has a scan but no report. Both reports and `writeup` recompute attack paths the same way, so one workspace always produces the same document.
- Reaching SYSTEM through MSSQL on a domain controller continues into a coupled DCSync step, so the path ends at domain compromise rather than at a foothold; on a member server it does not. MSSQL discovery also seeds targets from `MSSQLSvc` service accounts and from hosts a pivot confirmed listening, so an instance on a filtered port is attempted rather than skipped.
- `adscan check --fix` is accepted instead of rejected by the host command, `adscan check` reports the memory actually free and stops a run below 1 GB unless you pass `--allow-low-memory`, `adscan update` closes with an outcome instead of silence and upgrades a launcher installed with `uv tool install`, and `--partner-tag` activates PRO from the command line. `adscan execute` gained the read-only `users` verb and suggests the closest verb when you mistype one.
- `adscan ci` reports the scope it scanned and exits when domain discovery finds no controllers, instead of rescanning the same range indefinitely. Ctrl+C is reported as a partial scan listing what was captured; a domain scanned twice in one workspace stays initialized; the host range offered for discovery comes from your DC or your own interface rather than a fixed `10.10.10.0/24`; and a lab scan that meets its objective early is recorded as finished rather than offering to resume.
- Clearer output on a normal run. SMB collection collapses per-host access-denied errors into one line on large estates, a forest without the LAPS schema extension is asked once rather than on every object, the certificate-authority check reports "not permitted" instead of an error when the account lacks CA rights, and a password crack that hits its time limit names the cap it stopped at instead of reporting that it recovered nothing. File paths in panels and under `--debug` point at `~/.adscan` on your own machine rather than the container's `/opt/adscan`.

### Removed

- The `domain` command group — `domain select`, `domain create`, `domain delete`, `domain show` — is gone. The verb was already disabled in the shell, nothing else reached it, and its selection path was the one that could destroy a workspace's credentials. Workspace and domain context is set by `workspace select` and by the scan flow.

## [10.1.0] - 2026-07-24

### Added

- SQL Server attack coverage: linked-server lateral movement across domain and forest trusts, automated command execution through the database with escalation to SYSTEM, and arbitrary file read via bulk import. Each is surfaced as a first-class, validated attack step in the report.
- Shadow Credentials escalation: ADscan now detects when it can write a key credential to a target account and authenticate as it, and executes the full chain end to end.
- Extended-rights escalation is modeled per target and chained into attack paths: forced password reset, directory replication (DCSync), and LAPS password read.
- Control over a Group Policy Object is now chained through to code execution via a scheduled task on the machines the GPO applies to.
- Credential capture through a pivot: NTLM authentication can be captured across a routed tunnel, with per-target selection of the callback address.
- Writable-share credential bait (opt-in): ADscan plants a bait file on shares the current user can write to and captures the resulting authentication attempts as a background job that does not block the scan.
- Certificate Services attacks now run through a native implementation, including detection of delegated CA-management rights and detection of Extended Protection on the web-enrollment endpoint (which suppresses false ESC8 findings when enrollment is hardened).
- `adscan execute attack_paths` runs a single attack path or step against a saved workspace without a full scan. When the starting account is already owned, its credential is resolved from the workspace, so no username or password needs to be re-supplied. A companion re-arm resets step status so a path can be run again.
- REPL commands now accept flag-form arguments (`-d`/`--dc-ip`/`-u`/`-p`/`--host`/`--service`) alongside the existing positional form, with tab-completion for both flag names and values.
- Recovery of secrets protected with PowerShell `ConvertFrom-SecureString -Key`, chained into share-password findings.
- Web ports 8080 and 8443 are now included in the important-ports sweep and folded into service discovery.

### Changed

- Attack paths are ordered proof-first in the report and the web dashboard, leading with the validated low-privilege-to-domain-compromise path rather than theoretical ones.
- Attack-step headers in the report and web now read as plain-language business headlines, with the underlying technical name kept as a subtitle.
- More honest result states for attack paths: "Partially Validated" for a chain proven in part but not end to end, "Not Executed for Safety" for destructive steps ADscan deliberately refuses to run, and "Attack Surface Reduced — Hardening Observed" for avenues your own configuration closes.
- Remediation guidance is now written entirely in native Microsoft tooling (RSAT Active Directory module, `dsacls`, `Get-*`/`Set-*`), goes deeper on the exact object, command, and expected before/after, and no third-party or competitor product names appear anywhere in client-facing report text.
- The AD exposure score now combines proof strength with per-technique exploitability.
- The SQL Server post-authentication workflow runs automatically in unattended scans instead of defaulting to skip.
- New scan-configuration toggles for network pivoting and writable-share bait, available in both the CLI and the web console.
- Running the ADscan core directly on the host machine is now refused with a clear explanation; the tool runs only inside its container.

### Fixed

- An unauthenticated scan could fail to record its domain and silently drop findings.
- Password-spray coverage now distinguishes "lockout threshold unknown" from "lockout confirmed disabled" instead of conflating the two.
- A domain controller reachable but with its DNS service down is no longer reported as "Validation Failed".
- Scan timeline durations are no longer corrupted by mid-scan clock synchronization, which previously produced implausible multi-day phase times.
- Password cracking no longer takes over the terminal or prints recovered-hash previews into logs.
- Network preflight now correctly recognizes a hardened domain controller that exposes only Kerberos and LDAPS.
- Kerberos user enumeration streams its wordlist live with a dynamic early stop and no longer re-offers an auto-detect attempt that already failed.
- Directory changes ADscan makes (such as a planted key credential) are always disclosed in the report, and cleanup is reported accurately — including flagging the cases that require manual removal — even when a later step in the chain fails.
- Planted key credentials are removed by their exact stored value rather than a reformatted version, and the environment-change ledger is always initialized so every change ADscan made is attested.
- Group Policy password (GPP) findings are no longer misclassified, and false-positive findings are gated on confirmation before they reach the report.

### Removed

- Nine REPL commands were renamed to native names; the previous names are no longer accepted.
- The "Blocked by Active Controls" report category was removed. ADscan reports whether an attack path exists and never claims that a defensive product it cannot observe stopped an attack.

## [10.0.0] - 2026-07-17

### Added
- Password-strength auditing built into the scan. Credentials captured during a
  run (broadcast-poisoning responses, Kerberos service tickets, AS-REP hashes)
  are audited against a curated wordlist in the background while enumeration
  continues, and any recovered password is fed straight back into the attack
  path. Ships with the "ADscan AD Audit Wordlist", a 94-million-entry corpus, and
  a client-targeted wordlist generator that mines names, dates, and terms from the
  environment being assessed.
- Selectable cracking effort with realistic time estimates. A four-rung effort
  ladder (from a fast pass to a one-hour thorough run) is calibrated to the host's
  hardware so the estimated finish time is accurate before you commit, with live
  progress and ETA while it runs.
- Broadcast name-resolution poisoning capture. ADscan can passively capture
  network authentication attempts (LLMNR, NBT-NS, mDNS) as a background task to
  harvest credentials, surfaced as a finding and linked attack step. It runs with
  an explicit consent panel in interactive use and starts automatically in
  unattended scans, with an opt-out for out-of-scope or monitored engagements.
- Credential Harvest panel. A single view of every credential ADscan obtained
  during the scan (captured, cracked, and sprayed), each tagged with its privilege
  tier and what it can reach, plus an end-of-scan harvest summary and an on-demand
  `harvest` command.
- Privilege Blast Radius. Reports, the web platform, and the CLI now show the full
  set of assets and capabilities a single compromised account fans out to, making
  the reach of one weak credential explicit.
- Resumable scans. If a scan is interrupted (crash, disconnect, or a deliberate
  stop) ADscan offers to resume it from the last completed phase or host instead
  of starting over, and the web platform can stop a running scan gracefully and
  pick it back up.
- Background job management. A new `jobs` command lists long-running background
  work (poisoning capture, password cracking) and lets you review and stop it,
  with completed results surfaced at safe break points during the scan rather than
  interrupting the terminal.
- macOS and Apple Silicon support. The launcher now runs natively on macOS, and
  LITE and PRO images are published for ARM64/Apple Silicon in addition to x86-64.
- Scan configuration controls for cracking effort and poisoning, exposed both in
  the web platform and in the YAML scan-config file.
- Smoother first-run onboarding: a pre-filled workspace name, a first-run
  explainer, and an end-of-scan session rating prompt.

### Changed
- Credential recovery in reports and the web platform now classifies each
  harvested account by privilege tier and reach, so a cracked or captured password
  is shown in terms of what it actually unlocks.
- Network operations that previously relied on bundled external command-line tools
  (password spraying, share enumeration, SMB/LDAP hardening checks, local
  credential verification, account cleanup) now run on ADscan's built-in engine,
  giving consistent proxy support and a smaller footprint.

### Fixed
- Captured credentials are no longer lost in several edge cases: a sprayed
  credential deleted during re-verification, a captured hash dropped on a
  NetBIOS/domain-name mismatch, and a cracked password that could vanish if its
  background worker ended early.
- A best-effort file-copy step that retried against unreachable shares could stall
  and abort a long engagement; retries are now capped so the scan finishes.
- A corrupt or empty workspace file no longer breaks an existing workspace, and
  workspace writes are now atomic so an interrupted save cannot wipe collected
  data.
- Multi-domain resume now checkpoints correctly, so an interrupted scan across
  several domains can actually be resumed.
- Cross-forest and cross-realm Kerberos authentication now follows domain
  referrals correctly, including a crash on service tickets used for constrained
  delegation.
- The credential prompt now cancels cleanly on empty input, and unattended scans
  never block waiting for a prompt.
- Password-audit reporting is more accurate: an out-of-memory condition is
  reported as its own cause instead of "try a different wordlist", the patience/ETA
  notice is no longer far off, and long audit sessions are recorded reliably.
- Background cracking no longer competes with the interactive prompt for the
  terminal or for CPU, keeping the shell responsive while a crack runs.
- The Compliance page in the web platform now renders its interface text in
  English, and internal tool names no longer appear in client-facing live-scan
  output.

### Removed
- The bundled external third-party command-line security tools have been removed.
  Every capability they provided is now implemented directly in ADscan's native
  engine, which also reduces image size.

## [9.2.1] - 2026-06-29

### Added

- New `adscan doctor` preflight command: a non-interactive connection and environment check (reachability, enabled-user count, trust discovery) with JSON output. It also powers a live "Validate connection" console in the platform so you can confirm a target is ready before launching a scan.
- New `adscan execute <verb>` command to run a single step non-interactively without a full scan.
- Per-phase scan configuration: a dynamic "Create New Scan" form in the platform, and a `--scan-config` file for the CLI, to choose which phases, subphases and collectors run, scope the CVE check, and set lockout-safe spraying.
- Live scan visibility in the platform: watch hosts and users get discovered and compromised during a scan, with rate/ETA/elapsed progress for long steps (spraying, cracking, roasting, SMB/LDAP collection) at multi-thousand-host scale, and per-node provenance showing who was compromised, how, and the step that proves it.
- Share Exposure view: the SMB share tree with per-principal effective access, sensitive-file surfacing, and links to the related findings.
- Privilege Tier and Compromise Reach model across the CLI, report and platform: Tier 0/1/2 classification, a client glossary explaining it, tier breakdowns on the domain-takeover KPIs, and consistent reach labels.
- Cleanup and rollback reporting in the report and platform: every change ADscan made to the environment, split into reverted-and-verified versus manual-cleanup-required.
- Per-account credential provenance in the report and platform: how each credential was obtained, replacing generic "via unknown" attribution.
- Group Managed Service Accounts (gMSAs) are now tagged and kept in the Users inventory instead of being dropped alongside trust accounts.

### Changed

- Reach severity is now graded by the target's Privilege Tier and the access edge's control strength (full local admin outranks a remote session, which outranks database-only access), sharpening attack-path ordering.
- `adscan update` now reliably upgrades the launcher itself, and stale-runtime-image warnings are prominent and tell you to run it.
- The SMB enrichment sweep can be stopped early by the operator, from the CLI (Ctrl+C) or a button in the platform.

### Fixed

- Kerberos service-ticket and AS-REP hashes are now routed to the correct cracking mode per encryption type. On AES-only and hardened domains these hashes were previously sent to an RC4-only mode and silently never attempted.
- Credential verification now falls back to an NTLM bind when the Kerberos KDC is unreachable but LDAP/SMB is available, instead of failing with a misleading "verify the credential" message.
- Multi-host SMB sweeps now stop on account lockout instead of re-triggering the lockout across every remaining host.
- Share Exposure no longer reports a false Write or Full-Control right; rows whose NTFS permissions could not be verified are flagged as such.
- A DCSync capability already held by a domain-breaking principal is no longer reported as a separate finding.
- `adscan deliver --frameworks` now applies the selected compliance frameworks to the bonus documents (hardening playbook and remediation checklist), not just the main report.
- CLI numeric and selection prompts no longer hang or crash in non-interactive runs.

### Removed

- The WeasyPrint PDF path was removed; Chromium is now the sole report engine and the only `--report-engine` choice.

## [9.2.0] - 2026-06-23

### Added

- Live Scan Console in the Enterprise web platform: a real-time terminal view of a running scan in its own tab, with follow-tail, search, and a downloadable transcript that replays in full whether you open it mid-scan or after it finishes. A log-level toggle (Off / Verbose / Debug) filters the stream.
- Attack-graph edge detail in the web platform. Clicking any step now opens a two-level brief: plain-language business risk and impact for executives, and technique description, prerequisites, evidence, and command-level remediation for engineers, plus a "fixing this breaks N of M paths" blast-radius figure. It works even for theoretical steps that have no finding yet.
- Live finding detail during a running scan: a rich slide-over (description, impact, remediation, references, observed vs recommended) and a standalone finding register, both available before the scan completes.
- Exposure blast-radius dashboard: a headline showing what share of domain users have a validated path to full domain compromise, broken down into domain compromise, Tier 0 foothold, and stepping-stone.
- Engagement-posture Settings in the web platform: independent Offline-mode and Send-telemetry toggles, applied per scan.
- MSSQL authorization mapping: the scan enumerates SQL access and sysadmin rights across reachable database servers and adds them to the attack graph as escalation paths.
- Deleted-object (AD Recycle Bin) attack surface: ADscan discovers restorable tombstoned objects, flags ones an attacker could write to or reanimate, and can chain a restore into a live escalation path.
- Offline credential extraction from virtual-machine artifacts left on shares: virtual disks, including snapshot and differencing chains, and memory images are parsed offline to recover credentials.
- Machine-password rotation auditing: ADscan recovers the real rotation interval from policy and reports computers whose machine passwords are not rotating, scored by how stale they are.
- New findings for duplicate computer DNS (several enabled computer names pointing at one IP) and stale or obsolete enabled computers.
- Structured remediation runbooks on every finding: each carries a primary fix plus a fallback for constrained environments, with concrete GPO / PowerShell / registry / certutil commands and a validation step.
- Affected-assets appendix: deliverables now bundle a complete CSV and JSON list of every affected host, account, or certificate template, with inline lists capped for readability in large environments.
- Credential provenance: every recovered credential is labelled with how it was obtained, shown across the report and the web platform. The scan's own starting credential is no longer counted as a compromised credential.
- NIS2 is now a distinct, selectable compliance framework, previously folded into ENS.

### Changed

- Deliverables restructured into three documents: a concise Security Assessment Report (where, and how bad), an AD Hardening Playbook (deep remediation runbooks and a 30-day plan), and an AD Control Coverage Report (what was tested and what you are verified clear on). The MITRE coverage view is folded into the main report.
- Affected-assets lists now name the true affected entities: the vulnerable certificate template and issuing CA for ADCS findings, and the real hosts or accounts for posture findings, instead of the attack path's end target or a blanket "domain-wide".
- Multi-domain trust scope now defaults to the origin domain only; enumerating trusted domains is opt-in, since clients often do not authorize it. In the web platform the operator opts additional domains in through a domain-topology graph.
- Compliance frameworks are now opt-in, and the report and web view honor exactly the frameworks you selected for the scan (previously a fixed default set was shown regardless).
- After reaching Domain Admin, an audit now replicates the full credential database once, matching the CTF flow, so lateral-movement and offline-cracking impact is demonstrated rather than left implied.
- Spraying is redesigned into a coverage-driven, lockout-aware flow: it excludes already-locked and already-owned accounts, computes an effective bad-password count against the real lockout window, and covers username-as-password, blank-password, and pre-2000 computer variants.
- The web platform now presents a single workspace dashboard and lands you straight on your workspace when there is only one.
- Attack paths in domain scope return the shortest high-value route by default.
- The important-port scan streams results live into the scan dashboard with a top-open-ports ranking.

### Fixed

- Share looting and bait-drop now run as the assessed user rather than the session's active credential, so credentials embedded on shares that only that user can reach are no longer missed.
- Writable-share detection no longer reports false write access on read-only shares; effective access is intersected with the share-level cap and confirmed before an edge is drawn.
- A permission change is only offered when the granted right actually allows it (force-change-password no longer surfaced on rights that cannot perform it).
- Guest and null SMB sessions use NTLM instead of Kerberos, fixing a regression that broke them against hardened hosts.
- Kerberos service tickets are resolved against each host's own name during authenticated share enumeration, and a stale DNS name is self-healed at the connection layer, fixing authentication failures against non-DC hosts.
- Clock synchronization for certificate-based Kerberos (PKINIT and shadow credentials) now steps the host clock to the domain controller when needed and self-heals on drift.
- Remediation now renders for ADCS ESC techniques that previously showed no fix, and remediation accuracy was corrected for LSA Secrets and ADCS ESC9 / ESC10 / ESC16.
- The report cover no longer shows an internal execution-workspace name in place of the client name.
- Several client-facing strings that had leaked Spanish in the web platform and the DORA report section are now in English.
- The web deliverable-kit request no longer hits a dead route, restoring the compliance-framework export.
- In non-interactive and CI runs, live progress panels no longer flood the log.

### Removed

- The standalone MITRE Remediation Checklist and Coverage Matrix deliverables; their content is folded into the new three-document set.
- The web platform no longer offers unauthenticated scans or the CTF engagement type; both remain available from the command line.

## [9.1.1] - 2026-06-09

### Added

- AD Exposure Score: a single 0-100% headline metric for how exposed a domain is to full compromise from a low-privilege foothold, with a separate "Proven" figure (validated, not estimated). It leads the executive summary, the executive PDF hero on page 2, the technical report JSON, and the web dashboard, where it also trends over time across scans.
- Sample teaser report: a new short (~6-page) report profile for cold outreach, with a cover, industry benchmark, executive summary, one headline attack path, a DORA snapshot, and a call to action.
- The SMB share phase now captures credentials from writable shares (planting a lure that harvests authentication material) alongside the existing readable-share credential hunt.

### Changed

- PRO runs are now as fast as LITE. A packaging choice had made PRO 12-20x slower on large graphs; attack-path computation that previously took hundreds of seconds now finishes in tens.
- Attack paths that reach full domain compromise are now ranked above paths that only gain a foothold on a domain controller, so the top-listed path (and the one an unattended run executes) is the most impactful one.
- More domain-compromise routes are surfaced and correctly labeled: taking over a privileged user's logged-on session to run code as them or recover their credentials, constrained-delegation abuse, and admin access on a writable domain controller now chain through to "Domain Compromised".
- After the domain is compromised through an attack path, an audit run now re-collects the environment as the compromised admin and runs the credential-harvesting sweep automatically; previously this happened only when your starting account was already a Domain Admin. Redundant attack-path prompts after compromise were removed.
- Unattended (CI) audit runs are bounded on large estates: the readable-share credential hunt scans the top 25 highest-risk shares (logged; re-run interactively for all), and the heavy-artifact deep-analysis phase is skipped by default.
- The SMB share phase was renamed from "Share Credential Hunt" to "SMB Share Exposure".
- Before planting a share lure, ADscan asks for confirmation first and performs no folder enumeration if you decline (audit defaults to no, CTF defaults to yes).

### Fixed

- On rootless Docker and Podman, ADscan no longer fails at startup with a cryptic "Operation not permitted". It starts in a reduced-network mode and shows a clear panel covering what works, what is degraded, and how to restore full features.
- Very large SMB collections that could hang for many hours are fixed (a resource leak triggered by unreachable or dropped hosts).
- Credential replication against a bare account name such as `administrator` or `krbtgt` in a multi-domain forest now targets the correct domain instead of returning no data.
- Share access reporting no longer over-reports read-only shares as writable. Shares like NETLOGON and SYSVOL now show the effective access your account actually has, not the raw share grant.

### Removed

- The separate ADCS discovery step was removed from the scan flow; certificate-services detection is now handled earlier in the graph collection, so the scan runs one fewer redundant step.

## [9.1.0] - 2026-06-04

### Added

- SPN-jacking attack path. ADscan now detects and executes SPN-jacking with constrained delegation: it relocates a service principal name onto a target computer and impersonates a privileged user against it, turning a write-over-a-machine-account right into a full compromise path. Modeled in the attack graph and shown in reports.
- NTLMv1 exposure across the estate. A per-host sweep classifies which machines still negotiate NTLMv1 (not only the domain controller), with a live classification dashboard and a review table that flags NTLMv1 hosts as the actionable targets. The resulting coerce-to-relay and offline-crack techniques are modeled as attack steps with business labels and compliance mappings for ENS, NIS2, DORA, ISO 27001, and PCI DSS.
- NTLM-relay-to-LDAP workflow. A new relay command coerces a target, relays the authentication to LDAP, and writes either resource-based delegation or Shadow Credentials, then mints a service ticket to continue the chain. It opens with a go/no-go feasibility panel, resolves the victim's name automatically, can reuse an existing controlled machine account instead of creating a new one, and tracks every change it makes for clean rollback.
- Credential capture via writable-share bait. ADscan can drop a passive bait file into a writable share so that a user who merely browses the folder authenticates to ADscan, capturing their NTLM response. Supports per-folder targeting across multiple shares under one listener, reports the actual captured version (NTLMv1 flagged as higher value), and offers to crack the captured hash offline.
- MSSQL escalation to Domain Admin through service-account impersonation. When a SQL service account owns its own service principal name, ADscan can impersonate a privileged account to reach database sysadmin. On a domain controller, takeover now offers either creating a new Domain Admin account or promoting an already-controlled user.
- Effective share access. SMB share enumeration reports effective access (share permissions intersected with the underlying NTFS permissions) instead of share-level permissions alone, removing false "writable" results on hardened file servers.
- Progress feedback for long operations. SMB collection, Kerberos user enumeration, password spraying, and the important-port scan now show a live progress dashboard, with an up-front notice when a run is expected to take a while.
- Collection scope selector. At the start of domain collection you can choose which sub-collections run (directory/ACL base, local accounts, shares) for a faster directory-only pass.

### Changed

- Attack paths are ordered by how directly they reach domain compromise, and a foothold on a Tier 0 asset where control is still pending appears in its own "Tier 0 Footholds" section rather than being counted as a full domain compromise.
- Domain controller and KDC address selection is now reachability-aware, so ADscan uses the address it can actually reach on multi-homed hosts and over VPN instead of an internal, unroutable one.
- Large-estate SMB collection skips hosts that do not answer on the SMB port and skips disabled computer accounts, cutting scan time substantially (per-host timeouts on dead hosts were the main bottleneck).
- Durable AD objects ADscan creates during an engagement (machine accounts, delegation grants) are kept on success and reverted on failure, and the exit "revert these changes?" prompt now defaults to reverting so pressing Enter leaves a clean environment.
- Accounts ADscan mints (during MSSQL and relay workflows) now get a policy-compliant password by default, an editable name and password, and are rolled back automatically after use.

### Fixed

- Reliable operation against hardened domain controllers. NTLM-disabled / Kerberos-only DCs, AES-only KDCs with a non-default Kerberos salt, DCs enforcing LDAP signing and channel binding, and restricted-anonymous DCs are now detected and handled correctly. This resolves cases where the attack-graph collector returned no results, authentication or certificate enrollment failed, or a hardening control was mis-reported.
- Credential coercion now works against member servers and patched/hardened hosts that previously returned access-denied.
- Trust enumeration no longer misroutes to the wrong domain controller for a trusted domain, which had caused failed cross-domain lookups.
- Password reset via the ForceChangePassword right works again; a regression had corrupted the new password value and produced a misleading "insufficient rights" message.
- Cracking of Kerberos service-ticket and AS-REP hashes no longer silently fails to load the hashes.
- Attack paths no longer show false positives in which reaching a host through a user-level session was treated as owning that host.
- ADCS web enrollment (ESC8) is no longer falsely reported on hosts running unrelated web services with no certificate endpoint.
- Flag collection survives domain controllers that aggressively reset SMB sessions and now finds flags in custom top-level and domain-suffixed profile directories.
- Blank-password default accounts (such as Guest) are no longer stored or reused as credentials.
- The listener used for credential capture no longer crashes on connections from modern Windows SMB clients.
- The LITE post-scan panel no longer lists commands that do not exist.

### Removed

- (none)

## [9.0.1] - 2026-05-31

### Added
- Automatic credential recovery when a discovered account is not found in the
  domain: the recovered secret is fuzzy-matched against enumerated users and
  verified live, with a lockout-safe password-spray fallback to identify the
  account the secret actually belongs to.

### Changed

### Fixed
- WinRM Kerberos authentication now reuses the workspace TGT ticket cache (or
  mints one from the recovered password), fixing "matching credential not
  found" failures in environments without a local Kerberos credential cache.
- MSSQL Kerberos logins now target the domain KDC explicitly, fixing
  authentication when the runtime cannot resolve the KDC via DNS.

### Removed

## [9.0.0] - 2026-05-20

### Added
- S4U2Self elevation for machine account credentials with notifier callbacks
- LSA secrets parsing: Kerberos password, security questions, DefaultPassword
- AES-256 key derivation for machine account SMB/Kerberos authentication
- Backup Operators escalation path via RRP with S4U2Self elevation
- Machine account credential persistence and DC short hostname resolution
- Winlogon DefaultUserName retrieval in LSA secret parsing
- Clock-skew patches applied before all Kerberos calls

### Fixed
- AP-REQ uses clock-skew-adjusted time in construct_apreq_from_ticket
- Stale history entries suppressed in LSA secrets parsing
- Trailing null bytes stripped from Winlogon DefaultUserName

## [8.0.0] - 2026-04-26

### Added
- Major release — see GitHub release notes for full details

## [7.2.0] - 2026-04-19

### Added
- See GitHub release notes for details

## [7.1.0] - 2026-04-15

### Added
- See GitHub release notes for details

## [7.0.0] - 2026-04-13

### Added
- See GitHub release notes for details

## [6.5.0] - 2026-04-09

### Added
- See GitHub release notes for details

[Unreleased]: https://github.com/ADScanPro/adscan/compare/v11.0.0...HEAD
[11.0.0]: https://github.com/ADScanPro/adscan/compare/v10.1.0...v11.0.0
[10.1.0]: https://github.com/ADScanPro/adscan/compare/v10.0.0...v10.1.0
[10.0.0]: https://github.com/ADScanPro/adscan/compare/v9.2.1...v10.0.0
[9.2.1]: https://github.com/ADScanPro/adscan/compare/v9.2.0...v9.2.1
[9.2.0]: https://github.com/ADScanPro/adscan/compare/v9.1.1...v9.2.0
[9.1.1]: https://github.com/ADScanPro/adscan/compare/v9.1.0...v9.1.1
[9.1.0]: https://github.com/ADScanPro/adscan/compare/v9.0.1...v9.1.0
[9.0.1]: https://github.com/ADScanPro/adscan/compare/v9.0.0...v9.0.1
[9.0.0]: https://github.com/ADScanPro/adscan/compare/v8.0.0...v9.0.0
[8.0.0]: https://github.com/ADScanPro/adscan/compare/v7.2.0...v8.0.0
[7.2.0]: https://github.com/ADScanPro/adscan/compare/v7.1.0...v7.2.0
[7.1.0]: https://github.com/ADScanPro/adscan/compare/v7.0.0...v7.1.0
[7.0.0]: https://github.com/ADScanPro/adscan/compare/v6.5.0...v7.0.0
[6.5.0]: https://github.com/ADScanPro/adscan/releases/tag/v6.5.0
