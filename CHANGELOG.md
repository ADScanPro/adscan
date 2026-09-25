# Changelog

All notable changes to ADscan are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

### Changed

### Fixed

### Removed

## [13.1.0] - 2026-09-25

### Added

- ADCS findings now state exactly one of three honest outcomes: validated (the vulnerable
  certificate authority was reachable and the escalation ran to completion), a data gap (the
  weakness was detected but its CA could not be reached to prove it, with the step to validate
  it), or directory hygiene (a decommissioned CA still registered in the directory); a data gap
  never reads as a confirmed critical. An ESC8 finding additionally names the web-enrollment
  transport the assessment relayed over (HTTP or HTTPS) and the observed channel-binding state,
  so the remediation targets the exact vector (disable HTTP enrollment on that CA first) rather
  than generic hardening.
- The report and platform now show a "Most Exposed Accounts" block under the exposure headline:
  the accounts the most compromise paths can reach, worst first, stating how many paths reach
  each one and how many were validated end to end. It names the top accounts to prioritise for
  Protected Users, tiering, credential rotation and LAPS, and collapses the long tail so a large
  domain stays readable.
- ADscan now identifies a directory-synchronization account (a Microsoft Entra Connect / MSOL_*
  sync account) that holds directory-replication rights and classifies it as a Tier-0 control-plane
  asset. Its ability to replicate every secret in the domain is surfaced in the report, the coverage
  report and the platform as a Tier-0 hardening item to confirm and contain, hedged as a capability
  to verify is authorized rather than an attack ADscan performed, so a replication account created
  for cloud sync is no longer taken for a benign service account or lost among lower-severity findings.

### Changed

- The remediation section is now one ordered "Start Here" list, led by how many of your affected
  users each fix removes exposure for (as "N of M affected users (X%)"), with the attack-path count
  as a secondary figure: a fix that protects more people ranks above one that breaks more graph paths
  but touches fewer accounts, and a fix on a path executed end to end leads the ones only mapped. The
  former standalone "Structural Choke Points" table is gone (a fix with no alternate route now carries
  a "durable fix" badge on its row), and the "Vulnerability Impact on Attack Paths" table is reframed
  as a subordinate finding register that points back to Start Here for the order to work in.
- The attack-path listing in the exposure report no longer prints one near-identical row per
  foothold: when several routes reach the same target by the same technique from different
  starting accounts, they now show as a single finding that names every foothold it opens from,
  so a fan-out-heavy domain reads as a handful of findings instead of dozens of repeats. The
  identified-path counts are unchanged; only the presentation groups the duplicates.
- The report's Compromised Credentials section no longer lists every account one row at a
  time once the domain has fallen. Credentials obtained by targeted techniques (kerberoast,
  GPP, LSASS, spray, ADCS, ACL abuse) stay listed individually as the breach story, while the
  full-directory extraction that follows domain compromise collapses into a single line stating
  the total and the secret-type breakdown, with the complete per-account list in the appendix.
  A fully-owned domain that used to run tens of pages of identical DCSync rows now reads in one.
- Shadow Credentials (a pre-existing msDS-KeyCredentialLink entry) are now presented as a
  persistence indicator to investigate rather than an attack ADscan performs. The operator
  panel groups and caps the objects so a Windows Hello for Business rollout no longer floods
  the terminal, and surfaces Tier-0 assets first. The client finding is now Medium by default
  (a detection, not a proven exposure), rising only when the affected object is itself Tier-0.

### Fixed

- Remediation and verification commands in the report and hardening playbook now run as
  written. Commands that touch a computer account or a certificate template use the
  object-class-agnostic cmdlets (a machine account is no longer handed a user-only cmdlet
  that errors on paste), account names that would be misread by the shell are quoted, and
  every place a command needs a host or address the client supplies now shows a clear
  fill-in instead of a made-up example, so a copied command targets the real object rather
  than one that does not exist.

- Attack paths no longer over-claim domain compromise through a logged-on user's session
  without proving the takeover of that user. Reaching a user's live session now requires the
  step that actually seizes it (dump its credentials or run code as it) before the path can
  use that user's own access, so a chain like "admin on host A, a user is logged on there,
  that user can RDP to host B" no longer silently escalates to full domain compromise on host B.
- Reading arbitrary files off a SQL Server host via bulk operations is now reported as an
  over-privilege finding, not an attack step: it is a file read as the SQL service account, not
  host takeover, so it no longer appears as a hop in an attack path. A non-administrator holding
  the bulk-operations permission (which it should not) is flagged with native remediation to
  revoke it; for a SQL administrator, where the capability is inherent, it is not reported as noise.
- The domain-scope attack-path listing no longer buries a separately compromisable host
  or account just because a larger kill chain happens to pivot through it: a stepping
  stone on the way to a high-value target now appears as its own finding, so the
  most-direct and the holistic views of a domain show the same set of targets. Pure
  waypoints that only ever sit inside a chain stay folded into it, and a target reachable
  only as a dead end that leads nowhere toward a high-value asset stays out of the
  high-value listing.
- Principal, group, computer and domain names now read consistently in human form across
  the report and the platform. The attack-path "reachable via" routes and the
  choke-point "start here" table no longer show raw directory labels (an all-caps
  `SERVICE$@DOMAIN`, a `Everyone@WELLKNOWN` sentinel, or a shouting built-in group). Each
  object is named exactly as your directory holds it: a built-in group in a localized
  directory keeps its own display name (an Italian "Computer del dominio" reads "Computer
  del dominio", not an English translation), so the names in the report match the objects
  and remediation commands you run on the domain controller, and an account or host reads
  as its lower-cased name.
- The domain-compromise exposure headline now counts real standard users correctly. It
  previously mixed in machine accounts pulled in through Authenticated Users, which roughly
  doubled the figure, and separately dropped accounts whose username carries a locale-specific
  character (the Turkish dotless-i or the German ß), which undercounted it. The headline now
  leads with real user accounts only (for example "100% of standard user accounts, 1,150 of
  1,150"), and the figure reconciles across the free report, the client report and the platform.
- Domain name resolution during collection no longer aborts the whole batch when a
  configured resolver entry is a hostname rather than an IP address; the malformed
  entry is skipped and resolution proceeds through the valid nameservers.
- An ADCS relay attack (ESC8) whose listener port was already held by another
  ADscan listener (for example, LLMNR/NBT-NS poisoning or the credential-capture
  listener started earlier in the scan) no longer crashes the scan with a raw
  "address already in use" error. The relay step now reports the listener as
  unavailable and the scan continues to the next attack path and the
  password-spraying phase.
- When an attack-path step fails and the remaining steps are skipped, the halt message
  now states WHY it failed (the underlying exploit / LDAP cause) instead of only "step
  failed", so a blocked compromise is diagnosable from the run output and logs.
- LDAP channel binding now derives its `tls-server-end-point` token from the domain
  controller's own certificate signature algorithm instead of always using SHA-256. Against
  a DC whose LDAPS certificate is signed with SHA-384 or SHA-512, authentication no longer
  fails with `SEC_E_BAD_BINDINGS`, which previously could leave a scan returning near-empty
  results instead of a clear collection failure. Standard SHA-256 certificates are unaffected.
- Attack paths shown for a single owned or named account, and for "attack paths owned",
  now stop expanding once they reach a Tier-0 asset and close with the shortest route to
  full domain compromise, instead of also listing every further account and group that
  Tier-0 asset can reach. This removes hundreds of near-duplicate routes to the same
  finding on domains with a control mega-hub (an Account Operators-style group) and
  brings these views in line with what the full-domain exposure report already showed.
- Exposure reports and the platform now materialize attack paths completely on far more
  large directories with control mega-hubs, instead of falling back to a sampled result.
  A Tier-0 group that only ends a path is no longer mistaken for one that multiplies
  routes, and a conservative memory estimate that depended on transient free memory no
  longer aborts discovery, which previously could render "0 attack paths" even where the
  domain had been compromised. When a result is still sampled under real memory pressure it
  is labeled with its coverage, proven and reachable routes are stated distinctly, and a
  compromised domain is never reported as having none.

- GPP credential harvesting (cpassword and autologon) now completes on enterprise domains. It
  previously walked the entire SYSVOL tree under a single time budget and, on a domain with many
  Group Policy Objects, ran out of time and returned nothing; it now walks only the policy subtree
  where GPP files live, with a per-share budget that keeps partial results. It also reaches each
  domain controller by its correct Kerberos name, so a multi-controller domain (where it previously
  addressed a controller by IP with the wrong service name and built duplicate targets) no longer
  fails to read the replicated policy.
- ESC8 and ESC11 execution now targets the specific vulnerable certificate authority the
  finding identifies, so a domain with more than one CA no longer dead-ends on the
  first-discovered or a decommissioned one. ESC8 web enrollment over HTTPS also no longer fails
  when the CA does not cleanly close the TLS connection: teardown is best-effort, so a slow or
  ungraceful shutdown no longer masks a certificate that was already issued.
- The report and the hardening playbook now agree on the fix order and the headcount: the
  playbook runbooks follow the same Start Here order instead of re-ranking by severity, the
  severity score and the remediation order are labeled as two distinct things, and the number
  of standard user accounts with a path to full domain compromise reads identically on the
  free report, the paid report and the playbook.

### Removed

## [13.0.0] - 2026-09-19

### Added

- Zero-credential attack paths now begin at an explicit "Unauthenticated (null session)" entry
  step. The kill chain reads from the no-credential start, through the account it derived, all the
  way to full domain compromise, instead of silently starting mid-chain as if the attacker were
  already logged in. It is flagged "Executable without credentials, confirmed" and sorts to the top
  of the attack-path list, and ADscan can now execute such a path end to end straight from that
  entry instead of stalling with "no starting point you control". The recovered-credential finding
  behind the entry is rated by its proven context. It is Critical when the no-credential chain
  reaches full domain compromise, so a run that proves a zero-credential takeover no longer reports
  zero critical findings. The explanation stays honest about the mechanism: the file is reachable
  because the server permits null-session access to that share, not because an anonymous permission
  sits on it. The finding names the principals with measured read access and the null/guest session
  as an access vector, so the full remediable picture lives in the finding itself.
- A domain controller that accepts an unauthenticated anonymous LDAP bind is now a first-class
  "LDAP Anonymous Bind Enabled" finding with native remediation: disable anonymous operations via
  dsHeuristics, strip the Anonymous Logon read grants, each with a before/after check and a
  validation bind that should now fail. Because it needs no credential to begin, it leads the
  0-30 day remediation roadmap.
- On hosts where the scan account is a local administrator, collection now reads six host-local
  credential-protection settings over the same session and flags the weak ones: LSASS not running
  protected (RunAsPPL), WDigest cleartext caching, LM hash storage, a weak LAN Manager auth level,
  weak minimum NTLM session security, and custom Security Support Providers allowed into LSASS. Each
  carries native GPO/registry remediation and a `Get-ItemProperty` validation step. A non-admin host
  is skipped at no cost.
- A new configuration check flags a domain (or fine-grained password policy) that stores passwords
  with reversible encryption, recoverable to cleartext, with native remediation and validation.
- The compliance scorecard now includes the controls ADscan verified good, where before it listed
  only the broken ones. When ADscan reads a hardening setting and observes it correctly configured (passwords not stored reversibly, a
  machine-account quota of zero, hosts that refuse SMBv1 to a live negotiate probe), the mapped
  control is marked conformant across all six frameworks with the reading as evidence. Only a
  definitive observation greens a control; a setting ADscan could not read stays "not assessed"
  rather than assumed compliant.
- Compliance reports can now map findings to the CIS Microsoft Windows Server Benchmark, selectable
  alongside ENS, NIS2, ISO 27001, DORA and PCI DSS. Each executed path or validated finding is tied
  to the specific CIS control the environment deviates from, version-aware to each affected host's
  actual Windows release (Server 2016/2019/2022/2025, Windows 10/11), and shown in both the report
  and the platform. It is presented as a technical hardening baseline, kept apart from the regulatory
  frameworks, and makes no certification claim.
- The learning mode now teaches the full technique set it executes: ADCS ESC2 through ESC17, the
  coercion and relay techniques (PetitPotam, PrinterBug, DFSCoerce, coerce-and-relay to ADCS), the
  named CVEs (Zerologon, noPac, EternalBlue, PrintNightmare), the lateral-movement and access
  techniques, the DCSync and secret-dump primitives, the ACL-abuse and delegation escalations, and
  the MSSQL escalations. Each renders a full teaching card before it runs, and on demand through the
  `explain` command: what the weakness is and why it works, the by-hand command, the MITRE ATT&CK
  mapping and detection events, a native check, and remediation. These techniques previously
  executed but taught nothing.
- Reports and the CLI now show which non-privileged accounts can reach a Tier-0 asset (a domain
  controller, an ADCS certification authority, an Exchange server) and by what means: full local
  administrator, a remote session, or a database role, with the share of the domain that holds such
  access. It distinguishes what an account is granted from what it can reach. An ordinary account
  with a path onto a domain controller stays an ordinary account, and the finding is that it can
  reach the control plane at all.
- Attack paths can now be queried to one named target from the REPL. The `attack_paths` command
  takes a `--target "Domain Admins"` flag (a group, a host, or an OU) and shows only the validated
  routes that reach that object, resolving the name to its canonical graph label and listing the
  closest objects when a target does not match, instead of returning an empty result.
- Attack-path discovery shows a pre-flight panel before it runs: the graph's node and edge scale,
  the control hubs driving the density, and whether discovery will run in sampled mode on a large,
  dense directory. A new `graph_stats` command shows the same summary on demand and `adscan ci`
  prints a one-line version. It reads the already-computed graph, so it is instant.
- Attack-path results now persist per workspace, so reopening a workspace or a fresh `adscan ci` run
  reuses the prior path set instead of recomputing the full discovery pass when nothing in the
  directory changed. The cached set is dropped the moment the graph changes, so a stale set is never
  served, and it is skipped under `--no-cache`.

### Changed

- `adscan ci` (autonomous, non-interactive scanning) is now a PRO capability. The free LITE tier
  keeps the full interactive `adscan start` workflow on every platform; automation and unattended /
  CI runs are part of PRO. `adscan ci` is no longer marked beta.
- The minimum supported Python is now 3.10 (was 3.9). Field telemetry shows no one running ADscan on
  3.9. The lowest version in use is 3.10, so the 3.9 floor was carrying maintenance cost for an
  audience that no longer exists.
- Privilege-tier classification now recognizes the full Tier 0 control-plane set consistently across
  the report and the platform, from one authored source. Group Policy Creator Owners, DnsAdmins, the
  Exchange privileged groups, the read-only Domain Controller groups, Cryptographic Operators, and
  the Certification Authority and its templates are all graded Tier 0 wherever a tier is shown, and a
  Domain Admins member is graded Tier 0 by its membership rather than by name alone. The report's
  tier legend now states why each Tier 0 group is classified there, including the groups flagged
  Tier 0 for parity with industry tooling despite no known single-step technique, and shows the exact
  tier ("Tier 0: Domain Control", "Tier 0: Escalation-capable", "Tier 1: Server / Application Admin")
  in place of a coarse "High Value" badge.
- Member servers and accounts are now tiered by what they actually do, beyond their operating system
  or group membership. A Remote Desktop or Citrix host where ordinary users log on is Tier 2; a jump
  box, hypervisor or backup agent that administers a Tier 0 asset is raised to Tier 0; a SQL,
  Exchange or SharePoint host is recognised as an application server; and an account with local
  administrator (or SQL sysadmin) rights over a Tier 1 server is itself Tier 1. Every Tier 1 verdict
  records how it was inferred, and the report states that Tier 1 is heuristic and
  customer-overridable while Tier 0 is derived deterministically.
- A credential found in a file on a share (a Group Policy Preferences password, a recovered
  SecureString, a spidered secret) is now attributed in the attack graph to the principals that can
  actually read that share, the measured share-ACL and file-NTFS read set, in place of the account
  that happened to recover it. The report and the platform now agree on who could reach the exposed
  secret whether ADscan reached it unauthenticated or with credentials. Each attribution states its
  verification level: read access confirmed live, share and file NTFS both evaluated, or share-level
  access only with the file's NTFS unverified, so an auditor sees which attributions are proven and
  which are a lead.
- The Security Assessment Report reads as one finding, rather than a tool dump, when a dense domain
  produces dozens of near-identical attack paths that share one root cause. Routes that begin the
  same way and hit the same over-broad grant are grouped, the structurally-distinct examples shown
  in full and the rest folded into a compact "Tier 0 objects reachable by this same chain" table
  (one fix closes them all). The attack-graph diagrams also draw every interchangeable pivot behind
  a finding, each colored by whether that route was proven (green), attempted (amber) or theoretical
  (grey), so the reader sees the full set of ways in without the finding list exploding.
- The free exposure report now reads as a complete assessment. The executive page leads with a
  labelled exposure figure (the share of accounts with a validated path to Tier 0) set beside the
  posture score with each figure's direction spelled out, a green "attack surface already reduced"
  callout naming the attacker avenues your own configuration already closes, and a compact Tier 0/1/2
  legend that makes the direct-versus-escalation-capable split explicit for an auditor.
- The Force Change Password finding now separates expected Exchange self-management from genuinely
  over-scoped delegation. The Exchange management groups resetting their own system mailboxes fold
  into one annotated row, the human and service accounts that matter stay itemized, and the finding
  text names the distinction, so an Exchange-aware reader no longer dismisses a real over-scoped
  grant as background noise.
- Offline mode now also skips the launcher and runtime version check, so an air-gapped run makes no
  call to PyPI or Docker Hub. `--no-update-check` now also accepts `--no-update` as an alias.
- When a bundled tool fails to start because the machine's CPU lacks the x86-64-v2 baseline NumPy 2.x
  requires (common in a VM whose hypervisor exposes a generic CPU model), the startup check and the
  credential scan now name the real cause and the fix (give the guest the host CPU, `-cpu host`) in
  place of a raw NumPy baseline traceback that reads like a broken install. Credential scanning then
  degrades cleanly as an honest coverage gap and the scan continues.

### Fixed

- The report and the writeup now quote the same attack-path total, so a report can no longer read
  "closes all 42 paths" one page from a headline of "43". Both documents lead with the one validated
  inventory figure the exposure score already uses. The recovered-secret count is reconciled the same
  way: when the krbtgt key is among the recovered secrets, both documents footnote that the count
  includes it, so the credentials table and the writeup ledger never present two different totals.
- Principal and group names now read the way a consultant writes them across the report, the writeup
  and the attack-path diagram: an account renders as `michael.wrightson` and a group as
  `Backup Operators`, in place of a shouting `MICHAEL.WRIGHTSON@CICADA.HTB` login string, a raw SID,
  or an internal placeholder, and well-known identities keep their proper names. A principal in a
  different domain still shows its domain, so a cross-forest hop stays clear.
- Remediation and verification commands in the report and the playbook now carry the environment's
  real identifiers. An `NTAccount`/`dsacls` principal is written with the real NetBIOS name (for
  example `HTB\Account Operators`) in place of an unfilled placeholder or the DNS form Windows
  rejects, and every "verify this finding independently" command uses the object's real
  sAMAccountName, distinguished name or hostname rather than the display label, so a command a
  sysadmin pastes resolves the object instead of silently matching nothing.
- The report's executive summary no longer contradicts itself. The Compromise Reach cards now add up
  to the total attack-path count shown above them, the exposure gauge matches the same
  validated-exposure figure quoted elsewhere, the candidate routes discovery evaluated are named
  separately from the deduplicated paths the report presents (so two counts never share the word
  "route"), and the page leads with a single headline figure and states why findings rated Medium in
  isolation drive a Critical posture. Every count and score is unchanged; the page now explains them.
- Attack paths whose opening step ADscan actually executed now read as partially validated (or fully
  validated when the whole chain ran) in the report and the platform, in place of merely theoretical.
  The proof of that first step was being recorded against a separate representation of the same
  account and lost when the report re-derived the path. A route with no successful step still reads
  as theoretical.
- The free exposure report no longer overstates its evidence relative to the paid report. A route to
  full domain compromise that was mapped but not walked end to end now reads "a mapped path to full
  domain compromise whose entry step is proven" rather than "a validated path", and the free and paid
  reports now derive the same headline figures from one source: the share of accounts with a path to
  Tier 0 (previously blank in the free report) and the count of attacker avenues the environment
  already closes are computed once and read by both.
- A readable share reached over a null or guest SMB session now reports its actual authorized-reader
  list, read straight from the folder's security descriptor, in place of a lower-confidence inferred
  placeholder, so findings sourced from such a share cite the real principals with measured read
  access.
- A valid computer-account credential is no longer reported as invalid when the domain controller
  enforces AES Kerberos with a non-default salt; the check derives the machine-account key correctly
  and confirms the credential over RC4/NTLM before rejecting it. The authenticated scan also no longer
  prints a raw multi-line trace when only the Kerberos ticket step fails but the scan continues over
  NTLM, and no longer implies a valid credential was rejected in that case.
- The important-port scan is far faster on large domains. It previously retried each unreachable host
  up to ten times, so a domain with many stale or powered-off computer accounts spent most of the
  scan waiting on hosts that no longer exist. It now gives up on a non-responding host after a few
  tries and caps the time spent per host, so a scan of a thousand mostly-stale hosts finishes in
  minutes instead of over an hour, with identical results on the hosts that are up. The scan stays
  gentle by default (no increased packet rate against live hosts); operators who own the network can
  opt into faster timing with the `ADSCAN_PORTSCAN_NMAP_*` variables.
- Opening and working in a workspace for a large domain is far faster. The terminal no longer stalls
  and drips output line by line while loading a directory with thousands of accounts and computers.
  The slowdown grew with the size of the domain, so the biggest environments were the worst affected;
  a large lab that took over a minute to open now opens in a couple of seconds.
- Attack-path discovery on a large or dense directory no longer exhausts memory or gets killed. The
  result cache is now bounded by actual memory rather than a blind fixed path count, and on the
  native Windows build (which has no container cgroup) discovery reads the host's real memory limit
  and free memory, so a big run stops cleanly with a clear message instead of being killed. What
  ADscan computes and serves is unchanged.
- Password cracking no longer fails when a previous cracking run is still active; each run uses its
  own session so concurrent or leftover runs do not block a new one.
- `adscan ci` and other scans no longer abort at preflight when the bundled credential-scanning tool
  is a newer build than expected; the version check now matches the shipped tool.

## [12.0.0] - 2026-09-08

### Added

- ADscan now runs natively on Windows. Alongside the Linux Docker deployment,
  there is now a self-contained Windows build that runs the engine directly, with
  no Docker, no Python install, and no launcher. A low-privilege user can drop the
  bundle on a domain-joined Windows host and run a full scan from there; port
  scanning, password cracking, DNS resolution, clock sync and host DNS all work
  without the Linux-only plumbing the Docker deployment relied on. Linux is
  unchanged and remains the default.

- Attack-path discovery now completes on very large, dense directories that
  previously returned nothing. A directory with tens of thousands of objects and a
  few heavily-connected groups used to exhaust the analysis before it produced a
  single route; ADscan now detects that shape up front and switches to a bounded
  per-target search that returns a representative, honestly-declared set of routes
  with every reachable high-value target covered, instead of stopping empty.
  Ordinary-sized directories are unaffected and still return the full set of
  routes, byte-for-byte as before.

- The report and web platform now lead remediation with the fixes that break the
  most attack paths ADscan actually executed against your domain, so the
  highest-leverage fix is what you see at the top, on every surface — the free
  report, the paid deliverable, and the platform — reading the same ranking and
  the same numbers. Each fix states how many attack paths closing it removes, a
  fix that maps to an object with no alternate route is marked as a durable fix,
  and a fix that only touches theoretically-mapped routes is worded as such and
  never claimed as executed. When route discovery was sampled on a very large
  directory the ranking says so plainly.

- On a very large directory, the report and web platform now state plainly when
  attack-path routes are a representative sample rather than every route. Every
  reachable high-value target is still covered, and the finding to track over
  time is the exposure count — how many principals can reach a high-value target
  — which stays stable across re-scans even though the individual routes shown
  may change. Ordinary-sized directories are unaffected and continue to report
  the full set of routes.

- Port scanning now runs in-process on Windows, with no nmap or Npcap needed.
  A hardened, install-nothing Windows host has no nmap binary, and a SYN scan
  there needs the Npcap driver plus admin rights that such a host will not have;
  ADscan now uses a native async TCP connect scan instead. It is paced
  conservatively by default — comparable to nmap's production-safe timing, with
  a per-host limit and automatic back-off when the network shows signs of strain
  — so it stays gentle on fragile hosts and monitored enterprise networks rather
  than scanning as fast as possible. Operators who own the network can raise the
  throughput with the `ADSCAN_PORTSCAN_CONCURRENCY` and `ADSCAN_PORTSCAN_PER_HOST`
  environment variables. Linux is unchanged and still uses nmap's SYN scan.

- Password cracking now falls back to CPU on Windows hosts with no GPU stack.
  On a hardened Windows machine there is often no OpenCL/CUDA runtime, so the
  GPU cracker cannot run at all; roast and captured-network-authentication
  hashes now crack on pure CPU instead, with the recovered credentials recorded
  the same way and the report declaring the gap honestly when no cracker is
  available. Linux behaviour is unchanged.

### Changed

- The Windows download is roughly half the size. The bundled audit password
  list is now shipped compressed and unpacked once on first use, cutting the
  executable from about 1.2 GB to around 500 MB with no change to cracking
  behaviour — the same list is used, it is just carried more efficiently.

- Domain-wide attack-path discovery now targets high-value (Tier-0) assets
  instead of every object. The all-targets domain sweep could not finish on a
  large directory and the report and execution flows never used it, so a
  production run no longer launches it silently: the CLI prints an honest note
  and shows the Tier-0 targets, and the web platform does the same for a direct
  API request.

- Bulk DNS resolution — both during attack-graph collection and when resolving
  computer hostnames ahead of the important-port scan — is now faster on large
  domains and no longer needs the external massdns binary. Names resolve
  concurrently through the DC, so the dead hosts a big network always has
  (powered-off machines, stale A records) no longer serialize their timeouts and
  stall the pass — a 5000-host benchmark measured it about three times faster
  than the previous approach with identical coverage. Removing the last massdns
  dependency also means host resolution now works on a native Windows install,
  where that binary was unavailable.

### Fixed

- AS-REP roasting and Kerberoasting attack-path steps now target the user's own
  domain in cross-forest paths, instead of roasting the wrong domain and aborting
  the path. A trusted-domain target is roasted against its own domain controller
  and realm; if that domain was never enumerated, the step now says so honestly
  rather than reporting no hashes found in the wrong domain.
- Cross-forest AD CS attacks (ESC1, ESC3, ESC4, ESC5, ESC13) now authenticate as
  the enrolling principal against that principal's own forest, instead of assuming
  the certificate authority's forest. When an owned account in one forest holds
  enrollment or CA-backup rights across a trust, its ticket is now minted at its
  home domain controller so the enrollment succeeds, rather than failing because
  the request was sent to the wrong forest's KDC. The pre-flight readiness check
  for ESC1, ESC3, ESC4, and ESC13 was fixed the same way — it no longer reports
  "no stored domain credential found" for an enrolling principal whose credential
  is stored under its own forest.
- Attack-path steps that authenticate to a target host or exercise a directory
  permission (local admin, remote desktop, remote management, database access,
  full control, write property, password resets, managed-service-account and
  computer LAPS password reads) now look up the executing account's credential
  under that account's own domain in a cross-forest path, instead of assuming
  the domain currently being enumerated. A low-privilege account in one forest
  can now correctly authenticate a step against a target it can reach through a
  trust, rather than the step failing because the credential was searched for
  in the wrong domain.
- Constrained delegation and resource-based constrained delegation (RBCD)
  attack-path steps now look up the executing account's credential under that
  account's own domain in a cross-forest path, the same fix already applied to
  host-authentication and directory-permission steps, instead of assuming the
  domain currently being enumerated.
- HasSession no longer misses a viable executor discovered from an earlier
  cross-forest AdminTo step: the search for a reusable credential now checks
  the candidate's own domain, not only the domain currently being enumerated.
- When the configured scan interface is stale or has no address, ADscan now
  switches to the interface its own route check found reaches the target
  (offering the switch interactively, adopting it automatically in unattended
  runs) instead of dead-ending on "interface has no IPv4 address" and forcing a
  manual interface change.
- CPU cracking of multi-principal roast files (AS-REP and Kerberoast captures)
  now reliably recovers the cracked passwords. The crack and the result read
  could resolve different result stores, so recovery sometimes came back empty
  even after John had cracked the hash; the two steps now share one pinned
  store, and a live crack is also read directly as a backstop.
- Password cracking on Windows now falls back to a wordlist that is actually
  present instead of failing silently. On a Windows install the large audit
  wordlist is not bundled, and cracking would run against a missing file and
  recover nothing; it now degrades to the available list (rockyou) so a roasted
  hash whose password is in that list is recovered.

- Attack-path discovery no longer aborts to zero routes on a large,
  Exchange-heavy directory when scanning from owned principals. The memory
  estimate now reflects that a path starting from a single owned principal
  affects far fewer accounts than a domain-wide analysis, instead of assuming
  the whole directory as its blast radius.
- The posture probe no longer prints red error lines for its own expected
  results. Detecting that LDAP signing or channel binding is not enforced works
  by sending a deliberately-rejected bind, and checking for LDAPS on a closed or
  filtered port produces an expected connection error — both used to surface as
  an "An error occurred" banner directly above the panel that reported the same
  outcome as a success. A genuinely unexpected probe failure is still shown.
- DC-candidate discovery now reports the ports actually open on each host, not
  the ports it scanned for. A host answering only on 53/tcp (DNS) previously
  read as though every domain-controller port was open, making it look like a
  domain controller right before the scan stalled with nothing to enumerate.

- Session recordings no longer retain an organization or host name from Kerberos
  and SQL diagnostics — a Kerberos realm (including its short single-label form)
  in service-principal-name output, or a linked server's short hostname in
  SQL Server output. Each is now pseudonymized like every other domain and host,
  and consistently, before a recording is uploaded.
- Session recordings no longer retain an IP address or subnet embedded in an
  environment-variable hint or run together with other input. An address folded
  into a variable name, or two ranges pasted with no separator between them, is
  now pseudonymized like any other address before a recording is uploaded.

- Attack-path analysis no longer shows a "contact support" error anywhere it runs
  when route discovery is bounded by available memory on a large environment — the
  interactive listing, the report, and the platform snapshot all now state the
  coverage boundary honestly (how many routes were examined and that the set is not
  exhaustive) and continue instead of stopping.
- Resuming a scan whose stored credential has since been locked or disabled now
  shows a clear "the credential is locked or disabled — save a fresh one and
  re-run" line instead of raw Kerberos and LDAP error traces.
- Setting a username or password before a domain is configured no longer crashes;
  it prints a short prompt to configure a domain first (`set domain <fqdn>`).

### Removed

## [11.3.0] - 2026-09-01

### Added

- A DCSync can now replicate just the krbtgt account. When an operator already
  controls a Domain Admin, "krbtgt only" proves full domain compromise and
  captures the golden-ticket key without pulling every account out of the
  directory — the minimal-footprint way to mark a domain owned.
- Didactic mode: ADscan now explains each attack technique as it runs, so a scan on a lab or an HTB box teaches Active Directory pentesting instead of just doing it. Before a technique executes, a teaching card shows what the attack is and why it works, the equivalent command to run it by hand with the standard tool, its MITRE ATT&CK id, and the Windows Event IDs that detect it. Three levels: a full card (default on CTF/lab workspaces), a one-line summary (default on audits), or off, set with `set explain_level off|basic|deep`. The new `explain <technique>` command shows the full card for any technique on demand without running anything (e.g. `explain kerberoasting`, `explain "ADCS ESC1"`).
- Password spraying by month/season and year for audit engagements: a new spray option tries the predictable seasonal passwords forced rotation produces (March2026, Verano2026). Picking it lets you choose the pattern (month, season, or both) and the language: ADscan infers whether the environment is English or Spanish from language-independent account signals, shows its guess, and lets you keep or change it, remembering the choice per domain so later sprays do not ask again. With domain credentials it reads each user's last password-change month and sprays their most likely seasonal password; without credentials it uses the current month and season (editable at the prompt). Only Word+Year forms are tried, no trailing symbols, one attempt per account, inside the same lockout safety rules as every other spray. In an unattended `adscan ci` run the month and the season passes now both run. Configurable and skippable via the `month_season` spray strategy in the scan config.
- Reports and the web platform now include a "Verify this finding independently" block on each attack step, so the client can confirm a finding by hand and rule out a false positive. Each block gives a native Windows/PowerShell check (Get-ADUser, Get-Acl, dsacls, certutil) and a Linux/pentester equivalent, starting with the highest-volume techniques (Kerberoasting, AS-REP Roasting, DCSync, ADCS ESC1, and the GenericAll/GenericWrite/WriteDACL/WriteOwner ACL family). The Linux commands carry the environment's real domain controller IP and domain name instead of placeholders, so they are paste-and-run; credentials are never filled in for you. In the web platform each command has a one-click copy button.
- Attack paths now cross domain and forest boundaries. A workspace with more than one domain is analysed as one unified graph, so a low-privilege principal in one domain that can act on an object in another (through a foreign ACL, a group membership across a trust, a child-to-parent relationship, or a cross-organization TGT-delegation trust) yields a single end-to-end route that terminates in the domain it actually reaches. Same-named accounts across domains (administrator, guest, krbtgt) stay distinct, and single-domain workspaces are unchanged.
- After compromising one domain, ADscan now escalates into another on its own when a trust allows it. Two routes ship: from a compromised trusted forest into the trusting forest across a cross-organization TGT-delegation trust, and from a compromised child domain up to its forest root (RaiseChild). Each fires only when its trust condition holds. A successful escalation compromises the reached domain and runs its own post-compromise, so a foothold in one forest can carry through to full compromise of a forest that trusts it. Both routes are drawn on the attack graph and reported with native remediation.
- Cross-forest Kerberoasting and AS-REP Roasting routes now appear in multi-domain analysis: an authenticated principal in one forest can roast a service or no-preauth account in another domain across a trust, and that end-to-end route surfaces. The ADCS web-enrollment relay routes (ESC8/ESC11) surface across a trust for the same reason.
- Plaintext credentials left in an account's directory description or info attribute are now a validated attack step in the deliverable, not just a side finding: ADscan reads the attribute over LDAP, recovers the credential, and verifies a working login. The route also crosses forest boundaries.

### Changed

- A domain is reported as compromised once ADscan proves control of a Domain
  Admin, not only after the full krbtgt hash dump, so a validated Domain Admin
  takeover no longer shows as "not compromised" when the operator declines the
  full credential extraction.
- A DCSync now defaults to replicating the whole directory, so an unattended run
  performs the full domain password audit the cracking pipeline is built for;
  "krbtgt only" or a specific account narrows it.
- Child-to-forest-root escalation (RaiseChild) now lets you choose what to
  replicate from the forest root — the full directory, krbtgt only, or a specific
  administrator — instead of always pulling just krbtgt and Administrator, and
  marks the forest root compromised on proven Domain Admin control.
- The long "Choose Scan Type" explainer at the start of an unauthenticated scan now shows once and then steps aside on later scans; the quick "Do you have domain credentials?" question still appears every time. Non-interactive runs skip the explainer entirely.
- Password spraying now shows how ADscan keeps accounts safe: before an authenticated spray it states that it reads the domain lockout policy and each account's failed-password count, skips accounts near the threshold, holds back a safety margin, and limits itself to one attempt per account; before an unauthenticated spray, where the threshold can't be read, it surfaces the wait-between-attempts caution at the decision point. The custom-password prompt now shows a few example patterns to try.
- Attack-path computation is much faster on large directories. Work shared across routes with identical inputs (the path-status roll-up, per-step remediation, and blast-radius annotation) cuts a domain-wide run on a directory with tens of thousands of accounts and fifteen thousand routes from about a minute to about ten seconds, with identical results.
- The credential-replication panel now shows recovered computer accounts in their own row type, badged and counted separately (`5 users · 2 machine accounts`), so machine-account key material is visible without inflating the login count or reading as accounts to spray. They stay out of the deliverable's per-account detail and out of password cracking.
- Exception tracebacks now reach the sanitized session diagnostics recording, so a failure that shows the operator only a generic message can still be diagnosed afterward. The terminal is unchanged: full tracebacks stay on screen only under `--debug`.

### Fixed

- A targeted Kerberoasting attack-path step now roasts only the account it
  targets. Previously a step aimed at one service account requested service
  tickets for every account with a service principal name in the domain, so a
  step to roast one user pulled hashes for unrelated accounts and generated far
  more directory-service alerts than the step called for.

- The krbtgt (KDC service) account is now recognized as non-loginable by design:
  ADscan no longer tries to log-on-verify it or generate a ticket for it after
  extracting its hash — operations that always fail for that account — so a run
  no longer prints a spurious "locked out" verdict or ticket-generation error.
  Its hash is retained for offline ticket forging, and genuinely locked-versus-
  disabled accounts are now classified correctly instead of everything revoked
  being labelled "locked".

- In a multi-domain workspace, selecting a cross-domain attack path from a single domain's view now lets you execute it when the starting principal is one you own in another in-scope domain, instead of refusing with an "unsupported" message. Execution is now offered consistently whether the path is opened from a per-domain list or the combined cross-domain view; the set of discovered paths is unchanged.
- Attack paths in a multi-domain scan are now shown once per domain and can be executed directly from that view. Previously each per-domain list was display-only and execution was deferred to a separate cross-domain pass that computed just one domain and missed most routes; the unified per-domain flow keeps every route, shows each unique path once, and lets you run it where you see it.
- Attack-path discovery on a very large or densely connected directory now stops with a stated coverage boundary if it would exhaust memory mid-computation, instead of being killed by the operating system with no result. A directory that fits in memory is unaffected and its coverage is unchanged.

- A proven foothold on a host now carries into the next step of the same attack path. When an earlier step confirmed local admin on a server, the follow-up credential dump on that server runs to completion instead of stopping with a contradictory "this host is not yet compromised" message. A database-only session, or an access step that was never confirmed, still does not carry a foothold forward.
- An attack path from a compromised child domain to the forest root now runs to completion. ADscan forges the inter-realm ticket, reuses the child krbtgt key it already extracted rather than replicating it a second time, follows the cross-realm trust to the forest root, and replicates it — so a chain from a child-domain foothold to full forest compromise completes end to end instead of stopping partway with a directory-replication error.
- A credential-replication step (DCSync) and the credential-dump steps now run whenever ADscan already holds material that reaches the host, instead of stopping with a "not yet compromised" message. A delegation ticket minted earlier in the path, an owned domain controller's own machine account, or a proven foothold on the host each let the step proceed, so a chain like AllowedToDelegate then DCSync now replicates the domain to the end. A step that would modify the directory still runs only as a principal you actually control.
- Credential-template escalation findings (ESC1, ESC2, ESC3, ESC6, ESC9, ESC13, ESC14, ESC15) are now reported only for templates an enterprise CA actually publishes, so a vulnerable-by-configuration template that no CA issues no longer appears as an executable path to domain compromise that fails at request time. A policy-linked ESC13 finding on a template that grants no client authentication is also dropped.
- Attack-path discovery no longer returns zero routes on a large directory that fits in memory. A pre-emptive memory check was over-estimating a run's needs by roughly eleven times and aborting before any route was computed; the estimate is recalibrated, so these runs complete and report their real routes, while a genuinely oversized run is still stopped cleanly with a stated coverage boundary.
- Multi-domain analysis no longer invents impossible cross-domain routes. Built-in groups identical by identifier in every domain (such as `Administrators`) were collapsed into one node, making one domain's replication rights appear to reach another. Each domain's built-in groups are now distinct; genuinely global principals (Everyone, Authenticated Users) and real cross-domain techniques are unchanged.
- Credential replication now keeps the Kerberos keys of computer accounts, so the escalation steps that need a machine's own key (cross-forest TGT-delegation, resource-based constrained delegation, silver tickets, shadow credentials) run instead of dead-ending. The keys are used only as Kerberos key material; computer accounts never enter the credential list or the cracking queue.
- The CVE scanner targets a domain controller by its resolved hostname instead of its IP for Kerberos, so an authenticated scan across a forest trust no longer prints repeated "logon denied" errors for a controller in another domain. A controller the scan credential cannot authenticate to is skipped with a clear cross-domain note.
- Reading a certificate authority's security settings without CA-admin rights is now handled quietly. An ordinary account lacking those rights triggered an alarming red error with no cause after the colon on an otherwise-successful scan; that expected answer is now recorded as a routine skip.
- Unattended scans of a hardened directory with no anonymous access now try to detect the real username convention, or reuse one already found this run, before falling back to a generic name list, instead of blind-guessing common names and confirming nobody. The strategy is chosen on effectiveness and no longer depends on the workspace type.
- Kerberos username enumeration no longer loops back to the start after it finishes. Once the automatic sweep confirms users, ADscan remembers the detected format and offers one clear next step (exploit with the confirmed users, widen the list using that format, or stop) instead of a prompt that could silently restart the same multi-hour sweep.
- Environment configuration set on the host now reaches the containerized scan. Any `ADSCAN_*` variable an operator exports (attack-path tuning, cache sizes, depth limits, diagnostic toggles) is forwarded in, where before only a fixed subset was, so a documented setting could appear to have no effect.
- Session recordings now show a single, consistent masked name for each domain instead of several different masks for the same one, so a recording can be reviewed without ambiguity. The masking is unchanged: deterministic, per-install, non-reversible, with no additional data recorded.
- Typing `cves <domain>` in the shell now scans that domain instead of returning "unknown subcommand", the same way the other exploration commands accept a domain name.
- A PRO scan started without a partner tag is now refused on the host before the scan container starts, and the in-container check fails fast before the startup preflight rather than after it, so the operator no longer waits through the full tool-and-browser check to be told a one-line tag is missing. Passing `--partner-tag`, or having set it once, is unaffected.

### Removed

## [11.2.0] - 2026-08-21

### Added

- Optional `--dns-server` for segmented networks where the AD-zone DNS server is a separate host from the domain controller. It feeds name resolution only, and every resolution the scan needs follows it: domain and PDC-hostname discovery, host and CA names during SMB and ADCS enrollment, the Kerberos SPN lookup that keeps a scan on Kerberos instead of silently degrading to NTLM, cross-forest trust resolution, and the network-preflight DNS check. `--dc-ip` stays the authentication and enumeration target, and omitting `--dns-server` behaves exactly as before. Available on `adscan ci`, `adscan execute`, `adscan doctor`, the web connection check, and offered interactively when the DC does not answer DNS on port 53.
- Range discovery now finds a separate DNS server on its own when a scan starts from a host range instead of a known domain. When the domain controller does not answer DNS on port 53 and the same sweep saw a host that serves DNS but is not itself a controller, `adscan start` offers that host as the pre-filled default for the DNS-server prompt, and an unattended scan adopts it automatically only when it is the single such host on the range and it actually resolves the domain zone. The controller stays the authentication and enumeration target; the detected host is used only to resolve names.

### Fixed

- A Force Change Password step against a user now runs unattended in a CTF scan as intended. A second, hidden confirmation still defaulted to skip, so an unattended CTF run reset nothing and reported the step as not executed. Consent is now a single confirmation, so a CTF scan resets the user and continues the path while an audit scan still requires an explicit operator opt-in. Resetting a computer or machine account password stays refused outright in every mode.

## [11.1.0] - 2026-08-10

### Added

- ADscan now carries a cross-forest compromise all the way through. A forest trust that re-enables cross-organization Kerberos ticket delegation is identified and drawn as an escalation route, so when a trusted forest is compromised the route continues across the boundary into the trusting forest — the two forests read as the one blast radius that setting removes the protection against, with remediation to disable the delegation. Reaching SYSTEM on a trusted or foreign domain's controller through a pivot (for example an MSSQL linked-server chain into another forest) now surfaces the resulting directory replication as a coupled step, so the path terminates at the trusted domain that was compromised rather than stopping short at its controller.
- On a large directory ADscan offers a choice before the long SMB host-enrichment sweep instead of running it silently for hours. The identity graph (users, groups, computers, ACLs, ADCS, trusts) finishes in minutes and attack paths can be computed from it right away; the deeper per-host pass across tens of thousands of hosts is what takes time. When the reachable host count is large, an interactive run states the real numbers, shows an approximate time for each scope, and lets the operator enrich the recommended set, a number of hosts they choose, everything, or skip enrichment and compute paths now; an unattended scan honours the host cap set in the web UI or scan config. Whichever scope is chosen, the report and platform state exactly how many hosts were enriched of the reachable total, so a partial sweep is never presented as complete.
- Both reports and the platform now state how many accounts already hold Tier 0 privilege by group membership, beside the count that reach it through an attack path. The two answer different questions — whether you have tiering at all, and whether the tiering you have holds — and the second figure excludes the already-privileged accounts, which is only defensible while the first is printed next to it. Where a quarter or more of the directory already holds the control plane, that reading takes the headline: forty domain administrators in a hundred accounts do not need a route.

### Changed

- Trust relationships are now always mapped, and a separate choice governs which domains get collected. Mapping the trust graph is cheap and useful on its own, so an operator can see it without collecting a forest they are not authorized to touch. Which domains ADscan then collects follows the engagement type: a CTF scan collects every reachable domain, including a trusted forest a pivot just unlocked, and carries a cross-forest escalation through to the end unattended; an audit scan stays on the origin domain, since collecting a trusted forest is often outside the agreed legal scope. An interactive run pre-selects the newly-unlocked domains for the operator to decide. The default is overridable per scan (the web scan-setup domain-enumeration policy, or the `ADSCAN_TRUST_SCOPE` environment variable set to `all` or `origin`).
- Executing a Force Change Password step against a user now follows the engagement type when a scan runs unattended: a CTF scan resets the target and continues the attack path automatically, while an audit scan skips the reset unless an operator explicitly approves it, because changing a real user's password is irreversible and disruptive. Resetting a computer or machine account password is still refused outright in every mode, before any prompt.
- The MSSQL SYSTEM-escalation follow-up and the HasSession exploitation step now offer the same choice: mint a fresh privileged account, or elevate an account you already control. Both also stop assuming the elevation target is always a Domain Controller — HasSession's escalation used to add the new account to Domain Admins even on an ordinary member server; it now elevates to that host's own local Administrators group instead, and says so. At workspace exit, ADscan asks whether to delete an account it created during the MSSQL follow-up (default: yes); declining records the exact command to remove it later, so nothing is silently deleted or left behind. An account you already owned is never touched.

### Fixed

- Guest SMB share enumeration works against hardened, modern domain controllers. On a controller that enforces SMB signing and enables the Guest account (Windows Server 2022/2025), a guest session was seen in reconnaissance but then failed with "Connection closed" the moment the access probe read the shares, because the session was being encrypted where a guest session may not be. The connection now recognises a controller-granted guest or anonymous session and stops encrypting it, so the access a guest or anonymous caller genuinely has is enumerated.
- Credentials stored inside tables in Word, Excel and PDF documents on shares are now detected. A password in a table cell used to be read in isolation from its label cell in the next column, so a `Password | R3dT3am@Acc3ss#01` row was scanned as an anonymous token and dropped; the tables are now reconstructed into labelled `key: value` text before scanning, so a value pairs with its column header. This applies wherever ADscan reads documents for credentials — SMB shares, WinRM and MSSQL loot, and spidering — and files without tables are unaffected in speed.
- Kerberos-authenticated coercion no longer fails to start. The native SMB connection factory built a Kerberos credential with a mis-named argument, so every coercion or relay authenticating over Kerberos raised an internal error before it could send a request — the path the cross-forest ticket-capture escalation depends on.
- A scan of a large directory could freeze indefinitely while enriching hosts over SMB — draining a few hundred hosts, then stalling for hours until interrupted. Two unbounded operations are now bounded: closing a host's SMB connection had no time limit of its own, so a host that hung the close held its worker permanently; and the periodic mid-scan checkpoint wrote the partial graph to disk on the thread that drives every host, so a slow write froze the whole sweep. The teardown is now capped and the checkpoint runs off that thread, so a single stuck host is abandoned and the run continues.
- Attack-path discovery on a very large directory now stops cleanly and says what to do, instead of being killed for running out of memory. The analysis measures the memory it will need against the ceiling that actually applies (the container's, not the host's) and, when the two cannot be reconciled, stops before the fatal step and tells the operator to raise the memory or free what another workload holds. A bounded run is declared plainly: the report and platform state how many candidate routes were evaluated and that the set is not exhaustive.
- Pressing Ctrl+C during a long SMB host-enrichment sweep now stops the sweep and asks what to do next — continue enriching the remaining hosts, stop and continue with the hosts already collected, or exit. It can no longer abort the scan by accident however many times the key is pressed, since exiting is a deliberate menu choice; a run that has already taken hours can no longer be lost to a panicked keypress. Returning to a workspace whose enrichment was stopped early now resumes from where it left off and says so, instead of silently re-scanning every host; re-scanning from scratch stays available as an explicit opt-out.
- CVE checks preflight the port each check actually needs before connecting. Selecting every host used to connect to each one for each applicable check with no reachability preflight, so unreachable hosts each produced a per-host timeout — one audit surfaced 42 as identical "contact support" lines. Each check now declares its transport's port (135 for the RPC endpoint mapper, 88 for the Kerberos-based checks, 445 for SMB, 636/389 for LDAP), the sweep probes once up front, and a host that does not answer is recorded as not evaluated for that check — a stated data gap, never reported as not vulnerable.
- The certificate-services checks no longer report an attack as absent when the only problem was resolving the certificate authority's name. Where the domain controller's DNS could not resolve a member CA's hostname, the CA-security and web-enrollment probes gave up and the web-enrollment relay avenue (ESC8) read as "not present" — a silent false negative that hid a real, exploitable path on every affected authority. ADscan now recovers the authority's reachable address from what the scan already learned and connects on it, keeping the hostname for authentication. Where the host genuinely cannot be reached, ESC8 is reported as unverified rather than absent.
- A directory-replication (DCSync) run that recovers nothing now names the cause the domain controller actually returned, instead of always reading as a permissions problem. Replicating a domain reached across a forest trust no longer stalls on a prompt for the account to target when that domain was never enumerated on its own — it falls back to the domain's built-in Administrator so an unattended run continues, and an interactive run can still override. A confirmed vulnerability that grants domain compromise now reliably lands on the attack graph: the vulnerability catalog is checked against the graph's recorded techniques before a scan starts rather than mid-run, and the operator no longer sees a generic error with internal detail printed alongside it.
- A confirmed SYSTEM escalation on a Domain Controller via an MSSQL linked-server chain no longer reports zero domain compromise. The temporary account ADscan mints to prove the escalation was deleted before later steps had finished using it, and on a cross-forest chain it could be placed in the target's local administrators instead of Domain Admins — both silently discarded a proven full-domain compromise. ADscan now attempts directory replication directly from that SYSTEM session (with a registry-based fallback when the replication port is unreachable through a pivot), and no longer depends on an inconclusive admin-group membership check to do so, since the controller's own machine account already carries the rights.
- Report and platform diagrams now read as one consistent, legible system. A node's shape states what an object is and nothing else, resolved once across the whole document, so the same principal no longer changes shape between figures; where a route begins is drawn as a ring around that shape rather than a competing shape. Every one of a directory's object kinds — groups, machines, containers, certificate templates, group policy objects, organisational units — has its own shape and its own line in a key drawn beside each diagram, instead of a fallback style the key attributed to something else. A route's outcome is coloured from the same classification its label and counts come from (red for full domain compromise, amber for a Tier 0 foothold with control unproven, a dark neutral for a route that only advances, green for an avenue the client's configuration already closes), and the four are separated by weight as well as hue so a greyscale print does not read a route that merely advances as one that arrived. Steps that begin and end on the same machine are stated inside that object rather than drawn as an arrow leaving and re-entering it, so a route's arrows match its step count. Labels no longer shrink below print size on long routes, and the platform's graph is corrected the same way.
- The Attack Path Analysis section explains each technique once instead of once per route. Attack paths overlap heavily, so the same explanation and remediation were reprinted at every occurrence — on one example directory, 134 steps drew on 18 techniques across 49 pages of a 101-page report. Techniques are now set out once ahead of the routes, ordered so the one carrying the most routes is read first, and each step still names the principals and targets it applies to; the same section is now 31 pages of an 80-page report.
- The report's figures now agree with each other and count the right population. The blast-radius figure counts the ordinary (non-administrative) accounts the assessment actually resolved rather than rounding a broad-group path up to the whole directory, so an example workspace that read "10 of 10 domain users" now reads "6 of 6 ordinary domain users have a validated path to full domain compromise", states how many routes were executed end to end, and names any account with no route — and excluding accounts that already hold domain control stops the figure trending to 100% whatever the environment. The free and paid reports and the platform now lead with the same non-administrative figure. Group managed service accounts are left out of the exposure figures, since their password is a value the controller rotates and cannot be exposed the way that figure measures; their real exposure is still reported as its own finding. The executive page distinguishes its exposure score from its share-of-accounts figure, states the population its evidence split breaks down, and fits one printed sheet.
- Remediation for the two broadest directory permissions tells a system administrator how to remove them. Full-control and write access over an object each carried advice that mostly described how to watch the abuse; both now name the object, give the commands that list and delete the offending entry, state what the listing shows before and after, and say what to grant back so the delegation keeps working. Attack-path steps that start from a principal already inside the Tier 0 control plane no longer tell the client to dismantle their directory (remove Domain Admins from BUILTIN\Administrators, and the like) — those steps stay visible in the chain but say the relationship is by design and point at the earlier step where the exposure actually is.
- Every affected asset is labelled with the kind of object it actually is. The machine-readable appendix a GRC tool imports had filed workstations and service accounts as hosts, a domain controller as a user, and every group as an account; finding narratives introduced domain controllers as "affected account: 192.168.180.12". Types now come from the directory rather than the shape of the name, and the report's asset list, its prose and the appendix agree on both type and name. The AD Control Coverage Report also lists every control the assessment tested (it reported three of twenty-two) and states the actual check behind each — the attribute read, the protocol version negotiated, the template flag compared — with the compliance clauses it bears on.
- The MITRE ATT&CK Navigator layer bundled with the Client Deliverable Kit now contains the techniques the assessment exercised; it shipped empty. The ATT&CK kill-chain paragraph no longer says the assessment "confirmed" every route to full domain compromise, stating instead how many were identified and how many were walked end to end. Each compliance control states its attack-chain count against the assessment total ("24 of the 30 attack chains identified") so the figure cannot be read as a rival total, and the same wording reaches the platform.
- Several report and playbook details are corrected: a domain that never expires passwords is reported as such rather than as a `37201`-day measurement (in the platform too, now counted as a baseline failure); playbook remediation commands name the client's own domain rather than a documentation placeholder; the Technical Findings section explains that its severity chip and its ADscan Priority are two different scores; and a free-report containment instruction no longer breaks across a page from its heading.
- `adscan execute` no longer mistakes a verb's own argument for the domain. Passing the domain with `-d` and then the scope after `--` — `adscan execute attack_paths -d corp.local -- owned`, the form the help advertises — forwarded only `owned` to the verb, which read it as the domain name. Every verb taking the domain first now receives it whether or not you repeat it. A re-run that finds nothing to execute now names the earlier outcomes that made each path skip and gives the command that clears them, and the path table's readiness column is renamed "Cred" (it reports whether a usable credential was found, nothing else).
- SMB path checks report the directory-listing rights the account genuinely has (the probe called a method the SMB library does not expose, so every result recorded "cannot list this directory"), which also unblocks reading the user folders that exist on disk instead of guessing profile paths. RDP login checks account for every host they test, skipping Kerberos when no key distribution centre is reachable rather than abandoning the host. And the session summary no longer counts the credential you supplied as one ADscan obtained.
- A domain with no certificate services no longer prints a run of red errors during collection. The certificate-services containers on such a domain return the directory's ordinary "no such object" answer, which was surfaced as a failure; it is now a single quiet "no certificate services in this domain" line, while a genuine failure to read the containers still surfaces in full. A trusted domain reached across a forest trust also no longer reads as an anonymous scan — the per-phase panels now show the credential actually in use (the domain the operator authenticated to) rather than `Username: N/A`.
- A missing password-cracking corpus no longer aborts a scan. The startup check treated the audit wordlist as mandatory and denied collection, attack paths and the report over a file none of them read, while the cracking subsystem itself had always skipped an absent wordlist. The check now warns, and the report declares the narrower cracking: an account absent from the recovered-credentials list is stated as untested rather than left to read as proof its password held.

### Security

- Session recordings uploaded to ADscan can no longer carry a host's short NetBIOS name, your domain's own short name, a certificate authority name built from either, a named database instance, or a domain identifier in its binary form. Hosts are registered with the sanitiser as the scan discovers them rather than only from a file the first run has not written yet, and a name is masked wherever the directory composes one (as `HOST$`, as `NAME-CA`, and in a child domain of a forest). Recordings only leave your machine when telemetry is enabled, which is the default on the free and PRO tiers only.

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

[Unreleased]: https://github.com/ADScanPro/adscan/compare/v13.1.0...HEAD
[13.1.0]: https://github.com/ADScanPro/adscan/compare/v13.0.0...v13.1.0
[13.0.0]: https://github.com/ADScanPro/adscan/compare/v12.0.0...v13.0.0
[12.0.0]: https://github.com/ADScanPro/adscan/compare/v11.3.0...v12.0.0
[11.3.0]: https://github.com/ADScanPro/adscan/compare/v11.2.0...v11.3.0
[11.2.0]: https://github.com/ADScanPro/adscan/compare/v11.1.0...v11.2.0
[11.1.0]: https://github.com/ADScanPro/adscan/compare/v11.0.0...v11.1.0
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
