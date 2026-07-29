# Changelog

All notable changes to ADscan are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- The workspace dashboard now plots exposure across scans, under the headline number. One point per completed scan, drawn from the same engine figure the report prints, with the proven share as a second line and a plain sentence reading the movement ("Exposure down 27.7 points across 5 scans."). Until now every visit showed the current state and nothing else, so the work between two scans was invisible; this is where a closed finding or a newly joined machine actually shows up. A workspace with a single scan says the trend opens after the next one rather than drawing a lone dot.
- Comparing two scans in a workspace's history now shows what changed: the findings and attack paths that appeared, the ones no longer detected, the ones carried over, and the exposure movement between the two. It previously compared the wrong thing entirely and reported the workspace's domains as if they were findings, so the counts were wrong wherever a workspace held more than one domain. The per-scan cards in that list also show their new, remediated, reopened and carried-over counts, which had been reading zero on every scan.
- `writeup` saves the mechanical two thirds of a lab writeup while it is still on disk. It emits a Markdown file recording the ports that answered, what the directory held, the chain as an editable mermaid diagram, every step that ran with its outcome, timestamp and a public reference for the technique, which credential came from which technique, the flags, and the routes that went nowhere. It writes no analysis at all: the paragraphs a writeup is actually judged on are left as marked, empty placeholders. This matters because lab platforms hold publication until a target retires, so the post usually gets written months after the box was owned and the order of events is the first thing lost. The file is a local draft, marked as a draft in its frontmatter, and nothing is published or uploaded. After a lab scan the shell offers it in one line.
- An audit-mode scan now leaves the exposure report behind on its own. When the workspace type is `audit`, the HTML and PDF report is written the moment the scan finishes and the paths are shown with the results, so the artifact exists whether or not you remember the reporting command. Lab and CTF workspaces are left alone: no report is generated and nothing interrupts the run, just a single line naming the command if you want one. Nothing prompts, so unattended `adscan ci` runs behave the same as attended ones.
- `generate_report` now produces a self-contained HTML exposure report in the free tier, built from your own scan. It leads with the finding load and the number of paths to full domain compromise, explains in plain English why the exposure score sits where it does and what would move it, then lists every finding with its MITRE ATT&CK mapping and every validated attack path with each step's honest status. One file, no external assets, so it survives being emailed as an attachment. Compliance mapping, per-finding remediation and your own branding remain in PRO.
- The exposure score is now derived identically in the free HTML report and the PRO assessment report, so the same scan can no longer produce two different numbers.
- The free exposure report is now written twice, as HTML and as a properly paginated A4 PDF with page numbers. The HTML stays self-contained for anyone who just wants to open it; the PDF is the copy that gets past a mail gateway and in front of a board or an auditor. Both come from the same template and the same figures.
- Service accounts that carry an HTTP SPN are now flagged as a Kerberos web-application relay and coercion surface, with native remediation guidance in the report and the platform.
- `COVERAGE.md` lists every Active Directory attack technique ADscan implements, each mapped to MITRE ATT&CK and marked with whether ADscan executes it, detects it, or deliberately declines to run it for safety. The page is generated from the product catalog, so it cannot drift from what the tool actually does.
- The free exposure report now ends with a written record of every change ADscan made to the directory while proving an attack path: what was written, to which object, and whether it was undone and re-checked. The section is present on every scan, including one that wrote nothing, and anything that could not be reverted automatically is listed with its exact distinguished name so an administrator can reverse it. The report is routinely forwarded to whoever owns the domain, so it is the copy that has to carry this.
- The free exposure report now ranks the techniques that carry the most attack paths, with how many paths each one closes, what share of the total that is, and how many accounts it covers. Twenty-five paths are rarely twenty-five problems; naming the handful of techniques underneath them turns the finding into a short list of decisions. The step-by-step remediation for each remains in PRO.
- The free exposure report now leads with how much of the user population is affected, not just how many paths exist, and states each attack path's step count and the techniques it runs through so paths sharing a source and target can be told apart.
- The optional question ADscan asks once at the end of a session now names the channels people actually arrive through, including X, a search engine, an AI assistant and a coworker, and takes a one-line free-text answer when none of them fit. A second question, asked on a later session, records what kind of work you do. One question per session, never two; both end in "Prefer not to say"; and neither appears on an unattended run, an air-gapped deployment, or a machine with telemetry turned off.

### Changed

- The headline number in the free exposure report is now labelled "Posture score" and reads "higher is safer". It was labelled "Exposure score" in a document titled Active Directory Exposure Report, which invited exactly the wrong reading: the scale runs from 0 (worst) to 100 (healthy), so a 2 was being read as "2% exposed".
- Attack-path steps in the free exposure report now lead with the plain-language technique and name the object involved, instead of opening with a raw directory-permission token and, for certificate-services steps, describing nothing at all.

- The free exposure report has been redrawn on the same design as the paid assessment report: the warm bone paper, the editorial typography, the severity scale and the components are now one shared set, so the free artifact reads as the same product rather than as a dashboard export. It is still a short document, so it opens on a masthead instead of a cover page and states its verdict in a single sentence, and the severity breakdown is now a proportional bar rather than four cards, the last of which used to print with its right edge cut off.

### Fixed

- Both reports now read the record of what the scan changed in your directory from the ledger the scan is writing, instead of from a copy attached to the workspace only after the session ends. Because the report is produced before that point, a workspace's first run had no copy to read, and the free report stated "Nothing was changed — this scan made no writes to the directory" while the assessment report opened with "ADscan made no modifications to Active Directory during this assessment" — on runs whose ledger held created machine accounts, modified certificate templates and password resets awaiting manual cleanup. A later run of the same workspace looked correct only because the previous session had left its copy behind. Both documents now report the changes as they happened, and where the record genuinely cannot be read they say so plainly rather than issuing an all-clear: a missing record is no longer treated as proof that nothing was touched.
- The free exposure report now names the objects each finding is about — the accounts, the hosts by name and address, the shares and files, the certificate templates and the issuing authority. It named none of them: the report listed every finding by title and severity only, and the resolution that works out which object a finding affects ran exclusively in the paid tier, so the artifact a pentester forwards to a CISO said what was wrong without saying where. On a three-domain lab that is 50 of 51 findings that now carry an object, 39 of them a specific account, host or template rather than the domain. The two tiers resolve assets through one implementation, so the free report and the paid kit can no longer name different objects for the same finding.

- A certificate ADscan obtains from your certification authority while proving an ADCS attack path is now disclosed in the report's environment-changes section. Every ADCS path that issues a certificate — the web-enrollment and MS-ICPR relay chains and the enrollment-based escalations — records it the moment the CA hands it over, so an interrupted scan still leaves the record. The certificate lives in your CA and authenticates its subject until it expires or is revoked, and a relayed certificate for a domain controller's machine account is a domain-compromise-equivalent credential valid for about a year; revoking it needs certificate-manager rights the assessment does not hold, so it is listed under "Requires manual cleanup" with the serial, request id, template, CA and expiry, and a native `certutil` procedure to locate, revoke with the correct reason code, publish a fresh CRL, and verify the result. Before this, three assessments reached full domain compromise through a relayed DC certificate that was never written down, so the client had no way to know it existed.
- The scan-to-scan diff no longer reports attack paths that were present in both scans as newly appeared. Path presence was inferred from the "first seen" and "last seen" columns, which are rewritten on every re-detection and therefore only ever describe the latest scan, so a path that had been there for months arrived in the diff as new. It is now read from the same audit trail the findings half uses, and the diff also reports how many paths closed and how many carried over.
- The three documents in a Client Deliverable Kit now report the same finding inventory. A finding with no entry in the vulnerability catalog was dropped from both paid documents while the free report showed it, so a buyer received fewer findings than the free scan had already given them; an uncatalogued finding now renders on the title and severity the scan recorded for it. Separately, the assessment report counted findings by the contextual ADscan Priority overlay rather than by the severity the engine recorded, so one certificate-services finding was a High everywhere in the kit except on the page that counted it. Both figures are still shown per finding; only one of them now classifies the inventory.
- Password material found in an account's `description` attribute is now a first-class finding with its own remediation, in the report and the playbook, rather than a row that only the free report ever displayed.
- An attack path that the client's own configuration already closes no longer prints a domain-compromise verdict over it, and no longer bills the client to go and disable the thing they have demonstrably already disabled. The path reads as the positive finding it is: the route exists on paper, and their hardening ends it.
- An attack path now terminates at an outcome in every place the document states one. The card heading, the chain diagram and the verdict beneath them used to disagree — a route could be headed "→ Domain Admins", drawn ending on a Domain Admins node, and then closed with "Domain Compromised" — and one path was headed with the name of the technique it used, which is not something a client can act on. All three now read the same terminus, and a route that only reaches a Tier 0 escalation group says so instead of claiming a domain takeover.
- The Security Assessment Report now renders in the product's own typefaces. Its theme named faces it had no way to load, so the ninety-six page flagship printed in office fallbacks beside a companion document in the brand, with no error anywhere to indicate it.
- The page-2 summary of the assessment report no longer claims more than the assessment found. It read "proven 100%" on a scan where one route of twenty-five had been executed; it now states that split in counts, the same way the executive summary two pages later already did.
- The ATT&CK coverage matrix fits its page. Two tactic headings printed on top of each other, and the densest column ran past the bottom of the page, hiding techniques that had been found. The matrix now steps its cell density down as the column grows rather than clipping the tail.
- The kill-chain page no longer prints a column of empty boxes down its gutter where a severity mark should be.
- The AD Hardening Playbook no longer carries ADscan's own marketing inside a client deliverable: the cover's price tag is gone, the closing pages no longer instruct the client to run ADscan commands, and the closing figures are derived from the engagement instead of quoting a target the document never calculates. A cover metric that had nothing to report now shows the scope rather than a zero.
- A lab scan that reaches full domain compromise is now recorded as finished, not as interrupted. Once the domain was owned, ADscan correctly stopped the remaining offensive phases — but it stopped without writing the scan down as complete, so every later time you opened that workspace it offered to resume a scan that had already won, quoting the phase it "stopped at". The better the scan went, the earlier it stopped, and the more of it appeared unfinished. A scan that ends by meeting its objective now closes its own record, and the run also reports its completion metrics, which were being dropped on exactly the runs worth measuring. A scan that genuinely stops half-way, or one deliberately split across domains, stays resumable as before.
- A secret found on a file share is now reported by the file it sits in. Under "Affected assets" the finding listed the categories its detectors matched — "DOC_CREDENTIALS", "CMD ConvertTo-SecureString" — which named a scanner rule rather than anything an administrator could act on. It now lists `\\10.0.0.5\HR\Notice from HR.txt`, one line per file, and falls back to the share name only when the path genuinely is not known. The share list an attack path carries is the scan's scope rather than where the secret was, so it no longer sits beside the files, and it can no longer arrive as a single asset reading "DEV, HR, NETLOGON, SYSVOL".
- A secret found in a directory attribute now names the account and the attribute holding it, rather than the domain. `david.orelious · description` is where the sysadmin goes to clear it; `cicada.htb` was the whole environment. This reaches the platform's finding panel as well as the report, and the account remains the identifier the platform joins on.
- Twenty-nine findings, among them noPac, PrintNightmare, the NTLMv1 relay routes, shadow credentials and the LAPS coverage gap, now name the host or account they affect instead of the domain. Each one previously had no rule for composing its affected assets, so the report fell back to whatever list happened to sit in the finding's data — which is how a set of credential-detector category names once printed as a finding's affected assets. noPac now reads `MEEREEN.ESSOS.LOCAL (192.168.180.12)`, PrintNightmare lists both vulnerable hosts, and a Kerberos web-service exposure names the account and the service on it. A finding that genuinely records no locator now says the domain, plainly, rather than something that looks like data and is not. The platform's finding panel reads the same list, and a coverage check fails the build if a new finding ships without deciding what it affects.

- A proven attack step is no longer dropped from the attack graph because its target was named differently. A step that identifies a host by IP while the graph knows that host by name — an AD CS relay step is the usual case — used to record nothing at all, so a chain ADscan had actually walked end to end came out of the scan with zero attack paths and the report showed it as theoretical. Host endpoints now match across address, short name, fully-qualified name and machine account, and a certificate authority no longer risks having its result written onto one of the two sibling directory objects that share its display name. When an endpoint genuinely cannot be found, the log now says whether no such object exists at all or one exists under another name.
- A credential ADscan has just recovered is no longer declared invalid and offered for deletion because the domain controller refused it without saying why. Only a rejection the server names — a failed pre-authentication, a logon failure, an explicit account state — is now reported as wrong credentials; anything else is reported as unverified and the credential is kept. Deleting a stored credential is now opt-in and defaults to no, so an unattended run keeps it, and the log records the KDC error code, the encryption types requested and the clock correction in force, which previously left "Incorrect credentials" with nothing behind it.
- `writeup` no longer asserts a step succeeded when the workspace cannot prove it did. A recovered secret was being credited to every edge of the technique that produced it, so one roasted account marked three roasting hops as successes and one certificate abuse was written up as a proven hop on a run whose records contain no such execution. A recovered secret now proves only the hop it actually landed on; anywhere else the draft states the weaker, true version. Where nothing in the chain ran but the workspace still holds the hashes and the flags, the draft says so in a sentence instead of leaving the two halves to contradict each other, and a provenance column with nothing in it is dropped rather than filled with "unrecorded" on every row.
- `writeup` keeps the failure history on a step that eventually worked, written as "succeeded at 16:16, after 8 earlier attempts failed". Those failures are usually the target resetting itself on a timer, which is the most useful operational note anyone can make about a box, and suppressing the count threw it away.
- `writeup` records what the run changed in the directory and whether it was put back, taken from the rollback ledger rather than from memory, with the native command for anything still in place. It also names techniques in English throughout, so a draft no longer prints internal identifiers such as `Ntlmv1RelayRBCD` or `nt_hash`, drops the empty "Difficulty" cell, puts the starting credential at the top of the target card where an assume-breach premise belongs, and leaves out the reproduction command rather than naming a group that cannot be run as.
- `writeup` now works on a workspace that has a full scan but no technical report, instead of refusing with "No scan data found yet. Run a scan first" and telling the operator to redo a scan they had already run.
- The free exposure report, the paid assessment report and `writeup` now derive their attack paths from one canonical, whole-domain computation instead of from a saved file that any interactive path query could overwrite. A single-principal lookup run mid-session used to leave that file scoped to that one principal, so a later report or writeup could show a fragment that began in the middle of a chain, with no blast radius. All three artifacts now recompute the same picture every time, so the same workspace always produces the same document.
- `writeup` now builds its chain from the steps the run actually proved, in the order a reader would follow them, and states plainly how many of the proven steps appear ("All 4 edges this run proved appear below"). The step that reaches domain compromise is placed last, the reproduction command starts from the chain's own first account rather than whichever identity the session happened to end on, and a step that failed and then succeeded on a retry now shows both the failure and the success instead of a bare "succeeded".
- Neither report now calls an attack path validated unless it was. Every path carried the caption "Validated path to full domain compromise (control of a Tier 0 asset)" whatever its status, so a path whose own badge read Theoretical was contradicted two centimetres away on the same line. That sentence is a legend definition and now stays in the legend; each path is captioned with the reach it would achieve ("Full domain compromise"), and the badge alone says how far it was actually taken. Page one of the free report no longer claims every path below was walked by the scanner either, which was false for fourteen of fifteen paths on a typical run and contradicted the count printed three pages later.
- The paid assessment report carries the ADscan mark on its cover again. With no white-label logo supplied, which is the default, the cover printed the word "ADscan" set in a serif face instead of the logo, so the flagship deliverable shipped less branded than the free report. Supplying your own firm's mark still replaces ours, unchanged. The mark is now drawn from vector artwork, so it stays sharp at cover size.
- The remediation table now decides what a client can change per group membership and per permission holder, instead of per technique. "Remove this account from this group" is the most common fix in Active Directory and none of them were reaching the client, because excluding built-in nesting like `DOMAIN ADMINS` in `ADMINISTRATORS` had been done by suppressing group membership outright — on the workspaces used to check this, that hid a machine account in a custom server group carrying 40% of the domain's paths, and three ordinary users in departmental groups. In the other direction, directory replication ranked as the top fix at 39% of paths on a domain where every holder of it was a domain controller or a built-in administrative group, which cannot give the right up; replication now appears only where a principal holds it that should not. Both reports and the platform read one verdict, taken from the object's own identifiers rather than its name, so it holds on a Spanish- or German-language domain. Each verdict carries the change itself — "Remove MS01$@PIRATE.HTB from DOMAIN SECURE SERVERS@PIRATE.HTB" — and the remediation printed for a technique now names an instance that can actually be removed.
- The assessment report no longer offers built-in group nesting as something to remediate. Group membership carries a large share of the paths in any directory, so it ranked near the top of the client's remediation table telling them to remove `DOMAIN ADMINS` from `ADMINISTRATORS`, a Windows nesting that cannot be removed, on the same pages that correctly labelled those steps structural. Structural edges are now excluded from the ranking in both tiers, which also freed a place for a real technique that had been pushed off the table.
- The remediation ranking no longer counts routes that have nothing to fix. A path the client's own configuration already closed — the result the report presents as attack surface reduced — and a path ADscan had no reachable surface to walk were both counted as ordinary exposure. On a three-domain forest that produced four ranked priorities that existed for no other reason, and the top six each carried between two and nine such routes inside their counts, so the headline fix was credited with 21 paths where 12 are open. Both are now excluded in the free report, the assessment report and the platform. The table is shorter, and a certificate-services escalation ADscan had actually executed took one of the freed places. A partially validated path — one with a step that ran successfully against the live environment — no longer counts as a mere attempt either.
- The remediation table names techniques instead of internal tokens. Priorities that read "Adcsesc9", "Ntlmv1Relayrbcd" and "Canrdp" now read "Certificate Mapping Abuse (ADCS ESC9)", "Credential Relay to Delegation" and "Remote Desktop Access (CanRDP)". Six ATT&CK techniques that showed their bare id in the kill chain now show their names.
- The free report, the paid report and the platform now name each technique the same way and count the accounts it covers the same way. The paid remediation table kept a second set of names, so the technique a client read as "Replicate Directory Secrets (DCSync)" on one page was "DCSync (Domain Replication)" on the next; and its "Affected Principals" column showed the blast radius of one step rather than the accounts the fix covers, which printed 1 beside a technique the free report credited with 3. The column is now "Accounts Covered" and carries that figure. Three techniques that had no plain-language name — database session access, share write access and read-only domain controller replication control — no longer print as raw tokens anywhere.
- The AD Control Coverage Report now has something to attest after a credentialled scan. Every control the scan checked and found clear was being discarded rather than recorded, so the report only ever saw the handful of checks the unauthenticated phase writes and arrived empty on the most common engagement shape. Clear results are now kept, and ten further control areas render them, each stating what was checked and what clear means, with the frameworks it satisfies. A control whose weakness is reported elsewhere is never attested clear.
- A deliverable kit no longer ships an empty document. When a scan genuinely has no control coverage to attest, the AD Control Coverage Report is left out of the kit instead of shipping two pages explaining that there is nothing to show.
- The hardening playbook and the assessment report agree on the finding count. Where the same weakness appeared in two domains of a forest, the playbook counted it once and the assessment report twice, so a two-document kit stated two different totals for one engagement, and the F-NNN pointers between them drifted apart by the difference. Each domain now keeps its own row, its own affected assets and its own remediation.

- `adscan check --fix` now works. ADscan told you to run it whenever a bundled tool failed to start, but the host command rejected the flag outright, so the one repair the tool recommends could not be run. It is now accepted and carries out the repair inside the runtime container.
- `adscan check` now reports how much memory your machine actually has free, and no longer gives a clean bill of health to a host that cannot run a scan. `--allow-low-memory` also does what it has always said it does: below 1 GB free, `install`, `start` and `ci` stop with an explanation instead of starting a run the system will kill part-way through, and the flag is how you proceed anyway. Between 1 and 1.5 GB you get a warning and the run continues.
- `adscan update` no longer ends in silence when the image download fails. It used to print "Pulling image: ..." and then nothing at all — no success, no failure, no next step — which was the whole output for anyone who ran it because their runtime image was missing. Every outcome, including one you interrupt with Ctrl+C, now closes with what happened and what to do next.
- ADscan PRO can now be activated from the command line. `adscan start` and `adscan ci` accept `--partner-tag <tag>`, which saves the tag from your onboarding email on this machine and reuses it on every later run. Previously an unattended `adscan ci` refused to start and asked for `ADSCAN_PARTNER_TAG`, but that variable was never passed into the scan container, so the instruction could not be followed and the run failed identically on every retry. Setting `ADSCAN_PARTNER_TAG` in your environment now works as documented too.
- A credential that could not be verified is no longer thrown away. When ADscan has no domain controller address to check a credential against, it now keeps and stores it, reports that verification was skipped, and carries on — instead of discarding it and telling you the username or password was wrong. `adscan execute` was the most visible victim: it resolved the domain successfully, then rejected a perfectly valid credential.
- A successful DNS check now records the domain controller it resolved for the domain, so the rest of the run has a KDC to authenticate against. Previously only the failure paths saved it, which is what left credential verification with nothing to talk to.
- `adscan execute` gained the read-only `users` verb (the user, control-exposure and privileged-account inventories for an already-scanned domain), suggests the closest real verb when you mistype one, and no longer truncates its usage line halfway through the syntax on `--list`.
- A password crack that hits its time limit is now reported as what it is. It used to be logged as a failed command and then summarised as "finished without recovering any password", which reads as a verdict on the password when in fact most of the candidate space was never tried. The panel now names the cap it stopped at, says the search was not exhausted, and points at a longer effort level or a GPU instead of inviting a re-run that would stop at exactly the same place. AES service-ticket cracking on a CPU-only machine hits this every time.
- Free-tier scans no longer print an internal error about a missing module after the posture summary. The component it looks for is part of the paid tier and its absence is normal.
- `adscan update` now upgrades a launcher installed with `uv tool install`. It used to try pip inside a uv-managed environment, which has no pip, report the upgrade as failed, and suggest a pip command that cannot work — leaving the launcher pinned to an old version against a newer runtime image.
- The hardware benchmark that runs in the background no longer prints errors into a live prompt when it cannot measure your machine. It is optional: a failure quietly falls back to the conservative cracking preset.
- Collection against a forest without the LAPS schema extension no longer fills the screen with repeated errors. ADscan asked the domain controller for the same handful of attributes once per object it read permissions on, and treated each definitive "not in this schema" answer as a temporary fault worth retrying. It now takes the answer at face value and asks once.
- The platform's remediation page no longer overstates what a plan closes. It added up each technique's share of the attack paths, but those paths overlap, so the top three fixes were reported as closing 100% of an estate where the true figure is 94%, so a plan scheduled on that promise would have left 6% of the routes open. The figure is now the union of the paths those fixes actually close, and each technique states how many paths it closes beyond the ones ranked above it, which is what exposes a listed fix that adds nothing at all: on one environment the second-ranked change closes no route the first has not already closed, so the honest plan is two changes rather than five.
- Session recordings uploaded to ADscan no longer carry three kinds of identifier that were escaping pseudonymization: a domain controller's short hostname (its IP and its fully-qualified name beside it were already masked), the certificate authority's common name, which spells out your organisation and a DC's name, and IPv6 addresses. Recordings only leave your machine when telemetry is enabled, which is the default only on the free and PRO tiers.
- A password hash that Rich wrapped across two lines no longer reaches an uploaded session recording in the clear. On a narrow terminal the hash was split at the wrap point, and neither half was long enough for the pattern that masks key material, so the two lines could be joined back into the original hash. Wrapped hashes and Kerberos keys are now masked as one value. Recordings only leave your machine when telemetry is enabled, which is the default only on the free and PRO tiers.
- Angle-bracket placeholders in messages such as `usage: creds set <user> <value>` are no longer deleted from a session recording, which used to leave truncated text like "Incorrect usage: set" and made a recording harder to read than the terminal it came from.
- The certificate authority security check now reports "not permitted" instead of an error when the scanning account lacks CA administrator rights. That is the expected result for an ordinary domain account, so a normal run against a domain with ADCS no longer shows a red error line for something that did not go wrong.
- The executive summary page of the assessment report no longer pushes its closing "Bottom Line" onto a page of its own, leaving most of a sheet blank in the middle of the document.
- ESC13 remediation guidance is now complete. Removing the issuance-policy group link does not revoke privileges already granted: the domain controller carries the group SID forward into every renewal and service ticket without re-reading the directory, so a ticket issued before the fix keeps the privilege for up to 10 hours, renewable to 7 days. The report now says so and tells you how to revoke the access that was already granted, and warns that a configuration-only check will pass while live tickets still carry it.
- Turning telemetry off now applies everywhere. `set telemetry off` used to be saved inside the current workspace only, so the next workspace started recording again; the preference is now stored once for the user and persists across workspaces and sessions, including workspaces created later. Anyone who had already disabled telemetry in a workspace stays opted out, and `adscan start` accepts `--no-telemetry` and `--offline` for a single session, matching `adscan ci`.
- The reduced-network-mode notice shown when ADscan runs on a rootless Docker or Podman runtime no longer fails to render. It previously crashed on an undefined style and left the warning unseen; the notice about unavailable IPv6 poisoning and tunnel pivoting now displays correctly.
- A coerce-and-relay path against a single domain controller (relaying its own authentication back to itself) is no longer offered as an executable step. Windows reflection protection makes it impossible, so it is now correctly presented as mitigated by the environment's topology instead of a ready attack.
- Attack paths whose critical step is closed by the environment's configuration ("Attack Surface Reduced — Hardening Observed") are now view-only: selecting one shows its details instead of prompting to execute it, and the precondition-recovery menu no longer recommends starting from a later step whose prerequisites could only be granted by the closed step.
- Group Managed Service Accounts (gMSA) are no longer reported as Kerberoasting or AS-REP Roasting targets. Their passwords are machine-managed and uncrackable, so those were false-positive findings.
- File paths shown in panels and in `--debug` output now point at `~/.adscan/...` on your own machine instead of the container's internal `/opt/adscan/...`. The report-ready panel was the most visible case: the path it printed could not be opened from your shell.
- The free exposure report's PDF is now printed on paper that reaches the edge of the sheet. Chromium does not carry a page's background into its margin, so every page had a white border around a warm text column and read as a screenshot of a document rather than as a document.
- Changes ADscan makes to a directory are named in plain English wherever they are reported (report, platform and terminal). Several kinds had no display name and printed their internal identifier, so a client's cleanup list could read `template_mutated` instead of "Certificate template modified".
- `adscan ci` no longer loops when domain discovery finds no domain controllers. Unattended, it had nobody to supply a new host range, so it rescanned the same one indefinitely; it now reports the scope it scanned, tells you to widen the range or pass the domain and DC IP, and exits. Interactively, re-entering a range that already came back empty ends the flow instead of rescanning it.
- Scanning a domain a second time in the same workspace no longer leaves it permanently uninitialized. Every domain-scoped command (`attack_paths`, `enum_authenticated`, and the rest) was refused with "Domain context not initialized", and the fix it suggested — re-running `start_unauth` — could not repair the state. Existing workspaces recover on their own.
- Interrupting a scan with Ctrl+C after it has started is now reported as a partial scan, listing the credentials and domain context already captured, instead of "Nothing was executed, your workspace is unchanged" followed by an offer to retry and clean the workspace.
- Backing out of the target-context question no longer starts host-range discovery on its own. Choosing "I know nothing" and changing your mind halfway are now told apart, and the second is re-asked rather than assumed.
- After host-range discovery finds no domain controllers, the "switch to known domain/DC input" recovery no longer offers host-range discovery — the option that had just failed — and cancelling it now says so instead of ending the scan silently.
- The host range offered for domain discovery is now derived from the DC you supplied or from your own interface, instead of a fixed `10.10.10.0/24` that sent scans at an unrelated network.
- A mistyped target range (`10.10.10.0/24n`) is now rejected as a syntax error, with examples, at the moment you type it. It used to reach the scanner, which parsed nothing, and the empty result was reported as "no domain controllers found" — advice to widen a range that had never been scanned.
- The pre-scan network check no longer aborts on an interface that has no address recorded for it when the route to the target demonstrably originates from that interface. It adopts the source address the kernel reports and continues with a warning, and records the interface and route detail it saw for diagnosis.

### Removed

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

[Unreleased]: https://github.com/ADScanPro/adscan/compare/v10.1.0...HEAD
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
