"""Writeup evidence spine — the mechanical two thirds of a lab writeup.

A lab writeup is roughly one third prose and two thirds transcript: five
measured 0xdf-style posts carry 1,200-2,300 words of writing against 420-600
lines of terminal output, 40-60 code blocks and a handful of screenshots. This
module emits the second part and nothing else. It records what was scanned,
what the graph held, which steps ran, what came back, and what did not work,
in the section order the genre already uses. The writing stays with the author.

The split used to be literal: earlier versions of this module left an
HTML-comment marker (``adscan:write``) everywhere a human sentence belonged,
and rendered an unedited section as visibly empty rather than filler nobody
wrote. That marker is gone. Every section now drafts deterministically from
facts already on the workspace — the target, the proven chain in the order it
ran, the terminal outcome, the credentials recovered — in the tool's own
register: causal and verifiable, never a decision or a struggle sentence, and
never asserting more than the record supports. A run that proved nothing
still gets an honest sentence stating that. Nothing here interprets the run;
it states what happened and how each claim was proven, which is what makes
the artifact tool-native rather than a scaffold waiting on an author.

The problem being solved is not typing speed. Lab platforms hold back
publication until a target retires, so the gap between owning a box and writing
it up is routinely months: screenshots timestamped in November, post published
the following April. What is lost in that gap is the order things happened in,
the credential that came from which technique, and every route that was tried
and abandoned. All of that is already in the workspace and nowhere in a shell
history.

Four rules the content obeys:

* **Never assert more than the workspace supports.** A scaffold that occasionally
  claims a thing that did not happen is worth less than no scaffold, because the
  author then has to verify every generated line before trusting any of them. So
  a step is written as "succeeded" only where the record says an execution
  succeeded AT THAT EDGE; a credential the store attributes to a technique
  without an endpoint gets the weaker, true sentence instead; a provenance
  column with nothing in it is removed rather than filled with a placeholder;
  and where the chain reads "not executed" while the workspace holds the krbtgt
  hash and both flags, the document says so in one line rather than leaving the
  reader to notice the contradiction alone.
* **The client catalogs are a source of causal, offensive content here — never
  struggle narrative.** ``attack_step_catalog`` is authored to carry two things
  this artifact renders per step verbatim: the didactic ``narrative_template``
  ("why this technique works", causal and verifiable, the same register as the
  in-shell didactic card) and the ``manual_command`` (the real by-hand
  offensive command, copy-pasteable, the one field the catalog allows to name
  offensive tooling). Neither is struggle narrative — nothing here claims what
  the author felt or decided, only what the graph and the catalog prove is
  true. The PRO vulnerability catalog (client-safe, executive register) is
  still never consulted from this module. What is ALSO taken from
  ``attack_step_catalog`` is the public technique NAME and a canonical
  reference, so the writeup survives a reader who has never run ADscan.
* **Every step carries the public technique name and a reference**, so the
  writeup survives a reader who has never run ADscan. That is also what stops
  the artifact reading as an advertisement.
* **Only LITE verbs are surfaced.** A reproduction line that needs a paid tier
  turns the page into a sales sheet, and readers say so out loud.

The artifact defaults to a local, private file. It carries ``draft: true`` and
``published: false``, which Hugo and Jekyll both honour, so it cannot be built
into a site by accident. Nothing in this module publishes, uploads or shares.
"""

from __future__ import annotations

import dataclasses
import re
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from adscan_core import telemetry, tier
from adscan_core.reporting.kit_facts import chain_reconcile_clause
from adscan_core.reporting.unauthenticated_reach import (
    REACHED_VIA_NULL_SESSION,
    UNAUTHENTICATED_REACH_BADGE,
    entry_label_for_reached_via,
    is_unauthenticated_entry_label,
    notes_are_unauthenticated_reachable,
    reached_via_from_notes,
    unauthenticated_reach_view,
)
from adscan_core.rich_output import print_error, print_exception, print_info
from adscan_internal.interaction import is_non_interactive
from adscan_internal.services import cleanup_taxonomy
from adscan_internal.services.attack_path_presentation import (
    order_paths_for_client_presentation,
)
from adscan_internal.services.attack_step_catalog import (
    get_attack_step_entry,
    get_bh_canonical_cypher_name,
    normalize_relation,
    render_step_manual_command,
    render_step_narrative,
)
from adscan_internal.services.compromise_class import (
    CompromiseClass,
    derive_compromise_class_from_path,
)
from adscan_internal.services.credentials.credential_origin import origin_display_label
from adscan_internal.services.edge_kind import EdgeKind, classify_edge_kind
from adscan_internal.services.path_state import _PROVEN_STATUSES

# The post-scan seam owns the trigger vocabulary and the per-run bookkeeping for
# both artifacts, so a spine built by hand and one written automatically are
# counted on the same axis and neither is produced twice in a run. Safe to
# import at module level: that module's own reference to this one is lazy,
# inside the function that generates.
from adscan_internal.services.post_scan_report import (
    TRIGGER_REPL_WRITEUP,
    is_automatic_trigger,
    remember_post_scan_writeup_path,
)

# Where a generated spine lands inside the workspace. One directory per run so
# a second generation never overwrites an edited draft.
WRITEUP_DIRNAME = "writeups"
SPINE_FILENAME = "writeup.md"
ASSETS_DIRNAME = "assets"

# Kept as the structural regression check: the renderer no longer emits this
# marker anywhere (every section drafts deterministically instead), and
# ``count_write_markers``/the test suite grep for it so a future change that
# reintroduces a human-fill placeholder fails loudly rather than shipping.
WRITE_MARKER = "adscan:write"

# Verbs this module may print. Every one ships in LITE — a reproduction line
# that needs PRO would make the writeup read as an advert. Locked by
# ``tests/unit/services/test_writeup_spine.py``, which resolves the REPL verbs
# against the real ``PentestShell`` and the CLI verbs against the tier catalog.
LITE_REPL_VERBS: tuple[str, ...] = (
    "start_unauth",
    "start_auth",
    "attack_paths",
    "get_flags",
)
LITE_CLI_COMMANDS: tuple[str, ...] = ("execute",)

_MITRE_BASE = "https://attack.mitre.org/techniques"

# Public technique names, technical register. Keys are the FOLDED relation (or
# credential-origin) string: lower case with ``_`` and ``-`` removed, so
# ``ADCS-ESC9``, ``adcs_esc9`` and ``adcsesc9`` all land on one entry.
#
# Every relation in the live attack-step catalog has an entry here, including
# the ones whose internal name is already close to the community name, and
# ``tests/unit/services/test_writeup_spine.py`` fails the build when a new
# catalog entry arrives without one. That is deliberate: the alternative is the
# module's own promise ("the public technique name") quietly degrading into an
# internal identifier — ``Ntlmv1RelayRBCD``, ``writesmbpath`` — inside a
# document somebody publishes under their own name.
_TECHNIQUE_NAMES: dict[str, str] = {
    "adminto": "Local administrator",
    "addallowedtoact": "Resource-based constrained delegation (RBCD)",
    "addkeycredentiallink": "Shadow Credentials (msDS-KeyCredentialLink)",
    "addmember": "Group membership write",
    "addself": "Self-add to group",
    "allextendedrights": "AllExtendedRights",
    "allowedtoact": "Resource-based constrained delegation (RBCD)",
    "allowedtodelegate": "Constrained delegation (S4U2Proxy)",
    "asrep": "AS-REP Roasting",
    "asreproast": "AS-REP Roasting",
    "asreproasting": "AS-REP Roasting",
    "backupoperatorescalation": "Backup Operators to NTDS.dit",
    "backupoperators": "Backup Operators to NTDS.dit",
    "blankpassword": "Blank password",
    "canpsremote": "PowerShell Remoting (WinRM)",
    "canrdp": "RDP",
    "coerceandrelayntlmtoadcs": "ESC8 (NTLM relay to AD CS web enrollment)",
    "coerceandrelayntlmtoldap": "NTLM relay to LDAP",
    "coerceandrelayntlmtosmb": "NTLM relay to SMB",
    "coercetotgt": "Coerce to TGT (unconstrained delegation)",
    "computerpre2k": "Pre-Windows 2000 computer account",
    "crackntlmv1": "NTLMv1 offline crack",
    "cracksid": "Offline password cracking",
    "dcsync": "DCSync",
    "dfscoerce": "DFSCoerce (MS-DFSNM coercion)",
    "dnsadminabuse": "DnsAdmins abuse",
    "domainpassreuse": "Domain password reuse",
    "domainpassreusesource": "Domain password reuse (source account)",
    "dumpdpapi": "DPAPI secret dump",
    "dumplsa": "LSASS credential dump",
    "dumplsass": "LSASS credential dump",
    "dumpntds": "NTDS.dit dump",
    "dumpsam": "SAM hive dump",
    "executedcom": "DCOM lateral execution",
    "extractrodckrbtgtsecret": "RODC krbtgt secret extraction",
    "forcechangepassword": "Forced password reset",
    "forgerodcgoldenticket": "RODC Golden Ticket",
    "fullcontrolshare": "Full control of an SMB share",
    "genericall": "GenericAll",
    "genericwrite": "GenericWrite",
    "getchanges": "DS-Replication-Get-Changes",
    "getchangesall": "DS-Replication-Get-Changes-All",
    "getchangesinfilteredset": "DS-Replication-Get-Changes-In-Filtered-Set",
    "gppautologon": "GPP autologon password",
    "gppcpassword": "GPP cpassword",
    "gpppassword": "GPP cpassword",
    "guestsession": "Guest SMB session",
    "hassession": "Session hijack",
    "hasshadowcredentials": "Shadow Credentials",
    "hassprnwithoutpreauth": "AS-REP Roasting",
    "kerberoast": "Kerberoasting",
    "kerberoasting": "Kerberoasting",
    "kerberoskeylist": "Kerberos Key List request",
    "ldapanonymousbind": "Anonymous LDAP bind",
    "localadminpassreuse": "Local administrator password reuse",
    "localcredreusesource": "Local credential reuse (source host)",
    "localcredtodomainreuse": "Local to domain credential reuse",
    "managerodcprp": "RODC password-replication policy write",
    "memberof": "Group membership",
    "ms17010": "MS17-010 (EternalBlue)",
    "mseven": "MS-EVEN coercion",
    "mssqlimpersonatelogin": "MSSQL login impersonation (EXECUTE AS)",
    "mssqllinkedserverlateral": "MSSQL linked server",
    "mssqlntlmv2theft": "MSSQL NetNTLMv2 capture",
    "mssqlopenrowsetbulkread": "MSSQL OPENROWSET bulk file read",
    "mssqlseimpersonate": "MSSQL SeImpersonate to SYSTEM",
    "mssqlseimpersonateescalation": "MSSQL SeImpersonate to SYSTEM",
    "mssqltokentheftescalation": "MSSQL service-token theft to SYSTEM",
    "mssqltrustworthydbescalation": "MSSQL TRUSTWORTHY database escalation",
    "nopac": "noPac (CVE-2021-42278 / CVE-2021-42287)",
    "ntlmv1enabled": "NTLMv1 accepted",
    "ntlmv1relayrbcd": "NTLMv1 relay to RBCD",
    "ntlmv1relayshadowcreds": "NTLMv1 relay to Shadow Credentials",
    "owns": "Object ownership",
    "passwordinfile": "Password in a file on disk",
    "passwordinshare": "Password in an SMB share",
    "passwordinshares": "Password in an SMB share",
    "passwordspray": "Password spraying",
    "petitpotam": "PetitPotam (MS-EFSRPC coercion)",
    "poisoncapturentlmv2crack": "LLMNR/NBT-NS poisoning to NetNTLMv2 crack",
    "pre2k": "Pre-Windows 2000 computer account",
    "preparerodccredentialcaching": "RODC credential-caching setup",
    "printerbug": "PrinterBug (MS-RPRN coercion)",
    "printnightmare": "PrintNightmare",
    "printoperatorabuse": "Print Operators abuse",
    "privilegedgroupcontrol": "Control of a privileged group",
    "readgmsapassword": "gMSA password read",
    "readlapspassword": "LAPS password read",
    "crossorgtgtdelegation": "Cross-forest Kerberos TGT delegation",
    "raisechild": "Child-to-forest-root escalation",
    "readshare": "Read access to an SMB share",
    "scheduledtask": "Scheduled task as a logged-on user",
    "shadowcredentials": "Shadow Credentials",
    "spnjack": "SPN-jacking",
    "spnjacking": "SPN-jacking",
    "sqladmin": "MSSQL sysadmin",
    "sqlaccess": "MSSQL access",
    "syncedtoentraid": "Entra ID sync",
    "synclapspassword": "LAPS password sync",
    "timeroast": "Timeroasting",
    "timeroasting": "Timeroasting",
    "trustedtoauth": "Constrained delegation with protocol transition",
    "unconstraineddelegation": "Unconstrained delegation",
    "useraspass": "Username as password",
    "userasspass": "Username as password",
    "usernameaspassword": "Username as password",
    "userdescription": "Password in the description attribute",
    "writeaccountrestrictions": "Account restriction write",
    "writelogonscript": "Logon script write",
    "writeowner": "WriteOwner",
    "writedacl": "WriteDacl",
    "writeshare": "Write access to an SMB share",
    "writesmbpath": "Writable SMB path",
    "writespn": "Targeted Kerberoasting (SPN write)",
    "xpcmdshell": "xp_cmdshell",
    "zerologon": "Zerologon (CVE-2020-1472)",
}

# ``adcsesc9`` reads as ``ESC9`` everywhere outside this codebase.
_ESC_RELATION = re.compile(r"^adcsesc(\d+[ab]?)$")

# Splits an unmapped internal identifier into words as a last resort, so a
# relation that lands here reads as prose rather than as a symbol.
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")

# How a stored ``secret_kind`` is written in the credential ledger. The stored
# values are field names; ``nt_hash`` in a published table is a leaked variable.
_SECRET_KIND_LABELS: dict[str, str] = {
    "aes128_key": "AES-128 key",
    "aes256_key": "AES-256 key",
    "aes_key": "AES key",
    "certificate": "certificate",
    "ccache": "Kerberos ticket",
    "kerberos_ticket": "Kerberos ticket",
    "lm_hash": "LM hash",
    "nt_hash": "NT hash",
    "nthash": "NT hash",
    "password": "password",
    "plaintext": "password",
}

# Step ``details`` keys worth printing as evidence, and the label each one gets.
# Everything else in that dict is engine bookkeeping (scores, choke-point flags,
# collector method names, support versions) that means nothing to a reader and
# would bury the two or three facts that do. Ordered: the list is the print order.
_EVIDENCE_LABELS: tuple[tuple[str, str], ...] = (
    ("template", "certificate template"),
    ("certificate_template", "certificate template"),
    ("template_dn", "certificate template"),
    ("attack_chain", "technique chain"),
    ("impersonation_method", "impersonation"),
    ("impersonated_principal_hint", "impersonates"),
    ("serviceprincipalnames", "SPN"),
    ("spn", "SPN"),
    ("source_property", "from attribute"),
    ("right_name", "right"),
    ("rights", "rights"),
    ("share", "share"),
    ("share_path", "share path"),
    ("artifact", "artifact"),
    ("note", "note"),
    ("notes", "note"),
)

# Step / path statuses that mean "this did not get us anywhere", mapped to the
# phrasing used in the dead-ends section. Honest about cause: a step that simply
# did not complete is never described as having been stopped by a defence.
_DEAD_END_PHRASES: dict[str, str] = {
    "attempted": "ran, did not complete",
    "failed": "ran, did not complete",
    "error": "ran, did not complete",
    "aborted": "abandoned after an earlier step failed",
    "blocked": "not executed, ADscan refuses destructive steps",
    "closed_by_configuration": "closed by configuration on the target",
    "unsupported": "no execution path available",
    "unavailable": "no execution path available",
}

# How an alternate route's engine status reads in a writeup. The engine
# vocabulary (``theoretical``, ``exploited``) is precise and internal; a reader
# wants to know whether it was walked. "Structurally proven" (not a bare "not
# executed") is deliberate: these routes were derived from the reconciled
# attack graph by the same engine that walked the primary chain, not guessed —
# the gap is that ADscan did not RUN them, never that they are speculative.
_ROUTE_STATES: dict[str, str] = {
    "theoretical": "structurally proven, not executed",
    "discovered": "structurally proven, not executed",
    "attempted": "attempted, did not complete",
    "partial": "partly executed",
    "exploited": "executed",
    "success": "executed",
    "domain_compromised": "executed",
    "closed_by_configuration": "closed by configuration",
    "unsupported": "no execution path",
}

# Bounded-coverage cap for the route map (spec §6 / CLAUDE.md Exposure
# Validation): never silently truncate a client-facing evidence list. Below
# this count every discovered route is shown; at or above it the list is cut
# to the top-ranked ``_ROUTE_MAP_MAX`` (already proven-first, per
# ``order_paths_for_client_presentation``) and the render says so explicitly,
# so a reader can never mistake a bounded view for the complete graph.
_ROUTE_MAP_MAX = 50

# The compromise classes that describe a REAL compromise terminal — a proven
# chain that lands on one of these has actually reached a Tier-0 asset (or an
# escalation group / foothold on one). A chain that reaches anything else (a
# stepping-stone, or the entry principal itself) is a FOOTHOLD, never an
# achieved compromise, and the summary must never phrase it as one. See the
# nomenclature standard (axis 2, Compromise Reach) and the Exposure-Validation
# doctrine: never over-claim a compromise the run did not walk.
_REAL_COMPROMISE_CLASSES: frozenset[str] = frozenset(
    {
        CompromiseClass.DOMAIN_BREAKER.value,
        CompromiseClass.TIER0_FOOTHOLD.value,
        CompromiseClass.PRIVILEGED_ESCALATOR.value,
    }
)

# A prefix (the shared technique ROOT two near-identical routes hang off) that
# this many alternate routes share collapses to ONE root-cause family line in
# the route map, mirroring the client report's family grouping — 42 bullets that
# all begin "AS-REP Roasting -> GenericAll" read as noise and bury the one real
# fact (they share one fixable root). Below the threshold each route is its own
# bullet, so a small handful is never over-consolidated.
_ROUTE_FAMILY_MIN = 4

_PLATFORM_LABELS: dict[str, str] = {
    "hackthebox": "Hack The Box",
    "tryhackme": "TryHackMe",
    "vulnlab": "VulnLab",
    "proving_grounds": "Proving Grounds",
    "vulnhub": "VulnHub",
    "dockerlabs": "DockerLabs",
    "goad": "GOAD",
    "training_labs": "Training lab",
    "local_test": "Local lab",
}

_NT_HASH = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)

# How the scan's OWN starting credential reads in the ledger. Kept as a constant
# because two renderers have to agree on which row is the premise of the run and
# which rows are things the run went out and took.
_ORIGIN_SUPPLIED = "supplied at the start of the run"


# ── Data model ───────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class TechniqueRef:
    """The public name of a technique plus one canonical citation."""

    relation: str
    name: str
    mitre_id: str | None = None
    mitre_name: str | None = None

    @property
    def mitre_url(self) -> str | None:
        """Return the ATT&CK page for this technique, or ``None``."""
        if not self.mitre_id:
            return None
        return f"{_MITRE_BASE}/{self.mitre_id.replace('.', '/')}/"


@dataclass(frozen=True, slots=True)
class SpineStep:
    """One edge of the chain, with whatever execution record exists for it.

    ``source`` and ``target`` are already display labels: the realm is gone and
    the case is settled, so no renderer has to re-derive how a principal is
    written. ``target_is_account`` is what decides whether this step ends a
    stage, and it comes from the collected inventory rather than a guess.

    Three fields carry the honesty of the step line, and each one exists because
    the alternative was a sentence the workspace does not support:

    * ``credential_proof`` is set only when a stored credential belongs to THIS
      edge's target, which is the one case where the credential store proves the
      edge ran. ``credential_attribution`` is the weaker fact for every other
      case: a secret in the store is attributed to this technique, somewhere,
      but nothing ties it to this edge.
    * ``failures_before`` / ``failures_after`` split the recorded failures around
      the first success, because "6 earlier attempts failed" and "failed 6 times
      afterwards" are different stories about the target and neither is a bare
      count of attempts.
    """

    technique: TechniqueRef
    source: str
    target: str
    outcome: str
    attempts: int = 0
    at: str | None = None
    evidence: tuple[tuple[str, str], ...] = ()
    target_is_account: bool = False
    source_is_account: bool = False
    is_context: bool = False
    credential_proof: str | None = None
    credential_attribution: tuple[str, ...] = ()
    failures_before: int = 0
    failures_after: int = 0
    #: True only when the execution EVENTS prove this edge ran (an
    #: ``_execution_index`` record joined it). False when the outcome comes from
    #: the graph/snapshot status alone — the renderer then must not print a
    #: timeline (a timestamp, an attempt count, a failure history) it cannot
    #: stand behind.
    recorded: bool = False
    #: The raw ``{"action": <relation>, "details": {...}}`` dict the attack-step
    #: catalog helpers (``render_step_narrative``, ``render_step_manual_command``)
    #: expect. Carried alongside the already-resolved display fields above rather
    #: than reconstructed from them, because the catalog's placeholder
    #: substitution reads the ORIGINAL ``details`` (including ``dc_ip``/``domain``,
    #: which the display fields do not carry). ``None`` for a step built without a
    #: source raw dict — the renderer then omits the narrative/command cleanly.
    catalog_step: dict[str, Any] | None = None
    #: True when the graph edge's own ``notes.origin`` records this credential as
    #: found by unauthenticated enumeration (an anonymous/guest SMB sweep reading
    #: SYSVOL for GPP leaks) rather than an authenticated technique run against
    #: the directory. This is the entry-vector fact a writeup otherwise loses:
    #: the step still renders as an ordinary stage, but this marks the ONE stage
    #: that needed no credential at all to reach — read straight from the graph,
    #: never inferred.
    discovered_unauth: bool = False
    #: True when the graph edge's own ``notes.unauthenticated_reachable`` records
    #: this edge's read as PROVEN over an SMB null session (no credential at all).
    #: Stamped by the share-credential provenance service ONLY for a read
    #: genuinely proven over the null-session phase — never inferred from a broad
    #: source SID. This is the path's severity multiplier: when the ENTRY step
    #: carries it, the whole run began with no credential, and the writeup's entry
    #: framing and a per-step badge say so. Distinct from ``discovered_unauth``
    #: (which tracks only the weaker ``notes.origin`` provenance marker).
    unauthenticated_reachable: bool = False
    #: Which bind performed the proven no-credential read — ``null_session`` (the
    #: default) or ``guest_session``. Carried from the edge's ``notes.reached_via``
    #: so the entry badge states the real mechanism (a null-session read and a
    #: guest-session read are honestly different), never a hardcoded "null session".
    reached_via: str = REACHED_VIA_NULL_SESSION
    #: Extra read-capable source principals for this edge, beyond ``source``.
    #: Populated ONLY when several graph edges describe the SAME attack — one
    #: technique, one recovered secret, one artifact — reachable from MORE THAN
    #: one principal (e.g. a GPP cpassword in SYSVOL readable by both ``Everyone``
    #: and ``Domain Users``). The teaching prose is then narrated ONCE and names
    #: every reader parenthetically; the raw per-principal edges stay intact in
    #: ``chain_steps`` for the route map and the mermaid diagram, so the graph
    #: never loses a principal. Empty for an ordinary single-source step.
    sources: tuple[str, ...] = ()
    #: An extra clause APPENDED to this step's rendered narrative (after the
    #: catalog technique prose). The homogenized seam for a grant-then-DCSync
    #: money path: the terminal WriteDACL/Owns/GenericAll step onto the DOMAIN
    #: object confers replication rights, and the DCSync it chained is folded into
    #: THIS step's narrative rather than added as a separate step/node — so the
    #: path still terminates at the domain node with no step-count mismatch. Set
    #: ONLY when the workspace PROVED the replication loot (SSOT:
    #: ``adscan_core.reporting.dcsync_terminal``). Empty for every ordinary step.
    narrative_suffix: str = ""


@dataclass(frozen=True, slots=True)
class SpineStage:
    """A run of steps that ends in acquiring one identity."""

    principal: str
    got_a_session: bool
    proven: bool
    steps: tuple[SpineStep, ...]
    credential_origin: str | None = None
    secret_kind: str | None = None
    has_stored_secret: bool = False
    secret_value: str = ""

    @property
    def heading(self) -> str:
        """Return the stage heading, and never claim an identity nobody got.

        ``Shell as`` and ``Auth as`` are the genre's headings and they are also
        assertions. A step that did not succeed gets ``Route to`` instead: the
        chain is real and worth writing about, the identity was not obtained,
        and the heading has to say which of the two happened.
        """
        if not self.proven:
            return f"Route to {self.principal}"
        verb = "Shell" if self.got_a_session else "Auth"
        return f"{verb} as {self.principal}"

    @property
    def slug(self) -> str:
        """Return a filename-safe slug for the stage's screenshot placeholder."""
        return _slug(self.heading)


@dataclass(frozen=True, slots=True)
class ServiceRow:
    """One open port on one host, as the port scan reported it."""

    host: str
    port: str
    protocol: str
    service: str


@dataclass(frozen=True, slots=True)
class DeadEnd:
    """A route that was tried or considered and went nowhere."""

    technique: TechniqueRef
    source: str
    target: str
    phrase: str
    attempts: int = 0


@dataclass(frozen=True, slots=True)
class CredentialRow:
    """One secret recovered during the run and how it was recovered.

    ``origin`` is ``None`` when the workspace does not record how the secret was
    obtained. That is a real state, not a formatting gap, and the renderer says
    so rather than printing a placeholder that reads like a technique.
    """

    principal: str
    secret_kind: str
    origin: str | None = None
    value: str = ""


@dataclass(frozen=True, slots=True)
class ChangeRow:
    """One alteration ADscan made to the directory, and where it ended up."""

    kind: str
    target: str
    bucket: str
    status: str
    at: str | None = None
    instructions: str = ""


@dataclass(frozen=True, slots=True)
class FlagRow:
    """A captured flag, recorded by name and masked value."""

    name: str
    masked: str


@dataclass(frozen=True, slots=True)
class DiagramHop:
    """One hop of the connected teaching diagram ("The chain" mermaid).

    The diagram renders the CONNECTED materialized path (every node source-to-
    target, including the ``MemberOf`` pivots that bridge the proven edges),
    NOT the raw per-principal proven edges — those stay in ``chain_steps`` for
    the route map and the per-step prose. Without the pivots the proven edges
    are sourced from well-known groups (Everyone / Authenticated Users) and draw
    as disconnected fragments; the connected spine starts at the run's real
    entry (the synthetic ``Unauthenticated`` node for a no-credential path) and
    reads as one linear story.

    ``solid`` drives the arrow style: a PROVEN technique hop is solid (ADscan
    walked it), everything else dashed. A structural group-membership pivot is
    dashed (``structural=True``): it is a fact of the directory's hierarchy, not
    a technique step ADscan proved, so drawing it solid inflated the diagram to
    more "proved" hops than the summary's technique-step headline counts. The
    dashed membership pivot plus the reconciling footnote make the diagram match
    the count (spec §2 #13).
    """

    source: str
    target: str
    label: str
    solid: bool
    #: True when this hop is a structural group-membership pivot (``MemberOf`` …)
    #: rather than a proved technique step. Dashed in the diagram and counted as
    #: a structural hop in the step-vs-hop reconciliation footnote.
    structural: bool = False


@dataclass(frozen=True, slots=True)
class AltRoute:
    """Another chain the graph carried to a comparable target.

    ``status_reason`` is the evidence behind ``status``, pulled from the path's
    own steps rather than invented at render time: for a route closed by
    configuration it is the observed hardening fact (a POSITIVE finding, never
    a defensive-control claim — see the Exposure-Validation doctrine); for a
    route that was attempted and did not land it is where the chain stopped.
    Empty when the status carries no further evidence to add (an executed or
    unwalked route needs none).
    """

    source: str
    target: str
    techniques: tuple[str, ...]
    status: str
    status_reason: str = ""


@dataclass(frozen=True)
class SpineInputs:
    """Everything the renderer needs, already resolved from the workspace."""

    title: str
    domain: str
    platform: str | None = None
    difficulty: str | None = None
    dc_fqdn: str | None = None
    dc_ip: str | None = None
    operating_system: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    services: tuple[ServiceRow, ...] = ()
    scan_asset: str | None = None
    inventory: tuple[tuple[str, str], ...] = ()
    ca_name: str | None = None
    ca_host: str | None = None
    stages: tuple[SpineStage, ...] = ()
    terminal_steps: tuple[SpineStep, ...] = ()
    terminal_title: str = "Final access"
    terminal_proven: bool = False
    #: True ONLY when the PROVEN chain actually reaches a real compromise terminal
    #: (compromise class domain_breaker / tier0_foothold / privileged_escalator).
    #: ``terminal_proven`` alone is True whenever ANY step succeeded, which over-
    #: claims an entry-only foothold as a reached compromise — so the summary and
    #: the "beyond this route" pointer gate on THIS, never on bare
    #: ``terminal_proven``. See the shared honesty standard: entry proven is not
    #: domain compromise.
    terminal_compromise_proven: bool = False
    #: The shared "did the domain fall?" headline fact (spec §2 #19), computed
    #: once via ``kit_facts.domain_compromise_proven`` so the writeup headline and
    #: the Security Assessment Report headline read ONE signal and cannot
    #: disagree. Prefers the persisted ``promote_to_pwned`` verdict
    #: (``auth == "pwned"`` — proven Domain Admin control) and falls back to this
    #: run's own ``terminal_compromise_proven``. A pwned domain reads "falls" even
    #: where the narrated chain stopped short of the terminal edge.
    domain_compromise_proven: bool = False
    #: The onward compromise the graph MAPPED but the run did not walk, phrased
    #: for prose ("full domain compromise", "control of `X`", "a session on `X`").
    #: Set only when the proof is entry-only yet a real-compromise route exists in
    #: the graph; ``None`` when nothing further was mapped. Drives the honest
    #: entry-only summary wording.
    mapped_onward_compromise: str | None = None
    start_principal: str | None = None
    start_principal_note: str | None = None
    #: True when the chain's ENTRY edge was proven executable with NO credential
    #: (a share/file read over an SMB null session — ``notes.unauthenticated_
    #: reachable``). The run did not START with ``start_principal`` as a handed
    #: credential; it reached the entry point unauthenticated and DERIVED that
    #: principal from what it read. The target card and the entry framing say so
    #: rather than listing the derived principal as a "Starting credential".
    started_unauthenticated: bool = False
    chain_nodes: tuple[str, ...] = ()
    chain_steps: tuple[SpineStep, ...] = ()
    #: The proven steps that lie ON the connected primary spine (the same journey
    #: the mermaid draws). When set, ``_render_summary`` narrates THESE as the
    #: linear kill-chain and counts them, rather than the raw ``chain_steps`` —
    #: so a topologically disconnected standalone proof (e.g. an anonymous bind
    #: sourced from a well-known group) that ``_order_proven_edges`` linearized
    #: into ``chain_steps`` is not spliced into the linear chain. Empty when no
    #: connected spine was resolved (the summary then falls back to
    #: ``chain_steps``, preserving prior behaviour).
    primary_spine_steps: tuple[SpineStep, ...] = ()
    #: Proven steps that are NOT on the connected primary spine (the disconnected
    #: standalone proofs). Reported by ``_render_summary`` in a separate sentence
    #: ("ADscan also proved ... not on this chain: ...") so they are disclosed,
    #: never dropped, while the primary chain stays a single linear story.
    other_proven_steps: tuple[SpineStep, ...] = ()
    #: The connected teaching diagram ("The chain" mermaid): the materialized
    #: path source-to-target, starting at the run's real entry node, with the
    #: ``MemberOf`` pivots that bridge the proven edges. Empty when no connected
    #: materialized path matches the narrated chain — the mermaid then falls back
    #: to ``chain_steps`` (the raw proven edges), preserving prior behaviour.
    diagram_hops: tuple[DiagramHop, ...] = ()
    #: ``(shown, proven_total)`` — how many of the edges the run PROVED appear in
    #: the chain below, out of every proven edge. ``None`` when the run proved
    #: nothing (the chain, if any, is the theoretical fallback). Drives the
    #: honesty line under the diagram so a reader knows how complete it is.
    chain_coverage: tuple[int, int] | None = None
    alt_routes: tuple[AltRoute, ...] = ()
    dead_ends: tuple[DeadEnd, ...] = ()
    credentials: tuple[CredentialRow, ...] = ()
    changes: tuple[ChangeRow, ...] = ()
    flags: tuple[FlagRow, ...] = ()
    tags: tuple[str, ...] = ()

    @property
    def chain_has_proven_step(self) -> bool:
        """Return whether any step of the primary chain actually ran and worked."""
        return any(step.outcome == "success" for step in self.chain_steps)

    @property
    def has_recorded_provenance(self) -> bool:
        """Return whether the writeup documents how at least one secret was obtained.

        Provenance lives in three places, any one of which makes the "this run
        did not record how each secret was obtained" confession false: a
        credential row tagged with its origin, a stage tagged with its
        credential origin, or a proven chain step whose narrative already states
        the recovery technique (e.g. an executed AS-REP roast that yielded the
        account's secret). The confession may only appear when ALL three are
        absent — otherwise it contradicts prose already in the same document.
        """
        if any(row.origin for row in self.credentials):
            return True
        if any(stage.credential_origin for stage in self.stages):
            return True
        return self.chain_has_proven_step

    @property
    def beyond_root_warranted(self) -> bool:
        """Return whether there is a root to point beyond.

        "Beyond this route" is a pointer to the routes the graph found and did
        not walk, and its lead sentence claims the run "walked [one chain] end to
        end" — so it belongs ONLY in a document where a real compromise WAS
        walked, never on an entry-only foothold. It gates on
        ``terminal_compromise_proven`` (the proven chain reached a real
        compromise terminal), not bare ``terminal_proven`` (any step succeeded),
        so an entry-only run never claims it walked a chain to compromise. (The
        caller also requires ``alt_routes`` to be non-empty — a finished box with
        no other discovered route has nothing to point at either.)
        """
        return self.terminal_compromise_proven and bool(
            self.terminal_steps or self.flags
        )


@dataclass(frozen=True)
class SpineArtifacts:
    """What one generation wrote to disk."""

    markdown_path: str
    directory: str
    assets: tuple[str, ...] = ()


# ── Small helpers ────────────────────────────────────────────────────────────


def _slug(value: str) -> str:
    """Return a lowercase, hyphenated, filename-safe form of ``value``."""
    cleaned = re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower())
    return cleaned.strip("-") or "target"


def _node_account(node: str) -> str:
    """Return the account part of a ``NAME@REALM`` graph node label."""
    raw = str(node or "").strip()
    return raw.split("@", 1)[0] if "@" in raw else raw


def display_node(
    node: str, *, accounts: frozenset[str] = frozenset(), domain: str = ""
) -> str:
    """Return how a graph node is written in a writeup.

    Accounts are written the way an operator types them, lower case and without
    the realm, machine accounts keeping their ``$``. Groups keep their words but
    lose the directory's shouting, because ``DOMAIN ADMINS`` in running text
    reads as a typo. The domain itself stays lower case.
    """
    raw = str(node or "").strip()
    if not raw:
        return ""
    # A raw SID node label (a collector artifact where a principal was referenced
    # by SID before its LDAP object resolved — e.g. the phantom Guest
    # ``S-1-5-21-...-501`` node) is resolved to its friendly name FIRST, so no
    # writeup prose ever prints a bare ``S-1-...`` token. The @WELLKNOWN case is
    # left to the account/@-split logic below, which already strips that realm.
    if raw.split("@", 1)[0].strip().upper().startswith("S-1-"):
        from adscan_internal.services.well_known_principals import (
            humanize_principal_label,
        )

        humanized = humanize_principal_label(raw)
        if humanized and not humanized.upper().startswith("S-1-"):
            raw = humanized
    if raw.rstrip(".").upper() == str(domain or "").strip().rstrip(".").upper():
        return raw.lower()
    account = _node_account(raw)
    if not account:
        return raw
    if account.upper() in accounts or "@" not in raw:
        return account.lower()
    return account.title() if account.isupper() else account


def _account_names(domain_dir: Path) -> frozenset[str]:
    """Return every sAMAccountName the collector recorded for a user or computer.

    This is what separates ``management_svc`` (an account you become) from
    ``MANAGEMENT`` (a group you gain control of) — a distinction the graph node
    label alone does not carry, and getting it wrong produces headings like
    "Auth as domain admins", which is not a thing.
    """
    names: set[str] = set()
    for filename in ("users.json", "computers.json"):
        payload = _read_json(str(domain_dir / "inventory" / filename))
        records = payload.get("records") if isinstance(payload, dict) else None
        for record in records or []:
            if not isinstance(record, dict):
                continue
            sam = str(record.get("samaccountname") or "").strip()
            if sam:
                names.add(sam.upper())
    return frozenset(names)


def resolve_technique_name(relation: str) -> str | None:
    """Return the curated public name for a relation, or ``None``.

    ``None`` means "this module has no public name for that string", which is
    exactly what the drift test asserts never happens for a live catalog
    relation. Separators are folded before lookup because the same technique
    reaches this function as an edge relation (``hasshadowcredentials``) and as
    a stored credential origin (``shadow_credentials``).
    """
    normalized = normalize_relation(relation)
    key = normalized.replace("_", "").replace("-", "")
    name = _TECHNIQUE_NAMES.get(key) or _TECHNIQUE_NAMES.get(normalized)
    if name:
        return name
    esc = _ESC_RELATION.match(key)
    return f"ESC{esc.group(1).upper()}" if esc else None


def _words_from_identifier(value: str) -> str:
    """Return an identifier written as words: ``writeSmbPath`` to ``Write smb path``."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    spaced = _CAMEL_BOUNDARY.sub(" ", raw.replace("_", " ").replace("-", " "))
    collapsed = " ".join(spaced.split())
    return collapsed[:1].upper() + collapsed[1:] if collapsed else raw


def technique_for(relation: str) -> TechniqueRef:
    """Return the public name and citation for one relation.

    The name resolution order is deliberate: the curated technical-register map
    first, then the canonical graph edge name, then the raw relation written out
    as words. The citation comes from the catalog's ATT&CK mapping, which is
    tier-independent, so no PRO catalog is ever consulted from here.
    """
    name = resolve_technique_name(relation)
    if name is None:
        canonical = get_bh_canonical_cypher_name(relation)
        name = canonical or _words_from_identifier(relation)
    entry = get_attack_step_entry(relation)
    return TechniqueRef(
        relation=str(relation or "").strip(),
        name=name or normalize_relation(relation),
        mitre_id=entry.mitre_technique_id if entry else None,
        mitre_name=entry.mitre_technique_name if entry else None,
    )


def credential_origin_label(origin: str) -> str:
    """Return how a stored ``credential_origin`` slug is written in a writeup.

    Two vocabularies meet here. Most origins name a technique the chain also
    carries as an edge, and those must read identically in both places, so the
    curated technique map wins. The rest name an acquisition that is not a graph
    edge at all (an NTDS dump, a machine account, a session credential) and
    those resolve through the credential-provenance SSOT rather than a second
    copy of it. A raw slug never reaches the page from either route.
    """
    raw = str(origin or "").strip()
    if not raw:
        return ""
    name = resolve_technique_name(raw)
    if name:
        return name
    label = origin_display_label(raw)
    return label or _words_from_identifier(raw)


def secret_kind_label(secret_kind: str) -> str:
    """Return how a stored ``secret_kind`` is written in the credential ledger."""
    raw = str(secret_kind or "").strip()
    if not raw:
        return ""
    mapped = _SECRET_KIND_LABELS.get(raw.lower().replace("-", "_"))
    if mapped:
        return mapped
    return _words_from_identifier(raw).lower()


def _grants_a_session(relation: str) -> bool:
    """Return whether traversing this edge lands an interactive session.

    Keyed on the canonical edge-kind classifier rather than a private list, so a
    new access edge is picked up here the moment it is classified there.
    """
    return classify_edge_kind(relation) is EdgeKind.AUTH


def _is_account_node(
    node: str, *, domain: str, accounts: frozenset[str], kind_hint: str = ""
) -> bool:
    """Return whether the node names an account rather than a group or domain.

    Group and domain nodes are waypoints in a chain, not identities anyone
    becomes, so they never open a ``Shell as`` / ``Auth as`` section. The
    collected inventory decides; the step's own ``target_kind`` is consulted
    first for edges that carry it, and a well-known-group exclusion is the last
    resort for a workspace with no inventory on disk.
    """
    raw = str(node or "").strip().upper()
    if not raw or "@" not in raw:
        return False
    if raw.rstrip(".") == str(domain or "").strip().upper().rstrip("."):
        return False
    hint = str(kind_hint or "").strip().lower()
    if hint in {"user", "computer"}:
        return True
    if hint:
        return False
    account = _node_account(raw)
    if accounts:
        return account in accounts
    return account not in {
        "DOMAIN USERS",
        "DOMAIN COMPUTERS",
        "AUTHENTICATED USERS",
        "EVERYONE",
        "DOMAIN ADMINS",
        "ENTERPRISE ADMINS",
        "ADMINISTRATORS",
    }


def _timestamp_display(value: str | None) -> str | None:
    """Return ``YYYY-MM-DD HH:MM`` for an ISO timestamp, or ``None``."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).strftime(
            "%Y-%m-%d %H:%M"
        )
    except Exception:  # noqa: BLE001 - a malformed stamp is simply not shown
        return None


def _mask(secret: str) -> str:
    """Return a masked form of a flag value.

    Lab platforms do not allow flag values to be republished. Four characters
    are enough for the author to recognise their own capture, and are not the
    flag.
    """
    text = str(secret or "").strip()
    if len(text) < 8:
        return "captured"
    return f"{text[:4]}…"


def _flatten_detail(value: Any) -> str:
    """Return a one-line printable form of a step-detail value.

    A distinguished name collapses to its leaf: a reader needs the template
    called ``CertifiedAuthentication``, not the eighty characters of container
    path that follow it.
    """
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value if v not in (None, ""))
    if isinstance(value, dict):
        return ", ".join(f"{k}={v}" for k, v in value.items() if v not in (None, ""))
    text = str(value)
    if text.upper().startswith("CN=") and "," in text:
        return text.split(",", 1)[0][3:]
    return text


def _evidence_pairs(details: dict[str, Any] | None) -> tuple[tuple[str, str], ...]:
    """Return the printable subset of a step's ``details`` dict, labelled."""
    if not isinstance(details, dict):
        return ()
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for key, label in _EVIDENCE_LABELS:
        if key not in details or label in seen:
            continue
        rendered = _flatten_detail(details.get(key)).strip()
        if rendered:
            pairs.append((label, rendered))
            seen.add(label)
    resources = details.get("vulnerable_resources")
    if isinstance(resources, list):
        named = [
            f"{r.get('kind') or 'object'}: {r.get('name')}"
            for r in resources
            if isinstance(r, dict) and r.get("name")
        ]
        if named:
            pairs.append(("affected objects", "; ".join(named)))
    return tuple(pairs)


# ── Workspace collection ─────────────────────────────────────────────────────


def _read_json(path: str) -> Any:
    """Return parsed JSON from ``path``, or ``None`` when unreadable."""
    try:
        from adscan_internal.workspaces import read_json_file

        return read_json_file(path)
    except Exception:  # noqa: BLE001 - a missing artifact is simply absent
        return None


def _parse_gnmap(path: Path) -> tuple[ServiceRow, ...]:
    """Return the open ports from an nmap greppable output file.

    Filtered and closed ports are dropped: a writeup's recon section lists what
    answered, and the full scan output is linked as an asset for anyone who
    wants the rest.
    """
    rows: list[ServiceRow] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001 - no scan output is a normal state
        return ()
    for line in text.splitlines():
        if not line.startswith("Host:") or "Ports:" not in line:
            continue
        host = line.split("Host:", 1)[1].split("(", 1)[0].strip()
        for chunk in line.split("Ports:", 1)[1].split(","):
            parts = [p.strip() for p in chunk.strip().split("/")]
            if len(parts) < 5 or parts[1] != "open":
                continue
            rows.append(
                ServiceRow(
                    host=host, port=parts[0], protocol=parts[2], service=parts[4] or ""
                )
            )
    return tuple(rows)


def _find_scan_output(domain_dir: Path) -> tuple[Path | None, tuple[ServiceRow, ...]]:
    """Return the port-scan output file and the open ports it recorded."""
    nmap_dir = domain_dir / "nmap"
    if not nmap_dir.is_dir():
        return None, ()
    gnmap = sorted(nmap_dir.glob("*.gnmap"))
    if not gnmap:
        return None, ()
    services = _parse_gnmap(gnmap[0])
    readable = gnmap[0].with_suffix("")
    return (readable if readable.exists() else gnmap[0]), services


def _inventory_rows(
    domain_dir: Path, collection_stats: dict[str, Any] | None
) -> tuple[tuple[str, str], ...]:
    """Return the "what the directory held" table rows.

    Reads the collector's own stats first because they distinguish enabled from
    total objects, and tops them up with the graph totals from the inventory
    index, which is where the node and edge counts live.
    """
    rows: list[tuple[str, str]] = []
    stats = collection_stats if isinstance(collection_stats, dict) else {}

    def _both(label: str, enabled_key: str, total_key: str) -> None:
        total = stats.get(total_key)
        enabled = stats.get(enabled_key)
        if total is None and enabled is None:
            return
        if enabled is not None and total is not None and enabled != total:
            rows.append((label, f"{enabled} enabled of {total}"))
        else:
            rows.append((label, str(enabled if enabled is not None else total)))

    _both("Users", "enabled_users", "users")
    _both("Computers", "enabled_computers", "computers")
    for label, key in (("Groups", "groups"), ("OUs", "ous"), ("GPOs", "gpos")):
        if stats.get(key) is not None:
            rows.append((label, str(stats[key])))

    index = _read_json(str(domain_dir / "inventory" / "index.json"))
    if isinstance(index, dict):
        totals = index.get("totals")
        if isinstance(totals, dict):
            for label, key in (("Graph nodes", "nodes"), ("Graph edges", "edges")):
                if totals.get(key) is not None:
                    rows.append((label, str(totals[key])))
        files = index.get("files")
        if isinstance(files, dict):
            templates = files.get("adcs_templates.json")
            if isinstance(templates, dict) and templates.get("count"):
                rows.append(("Certificate templates", str(templates["count"])))
    return tuple(rows)


def _dc_operating_system(domain_dir: Path) -> str | None:
    """Return the domain controller's OS string from the collected inventory."""
    payload = _read_json(str(domain_dir / "inventory" / "computers.json"))
    records = payload.get("records") if isinstance(payload, dict) else None
    if not isinstance(records, list):
        return None
    for record in records:
        if not isinstance(record, dict):
            continue
        properties = record.get("properties")
        if isinstance(properties, dict) and properties.get("os"):
            return str(properties["os"])
    return None


def _execution_index(
    technical_report: dict[str, Any], domain: str
) -> dict[tuple, dict[str, Any]]:
    """Index the execution record by edge identity.

    The events are the only durable record of what ADscan actually ran; the
    path snapshot is a point-in-time view of the graph and can be regenerated
    after execution, losing the outcome. Joining on ``(relation, from, to)``
    rather than a path id keeps the join stable across re-derived paths — the
    same edge attempted inside three different chains folds into one record,
    which is also how an author remembers it.
    """
    domains = technical_report.get("domains")
    payload = domains.get(domain) if isinstance(domains, dict) else None
    events = payload.get("events") if isinstance(payload, dict) else None
    index: dict[tuple, dict[str, Any]] = {}
    if not isinstance(events, list):
        return index
    # Some executors record an edge's outcome on PATH-level events
    # (``path_started`` / ``path_aborted`` / ``path_completed``) rather than
    # ``step_*`` ones. Only ``path_aborted`` carries the edge identity
    # (``action`` / ``from`` / ``to``); ``path_started`` / ``path_completed``
    # identify the executable edge only by ``path_id``. So we remember which
    # edge key a ``path_id`` resolved to and reuse it for the identity-less
    # events of the same path — otherwise a recorded failure and its later
    # retry-success both vanish and the step renders a bare ``succeeded``.
    path_edge_key: dict[str, tuple] = {}
    attempting_stages = {"step_attempting", "path_started"}
    success_stages = {"step_succeeded", "path_completed"}
    accepted_stages = (
        attempting_stages
        | success_stages
        | {
            "step_failed",
            "step_blocked",
            "path_aborted",
        }
    )
    for event in events:
        if not isinstance(event, dict):
            continue
        details = event.get("details")
        if not isinstance(details, dict):
            continue
        stage = details.get("event_stage")
        if stage not in accepted_stages:
            continue
        action = normalize_relation(str(details.get("action") or ""))
        path_id = str(details.get("path_id") or "")
        if action or details.get("from") or details.get("to"):
            key = (
                action,
                str(details.get("from") or "").upper(),
                str(details.get("to") or "").upper(),
            )
            if path_id:
                path_edge_key[path_id] = key
        elif path_id and path_id in path_edge_key:
            # Identity-less path event (started/completed): attribute it to the
            # executable edge the same path already named in an earlier event.
            key = path_edge_key[path_id]
        else:
            # No edge identity resolvable — cannot attribute this event.
            continue
        record = index.setdefault(
            key,
            {
                "attempts": 0,
                "outcome": "",
                "at": None,
                "failures_before": 0,
                "failures_after": 0,
            },
        )
        if stage in attempting_stages:
            record["attempts"] += 1
            continue
        status = str(details.get("step_status") or "").strip().lower()
        succeeded = stage in success_stages or status in {
            "success",
            "succeeded",
            "completed",
        }
        timestamp = event.get("timestamp")
        if succeeded:
            # A success anywhere in the workspace history is the outcome that
            # matters, and its FIRST timestamp is the one the author is trying
            # to remember. Later re-runs must not overwrite it.
            if record["outcome"] != "success":
                record["outcome"] = "success"
                record["at"] = timestamp
        elif record["outcome"] == "success":
            record["failures_after"] += 1
        else:
            record["failures_before"] += 1
            record["outcome"] = status or "failed"
            record["at"] = timestamp
    return index


@dataclass(frozen=True, slots=True)
class _StepExecution:
    """What the workspace records about one edge having been run."""

    outcome: str
    attempts: int = 0
    at: str | None = None
    failures_before: int = 0
    failures_after: int = 0
    recorded: bool = False


def _step_outcome(
    step: dict[str, Any], execution: dict[tuple, dict[str, Any]]
) -> _StepExecution:
    """Return the execution record for one snapshot step.

    ``recorded`` distinguishes "the events prove this ran" from "the snapshot
    carries a status and nothing else", which is what stops the renderer
    claiming a timeline it does not have.
    """
    details = step.get("details") if isinstance(step.get("details"), dict) else {}
    key = (
        normalize_relation(str(step.get("action") or "")),
        str(details.get("from") or "").upper(),
        str(details.get("to") or "").upper(),
    )
    record = execution.get(key)
    if record:
        return _StepExecution(
            outcome=str(record.get("outcome") or "attempted"),
            attempts=int(record.get("attempts") or 0),
            at=record.get("at"),
            failures_before=int(record.get("failures_before") or 0),
            failures_after=int(record.get("failures_after") or 0),
            recorded=True,
        )
    return _StepExecution(
        outcome=str(step.get("status") or "discovered").strip().lower()
    )


@dataclass(frozen=True)
class CredentialOrigins:
    """The credential store read as evidence, at two different strengths.

    The credential store is a real second proof channel: not every technique
    runs through the attack-path executor, so a step can be absent from the
    execution events while the store plainly holds the secret it produced.

    What the store does NOT carry is an endpoint. It records "this account's
    secret came from ESC9", never "from the ESC9 edge between these two
    principals". A join on the technique alone therefore promotes EVERY edge of
    that technique in the graph to a success, which is how a workspace whose 97
    events contain no ESC9 at all still rendered "ESC9 succeeded" (and how three
    Kerberoasting edges would render three successes off one roasted account).

    So the join is split. ``by_edge`` is keyed ``(technique, PRINCIPAL)`` and
    only matches an edge that actually lands on the account whose secret this
    is: that edge really did produce the credential, and it is proven.
    ``by_technique`` is the weaker fact for everything else, rendered as the
    weaker sentence rather than promoted.
    """

    by_edge: dict[tuple[str, str], str]
    by_technique: dict[str, tuple[str, ...]]

    def attribution_for(self, relation: str) -> tuple[str, ...]:
        """Return the accounts the store credits to ``relation``, if any."""
        return self.by_technique.get(_technique_key(relation), ())

    def proof_for(self, relation: str, target: str) -> str | None:
        """Return the account proving ``relation`` produced a secret AT ``target``."""
        account = _node_account(target).strip().upper()
        if not account:
            return None
        return self.by_edge.get((_technique_key(relation), account))


def _technique_key(relation: str) -> str:
    """Return the folded lookup key shared by relations and origin slugs."""
    return normalize_relation(relation).replace("_", "").replace("-", "")


def _credential_origins(credential_meta: dict[str, Any]) -> CredentialOrigins:
    """Index the credential store by technique and by (technique, account)."""
    by_edge: dict[tuple[str, str], str] = {}
    by_technique: dict[str, list[str]] = {}
    for principal, meta in (credential_meta or {}).items():
        if not isinstance(meta, dict):
            continue
        origin = str(meta.get("credential_origin") or "").strip().lower()
        if not origin or origin == "authenticated_scan":
            continue
        key = origin.replace("_", "").replace("-", "")
        name = str(principal)
        by_edge.setdefault((key, _node_account(name).strip().upper()), name)
        bucket = by_technique.setdefault(key, [])
        if name not in bucket:
            bucket.append(name)
    return CredentialOrigins(
        by_edge=by_edge,
        by_technique={k: tuple(v) for k, v in by_technique.items()},
    )


def _build_steps(
    path: dict[str, Any],
    execution: dict[tuple, dict[str, Any]],
    *,
    domain: str,
    accounts: frozenset[str],
    origins: CredentialOrigins,
    dc_ip: str | None = None,
) -> list[SpineStep]:
    """Return the ordered steps of one chain, enriched with execution outcomes."""
    steps: list[SpineStep] = []
    for raw in path.get("steps") or []:
        if not isinstance(raw, dict):
            continue
        details = raw.get("details") if isinstance(raw.get("details"), dict) else {}
        relation = str(raw.get("action") or "")
        record = _step_outcome(raw, execution)
        entry = get_attack_step_entry(relation)
        target = str(details.get("to") or "")
        source = str(details.get("from") or "")
        outcome = record.outcome
        # Edge-scoped only: a stored secret promotes THIS edge to a success when
        # the secret belongs to the account this edge lands on, and never
        # otherwise. Anything looser credits an edge nobody walked.
        proof = origins.proof_for(relation, target)
        if proof:
            outcome = "success"
        attribution = () if proof else origins.attribution_for(relation)
        # The catalog's manual-command/narrative templates substitute {dc_ip} /
        # {domain} placeholders from ``details`` — a raw step from the graph
        # rarely carries them, so they are stamped in here from what the spine
        # already resolved for this domain. Missing values degrade to the
        # catalog's own literal <dc_ip>/<domain> tokens, never a crash.
        catalog_details = dict(details)
        catalog_details.setdefault("dc_ip", dc_ip or "")
        catalog_details.setdefault("domain", domain)
        # A PROVEN no-credential read (the run's real entry) is authored from the
        # synthetic ``Unauthenticated`` entry node, exactly as the SAR and the
        # mermaid diagram render it — never the raw read-set ACL principal, which
        # can be a well-known group or an unresolved SID node (the phantom Guest
        # ``S-1-5-21-...-501`` node). Rewriting the source here means the summary's
        # causal one-liner (built from ``catalog_step``) and the step header both
        # name the entry node, with no raw SID and no "and Everyone" read-set tail.
        step_unauth = notes_are_unauthenticated_reachable(details)
        step_reached_via = reached_via_from_notes(details)
        if step_unauth:
            entry_label = entry_label_for_reached_via(step_reached_via)
            source_display = entry_label
            catalog_details["from"] = entry_label
        else:
            source_display = display_node(source, accounts=accounts, domain=domain)
        target_display = display_node(target, accounts=accounts, domain=domain)
        # The catalog narrative/remediation substitutes {source}/{target} from the
        # step details, and a raw graph edge carries neither the stamped
        # sAMAccountName the report pipeline uses nor the writeup's own casing
        # rules. Feed the already-humanized display forms (accounts lower-cased,
        # groups de-shouted, realm stripped) so the rendered narrative reads
        # ``michael.wrightson`` / ``Backup Operators`` here too, never the
        # shouting ``MICHAEL.WRIGHTSON@CICADA.HTB`` UPN label. Commands still
        # degrade to the honest ``<...>`` identity fill-ins (no stamped identity).
        catalog_details["from"] = source_display
        catalog_details["display_to"] = target_display
        steps.append(
            SpineStep(
                technique=technique_for(relation),
                source=source_display,
                target=target_display,
                outcome=outcome,
                attempts=record.attempts,
                at=record.at,
                evidence=_evidence_pairs(details),
                target_is_account=_is_account_node(
                    target,
                    domain=domain,
                    accounts=accounts,
                    kind_hint=str(details.get("target_kind") or ""),
                ),
                source_is_account=_is_account_node(
                    source,
                    domain=domain,
                    accounts=accounts,
                    kind_hint=str(details.get("source_kind") or ""),
                ),
                is_context=bool(entry is not None and entry.category == "context"),
                credential_proof=proof,
                credential_attribution=attribution,
                failures_before=record.failures_before,
                failures_after=record.failures_after,
                recorded=record.recorded,
                catalog_step={"action": relation, "details": catalog_details},
                discovered_unauth=str(details.get("origin") or "").strip().lower()
                == "unauth_enrichment",
                unauthenticated_reachable=step_unauth,
                reached_via=step_reached_via,
            )
        )
    return steps


def _step_artifact(step: SpineStep) -> str:
    """Return the on-disk artifact a step's credential was read from, if any.

    The artifact (the SYSVOL file holding a GPP cpassword, a share path) is the
    third axis of the de-dup key below: two edges that recovered the SAME secret
    from the SAME file by the SAME technique are the SAME attack, narrated once.
    Read from the raw step ``details`` so it is the exact value the graph carried,
    not the already-labelled evidence string.
    """
    details = (step.catalog_step or {}).get("details")
    if not isinstance(details, dict):
        return ""
    for key in ("artifact", "share_path", "share"):
        value = details.get(key)
        if value:
            return _flatten_detail(value).strip()
    return ""


def _read_collapse_key(step: SpineStep) -> tuple[str, str, str] | None:
    """Return the ``(technique, recovered-secret, artifact)`` key a read step folds on.

    The recovered-secret proxy is the target account: a credential READ (not a
    modification) that lands on one account, by one technique, from one artifact,
    recovers that account's one secret — so two such edges differing only in their
    SOURCE principal describe the SAME recovered secret. ``None`` for a step that
    is not a credential read (no target account, or a membership/context edge):
    those never collapse, because distinct sources mean distinct attacks there.
    """
    if step.is_context or not step.target_is_account:
        return None
    artifact = _step_artifact(step)
    if not artifact:
        return None
    return (
        _technique_key(step.technique.relation),
        step.target.strip().lower(),
        artifact,
    )


def _collapse_multi_source_read_steps(steps: list[SpineStep]) -> list[SpineStep]:
    """Fold edges that narrate the SAME read (technique × secret × artifact) into one.

    Several principals can be able to read one credential — a GPP cpassword in
    SYSVOL is readable by ``Everyone`` AND ``Domain Users`` — and the graph
    records one edge per reader. They are the SAME attack: narrating the full
    teaching step once per reader is duplicated prose, the NOT-PREMIUM defect.

    So the first edge of each ``(technique, recovered-secret, artifact)`` group is
    kept and its ``sources`` tuple gains every OTHER reader; the duplicate edges
    are dropped from the teaching view. Completeness is preserved on two axes: the
    merged step still names every reader (rendered parenthetically), and the RAW
    per-principal edges are untouched in ``chain_steps``, which is what the route
    map and the mermaid diagram read — so the graph never loses a principal. Order
    is preserved; a step with no collapse key (a modification, a membership hop, or
    a read with no artifact) passes through unchanged.
    """
    first_by_key: dict[tuple[str, str, str], int] = {}
    extra_sources: dict[int, list[str]] = {}
    kept: list[SpineStep] = []
    for step in steps:
        key = _read_collapse_key(step)
        if key is not None and key in first_by_key:
            anchor = first_by_key[key]
            bucket = extra_sources.setdefault(anchor, [])
            if step.source and step.source not in bucket:
                bucket.append(step.source)
            continue
        if key is not None:
            first_by_key[key] = len(kept)
        kept.append(step)
    if not extra_sources:
        return steps
    return [
        dataclasses.replace(step, sources=tuple(extra_sources.get(i, ())))
        if i in extra_sources
        else step
        for i, step in enumerate(kept)
    ]


def _lookup_ci(mapping: dict[str, Any] | None, key: str) -> Any:
    """Return ``mapping[key]`` matched without regard to case."""
    if not isinstance(mapping, dict) or not key:
        return None
    if key in mapping:
        return mapping[key]
    wanted = key.strip().lower()
    for candidate, value in mapping.items():
        if str(candidate).strip().lower() == wanted:
            return value
    return None


def _split_into_stages(
    steps: list[SpineStep],
    *,
    credential_meta: dict[str, Any],
    credentials: dict[str, Any],
) -> tuple[tuple[SpineStage, ...], tuple[SpineStep, ...]]:
    """Split a chain into identity stages plus whatever trails after the last one.

    A stage closes the moment the chain lands on an account, because that is
    what a reader follows: which identity you were, and what you did with it.
    Group and domain hops accumulate into the stage that reaches through them,
    so an ACL write on a group and the account it hands you are one section.

    A stage counts as proven when the edge into it succeeded OR the workspace
    holds that account's secret. Holding the secret IS having the identity, and
    it is true whether or not the provenance of that secret was recorded, so the
    heading does not depend on a metadata field that older workspaces lack.
    """
    stages: list[SpineStage] = []
    pending: list[SpineStep] = []
    for step in steps:
        pending.append(step)
        if not step.target_is_account:
            continue
        meta = _lookup_ci(credential_meta, step.target)
        meta = meta if isinstance(meta, dict) else {}
        origin = str(meta.get("credential_origin") or "") or None
        stored_secret = _lookup_ci(credentials, step.target)
        has_secret = stored_secret is not None
        stages.append(
            SpineStage(
                principal=step.target,
                got_a_session=_grants_a_session(step.technique.relation),
                proven=step.outcome == "success" or has_secret,
                steps=tuple(pending),
                credential_origin=origin,
                secret_kind=str(meta.get("secret_kind") or "") or None,
                has_stored_secret=has_secret,
                secret_value=str(stored_secret or ""),
            )
        )
        pending = []
    return tuple(stages), tuple(pending)


def _terminal_title(compromise_class: str, target: str, *, proven: bool) -> str:
    """Return the heading for the section that closes the chain.

    Same rule as a stage heading: the compromise class describes where the chain
    REACHES in the graph, which is not the same claim as having got there. An
    unproven chain is titled as a route, never as an outcome.
    """
    normalized = str(compromise_class or "").strip().lower()
    if normalized == CompromiseClass.DOMAIN_BREAKER.value:
        outcome = "Domain compromise"
    elif normalized == CompromiseClass.TIER0_FOOTHOLD.value:
        outcome = f"Session on {target}"
    elif normalized == CompromiseClass.PRIVILEGED_ESCALATOR.value:
        outcome = f"Control of {target}"
    else:
        outcome = f"Final access: {target}"
    if proven:
        return outcome
    return f"Route to {outcome[0].lower() + outcome[1:]}"


def _compromise_reach_phrase(compromise_class: str, target: str) -> str:
    """Return how a mapped-but-unwalked compromise reads in a sentence.

    The prose form of a compromise class, for the entry-only summary that says
    "the graph mapped an onward route to <this>". Distinct from
    :func:`_terminal_title` (a section heading): this is a mid-sentence clause.
    """
    normalized = str(compromise_class or "").strip().lower()
    if normalized == CompromiseClass.DOMAIN_BREAKER.value:
        return "full domain compromise"
    if normalized == CompromiseClass.PRIVILEGED_ESCALATOR.value:
        return f"control of `{target}`"
    if normalized == CompromiseClass.TIER0_FOOTHOLD.value:
        return f"a session on `{target}`"
    return f"`{target}`"


def _mapped_onward_compromise(
    ordered: list[dict[str, Any]], *, accounts: frozenset[str], domain: str
) -> str | None:
    """Return the strongest real-compromise terminal the graph MAPPED, as prose.

    Walks the client-ordered routes for the highest-reaching real compromise
    (domain breaker over group takeover over Tier-0 foothold) and returns its
    prose reach phrase, or ``None`` when the graph mapped no onward compromise
    at all. Used only to word the honest entry-only summary — it states what the
    graph found beyond the proven foothold without claiming the run walked it.
    """
    rank = {
        CompromiseClass.DOMAIN_BREAKER.value: 3,
        CompromiseClass.PRIVILEGED_ESCALATOR.value: 2,
        CompromiseClass.TIER0_FOOTHOLD.value: 1,
    }
    best_rank = 0
    best_phrase: str | None = None
    for path in ordered:
        compromise_class = str(path.get("compromise_class") or "").strip().lower()
        current = rank.get(compromise_class, 0)
        if current <= best_rank:
            continue
        nodes = path.get("nodes")
        nodes = nodes if isinstance(nodes, list) else []
        target = (
            display_node(str(nodes[-1]), accounts=accounts, domain=domain)
            if nodes
            else domain
        )
        best_rank = current
        best_phrase = _compromise_reach_phrase(compromise_class, target)
    return best_phrase


def _route_status_reason(path: dict[str, Any]) -> str:
    """Return the evidence behind an alternate route's status, if any.

    Two statuses carry a reason worth showing a reader:

    * ``closed_by_configuration`` — the observed hardening fact (LDAP signing,
      no ADCS, single-DC reflection, …), read from the step's own
      ``blocked_reason`` note. A POSITIVE finding, so this is never phrased as
      a defensive product having stopped anything (Exposure-Validation
      doctrine) — it is stated as the configuration itself.
    * ``attempted`` (and its execution-record synonyms) — where the chain
      stopped: the technique of the last step the run actually tried.

    Every other status (executed, structurally proven, partial) needs no
    reason line — the status word already says what happened. Best-effort:
    a path with no matching step returns ``""`` rather than guessing.
    """
    status = str(path.get("status") or "").strip().lower()
    steps = path.get("steps")
    steps = steps if isinstance(steps, list) else []
    if status == "closed_by_configuration":
        for step in steps:
            if not isinstance(step, dict):
                continue
            if (
                str(step.get("status") or "").strip().lower()
                != "closed_by_configuration"
            ):
                continue
            details = step.get("details")
            details = details if isinstance(details, dict) else {}
            reason = str(details.get("blocked_reason") or "").strip()
            if reason:
                return reason
        return ""
    if status in {"attempted", "failed", "error"}:
        last_relation = ""
        for step in steps:
            if not isinstance(step, dict):
                continue
            step_status = str(step.get("status") or "").strip().lower()
            if step_status in {"attempted", "failed", "error"}:
                last_relation = str(step.get("action") or "").strip()
        if last_relation:
            return f"stopped at {technique_for(last_relation).name}"
        return ""
    return ""


def _collect_dead_ends(
    paths: list[dict[str, Any]],
    execution: dict[tuple, dict[str, Any]],
    *,
    domain: str,
    accounts: frozenset[str],
) -> tuple[DeadEnd, ...]:
    """Return every route that was tried or considered and went nowhere.

    Deduplicated by edge, because the same step attempted inside six chains is
    one dead end, not six. An edge that succeeded anywhere is never listed here
    even if an earlier attempt failed — that is a retry, not a dead end.
    """
    proven: set[tuple] = {
        key for key, record in execution.items() if record.get("outcome") == "success"
    }
    collected: dict[tuple, DeadEnd] = {}
    for path in paths:
        for raw in path.get("steps") or []:
            if not isinstance(raw, dict):
                continue
            details = raw.get("details") if isinstance(raw.get("details"), dict) else {}
            key = (
                normalize_relation(str(raw.get("action") or "")),
                str(details.get("from") or "").upper(),
                str(details.get("to") or "").upper(),
            )
            if key in proven or key in collected:
                continue
            record = _step_outcome(raw, execution)
            attempts = record.attempts
            phrase = _DEAD_END_PHRASES.get(record.outcome)
            if not phrase:
                continue
            collected[key] = DeadEnd(
                technique=technique_for(str(raw.get("action") or "")),
                source=display_node(
                    str(details.get("from") or ""), accounts=accounts, domain=domain
                ),
                target=display_node(
                    str(details.get("to") or ""), accounts=accounts, domain=domain
                ),
                phrase=phrase,
                attempts=attempts,
            )
    return tuple(collected.values())


def _collect_credentials(domain_data: dict[str, Any]) -> tuple[CredentialRow, ...]:
    """Return the credential ledger: what was recovered, and by which technique.

    This is the single most perishable fact in a lab run. Three months later the
    hashes are still in the workspace but nobody remembers which one came from
    the certificate abuse and which came from replication.

    Provenance is read, never inferred. ADscan began tagging every acquisition
    path with an origin in mid-2026, so a workspace older than that has the
    secrets and none of the attribution, and a run can still hold the odd
    credential that arrived by a path with nothing to tag. Both cases render as
    ``origin=None`` and the renderer says so in words rather than leaving a
    blank cell, because a guess in this column is worse than a gap.
    """
    credentials = domain_data.get("credentials")
    if not isinstance(credentials, dict):
        return ()
    meta = domain_data.get("credentials_meta")
    meta = meta if isinstance(meta, dict) else {}
    rows: list[CredentialRow] = []
    for principal in sorted(credentials):
        secret = str(credentials.get(principal) or "")
        entry = _lookup_ci(meta, str(principal))
        entry = entry if isinstance(entry, dict) else {}
        declared = secret_kind_label(str(entry.get("secret_kind") or ""))
        if declared:
            kind = declared
        elif _NT_HASH.match(secret):
            kind = "NT hash"
        elif secret:
            kind = "password"
        else:
            kind = "unknown"
        origin_raw = str(entry.get("credential_origin") or "").strip()
        if origin_raw and origin_raw != "authenticated_scan":
            origin = credential_origin_label(origin_raw)
        elif origin_raw == "authenticated_scan":
            origin = _ORIGIN_SUPPLIED
        else:
            origin = None
        rows.append(
            CredentialRow(
                principal=principal, secret_kind=kind, origin=origin, value=secret
            )
        )
    return tuple(rows)


def _cleanup_instruction(change: dict[str, Any]) -> str:
    """Return the cleanup instruction for one change, with the tool's name out of it.

    The ledger's stored instruction is the specific one (it carries the real
    object and path), so it is preferred. Some of those strings talk ABOUT
    ADscan though, which in a published writeup is either an advert or a
    confession in the author's own voice; when that happens the vendor-neutral
    per-kind template from the cleanup taxonomy is used instead.
    """
    stored = str(change.get("remediation_command") or "").strip()
    if stored and "adscan" not in stored.lower():
        return stored
    template = cleanup_taxonomy.remediation_template_for_kind(change.get("kind"))
    target = str(change.get("target") or "").strip()
    return template.replace("TARGET", target) if target else template


def _collect_environment_changes(
    workspace_dir: Path, *, domain: str
) -> tuple[ChangeRow, ...]:
    """Return what ADscan altered in the directory, and whether it was put back.

    A cleanup note is a genre element that authors write from memory days later
    and get wrong. The ledger has it exactly: the object, the kind of change,
    when, whether the revert was confirmed, and the native command for whatever
    still needs a hand. Buckets, labels and instructions come from the cleanup
    taxonomy rather than a second copy of that vocabulary living here.
    """
    from adscan_internal.services.environment_change_ledger import (
        build_cleanup_report_from_dict,
    )

    payload = _read_json(str(workspace_dir / "environment_changes.json"))
    report = build_cleanup_report_from_dict(
        payload if isinstance(payload, dict) else None
    )
    if not report:
        return ()
    wanted = str(domain or "").strip().lower()
    rows: list[ChangeRow] = []
    for bucket in cleanup_taxonomy.CLEANUP_BUCKETS:
        for change in report.get(bucket) or []:
            if not isinstance(change, dict):
                continue
            recorded_domain = str(change.get("domain") or "").strip().lower()
            if wanted and recorded_domain and recorded_domain != wanted:
                continue
            rows.append(
                ChangeRow(
                    kind=str(change.get("kind_display") or "").strip(),
                    target=str(change.get("target") or "").strip(),
                    bucket=bucket,
                    status=str(change.get("status_label") or "").strip(),
                    at=_timestamp_display(change.get("registered_at")),
                    instructions=(
                        _cleanup_instruction(change)
                        if bucket == cleanup_taxonomy.CLEANUP_BUCKET_MANUAL
                        else ""
                    ),
                )
            )
    return tuple(rows)


def _collect_flags(workspace_dir: Path) -> tuple[FlagRow, ...]:
    """Return the captured flags, by name, masked."""
    flags_dir = workspace_dir / "flags"
    if not flags_dir.is_dir():
        return ()
    rows: list[FlagRow] = []
    for entry in sorted(flags_dir.iterdir()):
        if not entry.is_file():
            continue
        try:
            value = entry.read_text(encoding="utf-8", errors="replace").strip()
        except Exception:  # noqa: BLE001 - an unreadable flag file is just absent
            continue
        if value:
            rows.append(FlagRow(name=entry.name, masked=_mask(value)))
    return tuple(rows)


def _build_tags(chain_steps: list[SpineStep], platform: str | None) -> tuple[str, ...]:
    """Return frontmatter tags derived from the techniques in the chain.

    Membership hops are skipped; every real technique in the chain becomes a
    tag, which is how a reader finds the post six months later.
    """
    tags: list[str] = ["active-directory"]
    for step in chain_steps:
        if step.is_context:
            continue
        slug = _slug(step.technique.name)
        if slug and slug not in tags:
            tags.append(slug)
    if platform:
        tags.append(_slug(platform))
    return tuple(tags[:8])


#: Relations that are pure directory structure — read out of the graph, never a
#: step the run "proved". A ``MemberOf`` edge is a fact, not an attack.
_STRUCTURAL_RELATIONS: frozenset[str] = frozenset(
    {"memberof", "member", "contains", "gplink", "trustedby", "hassession"}
)

#: Broad groups every authenticated principal already belongs to. An edge
#: sourced from one of these is enabled from the first foothold, so it never
#: creates an ordering dependency on a specific reached principal.
_BROAD_GROUP_TOKENS: frozenset[str] = frozenset(
    {"DOMAIN USERS", "AUTHENTICATED USERS", "EVERYONE", "DOMAIN COMPUTERS", "USERS"}
)


def _group_token(label: str) -> str:
    """Return the upper-cased group/principal name without its realm suffix."""
    return str(label or "").split("@", 1)[0].strip().upper()


def _order_proven_edges(proven: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Order proven edges from the run's foothold toward domain compromise.

    A reached-set walk, because the proven edges do not chain source-to-target:
    two of them are sourced from a GROUP (``Domain Users``, ``Backup
    Operators``) rather than the account that reached it. An edge is enabled
    when its source account is reached, its source is a broad group everyone is
    in, or the actor its escalation names is reached. Footholds (concrete-account
    sources) go first and terminal escalations onto a group/domain go last, which
    reproduces the order a reader follows. Edges that can never be linked are
    left out (so the coverage count can honestly fall below the proven total).
    """
    # Every principal a proven edge PRODUCES (control of, or a session on) — an
    # account or a group. A source that appears here is a waypoint the chain
    # reaches, never a starting foothold, so it must not be seeded.
    produced = {
        _group_token(e["to_label"]) for e in proven if _group_token(e["to_label"])
    }
    reached: set[str] = set(_BROAD_GROUP_TOKENS)
    for edge in proven:
        from_tok = _group_token(edge["from_label"])
        if (
            edge["from_is_foothold"]
            and from_tok
            and from_tok not in produced
            and from_tok not in _BROAD_GROUP_TOKENS
        ):
            # An entry node or a real account that no proven edge produces is a
            # foothold the run already held when it started.
            reached.add(from_tok)

    def _enabled(edge: dict[str, Any], *, allow_actor: bool) -> bool:
        # An edge is reachable when its source principal (account or group) is
        # already reached. The ``actor`` bridge — the member who wields a
        # group's power, e.g. the Backup Operator who runs the escalation — is
        # only consulted for TERMINAL escalations onto a group/domain, never to
        # order a control edge: a control edge's actor is a member the chain has
        # not necessarily reached yet, and trusting it lets a later edge jump the
        # queue ahead of the edge that actually granted the source.
        src = _node_account(edge["from_label"]).upper()
        if src and src in reached:
            return True
        if _group_token(edge["from_label"]) in reached:
            return True
        if not allow_actor:
            return False
        actor = _node_account(edge["actor"]).upper()
        return bool(actor and actor in reached)

    def _concrete_source(edge: dict[str, Any]) -> bool:
        src = _node_account(edge["from_label"]).upper()
        return bool(
            src
            and src in reached
            and _group_token(edge["from_label"]) not in _BROAD_GROUP_TOKENS
        )

    remaining = list(proven)
    ordered: list[dict[str, Any]] = []
    progressed = True
    while remaining and progressed:
        progressed = False
        # Preference: concrete-account non-terminal, then broad/group
        # non-terminal, then terminal escalations onto a group/domain.
        # Preference: (0) concrete-account non-terminal, (1) group/broad
        # non-terminal, (2) terminal escalation onto a group, (3) terminal onto
        # the domain object. Deferring the domain-compromise edge to LAST keeps
        # it at the end of a branching proof, so the chain closes on "Domain
        # compromise" rather than on whatever branch happened to sort last.
        for pref in range(4):
            pick: dict[str, Any] | None = None
            for edge in remaining:
                terminal = not edge["to_is_account"]
                if not _enabled(edge, allow_actor=terminal):
                    continue
                concrete = _concrete_source(edge)
                if pref == 0 and concrete and not terminal:
                    pick = edge
                    break
                if pref == 1 and not concrete and not terminal:
                    pick = edge
                    break
                if pref == 2 and terminal and not edge["to_is_domain"]:
                    pick = edge
                    break
                if pref == 3 and terminal and edge["to_is_domain"]:
                    pick = edge
                    break
            if pick is not None:
                ordered.append(pick)
                remaining.remove(pick)
                if pick["to_is_account"]:
                    reached.add(_node_account(pick["to_label"]).upper())
                else:
                    reached.add(_group_token(pick["to_label"]))
                progressed = True
                break
    # Whatever the walk could not thread onto the chain (a generic capability
    # like "Domain Controllers can DCSync", or a genuinely disjoint proof) is
    # still something the run PROVED — append it after the linked chain, in the
    # order the graph recorded it, rather than silently dropping evidence.
    ordered.extend(remaining)
    return ordered


def _compromise_class_for_terminal(
    terminal_label: str,
    ordered_edges: list[dict[str, Any]],
    ordered_canonical: list[dict[str, Any]],
) -> str:
    """Return the compromise class of the proven chain's terminal.

    Prefers the engine's own verdict: the canonical domain-scoped path that
    reaches the same terminal already carries a ``compromise_class``. Falls back
    to the shared classifier over the proven edges when no canonical path
    matches (e.g. a proven chain the domain listing did not surface).
    """
    target = terminal_label.strip().lower()
    for path in ordered_canonical:
        if str(path.get("target") or "").strip().lower() == target and path.get(
            "compromise_class"
        ):
            return str(path["compromise_class"])
    try:
        edge_dicts = [{"relation": e["relation"]} for e in ordered_edges]
        target_node = ordered_edges[-1].get("to_node") if ordered_edges else None
        return derive_compromise_class_from_path(edge_dicts, target_node).value
    except Exception:  # noqa: BLE001 - classification is best-effort
        return ""


#: Graph edge statuses that count as PROVEN — the run drove this edge to a
#: successful execution. Mirrors the report-tier proof vocabulary.
_PROVEN_EDGE_STATUSES: frozenset[str] = frozenset(
    {"success", "succeeded", "exploited", "domain_compromised"}
)


def _chain_from_graph(
    domain_dir: Path,
    domain: str,
    ordered_canonical: list[dict[str, Any]],
    *,
    accounts: frozenset[str],
    only_success: bool,
) -> tuple[dict[str, Any] | None, int, int]:
    """Assemble the chain the writeup narrates directly from the attack graph.

    The report answers "what is exposed" (the domain-scoped picture). The
    writeup answers "what happened", and that is the set of attack-graph edges
    the run drove to a proven status — the proven evidence, in the order a
    reader would follow it. The interactive path snapshot is deliberately NOT
    the source: it is whatever query last wrote it and can begin mid-chain.

    With ``only_success`` the chain is built from PROVEN edges only (the primary
    "what happened" chain). Without it, every non-structural edge is included and
    carries its real status, so a graph with no proven edge still yields the
    theoretical route — clearly marked unwalked — for a box where nothing ran.

    Returns ``(primary, proven_total, shown)``: a synthetic path dict ready for
    :func:`_build_steps`, the count of edges considered, and how many the
    assembled chain includes. ``primary`` is ``None`` when there is nothing to
    build, so a nothing-proven box never gains a fabricated (claimed) chain.
    """
    graph = _read_json(str(domain_dir / "attack_graph.json"))
    if not isinstance(graph, dict):
        return None, 0, 0
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []

    def _label(node_id: str, notes_label: str) -> str:
        node = nodes.get(node_id)
        if isinstance(node, dict) and node.get("label"):
            return str(node["label"])
        if notes_label:
            return notes_label
        raw = str(node_id or "")
        return raw.split(":", 1)[1] if raw.startswith("name:") else raw

    def _is_account(node: Any, label: str, kind_hint: str) -> bool:
        kind = str((node or {}).get("kind") or "").strip().lower()
        if kind in {"user", "computer"}:
            return True
        if kind:
            return False
        return _is_account_node(
            label, domain=domain, accounts=accounts, kind_hint=kind_hint
        )

    def _is_foothold(node: Any, label: str, kind_hint: str) -> bool:
        # A source the run could have STARTED from: a synthetic entry node (the
        # pre-auth foothold) or a real account. A group is never a starting
        # foothold — membership in it comes from an account the chain
        # compromises, so seeding it would let a later edge jump the queue.
        kind = str((node or {}).get("kind") or "").strip().lower()
        if kind == "entry":
            return True
        return _is_account(node, label, kind_hint)

    candidates: list[dict[str, Any]] = []
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        edge_status = str(edge.get("status") or "").strip().lower()
        relation = str(edge.get("relation") or "")
        is_structural = normalize_relation(relation) in _STRUCTURAL_RELATIONS
        if only_success:
            # The proven chain is attack steps only: a structural membership edge
            # is never a step the run "proved", and its status is never success.
            if edge_status not in _PROVEN_EDGE_STATUSES or is_structural:
                continue
        # In the theoretical fallback the structural edge is KEPT — it renders as
        # a context line ("X is a member of Y") that explains the next hop.
        notes = edge.get("notes") if isinstance(edge.get("notes"), dict) else {}
        to_id = str(edge.get("to") or "")
        from_id = str(edge.get("from") or "")
        to_node = nodes.get(to_id)
        from_node = nodes.get(from_id)
        to_label = _label(to_id, str(notes.get("to") or ""))
        from_label = _label(from_id, str(notes.get("from") or ""))
        source_kind = str(notes.get("source_kind") or "")
        target_kind = str(notes.get("target_kind") or "")
        candidates.append(
            {
                "relation": relation,
                "status": edge_status or "theoretical",
                "from_label": from_label,
                "to_label": to_label,
                "actor": str(notes.get("user") or notes.get("actor") or ""),
                "notes": notes,
                "source_kind": source_kind,
                "target_kind": target_kind,
                "to_node": to_node,
                "to_is_account": _is_account(to_node, to_label, target_kind),
                "to_is_domain": (
                    str((to_node or {}).get("kind") or "").strip().lower() == "domain"
                    or target_kind.strip().lower() == "domain"
                    or _group_token(to_label)
                    == str(domain or "").strip().rstrip(".").upper()
                ),
                "from_is_foothold": _is_foothold(from_node, from_label, source_kind),
            }
        )

    total = len(candidates)
    if not candidates:
        return None, 0, 0
    ordered_edges = _order_proven_edges(candidates)
    if not ordered_edges:
        return None, total, 0

    steps: list[dict[str, Any]] = []
    node_seq: list[str] = []
    relations: list[str] = []
    for edge in ordered_edges:
        details = dict(edge["notes"])
        details["from"] = edge["from_label"]
        details["to"] = edge["to_label"]
        if edge["source_kind"]:
            details.setdefault("source_kind", edge["source_kind"])
        if edge["target_kind"]:
            details.setdefault("target_kind", edge["target_kind"])
        shares = edge["notes"].get("shares")
        if shares and "share" not in details:
            # Surface the share the credential came from under a key the
            # evidence renderer recognises.
            details["share"] = shares
        steps.append(
            {
                "action": edge["relation"],
                # A proven chain marks every step ``success``; a theoretical
                # fallback carries each edge's real status so the honesty
                # rendering (``Route to``, "found in the graph, not executed")
                # still fires.
                "status": "success" if only_success else edge["status"],
                "details": details,
            }
        )
        relations.append(edge["relation"])
        if not node_seq:
            node_seq.append(edge["from_label"])
        node_seq.append(edge["to_label"])

    terminal_label = ordered_edges[-1]["to_label"]
    primary = {
        "steps": steps,
        "nodes": node_seq,
        "relations": relations,
        "source": ordered_edges[0]["from_label"],
        "target": terminal_label,
        "status": "exploited" if only_success else "theoretical",
        "compromise_class": _compromise_class_for_terminal(
            terminal_label, ordered_edges, ordered_canonical
        ),
    }
    return primary, total, len(ordered_edges)


def collect_spine_inputs(
    *,
    workspace_dir: str,
    domains_dir: str,
    workspace_name: str,
    domain: str,
    domain_data: dict[str, Any],
    technical_report: dict[str, Any],
    lab_provider: str | None = None,
    lab_name: str | None = None,
) -> SpineInputs | None:
    """Resolve everything the spine needs from one workspace and domain.

    Returns ``None`` only when there is no domain to write about. Every
    individual source is optional: a run with no port scan, no flags or no
    executed step still produces a usable spine, with those sections absent
    rather than invented.
    """
    if not domain:
        return None

    from adscan_internal.workspaces import domain_subpath

    workspace_path = Path(workspace_dir)
    domain_dir = Path(domain_subpath(workspace_dir, domains_dir, domain, ""))

    # Two artifacts, two questions. "What is EXPOSED" (alt routes, dead ends, and
    # the theoretical fallback when nothing ran) is the canonical domain-scoped
    # picture — the SAME computation the client report uses, never the
    # point-in-time interactive path snapshot (which is whatever query last
    # wrote it and can begin mid-chain).
    from adscan_internal.services.report_attack_paths import (
        compute_report_attack_paths,
    )

    paths = compute_report_attack_paths(workspace_dir, domain)
    ordered = order_paths_for_client_presentation(paths)

    execution = _execution_index(technical_report, domain)
    accounts = _account_names(domain_dir)
    credential_meta = domain_data.get("credentials_meta")
    credential_meta = credential_meta if isinstance(credential_meta, dict) else {}
    credentials = domain_data.get("credentials")
    credentials = credentials if isinstance(credentials, dict) else {}
    origins = _credential_origins(credential_meta)
    # Resolved once and reused both for the target card and for the catalog's
    # {dc_ip} placeholder substitution in each step's manual command / narrative.
    dc_ip = str(domain_data.get("dc_ip") or domain_data.get("pdc") or "") or None

    # "What HAPPENED" is the run's own PROVEN edges, assembled in order — the
    # primary chain, with a coverage line disclosing how much of what the run
    # proved it shows. When nothing was proven, the chain becomes a theoretical
    # route (clearly marked unwalked): the canonical top exposure route if the
    # engine surfaced one, else the graph's own edges directly, so a genuinely
    # nothing-proven box stays honest and never CLAIMS a chain it did not walk.
    proven_primary, proven_total, proven_shown = _chain_from_graph(
        domain_dir, domain, ordered, accounts=accounts, only_success=True
    )
    chain_coverage: tuple[int, int] | None = None
    if proven_primary is not None:
        primary = proven_primary
        chain_coverage = (proven_shown, proven_total)
    elif ordered:
        primary = ordered[0]
    else:
        theoretical_primary, _, _ = _chain_from_graph(
            domain_dir, domain, ordered, accounts=accounts, only_success=False
        )
        primary = theoretical_primary or {}
    chain_steps = (
        _build_steps(
            primary,
            execution,
            domain=domain,
            accounts=accounts,
            origins=origins,
            dc_ip=dc_ip,
        )
        if primary
        else []
    )
    # Stages narrate the TEACHING prose, so they fold several edges that describe
    # the same read (one technique, one recovered secret, one artifact — readable
    # by more than one principal) into one step that lists every reader. The raw
    # ``chain_steps`` below are left intact, so the mermaid diagram and the route
    # map still carry one edge per principal and the graph loses nobody.
    teaching_steps = _collapse_multi_source_read_steps(chain_steps)
    stages, terminal_steps = _split_into_stages(
        teaching_steps, credential_meta=credential_meta, credentials=credentials
    )
    # The teaching DIAGRAM ("The chain") renders the CONNECTED materialized path
    # (with the MemberOf pivots that bridge the proven edges, starting at the
    # run's real entry node), not the raw per-principal proven edges — those
    # would draw as disconnected fragments whenever a well-known group sources an
    # edge. chain_steps stays the raw edges for the route map and per-step prose.
    # When no canonical path matches the proven chain's terminal, diagram_hops is
    # empty and the mermaid falls back to chain_steps (prior behaviour).
    diagram_hops: tuple[DiagramHop, ...] = ()
    # F4: the SUMMARY chain and the coverage line must derive from the SAME
    # connected spine the mermaid draws, not the raw proven edges — otherwise a
    # topologically disconnected standalone proof (a well-known-group-sourced
    # anonymous bind) that _order_proven_edges linearized into chain_steps gets
    # spliced into the linear kill-chain while the diagram correctly omits it.
    primary_spine_steps: tuple[SpineStep, ...] = ()
    other_proven_steps: tuple[SpineStep, ...] = ()
    if primary and chain_steps:
        diagram_path = _canonical_diagram_path(ordered, primary)
        if diagram_path is not None:
            diagram_hops, diagram_coverage, shown_keys = _build_diagram_hops(
                diagram_path, chain_steps, accounts=accounts, domain=domain
            )
            if diagram_hops and shown_keys:
                # Split the proven chain steps by whether their (technique,
                # target) is on the connected diagram path. On-spine steps are
                # the linear chain the summary narrates; off-spine proven steps
                # are the standalone proofs it reports separately.
                on_spine: list[SpineStep] = []
                off_spine: list[SpineStep] = []
                for step in chain_steps:
                    key = (
                        _technique_key(step.technique.relation),
                        _node_account(step.target).strip().upper(),
                    )
                    if step.is_context:
                        on_spine.append(step)  # structural pivots stay with the chain
                    elif key in shown_keys:
                        on_spine.append(step)
                    elif step.outcome == "success":
                        off_spine.append(step)
                    else:
                        on_spine.append(step)
                primary_spine_steps = tuple(on_spine)
                other_proven_steps = tuple(off_spine)
                # The coverage line sits under the diagram: every connected
                # proven attack is drawn, so it reads "All N edges ... appear
                # below"; the off-spine proofs are disclosed in the summary's
                # own separate sentence, never dropped.
                chain_coverage = (len(shown_keys), len(shown_keys))
            elif diagram_hops and diagram_coverage is not None:
                # Diagram drew but nothing to split on — keep prior behaviour.
                chain_coverage = diagram_coverage
    # Homogenized grant-then-DCSync terminal: a money path whose terminal grant is
    # WriteDACL/Owns/GenericAll on the DOMAIN object confers replication rights, and
    # the DCSync it chained is FOLDED into that terminal step's narrative (never a
    # separate step/node — the path stays homogeneous, terminates at the domain
    # node, and the step count matches the diagram). Proven only, from the SAME
    # per-domain ``domain_compromise`` events the report reads. The events are
    # persisted under ``technical_report["domains"][domain]["events"]`` (the durable
    # record); ``domain_data`` is often EMPTY on a standalone ``deliver`` (it is not
    # the live in-memory session), so read the technical_report provenance first.
    from adscan_core.reporting.dcsync_terminal import (  # noqa: PLC0415
        extract_dcsync_tier0_secrets,
    )

    _dcsync_events = _domain_compromise_events(technical_report, domain, domain_data)
    _dcsync_secrets = extract_dcsync_tier0_secrets(
        _dcsync_events,
        compromised_credentials=domain_data.get("compromised_credentials"),
    )
    if _dcsync_secrets:
        primary_spine_steps, stages, terminal_steps = _fold_dcsync_into_rendered_collections(
            primary_spine_steps=primary_spine_steps,
            stages=stages,
            terminal_steps=terminal_steps,
            secrets=_dcsync_secrets,
            domain=domain,
        )
    chain_nodes = tuple(
        display_node(str(n), accounts=accounts, domain=domain)
        for n in (primary.get("nodes") or [])
        if n
    )

    # The route map is the differentiator: every route the graph carried to a
    # high-value target, not a curated top few — a competing writeup can only
    # show the ONE chain the author happened to walk. Uncapped, subject only to
    # the bounded-coverage honesty rule below (never silently truncate).
    alt_routes: list[AltRoute] = []
    for path in ordered[1:]:
        relations = [str(r) for r in (path.get("relations") or []) if r]
        nodes = [str(n) for n in (path.get("nodes") or []) if n]
        alt_routes.append(
            AltRoute(
                source=display_node(
                    str(path.get("source") or ""), accounts=accounts, domain=domain
                ),
                target=display_node(
                    nodes[-1] if nodes else "", accounts=accounts, domain=domain
                ),
                techniques=tuple(
                    technique_for(r).name
                    for r in relations
                    if normalize_relation(r) != "memberof"
                ),
                status=str(path.get("status") or "discovered"),
                status_reason=_route_status_reason(path),
            )
        )

    scan_file, services = _find_scan_output(domain_dir)
    # Only real step timestamps fill these two rows. Falling back to the report's
    # own ``generated_at`` printed "Last step executed" for a run where no step
    # executed at all, which is the report's clock presented as the operator's.
    timestamps = [record.get("at") for record in execution.values() if record.get("at")]
    terminal_proven = (
        any(step.outcome == "success" for step in terminal_steps)
        or str(primary.get("status") or "").strip().lower() in _PROVEN_STATUSES
    )
    # An ACHIEVED compromise, not merely a proven entry step: True only when the
    # PROVEN chain (``proven_primary`` — all-success by construction) reaches a
    # real compromise terminal. When the proof is entry-only, resolve the onward
    # compromise the graph mapped (but the run did not walk) so the summary can
    # state the honest split instead of naming the entry principal as an outcome.
    terminal_compromise_proven = (
        proven_primary is not None
        and str(proven_primary.get("compromise_class") or "").strip().lower()
        in _REAL_COMPROMISE_CLASSES
    )
    # The shared domain-compromise headline fact (spec §2 #19): prefer the
    # persisted promote_to_pwned verdict so the writeup and the Security
    # Assessment Report headline read ONE signal. ``domain_data`` carries the
    # live ``auth == "pwned"`` here; the SAR reads the same fact off the persisted
    # kit_facts block.
    from adscan_core.reporting.kit_facts import (  # noqa: PLC0415
        domain_compromise_proven as _domain_compromise_proven,
    )

    domain_compromise_proven = _domain_compromise_proven(
        domain_data, proven_domain_compromise=terminal_compromise_proven
    )
    mapped_onward_compromise = (
        None
        if terminal_compromise_proven
        else _mapped_onward_compromise(ordered, accounts=accounts, domain=domain)
    )
    # The start principal has to be an ACCOUNT, because it is pasted into a
    # command — and it has to be THIS chain's own entry point, not the session's
    # authenticated user. The two differ: the reproduce footer runs
    # ``adscan execute attack_paths <domain> <start>``, which replays the chain
    # from ``<start>``, so naming the session user (who may be a later,
    # already-escalated identity) prints a command that reproduces a DIFFERENT
    # chain. Walk the chain's own endpoints in order and take the FIRST real
    # account it holds (the chain often opens on a synthetic entry node or a
    # group, neither of which is a principal you can run as). Fall back to the
    # session user only when the chain names no account at all.
    start_principal = ""
    for step in chain_steps:
        if step.source_is_account:
            start_principal = step.source
            break
        if step.target_is_account:
            start_principal = step.target
            break
    if not start_principal:
        start_principal = str(domain_data.get("username") or "").strip()
    # The session's authenticated user is not automatically the credential the
    # author was HANDED: on one target it was recovered by a username-as-password
    # spray, and labelling it "(supplied)" would have credited the box with a
    # gift it never gave. The ledger already knows which it was.
    credential_rows = _collect_credentials(domain_data)
    start_row = next(
        (
            row
            for row in credential_rows
            if row.principal.strip().lower() == start_principal.strip().lower()
        ),
        None,
    )
    # The path's ENTRY edge is the foothold. When it was proven executable with
    # NO credential (a null-session share read), the run did not START with
    # ``start_principal`` as a handed credential — it reached the entry point
    # unauthenticated and DERIVED that principal. The first non-context chain
    # step is the entry; a purely-theoretical chain with no such step leaves this
    # False (no fabrication). This drives both the target-card framing and the
    # entry-section line, correcting a Target table that otherwise reads
    # "Starting credential: <derived-principal>" as if it were supplied.
    started_unauthenticated = next(
        (step.unauthenticated_reachable for step in chain_steps if not step.is_context),
        False,
    )
    if started_unauthenticated:
        start_principal_note = "derived, no starting credential"
    elif start_row is None or not start_row.origin:
        start_principal_note = None
    elif start_row.origin == _ORIGIN_SUPPLIED:
        start_principal_note = "supplied"
    else:
        start_principal_note = f"via {start_row.origin}"

    # The workspace name is what the operator typed, so it carries the target's
    # real capitalisation; the normalized lab name is lower-cased for telemetry
    # and would put a lower-case title on the post.
    title = str(workspace_name or "").strip() or str(lab_name or "").strip().title()

    return SpineInputs(
        title=title or domain,
        domain=domain,
        platform=_PLATFORM_LABELS.get(
            str(lab_provider or "").strip().lower(),
            str(lab_provider or "").strip() or None,
        ),
        difficulty=None,
        dc_fqdn=str(
            domain_data.get("pdc_hostname_fqdn") or domain_data.get("dc_fqdn") or ""
        )
        or None,
        dc_ip=dc_ip,
        operating_system=_dc_operating_system(domain_dir),
        first_seen=_timestamp_display(min(timestamps) if timestamps else None),
        last_seen=_timestamp_display(max(timestamps) if timestamps else None),
        services=services,
        scan_asset=str(scan_file) if scan_file else None,
        inventory=_inventory_rows(domain_dir, domain_data.get("collection_stats")),
        ca_name=str(domain_data.get("ca") or "") or None,
        ca_host=str(domain_data.get("adcs_fqdn") or domain_data.get("adcs") or "")
        or None,
        stages=stages,
        terminal_steps=terminal_steps,
        terminal_title=_terminal_title(
            str(primary.get("compromise_class") or ""),
            chain_nodes[-1] if chain_nodes else domain,
            proven=terminal_proven,
        ),
        terminal_proven=terminal_proven,
        terminal_compromise_proven=terminal_compromise_proven,
        domain_compromise_proven=domain_compromise_proven,
        mapped_onward_compromise=mapped_onward_compromise,
        start_principal=start_principal or None,
        start_principal_note=start_principal_note,
        started_unauthenticated=started_unauthenticated,
        chain_nodes=chain_nodes,
        chain_steps=tuple(chain_steps),
        primary_spine_steps=primary_spine_steps,
        other_proven_steps=other_proven_steps,
        diagram_hops=diagram_hops,
        chain_coverage=chain_coverage,
        alt_routes=tuple(alt_routes),
        dead_ends=_collect_dead_ends(
            paths, execution, domain=domain, accounts=accounts
        ),
        credentials=credential_rows,
        changes=_collect_environment_changes(workspace_path, domain=domain),
        flags=_collect_flags(workspace_path),
        tags=_build_tags(chain_steps, lab_provider),
    )


# ── Rendering ────────────────────────────────────────────────────────────────


def _asset_name(source: str) -> str:
    """Return the filename an asset takes inside the spine's ``assets`` folder.

    One definition, because the copy on disk and the relative link in the
    markdown have to agree; nmap's readable output has no suffix and gets a
    ``.txt`` so the link opens rather than downloads.
    """
    path = Path(source)
    return path.name if path.suffix else f"{path.name}.txt"


def _mermaid_label(value: str) -> str:
    """Return a node label safe inside a quoted mermaid node."""
    return str(value or "").replace('"', "#quot;").replace("\n", " ").strip()


def _diagram_node_label(raw: str, *, accounts: frozenset[str], domain: str) -> str:
    """Return a diagram node label, preserving the synthetic entry label verbatim.

    A real principal is written the operator's way (``display_node`` lower-cases
    accounts and strips the realm). The synthetic ``Unauthenticated (null
    session)`` entry node is NOT a directory principal, so it keeps its exact
    minted casing — the diagram has to start at a node a reader recognises as
    "no credential", not a lower-cased mangling of it.
    """
    if is_unauthenticated_entry_label(raw):
        return str(raw).strip()
    return display_node(raw, accounts=accounts, domain=domain)


def _canonical_diagram_path(
    ordered: list[dict[str, Any]], primary: dict[str, Any]
) -> dict[str, Any] | None:
    """Return the canonical materialized path to draw as the connected spine.

    The proven-edge chain (``primary``) is correct for the per-step prose but its
    edges do not join into one picture when they are sourced from well-known
    groups bridged by ``MemberOf`` pivots (the Active case: Everyone/Users read a
    GPP cpassword, Authenticated Users roasts, all disconnected). The canonical
    domain-scoped path carries the SAME journey WITH those pivots, connected
    source-to-target and starting at the run's real entry node.

    Matched by TERMINAL: the first canonical path whose last node is the proven
    chain's terminal. Returns ``None`` when no canonical path reaches that
    terminal (a theoretical / unmatched chain), so the caller falls back to the
    raw ``chain_steps`` diagram and nothing regresses.
    """
    terminal = _group_token(str(primary.get("target") or ""))
    if not terminal:
        return None
    for path in ordered:
        if not isinstance(path, dict):
            continue
        nodes = path.get("nodes")
        steps = path.get("steps")
        if not isinstance(nodes, list) or not nodes or not isinstance(steps, list):
            continue
        if _group_token(str(nodes[-1])) == terminal:
            return path
    return None


def _build_diagram_hops(
    path: dict[str, Any],
    chain_steps: list[SpineStep],
    *,
    accounts: frozenset[str],
    domain: str,
) -> tuple[tuple[DiagramHop, ...], tuple[int, int] | None, frozenset[tuple[str, str]]]:
    """Build the connected diagram hops from a canonical path + the proven set.

    The SKELETON (nodes, order, relation labels, the ``MemberOf`` pivots) comes
    from the canonical materialized ``path``; whether a technique hop is PROVEN
    comes from ``chain_steps`` (which already merged the run's execution events
    and the credential store), NOT from the canonical path's own step status —
    so a hop proven only at run time still draws solid.

    Coverage is counted over DISTINCT proven attacks (``(technique, target)``),
    so two well-known-source edges that recovered the same secret by the same
    technique (Everyone + Users reading one GPP file) count as ONE, and the
    diagram's edge count matches what a reader sees.
    """
    steps = path.get("steps")
    if not isinstance(steps, list) or not steps:
        return (), None, frozenset()

    proven_keys = {
        (_technique_key(s.technique.relation), _node_account(s.target).strip().upper())
        for s in chain_steps
        if s.outcome == "success" and not s.is_context
    }

    hops: list[DiagramHop] = []
    shown_keys: set[tuple[str, str]] = set()
    for raw in steps:
        if not isinstance(raw, dict):
            continue
        details = raw.get("details") if isinstance(raw.get("details"), dict) else {}
        relation = str(raw.get("action") or raw.get("relation") or "")
        src_raw = str(details.get("from") or "")
        dst_raw = str(details.get("to") or "")
        if not src_raw or not dst_raw:
            continue
        structural = normalize_relation(relation) in _STRUCTURAL_RELATIONS
        dst_label = _diagram_node_label(dst_raw, accounts=accounts, domain=domain)
        key = (_technique_key(relation), _node_account(dst_label).strip().upper())
        proven = (not structural) and key in proven_keys
        if proven:
            shown_keys.add(key)
        hops.append(
            DiagramHop(
                source=_diagram_node_label(src_raw, accounts=accounts, domain=domain),
                target=dst_label,
                label="member of" if structural else technique_for(relation).name,
                # A structural membership pivot is a directory fact, NOT a proved
                # technique hop — dash it so the count of solid arrows matches the
                # technique-step headline (spec §2 #13). Only a proven technique
                # hop draws solid.
                solid=proven,
                structural=structural,
            )
        )

    total = len(proven_keys)
    coverage = (len(shown_keys), total) if total else None
    # ``shown_keys`` are the proven-attack keys that lie ON the connected path —
    # the caller uses them to split the proven chain_steps into the on-spine
    # linear chain and the off-spine standalone proofs (F4).
    return tuple(hops), coverage, frozenset(shown_keys)


def _render_mermaid(inputs: SpineInputs) -> list[str]:
    """Return the chain as a mermaid flowchart.

    A diagram, not an image: it renders natively on GitHub and in Obsidian, it
    survives a diff, and the author can rename a node without opening an editor.
    A proved technique hop gets a solid arrow; a structural group-membership
    pivot and a graph-only (unwalked) hop get a dashed one — so the count of
    solid arrows matches the summary's technique-step headline (spec §2 #13).

    When a connected materialized spine is available (``diagram_hops``) it is
    drawn — one linear story from the run's real entry node through the
    ``MemberOf`` pivots to the terminal. Otherwise the raw proven ``chain_steps``
    are drawn (the theoretical / unmatched-terminal fallback).
    """
    # Each edge: (source, target, label, solid, structural).
    if inputs.diagram_hops:
        edges: list[tuple[str, str, str, bool, bool]] = [
            (h.source, h.target, h.label, h.solid, h.structural)
            for h in inputs.diagram_hops
            if h.source and h.target
        ]
    elif inputs.chain_steps:
        edges = [
            (
                step.source,
                step.target,
                step.technique.name,
                step.outcome == "success",
                step.is_context,
            )
            for step in inputs.chain_steps
            if step.source and step.target
        ]
    else:
        return []
    if not edges:
        return []
    lines = ["```mermaid", "flowchart TD"]
    nodes: list[str] = []
    for source, target, _label, _solid, _structural in edges:
        for endpoint in (source, target):
            if endpoint and endpoint not in nodes:
                nodes.append(endpoint)
    ids = {node: f"n{i}" for i, node in enumerate(nodes)}
    for node in nodes:
        lines.append(f'    {ids[node]}["{_mermaid_label(node)}"]')
    has_structural = any(structural for *_ignored, structural in edges)
    for source, target, label, solid, _structural in edges:
        arrow = "-->" if solid else "-.->"
        lines.append(
            f"    {ids[source]} {arrow}|{_mermaid_label(label)}| {ids[target]}"
        )
    lines.append("```")
    lines.append("")
    caption = (
        "Solid arrow: ADscan proved this technique hop. Dashed: present in the "
        "graph, not walked in this run"
    )
    caption += (
        " (a group-membership hop is a directory fact bridging the chain, not a "
        "proved step)."
        if has_structural
        else "."
    )
    lines.append(caption)
    return lines


def _coverage_line(coverage: tuple[int, int] | None) -> str:
    """Return the honesty line stating how complete the proven chain is.

    A reader has no way to tell a chain that shows everything the run proved from
    one that shows a fraction of it. This line closes that gap: it states, in
    plain numbers, how many of the run's proven edges appear below. ``None`` (the
    run proved nothing) prints nothing — the diagram is already marked unproven.
    """
    if not coverage:
        return ""
    shown, total = coverage
    if total <= 0:
        return ""
    if shown >= total:
        edges = "edge" if total == 1 else "edges"
        return f"All {total} {edges} this run proved appear below."
    return f"{shown} of the {total} edges this run proved appear below."


def _count_phrase(count: int, noun: str) -> str:
    """Return ``one recovered secret`` / ``15 recovered secrets``."""
    return f"one {noun}" if count == 1 else f"{count} {noun}s"


def _join_names(names: tuple[str, ...] | list[str]) -> str:
    """Return ``a``, ``a and b``, ``a, b and c`` for a list of code-spanned names."""
    quoted = [f"`{n}`" for n in names]
    if len(quoted) <= 1:
        return quoted[0] if quoted else ""
    return f"{', '.join(quoted[:-1])} and {quoted[-1]}"


def _success_phrase(step: SpineStep) -> str:
    """Return how a successful step reads, including the failures around it.

    The failure history belongs on a successful step, and an earlier version of
    this module suppressed it on the theory that "14 recorded attempts" makes
    the author look like they fumbled. Against a real target that reasoning
    inverts. On one Hack The Box machine the ACL write into a group failed eight
    times over twenty-four hours before it took, and every one of those failures
    was a scheduled reset script on the box undoing the change. The failures are
    the TARGET's doing, they are the most useful operational note anyone can
    make about that machine, and a writeup that hides them is the poorer for it.

    So the count is narrated rather than tallied: failures before the first
    success say the target resisted, failures after it say the target reverts,
    and those are different sentences about different behaviour.
    """
    # The timeline (timestamp + failure history) only exists when the execution
    # EVENTS recorded this edge. A success carried by the graph/snapshot status
    # alone has no timeline to narrate, so ``recorded`` gates it: without it the
    # step reads "succeeded" (or names the recovered credential) and never
    # invents an attempt count or a clock.
    stamp = _timestamp_display(step.at) if step.recorded else None
    opening = f"succeeded at {stamp}" if stamp else "succeeded"
    if step.credential_proof and not stamp:
        opening = f"succeeded, recovered the credential for `{step.credential_proof}`"
    if not step.recorded:
        return opening
    if step.failures_before == 1:
        return f"{opening}, after one earlier attempt failed"
    if step.failures_before > 1:
        return f"{opening}, after {step.failures_before} earlier attempts failed"
    if step.failures_after == 1:
        return f"{opening}, then failed once when it was run again"
    if step.failures_after > 1:
        return f"{opening}, then failed on {step.failures_after} later runs"
    return opening


def _attribution_phrase(step: SpineStep) -> str:
    """Return the weaker, true sentence when only the credential store implicates a step.

    The store knows a secret came from this technique. It does not know from
    WHICH edge, so this edge is not proven and must not be written as if it
    were. Stating the weaker fact costs the author nothing and keeps every
    stronger claim in the document worth believing.
    """
    who = _join_names(step.credential_attribution)
    return (
        "no execution record for this edge, though the stored secret for "
        f"{who} is attributed to this technique"
    )


def _render_step_command_block(catalog_step: dict[str, Any]) -> list[str]:
    """Return the offensive by-hand command for one step, fenced — or nothing.

    ``render_step_manual_command`` returns an empty string for a technique the
    catalog has no authored ``manual_command`` for yet (the P2-pending
    techniques). That is a real, honest state — not a formatting gap — so it
    renders as no block at all, never an empty fence and never a placeholder.
    """
    command = render_step_manual_command(catalog_step)
    if not command:
        return []
    return ["```text", command, "```", ""]


#: The one extra sentence a Kerberoasting step earns when its roasted account is
#: itself a domain-admin-equivalent (``to_control_level == "direct_domain_control"``).
#: Kerberoasting normally lands on a low-privileged service account that then needs
#: further pivoting, so roasting straight onto the control plane with no intermediate
#: hop is the unusual, quotable part of the chain, and a reader learns why it matters.
#: Two phrasings, because the gate is broader than the built-in Administrator: ANY
#: Tier-0 account (a Domain-Admin-member service account included) trips
#: direct_domain_control, so the SPECIFIC "built-in Administrator" claim is only true
#: when the roasted target really is RID 500. For any other Tier-0 target use the
#: honest generic phrasing — either way the no-intermediate-pivot point stays.
_KERBEROAST_BUILTIN_ADMIN_TWIST: str = (
    "Kerberoasting usually targets a low-privileged service account, but here the "
    "SPN sits on the built-in Administrator itself, so the roast lands straight on "
    "a domain-admin-equivalent account with no intermediate pivot."
)
_KERBEROAST_DA_EQUIVALENT_TWIST: str = (
    "Kerberoasting usually targets a low-privileged service account, but here the "
    "SPN sits on a domain-admin-equivalent account, so the roast lands straight on "
    "domain-admin-equivalent control with no intermediate pivot."
)


def _roasted_target_is_builtin_administrator(
    step: SpineStep, details: dict[str, Any]
) -> bool:
    """Return whether the roasted target is the built-in Administrator (RID 500).

    Checks, dependency-free, both signals available on the step: a target SID
    ending in ``-500`` (the canonical built-in Administrator RID), or the target
    account name resolving to ``administrator`` (its reserved sAMAccountName).
    A DA-member SERVICE account (Tier 0, so it trips the direct-domain-control
    gate) is NOT the built-in Administrator, so it returns ``False`` and the
    caller uses the honest generic phrasing.
    """
    for key in ("target_sid", "to_sid", "objectid", "object_id", "sid"):
        sid = str(details.get(key) or "").strip().upper()
        if sid.startswith("S-1-5-21-") and sid.endswith("-500"):
            return True
    candidates = [
        details.get("to"),
        details.get("target_label"),
        details.get("target"),
        step.target,
    ]
    for value in candidates:
        if isinstance(value, str) and value.strip():
            if _node_account(value).strip().lower() == "administrator":
                return True
    return False


def _kerberoast_direct_domain_twist(step: SpineStep) -> str:
    """Return the twist sentence for a Kerberoast that lands on the control plane.

    Gated to a Kerberoasting step whose roasted target directly controls the
    domain (``to_control_level == "direct_domain_control"``). That gate is
    broader than the built-in Administrator — any Tier-0 account (a Domain-Admin
    member service account included) trips it — so the SPECIFIC "built-in
    Administrator" wording is used only when the target really is RID 500;
    otherwise the honest generic "domain-admin-equivalent account" phrasing. For
    an ordinary roast onto a low-privileged service account there is no twist, so
    this returns ``""`` and the step renders unchanged.
    """
    if normalize_relation(step.technique.relation) != "kerberoasting":
        return ""
    details = (step.catalog_step or {}).get("details")
    if not isinstance(details, dict):
        return ""
    if (
        str(details.get("to_control_level") or "").strip().lower()
        != "direct_domain_control"
    ):
        return ""
    if _roasted_target_is_builtin_administrator(step, details):
        return _KERBEROAST_BUILTIN_ADMIN_TWIST
    return _KERBEROAST_DA_EQUIVALENT_TWIST


def _render_step(step: SpineStep) -> list[str]:
    """Return one step as a single dense line plus whatever evidence it carries.

    One line per step is the whole point: the technique, the two endpoints, what
    happened, and the citation, scannable at a glance. The citation is what lets
    a reader who has never run this tool follow the technique on their own.

    A membership edge gets no outcome at all. It is a fact about the directory,
    not something anyone runs, and writing "not executed" beside it invites the
    reader to think a step was skipped.
    """
    if step.is_context:
        return [
            f"**{step.technique.name}** · `{step.source}` is a member of `{step.target}`",
            "",
        ]

    lead: list[str] = []
    if step.unauthenticated_reachable:
        # The strongest initial-access fact: this read was PROVEN over an SMB
        # null session — no credential at all. Stated ahead of the step's own
        # line, with the honest mechanism (the server's null-session access, NOT
        # an Anonymous permission on the share), so an auditor who looks for an
        # Anonymous entry in the permissions and does not find one still trusts
        # the finding. The HOW matches the real bind (null vs guest session) via
        # the shared SSOT view keyed on the step's reached_via — never a hardcoded
        # "null session". Supersedes the weaker discovered_unauth line below.
        unauth_how = unauthenticated_reach_view(reached_via=step.reached_via)["how"]
        lead = [
            f"**{UNAUTHENTICATED_REACH_BADGE}.** {unauth_how}",
            "",
        ]
    elif step.discovered_unauth:
        # This is the initial-access fact a graph-edge-only writeup otherwise
        # skips: the credential below was not found by an authenticated
        # technique at all, it turned up in an anonymous SMB sweep before the
        # run held any credential. Stated once, ahead of the step's own line,
        # never folded into the technique's generic narrative (which assumes
        # an authenticated reader and would misstate this one).
        lead = [
            "Found during unauthenticated enumeration, before this run held "
            "any credential: the actual entry point.",
            "",
        ]

    # When several principals could read the same credential (one GPP cpassword
    # readable by Everyone AND Domain Users), name every reader on the one line
    # rather than repeating the whole teaching step per reader. A PROVEN
    # no-credential entry is the exception: its source is the single synthetic
    # ``Unauthenticated`` entry node (the read-set ACL principals are the "who the
    # ACL allows", already stated by the badge above), so it renders one source
    # with no read-set tail — matching the SAR and the mermaid diagram.
    if step.sources and not step.unauthenticated_reachable:
        readers = _join_names((step.source, *step.sources))
        endpoints = f"{readers} to `{step.target}`"
    else:
        endpoints = f"`{step.source}` to `{step.target}`"
    facts: list[str] = [
        f"**{step.technique.name}**",
        endpoints,
    ]
    if step.outcome == "success":
        facts.append(_success_phrase(step))
    elif step.outcome in _DEAD_END_PHRASES:
        facts.append(_DEAD_END_PHRASES[step.outcome])
        if step.credential_attribution:
            facts.append(_attribution_phrase(step))
    elif step.credential_attribution:
        # The attribution line already says there is no execution record, so it
        # REPLACES the generic phrasing rather than following it.
        facts.append(_attribution_phrase(step))
    else:
        facts.append("found in the graph, not executed")
    if step.attempts > 1 and step.outcome != "success":
        facts.append(f"{step.attempts} recorded attempts")
    if step.technique.mitre_url:
        facts.append(f"[{step.technique.mitre_id}]({step.technique.mitre_url})")

    lines = [*lead, " · ".join(facts), ""]
    # The causal "why this works" narrative and the offensive by-hand command,
    # both sourced from the catalog verbatim — never the defensive verify_*
    # command, which belongs to the client report, not a technique writeup.
    # Both are omitted cleanly (no placeholder, no empty fence) when the step
    # carries no raw dict (an older code path) or the catalog has no authored
    # content yet for this relation.
    if step.catalog_step is not None:
        narrative = render_step_narrative(step.catalog_step)
        if narrative or step.narrative_suffix:
            # Fold any chained-DCSync proof (narrative_suffix) into the SAME
            # paragraph as the technique narrative, so the terminal WriteDACL step
            # reads as one continuous account of the grant and the replication it
            # chained — no separate step, terminus stays the domain node.
            paragraph = " ".join(
                part for part in (narrative.rstrip() if narrative else "", step.narrative_suffix) if part
            ).strip()
            if paragraph:
                lines.append(paragraph)
                lines.append("")
        twist = _kerberoast_direct_domain_twist(step)
        if twist:
            lines.append(twist)
            lines.append("")
        lines.extend(_render_step_command_block(step.catalog_step))
    if step.evidence:
        lines.append("```text")
        lines.extend(f"{label}: {value}" for label, value in step.evidence)
        lines.append("```")
        lines.append("")
    return lines


def _summary_step_phrase(step: SpineStep) -> str:
    """Return one link of the Summary's chain: the step's short causal narrative.

    ``render_step_narrative(..., short=True)`` is the catalog's pre-authored,
    causal one-liner — the same register as the per-step narrative rendered
    lower in the document, never a decision or struggle sentence invented here.
    A technique with no authored short narrative yet (a P2-pending catalog
    entry, e.g. GPP cpassword at the time of writing) has nothing to render, so
    the chain falls back to the technique's public display name rather than a
    blank link — the reader still sees every hop that happened.

    The catalog narrative is authored as a standalone sentence (trailing
    period included), but here it is one link in a " → " chain that the
    caller closes with its own clause (", ending in ..."). A trailing period
    carried into the middle of that sentence prints as a stray ``.,`` — so the
    period is dropped here, once, for every caller of this chain link.
    """
    if step.catalog_step is not None:
        narrative = render_step_narrative(step.catalog_step, short=True)
        if narrative:
            return narrative.removesuffix(".")
    return step.technique.name.removesuffix(".")


def _render_summary(inputs: SpineInputs) -> list[str]:
    """Return the ``## Summary`` section, drafted from the executed chain.

    One deterministic paragraph, built from facts the workspace already proved
    rather than a placeholder waiting on the author: the target, the proven
    steps chained in the order they ran, and the terminal outcome. This is
    causal, not struggle narrative — it states what the chain IS ("X falls in
    N steps: A leads to B leads to C, ending in domain compromise"), never why
    anyone chose it or how it felt to run. No LLM, no interpretation: every
    clause traces to a field already on ``inputs``.

    An unproven chain (nothing this run executed) still drafts a paragraph —
    the same causal register, with the honest qualifier that the graph found
    the route rather than the run proving it, never a claim of execution the
    workspace does not support. A workspace with no chain at all (enumeration
    only, no path discovered) falls back to the plainest true sentence: what
    was scanned and what came of it.
    """
    # The headline counts the ATTACK, so it counts the teaching view: several
    # edges describing one read (same technique, secret and artifact, different
    # reader) are one step here, exactly as the stages below narrate them once.
    # When a connected primary spine was resolved (the same chain the mermaid
    # draws), narrate THAT as the linear kill-chain — never the raw chain_steps,
    # which _order_proven_edges may have linearized a disconnected standalone
    # proof into. The off-spine proofs are disclosed in a separate sentence.
    if inputs.primary_spine_steps:
        teaching_steps = _collapse_multi_source_read_steps(list(inputs.primary_spine_steps))
    else:
        teaching_steps = _collapse_multi_source_read_steps(list(inputs.chain_steps))
    proven_steps = [
        step
        for step in teaching_steps
        if not step.is_context and step.outcome == "success"
    ]
    discovered_steps = [step for step in teaching_steps if not step.is_context]
    if not proven_steps and not discovered_steps:
        return [f"`{inputs.domain}` was enumerated; the graph found no route to walk."]
    if not proven_steps:
        chain = " → ".join(_summary_step_phrase(step) for step in discovered_steps)
        step_count = _count_phrase(len(discovered_steps), "step")
        return [
            f"`{inputs.domain}`: the graph found a route in {step_count}: "
            f"{chain}. Structurally proven, not executed this run."
        ]
    chain = " → ".join(_summary_step_phrase(step) for step in proven_steps)
    step_count = _count_phrase(len(proven_steps), "step")
    # The step-vs-hop reconciliation footnote (spec §2 #13): the headline counts
    # PROVED TECHNIQUE steps, while the diagram (and the Security Assessment
    # Report) count graph HOPS — including the structural group-membership pivots
    # that bridge the chain. One shared clause, rendered on both surfaces, states
    # the difference so a reader crossing the two documents is not confused.
    structural_hops = sum(1 for h in inputs.diagram_hops if h.structural)
    reconcile_clause = chain_reconcile_clause(
        technique_steps=len(proven_steps),
        hop_count=len(proven_steps) + structural_hops,
        structural_hops=structural_hops,
    )
    reconcile_suffix = f" The chain is {reconcile_clause}." if reconcile_clause else ""
    # Disclose any proven finding that is NOT on the connected primary chain
    # (a topologically disconnected standalone proof) in its own sentence, so
    # the linear chain above stays one story while the run's full proof is
    # never hidden.
    other_note = _render_other_proven_note(inputs)
    # Only phrase the outcome as an ACHIEVED compromise when the domain is proven
    # compromised — the run's proven chain reached a real compromise terminal, OR
    # the persisted promote_to_pwned SSOT records proven Domain Admin control
    # (the shared headline fact the Security Assessment Report reads too, spec §2
    # #19). An entry-only proof with no compromise states the honest split: the
    # foothold was proven; the onward route to compromise was mapped, not walked.
    if inputs.terminal_compromise_proven or inputs.domain_compromise_proven:
        outcome = inputs.terminal_title[0].lower() + inputs.terminal_title[1:]
        return [
            f"`{inputs.domain}` falls in {step_count}: {chain}, ending in "
            f"{outcome}.{reconcile_suffix}"
        ] + other_note
    if inputs.mapped_onward_compromise:
        return [
            f"`{inputs.domain}`: ADscan proved the entry in {step_count}: {chain}. "
            f"The graph mapped an onward route to {inputs.mapped_onward_compromise} "
            f"that this run did not walk end to end.{reconcile_suffix}"
        ] + other_note
    return [
        f"`{inputs.domain}`: ADscan proved the entry in {step_count}: {chain}. "
        f"No onward route to full domain compromise was mapped this run.{reconcile_suffix}"
    ] + other_note


def _render_other_proven_note(inputs: SpineInputs) -> list[str]:
    """Return the "other proven findings" sentence, or ``[]`` when there are none.

    A proven edge that is NOT on the connected primary spine (a standalone
    proof the reached-set walk would otherwise splice into the linear chain) is
    disclosed here — named, never dropped — so the summary chain stays one
    linear story while the run's full proof is still reported.
    """
    others = [
        step
        for step in _collapse_multi_source_read_steps(list(inputs.other_proven_steps))
        if not step.is_context and step.outcome == "success"
    ]
    if not others:
        return []
    phrases = "; ".join(_summary_step_phrase(step) for step in others)
    count_word = "one standalone finding" if len(others) == 1 else f"{len(others)} standalone findings"
    return [
        "",
        f"ADscan also proved {count_word} not on this chain: {phrases}.",
    ]


def _domain_compromise_events(
    technical_report: dict[str, Any], domain: str, domain_data: dict[str, Any]
) -> list[Any]:
    """Return the per-domain event list, preferring the persisted technical_report.

    The ``domain_compromise`` events are the durable proof record. On a standalone
    ``deliver`` (rendering from persisted artifacts, not a live session)
    ``domain_data`` is NOT the in-memory ``shell.domains_data`` and carries no
    ``events``; the events live in ``technical_report["domains"][domain]["events"]``.
    So read the technical_report provenance first, falling back to ``domain_data``
    for the live-session path where both are populated.
    """
    domains = technical_report.get("domains") if isinstance(technical_report, dict) else None
    payload = domains.get(domain) if isinstance(domains, dict) else None
    events = payload.get("events") if isinstance(payload, dict) else None
    if isinstance(events, list):
        return events
    fallback = domain_data.get("events") if isinstance(domain_data, dict) else None
    return fallback if isinstance(fallback, list) else []


def _fold_dcsync_into_terminal_step(
    *,
    primary_spine_steps: tuple[SpineStep, ...],
    secrets: list[str],
    domain: str,
) -> tuple[SpineStep, ...]:
    """Fold a chained DCSync into the terminal WriteDACL->domain step's narrative.

    A money path that ends by granting replication rights on the DOMAIN object
    (WriteDACL / Owns / GenericAll) terminates at that grant; the DCSync it enabled
    is not a graph edge, so the chain stops there. HOMOGENIZATION (founder
    2026-09-18): every path terminates at the domain node, so the DCSync is NOT a
    separate step/hop — it is folded into the terminal grant step's OWN narrative
    (``narrative_suffix``), naming the proven Tier-0 secrets. The step count, the
    diagram and the coverage are UNCHANGED (no self-loop, no 3-vs-N mismatch).

    Scans for the LAST grant-relation step onto the domain object (robust to a
    disconnected proven edge trailing after the real terminal) and enriches only
    that one. A no-op (returns the tuple unchanged) unless the workspace PROVED the
    loot (``secrets`` non-empty) AND the chain carries such a terminal. SSOT for the
    decision + prose: ``adscan_core.reporting.dcsync_terminal``.
    """
    from adscan_core.reporting.dcsync_terminal import (  # noqa: PLC0415
        build_dcsync_chain_enrichment,
        is_grant_relation,
        terminal_target_is_domain,
    )

    if not primary_spine_steps or not secrets:
        return primary_spine_steps
    grant_idx = next(
        (
            i
            for i in range(len(primary_spine_steps) - 1, -1, -1)
            if not primary_spine_steps[i].is_context
            and is_grant_relation(primary_spine_steps[i].technique.relation)
            and terminal_target_is_domain(
                terminal_target_label=primary_spine_steps[i].target,
                domain_display=domain,
            )
        ),
        None,
    )
    if grant_idx is None:
        return primary_spine_steps
    terminal = primary_spine_steps[grant_idx]
    enrichment = build_dcsync_chain_enrichment(
        path_status="success",
        terminal_relation=terminal.technique.relation,
        terminal_target_label=terminal.target,
        domain_display=domain,
        secrets=secrets,
    )
    if enrichment is None:
        return primary_spine_steps
    long_clause, _short_clause = enrichment
    existing = terminal.narrative_suffix.strip()
    merged = f"{existing} {long_clause}".strip() if existing else long_clause
    steps = list(primary_spine_steps)
    steps[grant_idx] = dataclasses.replace(terminal, narrative_suffix=merged)
    return tuple(steps)


def _fold_dcsync_into_rendered_collections(
    *,
    primary_spine_steps: tuple[SpineStep, ...],
    stages: tuple[SpineStage, ...],
    terminal_steps: tuple[SpineStep, ...],
    secrets: list[str],
    domain: str,
) -> tuple[tuple[SpineStep, ...], tuple[SpineStage, ...], tuple[SpineStep, ...]]:
    """Apply the DCSync fold to EVERY collection that renders the money path.

    The terminal grant->domain step appears in more than one collection: the
    ``primary_spine_steps`` (the SUMMARY one-liner + the diagram) and the
    per-step SECTION collections (``stages`` + ``terminal_steps``, built from
    ``chain_steps``). The narrative enrichment must land in all of them, or the
    proof shows on one surface (e.g. the diagram-derived summary) but not the
    per-step section a reader actually studies. Each collection is enriched
    independently through the same SSOT helper, so the terminal step folds the
    chained-DCSync clause identically everywhere and nowhere else.
    """
    new_primary = _fold_dcsync_into_terminal_step(
        primary_spine_steps=primary_spine_steps, secrets=secrets, domain=domain
    )
    new_terminal = _fold_dcsync_into_terminal_step(
        primary_spine_steps=terminal_steps, secrets=secrets, domain=domain
    )
    new_stages = tuple(
        dataclasses.replace(
            stage,
            steps=_fold_dcsync_into_terminal_step(
                primary_spine_steps=stage.steps, secrets=secrets, domain=domain
            ),
        )
        for stage in stages
    )
    return new_primary, new_stages, new_terminal


def _render_frontmatter(inputs: SpineInputs, *, today: str) -> list[str]:
    """Return the YAML frontmatter, defaulting to unpublishable.

    ``draft`` and ``published`` are not decoration: Hugo skips a draft and
    Jekyll skips ``published: false``, so a spine dropped into a site
    repository does not go live because someone forgot.
    """
    lines = [
        "---",
        f'title: "{inputs.title}"',
        f"date: {today}",
        "draft: true",
        "published: false",
    ]
    if inputs.tags:
        rendered = ", ".join(f'"{t}"' for t in inputs.tags)
        lines.append(f"tags: [{rendered}]")
    if inputs.platform:
        lines.append(f'platform: "{inputs.platform}"')
    lines.append(f'target: "{inputs.domain}"')
    if inputs.operating_system:
        lines.append(f'os: "{inputs.operating_system}"')
    lines.append("---")
    return lines


def _render_header_note() -> list[str]:
    """Return the one comment block explaining what this file is."""
    return [
        "<!--",
        "  Evidence spine generated by ADscan from the scan workspace. Everything",
        "  below is mechanical: what answered, what the directory held, which steps",
        "  ran and what came back.",
        "",
        "  Solutions to a practice target are normally publishable only once the",
        "  target has retired; confirming that, and clearing `draft: true`, is the",
        "  author's call.",
        "-->",
    ]


#: The accountability line every spine carries near the top: what the reader
#: is holding was not written by a person filling in gaps, it was generated
#: from the same graph the tool used to run the attack — and every claim in
#: it is tagged with how it was proven (executed, structurally proven, not
#: executed) rather than asserted flat.
PROVENANCE_NOTE = (
    "This writeup was generated deterministically from an executed, verified "
    "attack graph. Every claim carries its evidence status; nothing was "
    "inferred."
)


def _render_target_table(inputs: SpineInputs) -> list[str]:
    """Return the target card.

    A field ADscan does not know is dropped, never filled with a plausible value
    and never left as an empty cell: a row reading ``| Difficulty |  |`` is the
    document telling the reader it was generated and not finished.

    The starting credential belongs here, at the top. On an assume-breach target
    it is the premise of everything below, and it used to sit in a table at the
    very bottom among fifteen secrets the run went on to recover.
    """
    if inputs.dc_fqdn and inputs.dc_ip:
        controller = f"`{inputs.dc_fqdn}` ({inputs.dc_ip})"
    elif inputs.dc_fqdn:
        controller = f"`{inputs.dc_fqdn}`"
    else:
        controller = inputs.dc_ip or ""
    start = ""
    if inputs.started_unauthenticated:
        # The run began with NO credential: say that plainly, and name the
        # derived principal as what the unauthenticated entry YIELDED, not as a
        # handed starting credential.
        if inputs.start_principal:
            start = f"None: unauthenticated start; derived `{inputs.start_principal}`"
        else:
            start = "None: unauthenticated start"
    elif inputs.start_principal:
        start = f"`{inputs.start_principal}`"
        if inputs.start_principal_note:
            start += f" ({inputs.start_principal_note})"
    start_label = (
        "Starting access" if inputs.started_unauthenticated else "Starting credential"
    )
    rows = [
        ("Domain", f"`{inputs.domain}`"),
        ("Domain controller", controller),
        ("Operating system", inputs.operating_system or ""),
        ("Platform", inputs.platform or ""),
        (start_label, start),
        ("First step executed", inputs.first_seen or ""),
        ("Last step executed", inputs.last_seen or ""),
    ]
    lines = ["| | |", "|---|---|"]
    lines.extend(f"| {label} | {value} |" for label, value in rows if value)
    return lines


def _render_recon(inputs: SpineInputs, *, asset_link: str | None) -> list[str]:
    """Return the recon section: what answered, per host.

    Suppressed entirely when the workspace holds no port-scan output — an empty
    section whose only content is "no output" is a confession of absence that
    reads as a rendering failure, not a finding. The section simply does not
    appear (an assume-breach or LDAP-only run has nothing to show here).
    """
    if not inputs.services:
        return []
    lines = ["## Recon", ""]
    by_host: dict[str, list[ServiceRow]] = {}
    for row in inputs.services:
        by_host.setdefault(row.host, []).append(row)
    for host, rows in by_host.items():
        lines.append(f"### {host}")
        lines.append("")
        lines.append("```text")
        for row in rows:
            lines.append(f"{row.port + '/' + row.protocol:<10} open   {row.service}")
        lines.append("```")
        lines.append("")
    if asset_link:
        lines.append(f"Full scan output: [{asset_link}]({asset_link})")
        lines.append("")
    return lines


def _render_enumeration(inputs: SpineInputs) -> list[str]:
    """Return the directory-collection section and the chain diagram."""
    lines = ["## Domain enumeration", ""]
    if inputs.inventory:
        lines.append("| | |")
        lines.append("|---|---|")
        lines.extend(f"| {label} | {value} |" for label, value in inputs.inventory)
        lines.append("")
    if inputs.ca_name:
        host = f" on `{inputs.ca_host}`" if inputs.ca_host else ""
        lines.append(f"Certificate authority: `{inputs.ca_name}`{host}.")
        lines.append("")
    diagram = _render_mermaid(inputs)
    if diagram:
        lines.append("### The chain")
        lines.append("")
        lines.extend(diagram)
        lines.append("")
        coverage = _coverage_line(inputs.chain_coverage)
        if coverage:
            lines.append(coverage)
            lines.append("")
    lines.extend(_render_route_map(inputs))
    return lines


def _route_technique_root(route: AltRoute) -> tuple[str, ...]:
    """Return the shared technique ROOT a family of near-identical routes hangs off.

    The first two techniques of the route — the root the client report groups on
    (e.g. ``AS-REP Roasting → GenericAll``). A route with a single technique
    keys on that one; a purely-structural route on a placeholder so it never
    silently folds into a technique family.
    """
    if not route.techniques:
        return ("a direct edge",)
    return tuple(route.techniques[:2])


def _route_family_key(route: AltRoute) -> tuple[str, ...]:
    """Return the key routes must SHARE to collapse into one root-cause line.

    Both the verification STATUS and the technique root: routes are only folded
    when they are near-identical AND verified to the same depth. Verification
    status is the fact a reader most needs per route, so a proven route and a
    theoretical route sharing a root are never silently merged — only genuine
    duplicates (same root, same status) collapse.
    """
    return (route.status, *_route_technique_root(route))


def _render_route_bullet(route: AltRoute) -> str:
    """Return one route as its own bullet (small families and singletons)."""
    via = ", then ".join(route.techniques) if route.techniques else "a direct edge"
    state = _ROUTE_STATES.get(route.status, route.status)
    reason = f": {route.status_reason}" if route.status_reason else ""
    return f"- `{route.source}` to `{route.target}` via {via} ({state}){reason}"


def _render_route_family(group: list[AltRoute]) -> str:
    """Return one consolidated line for a family of routes sharing root and status.

    States the shared root, how far the family was verified, and the distinct
    targets it reaches — every fact drawn from the routes themselves, none
    invented. This is what turns forty near-duplicate bullets into one readable
    root-cause statement. All routes in the group share the same status by
    construction, so the verification state is stated once.
    """
    first = group[0]
    root = " → ".join(_route_technique_root(first))
    state = _ROUTE_STATES.get(first.status, first.status)
    targets: list[str] = []
    for route in group:
        if route.target and route.target not in targets:
            targets.append(route.target)
    target_list = ", ".join(f"`{t}`" for t in targets)
    return (
        f"- {len(group)} further routes share the same {root} root "
        f"({state}); targets: {target_list}."
    )


def _render_route_map(inputs: SpineInputs) -> list[str]:
    """Return the route-map section: every route the graph carried, tagged honestly.

    This is the differentiator over a hand-written writeup: a human author
    documents the ONE chain they walked, while ADscan's graph carries every
    OTHER route it discovered to a comparable target — and each one is tagged
    with exactly how far it was verified. An unexecuted route is never
    dressed up as proven, and a route closed by observed configuration is
    stated as the positive hardening fact it is, not as a failure.

    Bounded-coverage honesty rule (spec §6): the list is never silently cut.
    Under ``_ROUTE_MAP_MAX`` every route shows; at or above it, only the
    top-ranked ``_ROUTE_MAP_MAX`` are shown (the routes are already ordered
    proven-first) and the section says in words how many were left out.
    """
    if not inputs.alt_routes:
        return []
    total = len(inputs.alt_routes)
    bounded = total > _ROUTE_MAP_MAX
    shown = inputs.alt_routes[:_ROUTE_MAP_MAX] if bounded else inputs.alt_routes
    lines = ["### Other routes in the graph", ""]
    lines.append(
        "Every other route ADscan's graph carried to a comparable target, and "
        "how far each one was verified, not just the one chain above."
    )
    lines.append("")
    # Collapse near-identical routes that share a technique ROOT into ONE
    # root-cause family line (mirrors the client report's family grouping): a
    # long list of routes all beginning with the same two techniques reads as
    # noise and buries the one fact that matters — they share a single fixable
    # root. Small groups stay one bullet per route. Grouping is derived from the
    # routes' own shared technique prefix, never fabricated.
    families: dict[tuple[str, ...], list[AltRoute]] = {}
    for route in shown:
        families.setdefault(_route_family_key(route), []).append(route)
    for group in families.values():
        if len(group) >= _ROUTE_FAMILY_MIN:
            lines.append(_render_route_family(group))
        else:
            lines.extend(_render_route_bullet(route) for route in group)
    if bounded:
        lines.append("")
        lines.append(
            f"Showing {len(shown)} of {total} discovered routes "
            f"(ranked proven-first; the rest were not walked)."
        )
    lines.append("")
    return lines


def _render_stage(stage: SpineStage, *, index: int) -> list[str]:
    """Return one identity stage: heading, steps, then the recovered secret.

    No stage-level "how you found this and why it worked" placeholder: the
    catalog's causal narrative is already rendered per step by
    ``_render_step`` (``render_step_narrative``), so a second slot asking the
    same question at the stage level would either repeat that prose or sit
    empty. The steps above already say why the technique works; this section
    adds only what the graph does not already state per edge.
    """
    lines = [f"## {stage.heading}", ""]
    for step in stage.steps:
        lines.extend(_render_step(step))
    kind = secret_kind_label(stage.secret_kind or "") or "credential"
    if stage.credential_origin and stage.secret_value:
        lines.append(
            f"`{stage.principal}` → {kind} `{stage.secret_value}` "
            f"(recovered via {credential_origin_label(stage.credential_origin)})."
        )
        lines.append("")
    elif stage.has_stored_secret and stage.secret_value:
        lines.append(f"`{stage.principal}` → {kind} `{stage.secret_value}`.")
        lines.append("")
    lines.append(f"<!-- screenshot: {ASSETS_DIRNAME}/{index:02d}-{stage.slug}.png -->")
    lines.append("")
    return lines


def _render_unexecuted_note(inputs: SpineInputs) -> list[str]:
    """Return the one line that stops the document contradicting itself.

    A run can end with every step of the chain reading "found in the graph, not
    executed" and, eight lines below, a ledger holding the krbtgt hash and both
    flags. Both halves are true and the reader is left to reconcile them alone,
    which reads as a document that does not know what it is claiming. Saying it
    outright, in the author's favour, turns the worst sentence on the page into
    the most credible one.
    """
    # No chain means no contradiction: there is nothing above for the loot to
    # disagree with, and "the chain above" would point at a section that is not
    # in the document.
    if not inputs.chain_steps or inputs.chain_has_proven_step:
        return []
    secrets = [row for row in inputs.credentials if row.origin != _ORIGIN_SUPPLIED]
    if not secrets and not inputs.flags:
        return []
    holdings = []
    if secrets:
        holdings.append(_count_phrase(len(secrets), "recovered secret"))
    if inputs.flags:
        holdings.append(_count_phrase(len(inputs.flags), "captured flag"))
    plural = len(secrets) + len(inputs.flags) > 1
    tail = (
        "They did not come from anything this run recorded, so how they were "
        "obtained is yours to write."
        if plural
        else "It did not come from anything this run recorded, so how it was "
        "obtained is yours to write."
    )
    return [
        "No step in the chain above was executed under ADscan, and the workspace "
        f"still holds {' and '.join(holdings)}. {tail}",
        "",
    ]


def _render_credential_ledger(inputs: SpineInputs) -> list[str]:
    """Return the credential ledger, with a column that earns its place.

    Provenance is the reason this table exists, so when the workspace has none
    of it the column is dropped and the gap is stated once in a sentence. A
    table whose every cell reads "unrecorded" is worse than no column: it looks
    like a rendering failure, and it costs the reader a scan of every row to
    learn nothing.
    """
    if not inputs.credentials:
        return []
    known = [row for row in inputs.credentials if row.origin]
    lines = ["### Credentials recovered", ""]
    # Accounts-vs-secrets reconciliation (kit-facts SSOT, spec §2 #12): this
    # ledger frames the recovered set as "secrets" while the Security Assessment
    # Report §09 frames the same credential store as "accounts". When the krbtgt
    # account key is among them, both surfaces render this ONE shared clause,
    # computed from the same count, so a reader crossing the two documents is not
    # left with two different totals.
    from adscan_core.reporting.kit_facts import (  # noqa: PLC0415
        recovered_secret_reconcile_clause,
    )

    _krbtgt_recovered = any(
        row.principal.strip().lower() == "krbtgt" for row in inputs.credentials
    )
    _recovered_secret_note = recovered_secret_reconcile_clause(
        total_secrets=len(inputs.credentials), krbtgt_included=_krbtgt_recovered
    )
    if not known:
        lines.append("| Account | Secret | Value |")
        lines.append("|---|---|---|")
        for row in inputs.credentials:
            shown = f"`{row.value}`" if row.value else "n/a"
            lines.append(f"| `{row.principal}` | {row.secret_kind} | {shown} |")
        lines.append("")
        # The confession is only honest when the workspace records NO provenance
        # anywhere. It must not fire when the executed chain (or a stage/row)
        # already states how a secret was obtained — printing "did not record how
        # each secret was obtained" above a chain that narrates the AS-REP roast
        # that yielded one contradicts the document itself.
        if not inputs.has_recorded_provenance:
            lines.append(
                "This run did not record how each secret was obtained, so the "
                "provenance is not in the workspace to print."
            )
            lines.append("")
        if _recovered_secret_note:
            lines.append(_recovered_secret_note)
            lines.append("")
        return lines
    lines.append("| Account | Secret | Value | Recovered via |")
    lines.append("|---|---|---|---|")
    for row in inputs.credentials:
        shown = f"`{row.value}`" if row.value else "n/a"
        lines.append(
            f"| `{row.principal}` | {row.secret_kind} | {shown} | "
            f"{row.origin or 'not recorded'} |"
        )
    lines.append("")
    if _recovered_secret_note:
        lines.append(_recovered_secret_note)
        lines.append("")
    return lines


def _terminal_outcome_statement(inputs: SpineInputs) -> str:
    """Return the one fact-only sentence closing the terminal section.

    Sourced entirely from the terminal step's own technique name and the
    credential ledger already printed above it — never a struggle or decision
    sentence, only what the last edge and the recovered secrets prove. A
    chain that never landed states where it stopped, in the same neutral
    register the dead-ends section already uses, never a claim that a
    defence stopped it (Exposure-Validation doctrine).
    """
    last = inputs.terminal_steps[-1] if inputs.terminal_steps else None
    if not inputs.terminal_proven:
        if last is None:
            return ""
        stopped_at = _DEAD_END_PHRASES.get(last.outcome, "did not complete")
        return (
            f"`{last.technique.name}` against `{last.target}` {stopped_at}. "
            "Nothing below this line was confirmed."
        )
    secrets = [row for row in inputs.credentials if row.value]
    outcome = inputs.terminal_title[0].lower() + inputs.terminal_title[1:]
    if last is None:
        if not secrets:
            return f"This run confirmed {outcome}."
        return (
            f"This run confirmed {outcome}, recovering "
            f"{_count_phrase(len(secrets), 'secret')}."
        )
    technique = last.technique.name
    target = last.target
    if not secrets:
        return f"`{technique}` against `{target}` succeeded, confirming {outcome}."
    kinds = sorted(
        {secret_kind_label(row.secret_kind) or row.secret_kind for row in secrets}
    )
    kind_phrase = _join_bare(kinds)
    return (
        f"`{technique}` against `{target}` succeeded, returning "
        f"{_count_phrase(len(secrets), 'secret')} ({kind_phrase}) and confirming "
        f"{outcome}."
    )


def _join_bare(names: list[str]) -> str:
    """Return ``a``, ``a and b``, ``a, b and c`` for plain (unquoted) names."""
    if len(names) <= 1:
        return names[0] if names else ""
    return f"{', '.join(names[:-1])} and {names[-1]}"


def _render_terminal(inputs: SpineInputs, *, index: int) -> list[str]:
    """Return the closing section: last steps, the credential ledger, the flags."""
    heading = (
        inputs.terminal_title if inputs.terminal_steps else "What the run recovered"
    )
    lines = [f"## {heading}", ""]
    for step in inputs.terminal_steps:
        lines.extend(_render_step(step))
    lines.extend(_render_unexecuted_note(inputs))
    lines.extend(_render_credential_ledger(inputs))
    if inputs.flags:
        lines.append("### Flags")
        lines.append("")
        for flag in inputs.flags:
            lines.append(f"- `{flag.name}`: `{flag.masked}`")
        lines.append("")
        lines.append(
            "Truncated on purpose. Platforms ask that flag values are not "
            "republished in full."
        )
        lines.append("")
    lines.append(
        f"<!-- screenshot: {ASSETS_DIRNAME}/{index:02d}-{_slug(heading)}.png -->"
    )
    lines.append("")
    statement = _terminal_outcome_statement(inputs)
    if statement:
        lines.append(statement)
        lines.append("")
    return lines


def _render_dead_ends(inputs: SpineInputs) -> list[str]:
    """Return the routes that went nowhere.

    A genre requirement, and the section a scanner's record covers better than
    memory does. Each line states what was tried and what happened, and nothing
    about defences: ADscan proves whether a path exists, it does not test a
    security product, so a step that did not complete is never written up as
    having been stopped by one.
    """
    if not inputs.dead_ends:
        return []
    lines = ["## What didn't work", ""]
    for dead in inputs.dead_ends:
        attempts = f" ({dead.attempts} attempts)" if dead.attempts > 1 else ""
        lines.append(
            f"- **{dead.technique.name}** · `{dead.source}` to `{dead.target}` · "
            f"{dead.phrase}{attempts}"
        )
    lines.append("")
    return lines


def _render_changes(inputs: SpineInputs) -> list[str]:
    """Return what ADscan altered in the directory and whether it was put back.

    Every writeup in the genre ends with the author remembering, days later,
    which machine account they left behind. The ledger already knows, exactly,
    so this section is written from the record rather than from memory.

    Anything still needing a hand is listed individually with its native
    command, however long the section gets, because that is the part with
    consequences. Everything already undone is collapsed by kind, because eight
    identical file uploads reverted eight times is one fact.
    """
    if not inputs.changes:
        return []
    manual = [
        c for c in inputs.changes if c.bucket == cleanup_taxonomy.CLEANUP_BUCKET_MANUAL
    ]
    rest = [
        c for c in inputs.changes if c.bucket != cleanup_taxonomy.CLEANUP_BUCKET_MANUAL
    ]

    lines = ["## What ADscan changed, and what it put back", ""]
    grouped: dict[tuple[str, str], list[ChangeRow]] = {}
    for change in rest:
        grouped.setdefault((change.kind, change.status), []).append(change)
    for (kind, status), group in grouped.items():
        first = group[0]
        if len(group) == 1:
            when = f" at {first.at}" if first.at else ""
            lines.append(f"- **{kind}** · `{first.target}` · {status.lower()}{when}")
        else:
            lines.append(
                f"- **{kind}** · {len(group)} changes, first `{first.target}` · "
                f"{status.lower()}"
            )
    for change in manual:
        when = f" at {change.at}" if change.at else ""
        lines.append(
            f"- **{change.kind}** · `{change.target}` · {change.status.lower()}{when}"
        )
    lines.append("")
    if manual:
        lines.append(
            "One change could not be rolled back automatically and is still on "
            "the target:"
            if len(manual) == 1
            else f"{len(manual)} changes could not be rolled back automatically "
            "and are still on the target:"
        )
        lines.append("")
        printed: set[tuple[str, str]] = set()
        for change in manual:
            key = (change.target, change.instructions)
            if not change.instructions or key in printed:
                continue
            printed.add(key)
            lines.append(f"`{change.target}`:")
            lines.append("")
            lines.append("```text")
            lines.extend(change.instructions.splitlines())
            lines.append("```")
            lines.append("")
    return lines


def render_spine_markdown(inputs: SpineInputs, *, today: str | None = None) -> str:
    """Return the full spine as CommonMark.

    Pure: same inputs, same bytes. The whole document is assembled here so the
    section order, the one the genre already uses, is readable in one place.
    """
    stamp = today or datetime.now().strftime("%Y-%m-%d")
    asset_link = (
        f"{ASSETS_DIRNAME}/{_asset_name(inputs.scan_asset)}"
        if inputs.scan_asset
        else None
    )

    lines: list[str] = []
    lines.extend(_render_frontmatter(inputs, today=stamp))
    lines.append("")
    lines.extend(_render_header_note())
    lines.append("")
    lines.append(f"# {inputs.title}")
    lines.append("")
    lines.append(f"> {PROVENANCE_NOTE}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.extend(_render_summary(inputs))
    lines.append("")
    lines.append("## Target")
    lines.append("")
    lines.extend(_render_target_table(inputs))
    lines.append("")
    lines.extend(_render_recon(inputs, asset_link=asset_link))
    lines.extend(_render_enumeration(inputs))
    for index, stage in enumerate(inputs.stages, start=1):
        lines.extend(_render_stage(stage, index=index))
    if inputs.terminal_steps or inputs.credentials or inputs.flags:
        lines.extend(_render_terminal(inputs, index=len(inputs.stages) + 1))
    lines.extend(_render_dead_ends(inputs))
    lines.extend(_render_changes(inputs))
    if inputs.beyond_root_warranted and inputs.alt_routes:
        lines.append("## Beyond this route")
        lines.append("")
        lines.append(
            f"This is the one chain the run walked end to end. The graph carried "
            f"{_count_phrase(len(inputs.alt_routes), 'other route')} to a "
            'comparable target; see "Other routes in the graph" under Domain '
            "enumeration for how far each one was verified."
        )
        lines.append("")
    lines.extend(_render_reproduce(inputs))
    return "\n".join(lines).rstrip() + "\n"


def _render_reproduce(inputs: SpineInputs) -> list[str]:
    """Return the reproduction footer.

    Four lines, placed last, because a writeup that leads with a tool is an
    advert. Every verb here ships in the free tier, and the list is locked by a
    test so a future paid-tier verb cannot land in someone's published post.

    The start principal is the authenticated account, or the first node of the
    chain that the collected inventory confirms IS an account. A chain routinely
    starts at a group, and the older rule (first source with no space in it)
    printed the chain's destination group as the account to run as: a command
    that cannot work, in a published post. When no account resolves, the line is
    left out rather than guessed.
    """
    lines = [
        "---",
        "",
        "```text",
        "adscan start",
        "> start_auth",
        f"> attack_paths {inputs.domain}",
    ]
    if inputs.start_principal:
        lines.append("")
        lines.append(
            f"adscan execute attack_paths {inputs.domain} {inputs.start_principal}"
        )
    lines.append("```")
    lines.append("")
    return lines


# ── Generation ───────────────────────────────────────────────────────────────


def _resolve_domain(shell: Any, technical_report: dict[str, Any]) -> str:
    """Return the domain this spine is about.

    The session's current domain wins; otherwise the first domain the technical
    report carries, which is the one a single-target lab run always produces.
    """
    current = str(
        getattr(shell, "domain", None) or getattr(shell, "current_domain", None) or ""
    )
    domains = technical_report.get("domains")
    names = [str(d) for d in domains.keys() if d] if isinstance(domains, dict) else []
    if current and (not names or current in names):
        return current
    return names[0] if names else current


def _copy_assets(scan_asset: str | None, assets_dir: Path) -> tuple[str, ...]:
    """Copy the raw scan output beside the spine and return what was written.

    Separate files with relative links, never inlined: base64 in a markdown file
    breaks diffs and Obsidian both. A suffix is added when the source has none,
    so the link opens as text in a browser instead of downloading.
    """
    if not scan_asset:
        return ()
    source = Path(scan_asset)
    if not source.exists():
        return ()
    try:
        assets_dir.mkdir(parents=True, exist_ok=True)
        destination = assets_dir / _asset_name(scan_asset)
        shutil.copyfile(source, destination)
        return (str(destination),)
    except Exception as exc:  # noqa: BLE001 - the markdown stands without the asset
        print_exception(exception=exc)
        return ()


def _emit_generated(properties: dict[str, Any]) -> None:
    """Capture ``writeup_spine_generated`` without disturbing the caller.

    The event name is a literal here on purpose: the closed-vocabulary lock in
    ``tests/unit/test_telemetry_event_name_allowlist.py`` reads
    ``telemetry.capture`` first arguments straight out of the AST.
    """
    try:
        telemetry.capture("writeup_spine_generated", properties)
    except Exception as exc:  # noqa: BLE001 - analytics must never break a flow
        try:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
        except Exception:  # noqa: BLE001 - the sinks themselves must never raise
            pass


def count_write_markers(markdown: str) -> int:
    """Return how many human-only placeholders a rendered spine carries.

    The renderer no longer emits any — every section drafts from the
    workspace or states its own gap honestly — so this stays at 0 for every
    spine this module writes today. Kept as a structural check: a marker
    reappearing here means a future change regressed the tool-native
    guarantee, and this is what a test greps for to catch it.
    """
    return markdown.count(f"<!-- {WRITE_MARKER}:")


def _print_ready_panel(artifacts: SpineArtifacts, markers: int) -> None:
    """Print the post-generation panel: the path, then what is in it."""
    from rich.console import Group
    from rich.text import Text

    from adscan_core.rich_output import print_panel

    lines = [
        Text(artifacts.markdown_path, style="bold"),
        Text(""),
        Text(
            "Recon, enumeration, every step that ran and every route that didn't, "
            "in the order it happened."
        ),
        Text(""),
        Text(
            "Generated end to end from the workspace: nothing is left blank for "
            "hand-fill, and every claim states how it was proven."
            if markers == 0
            else f"{markers} place(s) still carry a `{WRITE_MARKER}` marker. "
            "unexpected; search for them before publishing."
        ),
        Text(""),
        Text(
            "It is a local draft. Solutions to a practice target are normally "
            "publishable only after it retires.",
            style="dim",
        ),
    ]
    print_panel(Group(*lines), title="Writeup spine ready", border_style="green")


def generate_writeup_spine(
    shell: Any,
    *,
    output_dir: str | None = None,
    trigger: str = TRIGGER_REPL_WRITEUP,
) -> SpineArtifacts | None:
    """Write the evidence spine for the active workspace and return what it wrote.

    The single instrumented entry point for every spine, so the one number this
    feature is judged on stays readable: how many writeups exist because ADscan
    wrote them at the end of a lab scan versus because somebody typed the verb.
    That is what ``trigger`` records, and it is the same vocabulary the exposure
    report reports on, so the two artifacts can be compared directly.

    Best-effort and never raises: this is a convenience on top of a finished
    scan, so a missing artifact degrades the document rather than failing the
    caller.

    Args:
        shell: The active CLI shell (workspace context).
        output_dir: Explicit destination directory. Defaults to a timestamped
            directory under ``<workspace>/writeups/``.
        trigger: Which on-ramp asked for the spine, one of the ``TRIGGER_*``
            constants in :mod:`adscan_internal.services.post_scan_report`.
            Defaults to the operator typing ``writeup``.

    Returns:
        The written artifacts, or ``None`` when there was no scan data.
    """
    started = datetime.now()
    inputs: SpineInputs | None = None
    artifacts: SpineArtifacts | None = None
    try:
        from adscan_core.reporting.technical_report import _get_technical_report_path

        workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "")
        if not workspace_dir:
            print_error("No workspace is open. Run a scan first.")
            return None

        # The technical report supplies the execution EVENTS, and nothing else
        # the spine needs. A workspace can hold a full scan (port scan, graph,
        # attack paths, credentials, flags) and no report at all, and refusing
        # to write anything for it was wrong twice over: the spine is genuinely
        # useful without the events, and "no scan data found yet" told the
        # operator to re-run a scan they had already run.
        report_path = Path(_get_technical_report_path(shell))
        loaded = _read_json(str(report_path)) if report_path.exists() else None
        technical_report = loaded if isinstance(loaded, dict) else {}

        domain = _resolve_domain(shell, technical_report)
        domains_data = getattr(shell, "domains_data", None)
        domain_data = (
            domains_data.get(domain) if isinstance(domains_data, dict) else None
        )
        if not domain:
            print_error(
                "No domain in this workspace yet. Run a scan first, then build "
                "the spine."
            )
            return None
        if not technical_report:
            print_info(
                "No execution record in this workspace, so every step is written "
                "as found in the graph rather than run."
            )

        inputs = collect_spine_inputs(
            workspace_dir=workspace_dir,
            domains_dir=str(getattr(shell, "domains_dir", "domains") or "domains"),
            workspace_name=str(getattr(shell, "current_workspace", "") or ""),
            domain=domain,
            domain_data=domain_data if isinstance(domain_data, dict) else {},
            technical_report=technical_report,
            lab_provider=getattr(shell, "lab_provider", None),
            lab_name=getattr(shell, "lab_name", None),
        )
        if inputs is None:
            print_error("No domain data to build a spine from.")
            return None

        stamp = started.strftime("%Y%m%d-%H%M%S")
        target_dir = (
            Path(output_dir)
            if output_dir
            else Path(workspace_dir)
            / WRITEUP_DIRNAME
            / f"{_slug(inputs.title)}-{stamp}"
        )
        target_dir.mkdir(parents=True, exist_ok=True)
        assets = _copy_assets(inputs.scan_asset, target_dir / ASSETS_DIRNAME)

        markdown_path = target_dir / SPINE_FILENAME
        markdown = render_spine_markdown(inputs, today=started.strftime("%Y-%m-%d"))
        markdown_path.write_text(markdown, encoding="utf-8")
        artifacts = SpineArtifacts(
            markdown_path=str(markdown_path),
            directory=str(target_dir),
            assets=assets,
        )
        remember_post_scan_writeup_path(shell, artifacts.markdown_path)
        _print_ready_panel(artifacts, count_write_markers(markdown))
        return artifacts
    except Exception as exc:  # noqa: BLE001 - a convenience must never break a scan
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error("Failed to build the writeup spine.")
        return None
    finally:
        _emit_generated(
            {
                "trigger": str(trigger),
                "automatic": is_automatic_trigger(trigger),
                "success": artifacts is not None,
                "stage_count": len(inputs.stages) if inputs else 0,
                "step_count": len(inputs.chain_steps) if inputs else 0,
                "dead_end_count": len(inputs.dead_ends) if inputs else 0,
                "credential_count": len(inputs.credentials) if inputs else 0,
                "flag_count": len(inputs.flags) if inputs else 0,
                "has_diagram": bool(inputs and inputs.chain_steps),
                "non_interactive": bool(is_non_interactive(shell)),
                "tier": tier.tier_name(),
            }
        )


__all__ = [
    "ASSETS_DIRNAME",
    "LITE_CLI_COMMANDS",
    "LITE_REPL_VERBS",
    "PROVENANCE_NOTE",
    "SPINE_FILENAME",
    "WRITEUP_DIRNAME",
    "WRITE_MARKER",
    "AltRoute",
    "ChangeRow",
    "CredentialOrigins",
    "CredentialRow",
    "DeadEnd",
    "FlagRow",
    "ServiceRow",
    "SpineArtifacts",
    "SpineInputs",
    "SpineStage",
    "SpineStep",
    "TechniqueRef",
    "collect_spine_inputs",
    "count_write_markers",
    "credential_origin_label",
    "display_node",
    "generate_writeup_spine",
    "render_spine_markdown",
    "resolve_technique_name",
    "secret_kind_label",
    "technique_for",
]
