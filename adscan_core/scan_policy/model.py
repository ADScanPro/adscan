"""Scan-policy check model: the check record, the safety enums and their wording.

Every client-facing phrase the scan-policy surfaces print about a check's safety
(the environment-change line, the lockout line, the interference line, the
events line, the per-change rollback clause) is worded HERE, once. The web, the
policy export and the report read these tables; no surface words them again.

Two wording rules are structural, not stylistic:

* No environment-change label for a writing technique reads "rolled back
  automatically" without "otherwise listed for manual cleanup". Every revert plan
  in the cleanup layer can end in ``manual_required``.
* Events are stated as what a technique *typically produces when the matching
  audit policy is enabled*. Never as what a client's monitoring will see.

Design: docs/superpowers/specs/2026-11-04-scan-policy-checks-by-family-design.md § 5.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from typing import Any, Mapping

UNDECLARED = "undeclared"

KIND_TECHNIQUE = "technique"
KIND_DETECTION = "detection"
KINDS: frozenset[str] = frozenset({KIND_TECHNIQUE, KIND_DETECTION})

SOURCE_ATTACK_STEP = "attack_step"
SOURCE_FINDING = "finding"
SOURCE_PROBE = "probe"
SOURCE_MODULE = "module"

LOCKED_ALWAYS_RUNS = "always_runs"
LOCKED_NEVER_EXECUTED = "never_executed"

# ── Groups (spec 2026-11-04-scan-policy-two-groups-three-states § 2) ─────────
GROUP_ATTACK_STEPS = "attack_steps"
GROUP_VULNERABILITIES = "vulnerabilities"
GROUP_COLLECTION = "collection"
GROUPS: tuple[str, ...] = (GROUP_COLLECTION, GROUP_ATTACK_STEPS, GROUP_VULNERABILITIES)
#: Groups a policy toggle governs for a technique: attack steps run or not,
#: vulnerabilities are checked or not, collection is collected or not.
GROUP_LABELS: dict[str, str] = {
    GROUP_COLLECTION: "Discovery & Collection",
    GROUP_ATTACK_STEPS: "Attack steps",
    GROUP_VULNERABILITIES: "Vulnerabilities",
}
GROUP_DESCRIPTIONS: dict[str, str] = {
    GROUP_COLLECTION: (
        "What ADscan reads from the directory and the hosts before anything else. "
        "Both other groups build on it."
    ),
    GROUP_ATTACK_STEPS: (
        "Techniques ADscan can execute. Every attack step is mapped whatever its "
        "switch says, and the weakness it relies on is always reported. The switch "
        "decides whether ADscan executes it."
    ),
    GROUP_VULNERABILITIES: (
        "Weaknesses ADscan looks for without attacking them. The switch decides "
        "whether each one is checked."
    ),
}

# ── How a technique produces its result ──────────────────────────────────────
#: A graph step: the collector maps it, the switch decides execution. Off, it
#: stays on its path as "not executed by the policy" and the path stops there.
EXECUTION_GRAPH = "graph"
#: An active technique: it produces something only by running (spraying,
#: timeroasting, poisoning, the share hunt). Off, it is not assessed.
EXECUTION_ACTIVE = "active"
#: A probe: it observes a weakness without exploiting it. Off, it is not checked.
EXECUTION_PROBE = "probe"
#: A detection: it evaluates data already collected.
EXECUTION_DETECTION = "detection"
EXECUTION_KINDS: frozenset[str] = frozenset(
    {EXECUTION_GRAPH, EXECUTION_ACTIVE, EXECUTION_PROBE, EXECUTION_DETECTION}
)

# ── Availability: the three states of a check ────────────────────────────────
AVAILABILITY_LOCKED = "locked"
AVAILABILITY_OPT_IN = "opt_in"
AVAILABILITY_DEFAULT = "default"
AVAILABILITY_VALUES: tuple[str, ...] = (
    AVAILABILITY_DEFAULT,
    AVAILABILITY_OPT_IN,
    AVAILABILITY_LOCKED,
)
AVAILABILITY_LABELS: dict[str, str] = {
    AVAILABILITY_DEFAULT: "On by default",
    AVAILABILITY_OPT_IN: "Off by default",
    AVAILABILITY_LOCKED: "Locked",
}
#: Locked checks say which way they are locked.
LOCKED_STATE_LABELS: dict[str, str] = {
    LOCKED_ALWAYS_RUNS: "Always runs",
    LOCKED_NEVER_EXECUTED: "Never executed by ADscan",
}

# ── Environment change (derived from the declared change kinds) ─────────────
ENV_NONE = "none"
ENV_REVERTED_AUTO = "reverted_auto"
ENV_REVERTED_AT_EXIT = "reverted_at_exit"
#: The change can be undone only by an account allowed to remove it, which the
#: assessment does not normally hold (deleting a computer account created under
#: the machine-account quota, clearing an attribute a relayed computer wrote on
#: itself). Resolved per run from the client's cleanup account
#: (``adscan_core.scan_policy.revert_permission``). Ranked between
#: ``reverted_at_exit`` and ``manual_cleanup``: a policy that allows no manual
#: cleanup runs it only with a verified cleanup account, and never leaves a
#: manual item for it, because the step declines instead.
#: Design: docs/superpowers/specs/2026-11-06-reversible-by-construction-design.md § 3, § 8.
ENV_REVERTED_WHEN_PERMITTED = "reverted_when_permitted"
ENV_MANUAL_CLEANUP = "manual_cleanup"
ENV_NOT_REVERSIBLE = "not_reversible"
ENV_NEVER_EXECUTED = "never_executed"
ENV_NOT_APPLICABLE = "not_applicable"  # detections: they read collected data

ENVIRONMENT_CHANGE_LABELS: dict[str, str] = {
    ENV_NONE: "Read-only. Changes nothing.",
    ENV_REVERTED_AUTO: (
        "Writes to your environment. Rolled back automatically when possible, "
        "otherwise listed for manual cleanup."
    ),
    ENV_REVERTED_AT_EXIT: (
        "Writes to your environment. Kept for the session and rolled back at exit "
        "when possible, otherwise listed for manual cleanup."
    ),
    ENV_REVERTED_WHEN_PERMITTED: (
        "Writes to your environment. Undoing it needs an account allowed to remove "
        "the change, such as a cleanup account you supply. With one, ADscan reverts "
        "it and re-reads to confirm. Without one, a policy that allows no manual "
        "cleanup skips the step, and any other policy lists the object for manual "
        "cleanup."
    ),
    ENV_MANUAL_CLEANUP: (
        "Writes to your environment. Rollback needs a manual step by your team, "
        "and the report names the object."
    ),
    ENV_NOT_REVERSIBLE: (
        "Makes a change that cannot be undone, such as a password reset. The "
        "report names the object."
    ),
    ENV_NEVER_EXECUTED: "Never executed by ADscan.",
    ENV_NOT_APPLICABLE: "Evaluates data already collected and changes nothing.",
    UNDECLARED: "Not declared.",
}

#: Values that count as "writes to the environment" in a policy summary.
WRITING_ENVIRONMENT_CHANGES: frozenset[str] = frozenset(
    {
        ENV_REVERTED_AUTO,
        ENV_REVERTED_AT_EXIT,
        ENV_REVERTED_WHEN_PERMITTED,
        ENV_MANUAL_CLEANUP,
        ENV_NOT_REVERSIBLE,
    }
)

# ── What undoing a change needs (``revert_requires`` / ``revert_rights``) ─────
#: ``revert_requires`` value of a check whose revert needs the client's cleanup
#: account (or another account the assessment does not normally hold).
REVERT_REQUIRES_CLEANUP_ACCOUNT = "cleanup_account"
#: The directory right each such revert needs, one token per change kind.
REVERT_RIGHT_DELETE_COMPUTER_ACCOUNT = "delete_computer_account"
REVERT_RIGHT_WRITE_RBCD_DELEGATION = "write_rbcd_delegation"
REVERT_RIGHT_WRITE_KEY_CREDENTIAL_LINK = "write_key_credential_link"
#: Client-facing name of each right (completes "an account allowed to ...").
REVERT_RIGHT_LABELS: dict[str, str] = {
    REVERT_RIGHT_DELETE_COMPUTER_ACCOUNT: "delete the computer account ADscan created",
    REVERT_RIGHT_WRITE_RBCD_DELEGATION: (
        "restore msDS-AllowedToActOnBehalfOfOtherIdentity on the target computer"
    ),
    REVERT_RIGHT_WRITE_KEY_CREDENTIAL_LINK: (
        "restore msDS-KeyCredentialLink on the target computer"
    ),
}

# ── Lockout risk (declared) ──────────────────────────────────────────────────
LOCKOUT_NOT_APPLICABLE = "not_applicable"
LOCKOUT_NONE = "none"
LOCKOUT_BOUNDED = "bounded"
LOCKOUT_POSSIBLE = "possible"
LOCKOUT_VALUES: frozenset[str] = frozenset(
    {LOCKOUT_NOT_APPLICABLE, LOCKOUT_NONE, LOCKOUT_BOUNDED, LOCKOUT_POSSIBLE, UNDECLARED}
)

LOCKOUT_GUARD_SPRAY_ELIGIBILITY = "spray_eligibility"
LOCKOUT_GUARD_SINGLE_ATTEMPT = "single_attempt_per_candidate"
#: Probes whose negative outcome is a failed sign-in for the scan account
#: (``adscan_internal.services.failing_auth_budget``): each reserves one attempt
#: from the account's real lockout headroom before it sends anything.
LOCKOUT_GUARD_FAILING_AUTH_BUDGET = "failing_auth_budget"
#: Sign-ins as a host-local account (a recovered local credential tried on other
#: hosts). Its lockout counter lives on the host and cannot be read remotely, so
#: the auth attempt guard counts its own failures per local account per host
#: (``adscan_core.auth_attempt_guard.local_realm``) and never re-sends a rejected
#: secret to the same host.
LOCKOUT_GUARD_HOST_LOCAL_ATTEMPTS = "host_local_attempt_count"
#: Recovered passwords verified by requesting a Kerberos ticket as their domain
#: account (the DPAPI secrets dump): at most two candidates per account, each
#: allowed by the auth attempt guard (``adscan_core.auth_attempt_guard``), which in
#: a real environment reads the account's live failed sign-in count and lockout
#: threshold first (``services/lockout_headroom.py``) and never re-sends a
#: rejected secret.
LOCKOUT_GUARD_LIVE_HEADROOM = "live_lockout_headroom"
#: The pre-Windows 2000 computer-account check: one password guess per enabled
#: computer account (the computer's own name), not repeated automatically in the
#: same workspace (``cli/spraying.py::_pre2k_already_attempted``). Computer
#: accounts do not lock out, but a wrong guess still raises the account's failed
#: sign-in count and writes its last-failure time on the DC, so the check sends
#: password attempts and is declared ``bounded``, never ``none``.
LOCKOUT_GUARD_ONE_GUESS_PER_COMPUTER = "one_guess_per_computer_account"
#: Candidates the DPAPI verification tries per account at most. The single source
#: for ``dpapi_credential_processor`` and the client statement below.
RECOVERED_SECRET_CANDIDATES_PER_ACCOUNT = 2

#: Attempts a deliberately-failing probe always leaves unused below the scan
#: account's lockout threshold. The single source for ``failing_auth_budget``
#: and for the client statement below.
FAILING_SIGN_IN_SAFETY_MARGIN = 2

LOCKOUT_GUARD_LABELS: dict[str, str] = {
    LOCKOUT_GUARD_SPRAY_ELIGIBILITY: (
        "a per-account check of recent failed attempts against the lockout threshold"
    ),
    LOCKOUT_GUARD_SINGLE_ATTEMPT: (
        "one attempt per discovered password, never retried after a rejection"
    ),
    LOCKOUT_GUARD_FAILING_AUTH_BUDGET: (
        f"the scan account's lockout budget, which keeps {FAILING_SIGN_IN_SAFETY_MARGIN} "
        "attempts spare below its threshold"
    ),
    LOCKOUT_GUARD_HOST_LOCAL_ATTEMPTS: (
        "one attempt per host for each recovered local credential, never repeated on a "
        "host that rejected it, with failures counted per local account on each host"
    ),
    LOCKOUT_GUARD_LIVE_HEADROOM: (
        f"at most {RECOVERED_SECRET_CANDIDATES_PER_ACCOUNT} recovered passwords per "
        "account, each sent only while the account's live failed sign-in count leaves "
        "the policy's reserve below its lockout threshold"
    ),
    LOCKOUT_GUARD_ONE_GUESS_PER_COMPUTER: (
        "one guess per enabled computer account, not repeated automatically in the "
        "same workspace"
    ),
}

#: Guards whose checks are described by their own sentence instead of the
#: generic "Sends password attempts, limited by {guard}." template.
LOCKOUT_GUARD_STATEMENTS: dict[str, str] = {
    LOCKOUT_GUARD_ONE_GUESS_PER_COMPUTER: (
        "Sends one password guess to each enabled computer account: the computer's "
        "own name, which is the default password of a computer account created as "
        "pre-Windows 2000 compatible. A wrong guess raises that computer account's "
        "failed sign-in count by one and records the time of the failure on it. "
        "Computer accounts are not locked out by it. The guess is not repeated "
        "automatically in the same workspace."
    ),
    LOCKOUT_GUARD_LIVE_HEADROOM: (
        "Verifies each password it recovers by requesting a Kerberos ticket as that "
        f"domain account, trying at most {RECOVERED_SECRET_CANDIDATES_PER_ACCOUNT} "
        "candidates per account. In a real environment ADscan first reads the "
        "account's live failed sign-in count and lockout threshold and sends a "
        "candidate only while the policy's reserve of attempts stays unused below "
        "that threshold. A password the domain rejected is never sent again."
    ),
    LOCKOUT_GUARD_HOST_LOCAL_ATTEMPTS: (
        "Sends password attempts against host-local accounts, which count toward each "
        "host's own local lockout policy: one attempt per host for each recovered local "
        "credential, never repeated on a host that rejected it. A local account's failed "
        "sign-in count cannot be read remotely, so ADscan counts its own failures per "
        "local account on each host."
    ),
    LOCKOUT_GUARD_FAILING_AUTH_BUDGET: (
        "Sends one deliberately invalid sign-in for the scan account to each host it "
        "checks, only while that account has lockout headroom left, and always keeps "
        f"{FAILING_SIGN_IN_SAFETY_MARGIN} attempts spare below its lockout threshold."
    ),
}

LOCKOUT_LABELS: dict[str, str] = {
    LOCKOUT_NOT_APPLICABLE: "Sends no password attempts with unverified passwords.",
    LOCKOUT_NONE: "Sends authentication requests that do not count toward account lockout.",
    LOCKOUT_BOUNDED: "Sends password attempts, limited by {guard}.",
    LOCKOUT_POSSIBLE: "Sends password attempts that can count toward account lockout.",
    UNDECLARED: "Lockout risk not declared.",
}

# ── Service interference (declared) ─────────────────────────────────────────
INTERFERENCE_NONE = "none"
INTERFERENCE_TRANSIENT = "transient"
INTERFERENCE_VALUES: frozenset[str] = frozenset(
    {INTERFERENCE_NONE, INTERFERENCE_TRANSIENT, UNDECLARED}
)
INTERFERENCE_LABELS: dict[str, str] = {
    INTERFERENCE_NONE: "Does not interfere with other systems.",
    INTERFERENCE_TRANSIENT: (
        "Makes servers or clients authenticate to the scanner while it runs."
    ),
    UNDECLARED: "Interference not declared.",
}

# ── Events (the existing detection_event_ids, worded once) ──────────────────
EVENTS_DECLARED = "declared"
EVENTS_NO_NATIVE = "no_native_event"
EVENTS_DETECTION = "detection"

#: Names for the Windows event ids the catalog declares. Only ids whose meaning
#: is unambiguous are named; any other id renders as its number alone.
EVENT_NAMES: dict[str, str] = {
    "4624": "successful logon",
    "4625": "failed logon",
    "4648": "logon with explicit credentials",
    "4656": "handle to an object requested",
    "4662": "operation performed on a directory object",
    "4663": "attempt to access an object",
    "4672": "special privileges assigned to a new logon",
    "4688": "new process created",
    "4698": "scheduled task created",
    "4723": "password change attempted",
    "4724": "password reset attempted",
    "4728": "member added to a security-enabled global group",
    "4732": "member added to a security-enabled local group",
    "4741": "computer account created",
    "4742": "computer account changed",
    "4756": "member added to a security-enabled universal group",
    "4768": "Kerberos ticket-granting ticket requested",
    "4769": "Kerberos service ticket requested",
    "4771": "Kerberos pre-authentication failed",
    "4778": "remote session reconnected",
    "4886": "certificate request received",
    "4887": "certificate request approved and issued",
    "5136": "directory object modified",
    "5140": "network share accessed",
    "5145": "network share object checked for access",
    "7045": "service installed",
}


def _event_phrase(event_id: str) -> str:
    name = EVENT_NAMES.get(event_id)
    return f"{event_id} ({name})" if name else event_id


def events_statement(event_ids: tuple[str, ...], state: str) -> str:
    """Client-facing events line for one check.

    Args:
        event_ids: The declared Windows event ids.
        state: ``declared`` / ``no_native_event`` / ``detection`` / ``undeclared``.

    Returns:
        One sentence. Never a claim about what the client's monitoring sees.
    """
    if state == EVENTS_DETECTION:
        return "Reads data already collected and produces no additional events."
    if state == EVENTS_NO_NATIVE:
        return "Typically produces no Windows event of its own."
    if state == EVENTS_DECLARED and event_ids:
        joined = ", ".join(_event_phrase(e) for e in event_ids)
        return (
            f"Typically produces Windows events {joined} when the matching audit "
            "policy is enabled."
        )
    return "Events not declared yet."


def lockout_statement(risk: str, guard: str) -> str:
    """Client-facing lockout line for one check."""
    template = LOCKOUT_LABELS.get(risk, LOCKOUT_LABELS[UNDECLARED])
    if risk == LOCKOUT_BOUNDED:
        if guard in LOCKOUT_GUARD_STATEMENTS:
            return LOCKOUT_GUARD_STATEMENTS[guard]
        return template.format(guard=LOCKOUT_GUARD_LABELS.get(guard, "a named guard"))
    return template


# ── Rollback clauses, per lifecycle class (classes derive from the ledger) ──
#: Keyed by ``safeguard_profile`` rollback class tokens. ``{what}`` is the
#: change kind's client display name (``cleanup_taxonomy.KIND_DISPLAY``).
ROLLBACK_CLAUSES: dict[str, str] = {
    "auto_verified": (
        "{what}, removed at the end and re-read to confirm, or listed for manual "
        "cleanup if that fails."
    ),
    "auto_unconfirmed": (
        "{what}, removed at the end of the step, or listed for manual cleanup if "
        "that fails."
    ),
    "host_artifact": (
        "{what}, deleted from the host at the end, or listed for manual cleanup if "
        "that fails."
    ),
    "operator_confirmed": (
        "{what}, kept for the session and removed at exit, or listed for manual "
        "cleanup if that fails."
    ),
    "never_reverted": "{what}, left in place and listed in the report for your team to remove.",
    "cleanup_account": (
        "{what}, removed and re-read to confirm with an account allowed to remove it, "
        "such as the cleanup account you supply, otherwise listed for your team to "
        "remove."
    ),
    "unsettled": (
        "{what}, removed by the step at the end and listed for you to confirm by hand."
    ),
    "password_changed": (
        "{what}. The original password cannot be restored, and the report names "
        "the account so your team can set a new one."
    ),
    "ca_private_key_exfiltrated": (
        "{what}, which cannot be undone. The report names the CA so its key can "
        "be renewed."
    ),
    "issued_certificate": (
        "{what}, revoked on your CA and confirmed by re-reading the CA database "
        "when the run holds an account allowed to revoke it, or listed with its "
        "serial number for your team to revoke."
    ),
    "forged_certificate": (
        "{what}, which your CA cannot revoke because it never issued it. The report "
        "names the CA so its key can be renewed."
    ),
}

#: Change kinds whose rollback line is worded per kind rather than per class.
KIND_SPECIFIC_ROLLBACK_CLAUSES: frozenset[str] = frozenset(
    {"password_changed", "ca_private_key_exfiltrated", "issued_certificate", "forged_certificate"}
)


@dataclass(frozen=True)
class CheckDefinition:
    """One check in the registry. Built from ``registry_data`` dicts.

    Field meanings follow the design spec § 5.1. Every tuple field is a tuple of
    strings; ``requires`` uses any-of semantics for detections (``evidence``)
    and all-of for techniques.
    """

    check_id: str
    kind: str
    source: str
    family: str
    title: str
    selectable: bool
    locked_state: str
    environment_change: str
    change_scope: tuple[str, ...]
    rollback_detail: str
    lockout_risk: str
    lockout_guard: str
    service_interference: str
    event_ids: tuple[str, ...]
    events_declared: str
    relations: tuple[str, ...] = ()
    finding_keys: tuple[str, ...] = ()
    subphases: tuple[str, ...] = ()
    phases: tuple[str, ...] = ()
    cve_ids: tuple[str, ...] = ()
    jobs: tuple[str, ...] = ()
    requires: tuple[str, ...] = ()
    requires_any: tuple[str, ...] = ()
    related: tuple[str, ...] = ()
    mitre: tuple[str, ...] = ()
    reads_credential_material: bool = False
    introduced_in: int = 1
    group: str = ""
    execution: str = ""
    availability: str = ""
    owned_by: tuple[str, ...] = ()
    owns: tuple[str, ...] = ()
    #: ``cleanup_account`` when undoing what the check writes needs an account
    #: the assessment does not normally hold; ``revert_rights`` names the right
    #: (``REVERT_RIGHT_*``). Recorded on every check that writes such a change,
    #: whatever its ``environment_change``; only ``reverted_when_permitted``
    #: checks are resolved against it per run.
    revert_requires: str = ""
    revert_rights: tuple[str, ...] = ()

    _TUPLE_FIELDS = (
        "change_scope", "event_ids", "relations", "finding_keys", "subphases",
        "phases", "cve_ids", "jobs", "requires", "requires_any", "related", "mitre",
        "owned_by", "owns", "revert_rights",
    )

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "CheckDefinition":
        """Build a definition from one ``registry_data.CHECKS`` entry."""
        values = dict(data)
        for name in cls._TUPLE_FIELDS:
            values[name] = tuple(values.get(name) or ())
        return cls(**values)

    def to_mapping(self) -> dict[str, Any]:
        """Return the JSON-ready mapping (the API and snapshot shape)."""
        out: dict[str, Any] = {}
        for name in (f.name for f in fields(self)):
            value = getattr(self, name)
            out[name] = list(value) if isinstance(value, tuple) else value
        return out

    @property
    def is_technique(self) -> bool:
        return self.kind == KIND_TECHNIQUE

    @property
    def is_paired_detection(self) -> bool:
        """A detection reported with the attack step or probe that owns it."""
        return self.kind == KIND_DETECTION and bool(self.owned_by)

    @property
    def is_attack_step(self) -> bool:
        """A technique of the Attack steps group (graph step or active technique)."""
        return self.kind == KIND_TECHNIQUE and self.group == GROUP_ATTACK_STEPS

    def safety_lines(self) -> dict[str, str]:
        """The four client-facing safety lines for this check."""
        return {
            "environment_change": ENVIRONMENT_CHANGE_LABELS.get(
                self.environment_change, ENVIRONMENT_CHANGE_LABELS[UNDECLARED]
            ),
            "lockout": lockout_statement(self.lockout_risk, self.lockout_guard),
            "interference": INTERFERENCE_LABELS.get(
                self.service_interference, INTERFERENCE_LABELS[UNDECLARED]
            ),
            "events": events_statement(self.event_ids, self.events_declared),
        }


@dataclass(frozen=True)
class CheckRegistryData:
    """The raw generated payload (see ``registry_data``)."""

    version: int
    checks: tuple[Mapping[str, Any], ...]
    retired: Mapping[str, str | None] = field(default_factory=dict)
    non_check_relations: tuple[str, ...] = ()


__all__ = (
    "AVAILABILITY_DEFAULT",
    "AVAILABILITY_LABELS",
    "AVAILABILITY_LOCKED",
    "AVAILABILITY_OPT_IN",
    "AVAILABILITY_VALUES",
    "EXECUTION_ACTIVE",
    "EXECUTION_DETECTION",
    "EXECUTION_GRAPH",
    "EXECUTION_KINDS",
    "EXECUTION_PROBE",
    "GROUPS",
    "GROUP_ATTACK_STEPS",
    "GROUP_COLLECTION",
    "GROUP_DESCRIPTIONS",
    "GROUP_LABELS",
    "GROUP_VULNERABILITIES",
    "LOCKED_STATE_LABELS",
    "CheckDefinition",
    "CheckRegistryData",
    "ENVIRONMENT_CHANGE_LABELS",
    "EVENT_NAMES",
    "INTERFERENCE_LABELS",
    "KINDS",
    "FAILING_SIGN_IN_SAFETY_MARGIN",
    "LOCKOUT_GUARD_FAILING_AUTH_BUDGET",
    "LOCKOUT_GUARD_HOST_LOCAL_ATTEMPTS",
    "LOCKOUT_GUARD_LIVE_HEADROOM",
    "LOCKOUT_GUARD_ONE_GUESS_PER_COMPUTER",
    "RECOVERED_SECRET_CANDIDATES_PER_ACCOUNT",
    "LOCKOUT_GUARD_LABELS",
    "LOCKOUT_GUARD_STATEMENTS",
    "LOCKOUT_LABELS",
    "LOCKOUT_VALUES",
    "INTERFERENCE_VALUES",
    "REVERT_REQUIRES_CLEANUP_ACCOUNT",
    "REVERT_RIGHT_DELETE_COMPUTER_ACCOUNT",
    "REVERT_RIGHT_LABELS",
    "REVERT_RIGHT_WRITE_KEY_CREDENTIAL_LINK",
    "REVERT_RIGHT_WRITE_RBCD_DELEGATION",
    "ROLLBACK_CLAUSES",
    "UNDECLARED",
    "WRITING_ENVIRONMENT_CHANGES",
    "events_statement",
    "lockout_statement",
)
