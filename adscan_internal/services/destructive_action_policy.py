"""Destructive-action guardrail — single source of truth (safety-critical).

ADscan is an authorized assessment tool. This module is a HARD REFUSAL layer:
it classifies Active Directory relationship steps that would DISRUPT a client's
production systems and lets every execution gate refuse to run them. It strictly
NARROWS what ADscan will execute — it adds no offensive capability.

Two axes are expressed by :class:`DestructiveVerdict`:

- ``hard_blocked`` — NEVER executable, in ANY mode (interactive, CTF, or
  non-interactive ``adscan ci`` / web). A pentester cannot force it.
- ``opt_in_only`` — disabled by default; runs only on an explicit interactive
  operator opt-in and is skipped in non-interactive mode.

The single classifier :func:`classify_destructive` is consumed by the execution
gates (``run_exploit_force_change_password``, the ACE-step dispatcher, the
attack-path executor) and by the graph stamping so the display and the executor
never disagree about what is refused.

This module is also the single source of truth for the CLIENT-FACING wording of
why a step did not execute — :func:`non_execution_statement` and the constants
behind it. A step that did not run has exactly two honest client statements: a
deliberate safety abstention (only ever a hard-blocked step, keyed on
:data:`DANGEROUS_DESTRUCTIVE_MARKER`) or "mapped but not exercised". Everything
else — the catalog's engineering-register ``support_reason`` in particular — is
screened out by :func:`is_internal_engineering_reason` before it can reach a
deliverable.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from adscan_core.reporting.execution_status import (
    DANGEROUS_DESTRUCTIVE_MARKER,
    step_is_safety_abstention as _shared_step_is_safety_abstention,
)

__all__ = [
    "DestructiveVerdict",
    "classify_destructive",
    "opt_in_default_for_environment",
    "skipped_by_default_in_audit",
    "OPT_IN_PREAPPROVED_ENVIRONMENTS",
    "HARD_BLOCKED_TARGET_VARIANTS",
    "client_safe_step_reason",
    "is_machine_account_name",
    "classify_password_dependent_account",
    "PASSWORD_DEPENDENT_ACCOUNT_CLASSES",
    "PROTECTED_ACCOUNT_COMPUTER",
    "PROTECTED_ACCOUNT_KRBTGT",
    "PROTECTED_ACCOUNT_MANAGED_SERVICE",
    "PROTECTED_ACCOUNT_DIRECTORY_SYNC",
    "PROTECTED_ACCOUNT_CLASS_KEY",
    "step_target_identity",
    "relation_safety_note",
    "is_internal_engineering_reason",
    "non_execution_statement",
    "safety_abstention_statement",
    "DANGEROUS_DESTRUCTIVE_MARKER",
    "GENERIC_DISRUPTION_CLAUSE",
    "NOT_EXERCISED_STATEMENT",
    "SAFETY_ABSTENTION_LABEL",
    "SAFETY_ABSTENTION_LEAD",
    "path_is_safety_abstention",
    "step_is_safety_abstention",
    "safety_abstention_position",
    "SAFETY_ABSTENTION_TERMINAL",
    "SAFETY_ABSTENTION_MID_CHAIN",
    "path_safety_abstention_reason",
    "path_safety_abstention_relations",
    "safety_abstention_disruption_clause",
    "safety_abstention_notes",
]

# Graph-edge marker (``blocked_kind``) stamped on an edge whose step ADscan
# hard-refused for safety. It marks EVERY safety abstention — a destructive reset
# (ForceChangePassword on a computer) OR a disruptive technique (Zerologon, NoPac,
# PrintNightmare, DNSAdmins abuse) — routed uniformly through the single
# :func:`classify_destructive` classifier. The client-facing render keys off this
# marker to place the path in the "Not executed for safety" bucket.
#
# ADscan is an EXPOSURE-VALIDATION product, not a security-validation product: it
# proves a path EXISTS but never attributes a non-execution to a defensive control
# (EDR/AV/MDI) it cannot observe remotely with certainty. There is therefore NO
# "an environment control blocked us" marker — an execution that did not complete
# is ``attempted`` (neutral), never a claim that a client control stopped it.
# Declared once in ``adscan_core.reporting.execution_status`` (imported above), so
# the web ingestion reads the same marker when it stores a path's status.

# Client-facing display label + framing for a path/step ADscan deliberately did
# not execute for safety. These are consumed verbatim by the PDF report bucket
# and the attack-step narrative, and MIRRORED by the web platform (adscan_web
# frontend, which runs as a separate process and cannot import this module). A
# contract test keeps the two in sync so report and web say the same thing.
SAFETY_ABSTENTION_LABEL = "Not executed for safety"
SAFETY_ABSTENTION_LEAD = (
    "This attack path is real and exploitable. ADscan deliberately chose not to "
    "execute this step to avoid disrupting production systems."
)

# Client-facing statement for a step that simply was NOT run — the honest
# alternative to the safety framing above, and the default for every
# non-execution that is not a hard-blocked safety abstention.
#
# The distinction is not cosmetic: claiming a protective motive for a step
# ADscan did not attempt misrepresents the engagement, and stating WHY ADscan
# did not attempt it ("not implemented yet") is a capability-gap confession that
# belongs in the engineering log, never in a priced deliverable. What is true
# and useful to the reader is that the step was derived from the environment's
# own configuration and left unexercised, so the finding still stands on the
# evidence that produced it.
NOT_EXERCISED_STATEMENT = (
    "This step was identified from the environment's configuration and was not "
    "exercised during this engagement."
)

# Statically disruptive techniques ADscan refuses to execute in every mode.
# Kept in lockstep with the ``policy_blocked`` catalog entries; the client-safe
# reason is sourced from that catalog (see ``_hard_blocked_reason``) so this
# stays a single source of truth rather than a second hardcoded copy.
_HARD_BLOCKED_RELATIONS: frozenset[str] = frozenset(
    {"zerologon", "nopac", "printnightmare", "dnsadminabuse"}
)

_FCP_RELATION = "forcechangepassword"
_ALL_EXTENDED_RIGHTS_RELATION = "allextendedrights"
#: Relations whose execution, on a user-class target, IS a password reset.
_PASSWORD_RESET_RELATIONS: frozenset[str] = frozenset(
    {_FCP_RELATION, _ALL_EXTENDED_RIGHTS_RELATION}
)

# ── Workspace-type consent defaults for opt-in-only steps ────────────────────
# An ``opt_in_only`` step does not run unless the operator says yes, and the
# centralized prompt helpers AUTO-RESOLVE to the prompt's default when nobody is
# at the keyboard (``adscan ci``, the web PoV worker). So the DEFAULT is what
# decides whether an unattended run performs the action at all, and it depends
# on the scan policy's environment: a lab target is disposable, a real
# environment is not.
#
# This is the SSOT for that rule. ``run_exploit_force_change_password`` (the
# single ForceChangePassword consent choke point) consumes it, and the
# customer-facing safeguard matrix derives its "not executed in an audit"
# statement from it, so the document and the gate can never disagree.
OPT_IN_PREAPPROVED_ENVIRONMENTS: frozenset[str] = frozenset({"lab"})


def opt_in_default_for_environment(environment: str | None) -> bool:
    """Return the consent DEFAULT for an opt-in-only step under a policy's environment.

    Args:
        environment: The scan policy's environment (``"lab"`` / ``"real"``;
            ``None`` when unknown, read as a real environment).

    Returns:
        True when the step is pre-approved for that environment (an unattended
        run performs it), False when the default is to decline (an unattended
        run SKIPS it, and an interactive operator is asked with the answer
        preset to no).
    """
    return str(environment or "").strip().lower() in OPT_IN_PREAPPROVED_ENVIRONMENTS


def skipped_by_default_in_audit(relation: str, target_kind: str | None) -> bool:
    """Whether this step is declined by default in an ``audit`` workspace.

    True only for a step that is opt-in-only AND not pre-approved for an audit
    engagement, i.e. one ADscan does not perform on its own against a real
    client: unattended it is skipped outright, and interactively the operator
    has to override a prompt that defaults to no.
    """
    verdict = classify_destructive(relation, target_kind)
    return verdict.opt_in_only and not opt_in_default_for_environment("real")

# Client-facing reasons — no offensive-tool names (they flow into deliverables).
_FCP_COMPUTER_REASON = (
    "Resetting a computer account password would disrupt that host; "
    "ADscan does not execute it."
)
_FCP_USER_REASON = (
    "Resetting a user's password is disruptive and irreversible, so ADscan "
    "only executes it with explicit operator opt-in."
)
_GENERIC_HARD_BLOCK_REASON = (
    "This technique is disruptive and ADscan does not execute it automatically."
)

# ── Accounts whose password a system depends on ──────────────────────────────
# A password reset is refused in EVERY mode (no scan policy can enable it) when
# the target is an account whose current password a running system depends on
# AND whose previous value ADscan cannot put back afterwards. Four classes:
#
# * a computer account: the host holds the password in its own secure channel;
# * ``krbtgt`` (RID 502) and the per-RODC ``krbtgt_<n>`` accounts: every Kerberos
#   ticket in the domain is encrypted with their key, the previous key is never
#   known to ADscan, and a second reset (or one soon after the client's own) voids
#   every ticket in the domain at once;
# * a managed service account (gMSA, sMSA, dMSA): the directory generates the
#   password and the services running under it depend on that value;
# * an Entra ID / Azure AD Connect sync account (``MSOL_<hex>``): the sync
#   service stores its password, so a reset stops directory synchronization.
#
# The class tokens double as ``target_kind`` values, which is how the scan-policy
# registry and the safeguard matrix ask the classifier about a class without a
# graph node in hand.
PROTECTED_ACCOUNT_COMPUTER = "computer"
PROTECTED_ACCOUNT_KRBTGT = "krbtgt"
PROTECTED_ACCOUNT_MANAGED_SERVICE = "managed_service_account"
PROTECTED_ACCOUNT_DIRECTORY_SYNC = "directory_sync"

#: Precedence order: the most specific class wins (an sMSA / dMSA is also of
#: object class ``computer``, and its accurate reason is the managed one).
PASSWORD_DEPENDENT_ACCOUNT_CLASSES: tuple[str, ...] = (
    PROTECTED_ACCOUNT_KRBTGT,
    PROTECTED_ACCOUNT_MANAGED_SERVICE,
    PROTECTED_ACCOUNT_DIRECTORY_SYNC,
    PROTECTED_ACCOUNT_COMPUTER,
)

#: The step/edge ``details`` key a stamped safety abstention records its class
#: under, so a later consumer (report clause, executor backstop) reads the class
#: the graph stamp decided instead of re-deriving it from fewer signals.
PROTECTED_ACCOUNT_CLASS_KEY = "protected_account_class"

_FCP_KRBTGT_REASON = (
    "The krbtgt account encrypts every Kerberos ticket in the domain. A reset "
    "cannot be undone because its previous key cannot be restored, and a second "
    "reset, or one soon after a reset by your own team, invalidates every ticket "
    "in the domain at once. ADscan does not execute it. Whoever holds this right "
    "controls the domain. You can confirm who holds it by reading the account's "
    "ACL with Get-Acl."
)
_FCP_MANAGED_SERVICE_REASON = (
    "Active Directory generates and rotates the password of a managed service "
    "account, and the services running under it depend on that value. Resetting "
    "it would break them, and the previous value cannot be restored. ADscan does "
    "not execute it. You can confirm who holds this right by reading the "
    "account's ACL with Get-Acl."
)
_FCP_DIRECTORY_SYNC_REASON = (
    "This account carries directory synchronization with Entra ID, and the sync "
    "service stores its password. Resetting it would stop synchronization until "
    "the service is reconfigured, and the previous password cannot be restored. "
    "ADscan does not execute it. You can confirm who holds this right by reading "
    "the account's ACL with Get-Acl."
)

_FCP_REASON_BY_CLASS: dict[str, str] = {
    PROTECTED_ACCOUNT_COMPUTER: _FCP_COMPUTER_REASON,
    PROTECTED_ACCOUNT_KRBTGT: _FCP_KRBTGT_REASON,
    PROTECTED_ACCOUNT_MANAGED_SERVICE: _FCP_MANAGED_SERVICE_REASON,
    PROTECTED_ACCOUNT_DIRECTORY_SYNC: _FCP_DIRECTORY_SYNC_REASON,
}

#: Per-TARGET hard blocks of a relation that is otherwise executable: the
#: ``(relation, target class)`` pairs :func:`classify_destructive` refuses in
#: every mode, with the client-facing reason. The scan-policy registry builder
#: turns each into a locked "never executed" check, so the policy a client signs
#: lists it beside the statically blocked techniques. Kept as data next to the
#: rule that enforces it; a unit test asserts every pair here is refused by
#: :func:`classify_destructive`.
HARD_BLOCKED_TARGET_VARIANTS: dict[tuple[str, str], str] = {
    (_FCP_RELATION, account_class): reason
    for account_class, reason in _FCP_REASON_BY_CLASS.items()
}

# Authored, client-facing reasons for each statically hard-blocked technique.
# Deep and specific (the disruption mechanism a CISO's sysadmin will recognize),
# free of offensive-tool names (they flow verbatim into the PDF report and the web
# platform). These are the specific "why" that :func:`safety_abstention_statement`
# appends to the fixed lead ("…real and exploitable… ADscan deliberately chose not
# to execute…"), so they state the MECHANISM, not the abstention itself.
_HARD_BLOCKED_REASONS: dict[str, str] = {
    "zerologon": (
        "Exploiting this domain-controller authentication weakness resets the "
        "domain controller's own machine-account password to an empty value. That "
        "severs the controller from the domain and can take Active Directory "
        "offline for every user."
    ),
    "nopac": (
        "This technique creates and manipulates a machine account to impersonate a "
        "domain controller. Executing it leaves rogue accounts behind and can "
        "disrupt domain authentication."
    ),
    "printnightmare": (
        "This technique abuses the print spooler service to run code on the target "
        "with system privileges. Executing it can crash the spooler service or the "
        "host itself."
    ),
    "dnsadminabuse": (
        "This technique loads attacker-controlled code into the DNS service running "
        "on the domain controller. Executing it can crash DNS and break name "
        "resolution across the whole domain."
    ),
}

# Short disruption CLAUSES, one per hard-blocked technique. These are the verb
# phrase that completes "Running {it} would have ..." in the executive summary,
# where the full authored sentence above is too long to carry. Client-facing
# prose: name the disruption the client's own sysadmin would recognise, never a
# tool and never ADscan's internals.
_HARD_BLOCKED_DISRUPTION_CLAUSES: dict[str, str] = {
    "zerologon": (
        "severed a domain controller from the domain and taken Active Directory "
        "offline for every user"
    ),
    "nopac": "disrupted domain authentication and left rogue machine accounts behind",
    "printnightmare": "crashed the print spooler service or the host running it",
    "dnsadminabuse": "disrupted name resolution for your production domain",
    _FCP_RELATION: (
        "broken the domain membership of the production host whose account "
        "password it resets"
    ),
    # Per-target variants of the password reset, keyed ``<relation>.<class>``
    # (see :func:`_abstention_technique_key`). The bare relation key above stays
    # the computer case, which is what a step stamped before the class existed
    # always was.
    f"{_FCP_RELATION}.{PROTECTED_ACCOUNT_KRBTGT}": (
        "invalidated Kerberos tickets across the whole domain"
    ),
    f"{_FCP_RELATION}.{PROTECTED_ACCOUNT_MANAGED_SERVICE}": (
        "broken the services that run under a managed service account"
    ),
    f"{_FCP_RELATION}.{PROTECTED_ACCOUNT_DIRECTORY_SYNC}": (
        "stopped directory synchronization with Entra ID"
    ),
}

#: The truthful fallback when the abstained techniques are mixed, or when the
#: technique is one this table does not name specifically. Deliberately vague
#: about the mechanism rather than guessing one: a wrong mechanism in a client
#: deliverable is worse than a general one.
GENERIC_DISRUPTION_CLAUSE = "disrupted production services"


@dataclass(frozen=True, slots=True)
class DestructiveVerdict:
    """Classification of a relationship step against the destructive-action policy.

    Attributes:
        hard_blocked: The step is NEVER executable, in any mode.
        opt_in_only: The step is disabled by default and runs only on an explicit
            interactive operator opt-in (skipped in non-interactive mode).
        client_safe_reason: A client-facing sentence explaining the decision,
            free of offensive-tool names (safe to surface in deliverables).
    """

    hard_blocked: bool
    opt_in_only: bool
    client_safe_reason: str


def is_machine_account_name(name: str | None) -> bool:
    """Return True when a principal name denotes a machine/computer account.

    Windows machine accounts have a ``$``-suffixed sAMAccountName. This is an
    independent signal from the graph node ``kind`` — either is sufficient to
    treat a target as a computer for the guardrail.
    """
    return bool(name) and str(name).strip().endswith("$")


def _is_computer_target(target_kind: str | None) -> bool:
    """Return True when ``target_kind`` denotes a computer/machine target.

    Accepts a graph node kind (``"Computer"``/``"computer"``/``"machine"``) or a
    ``$``-suffixed value (a sAMAccountName passed in place of a kind), so a
    machine target is detected from either signal.
    """
    value = (target_kind or "").strip().lower()
    if not value:
        return False
    if value.endswith("$"):
        return True
    return value in {"computer", "machine"}


def _hard_blocked_reason(relation: str) -> str:
    """Return the client-safe reason for a statically hard-blocked technique.

    Prefers the authored, client-facing wording in :data:`_HARD_BLOCKED_REASONS`
    (deep + deliverable-safe). Falls back to the catalog ``support_reason`` via
    the support registry, then to a generic sentence, so the guardrail never
    raises even if the registry is unavailable.
    """
    authored = _HARD_BLOCKED_REASONS.get(relation)
    if authored:
        return authored
    try:
        from adscan_internal.services.attack_step_support_registry import (
            POLICY_BLOCKED_RELATIONS,
        )

        reason = POLICY_BLOCKED_RELATIONS.get(relation)
        if reason:
            return str(reason)
    except Exception:  # noqa: BLE001 - best-effort; never break the guardrail.
        pass
    return _GENERIC_HARD_BLOCK_REASON


#: RID 502 is the domain's own ``krbtgt``. The per-RODC KDC accounts get an
#: ordinary RID, so they are recognised by the directory's other signals below.
_KRBTGT_RID = "502"
#: The sAMAccountNames the directory itself reserves for the KDC accounts: the
#: domain ``krbtgt`` and the per-RODC ``krbtgt_<number>`` it creates when an
#: RODC is promoted. Accepted as a signal on their own because they are assigned
#: by Active Directory, not chosen by an administrator, and because the decision
#: they feed is a REFUSAL: a false match costs one reset ADscan does not run,
#: while a miss costs every Kerberos ticket in the domain.
_KRBTGT_SAM_RE = re.compile(r"\Akrbtgt(?:_\d+)?\Z", re.IGNORECASE)
#: The delegated managed service account (Windows Server 2025). Read here rather
#: than added to ``adscan_core.kerberos_roasting.MANAGED_SERVICE_ACCOUNT_OBJECT_CLASSES``
#: because that tuple also builds a live LDAP filter, and a filter naming an
#: object class the DC's schema lacks must not be risked for this decision.
_DELEGATED_MSA_OBJECT_CLASS = "msds-delegatedmanagedserviceaccount"
_DELEGATED_MSA_ACCOUNT_TYPES = frozenset({"dmsa"})


def _lower_keys(mapping: Mapping[str, Any]) -> dict[str, Any]:
    """Return ``mapping`` with case-folded string keys (first occurrence wins)."""
    folded: dict[str, Any] = {}
    for key, value in mapping.items():
        folded.setdefault(str(key).strip().lower(), value)
    return folded


def _target_properties(target: Mapping[str, Any] | None) -> dict[str, Any]:
    """Flatten a graph node, a step identity or raw props into one mapping.

    Accepts a persisted attack-graph node (``kind`` / ``label`` / ``objectId`` at
    the top, attributes under ``properties``), the flat identity
    :func:`step_target_identity` builds from a step's details, or LDAP-shaped
    properties. Keys are case-folded; node-level keys fill gaps the properties
    leave.
    """
    if not isinstance(target, Mapping):
        return {}
    props: dict[str, Any] = {}
    nested = target.get("properties")
    if isinstance(nested, Mapping):
        props.update(_lower_keys(nested))
    for key, value in _lower_keys(target).items():
        if key == "properties":
            continue
        props.setdefault(key, value)
    kind = props.get("kind") or props.get("type") or props.get("labels")
    if isinstance(kind, (list, tuple)):
        kind = next((str(item) for item in kind if str(item).strip()), "")
    props["kind"] = str(kind or "").strip()
    return props


def _identity_samaccountname(props: Mapping[str, Any]) -> str:
    """Return the bare sAMAccountName a target carries, or ``""``.

    Falls back to the display label (``NAME@REALM``) only for the account part,
    which is how a step names its target when the graph node is not in hand.
    """
    for key in ("samaccountname", "target_samaccountname", "name", "label", "to"):
        raw = str(props.get(key) or "").strip()
        if not raw:
            continue
        if "\\" in raw:
            raw = raw.split("\\", 1)[1]
        if "@" in raw:
            raw = raw.split("@", 1)[0]
        raw = raw.strip()
        if raw:
            return raw
    return ""


def _identity_sid(props: Mapping[str, Any]) -> str:
    for key in ("objectid", "objectsid", "target_sid", "sid"):
        raw = str(props.get(key) or "").strip().upper()
        if raw.startswith("S-1-"):
            return raw
    return ""


def _as_text_tuple(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,) if value.strip() else ()
    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(str(item) for item in value if str(item).strip())
    return ()


def _is_krbtgt_account(props: Mapping[str, Any]) -> bool:
    sid = _identity_sid(props)
    if sid.startswith("S-1-5-21-") and sid.rsplit("-", 1)[-1] == _KRBTGT_RID:
        return True
    # The per-RODC KDC account carries the back-link to its RODC and its own
    # secondary-KDC number; either is the directory saying "this is a krbtgt".
    if props.get("msds-krbtgtlinkbl") or props.get("msds-secondarykrbtgtnumber"):
        return True
    return bool(_KRBTGT_SAM_RE.match(_identity_samaccountname(props)))


def _is_managed_service_account(props: Mapping[str, Any]) -> bool:
    from adscan_core.kerberos_roasting import (  # noqa: PLC0415
        AccountSignals,
        is_managed_service_account,
    )

    flat = dict(props)
    dn = str(props.get("distinguishedname") or props.get("target_dn") or "")
    if dn:
        flat["distinguishedname"] = dn
    if is_managed_service_account(AccountSignals.from_properties(flat)):
        return True
    account_type = str(props.get("account_type") or "").strip().lower()
    if account_type in _DELEGATED_MSA_ACCOUNT_TYPES:
        return True
    object_classes = _as_text_tuple(
        props.get("objectclasses") or props.get("objectclass")
    )
    return any(
        value.strip().lower() == _DELEGATED_MSA_OBJECT_CLASS for value in object_classes
    )


def _is_directory_sync_account(props: Mapping[str, Any]) -> bool:
    """Entra ID sync account, through the ONE detection SSOT.

    ``compromise_class.is_control_plane_sync_account`` returns CONFIRMED (the
    ``MSOL_<12 hex>`` name AND the AAD Connect description) or AMBIGUOUS (the
    name alone). Both refuse here: the name is a fixed, installer-generated
    pattern, and the decision it feeds is a refusal, so the uncertain case falls
    on the side that cannot break synchronization.
    """
    try:
        from adscan_internal.services.compromise_class import (  # noqa: PLC0415
            SyncAccountState,
            is_control_plane_sync_account,
        )
    except Exception:  # noqa: BLE001 - a trimmed deployment keeps the other checks.
        return False
    description = props.get("description")
    state = is_control_plane_sync_account(
        samaccountname=_identity_samaccountname(props),
        description=description if isinstance(description, str) else None,
    )
    return state is not SyncAccountState.NONE


def classify_password_dependent_account(
    target_kind: str | None = None,
    target: Mapping[str, Any] | None = None,
) -> str:
    """Return the class of account whose password ADscan must never reset, or "".

    The ONE classifier for "a running system depends on this account's password
    and ADscan could not restore it after a reset". Every password-setting path
    reaches it through :func:`classify_destructive`.

    Signals, all structural and read from whatever the caller holds:

    * krbtgt: a domain SID ending in RID 502, the RODC back-link
      ``msDS-KrbTgtLinkBl`` / ``msDS-SecondaryKrbTgtNumber``, or the reserved
      ``krbtgt`` / ``krbtgt_<n>`` sAMAccountName (see :data:`_KRBTGT_SAM_RE`).
    * managed service account: ``adscan_core.kerberos_roasting.is_managed_service_account``
      (``is_gmsa`` / ``account_type`` / ``msDS-*ManagedServiceAccount`` object
      class / the ``CN=Managed Service Accounts`` DN) plus the dMSA object class.
    * Entra ID sync account: ``compromise_class.is_control_plane_sync_account``.
    * computer: a ``Computer``/``machine`` kind, a computer object class, or a
      ``$``-suffixed sAMAccountName.

    Args:
        target_kind: The target's graph node kind, a ``$``-suffixed name, or one
            of the class tokens (``"krbtgt"``, ``"managed_service_account"``,
            ``"directory_sync"``, ``"computer"``) when the caller asks about a
            class rather than an object.
        target: Anything describing the object: a graph node, a step identity
            (:func:`step_target_identity`) or flat / LDAP-shaped properties. A
            class already stamped under :data:`PROTECTED_ACCOUNT_CLASS_KEY` is
            honoured as is.

    Returns:
        One of :data:`PASSWORD_DEPENDENT_ACCOUNT_CLASSES`, or ``""``.
    """
    kind_token = str(target_kind or "").strip().lower()
    if kind_token in PASSWORD_DEPENDENT_ACCOUNT_CLASSES:
        return kind_token
    props = _target_properties(target)
    stamped = str(props.get(PROTECTED_ACCOUNT_CLASS_KEY) or "").strip().lower()
    if stamped in PASSWORD_DEPENDENT_ACCOUNT_CLASSES:
        return stamped
    if props:
        if _is_krbtgt_account(props):
            return PROTECTED_ACCOUNT_KRBTGT
        if _is_managed_service_account(props):
            return PROTECTED_ACCOUNT_MANAGED_SERVICE
        if _is_directory_sync_account(props):
            return PROTECTED_ACCOUNT_DIRECTORY_SYNC
    if _is_computer_target(target_kind):
        return PROTECTED_ACCOUNT_COMPUTER
    if props:
        node_kind = props.get("kind") or props.get("target_kind")
        if _is_computer_target(str(node_kind or "")):
            return PROTECTED_ACCOUNT_COMPUTER
        object_classes = _as_text_tuple(
            props.get("objectclasses") or props.get("objectclass")
        )
        if any(value.strip().lower() == "computer" for value in object_classes):
            return PROTECTED_ACCOUNT_COMPUTER
        if is_machine_account_name(_identity_samaccountname(props)):
            return PROTECTED_ACCOUNT_COMPUTER
    return ""


def step_target_identity(details: Mapping[str, Any] | None) -> dict[str, Any]:
    """Build the classifier's target identity from a step's ``details``.

    The report pipeline stamps the target's real identifiers on every step
    (``target_samaccountname`` / ``target_dn`` / ``target_sid`` /
    ``target_kind``, see ``attack_graph_core._stamp_step_identity``) and a graph
    stamp may already carry the class. This turns them into the flat shape
    :func:`classify_password_dependent_account` reads, so a consumer holding only
    a step decides from the same signals as one holding the node.
    """
    if not isinstance(details, Mapping):
        return {}
    identity: dict[str, Any] = {
        "samaccountname": details.get("target_samaccountname") or "",
        "distinguishedname": details.get("target_dn") or "",
        "objectid": details.get("target_sid") or "",
        "kind": details.get("target_kind") or "",
        "to": details.get("to") or "",
    }
    stamped = details.get(PROTECTED_ACCOUNT_CLASS_KEY)
    if stamped:
        identity[PROTECTED_ACCOUNT_CLASS_KEY] = stamped
    return {key: value for key, value in identity.items() if value}


def classify_destructive(
    relation: str,
    target_kind: str | None,
    *,
    target: Mapping[str, Any] | None = None,
) -> DestructiveVerdict:
    """Classify one relationship step against the destructive-action policy.

    Args:
        relation: The BloodHound/ACL relationship name (case-insensitive).
        target_kind: The target's graph node kind (``"Computer"``/``"User"``/…),
            a ``$``-suffixed sAMAccountName, or a protected-account class token
            (:data:`PASSWORD_DEPENDENT_ACCOUNT_CLASSES`).
        target: The target object when the caller has it (graph node, step
            identity, flat properties). Needed to recognise krbtgt, managed
            service accounts and Entra ID sync accounts, which a node kind alone
            cannot tell apart from an ordinary user.

    Returns:
        A :class:`DestructiveVerdict`. Relations not covered by the policy return
        ``DestructiveVerdict(False, False, "")`` (no change to their behavior).
    """
    rel = (relation or "").strip().lower()
    if not rel:
        return DestructiveVerdict(False, False, "")
    if rel in _HARD_BLOCKED_RELATIONS:
        return DestructiveVerdict(True, False, _hard_blocked_reason(rel))
    if rel == _FCP_RELATION:
        account_class = classify_password_dependent_account(target_kind, target)
        if account_class:
            return DestructiveVerdict(True, False, _FCP_REASON_BY_CLASS[account_class])
        return DestructiveVerdict(False, True, _FCP_USER_REASON)
    if rel == _ALL_EXTENDED_RIGHTS_RELATION:
        # On a user-class object the only abuse of AllExtendedRights is the
        # password reset (``ace_step_execution`` remaps it to ForceChangePassword),
        # so on an account ADscan never resets it is the same refusal. On a
        # computer-class object it remaps to a LAPS read, which changes nothing,
        # and stays executable; that includes an sMSA / dMSA, whose object class
        # is computer.
        if _is_computer_target(target_kind) or _is_computer_target(
            str(_target_properties(target).get("kind") or "")
        ):
            return DestructiveVerdict(False, False, "")
        account_class = classify_password_dependent_account(target_kind, target)
        if account_class and account_class != PROTECTED_ACCOUNT_COMPUTER:
            return DestructiveVerdict(True, False, _FCP_REASON_BY_CLASS[account_class])
    return DestructiveVerdict(False, False, "")


def relation_safety_note(relation: str) -> str:
    """Return the client-facing "what ADscan never runs here" note, or "".

    For the didactic card of a bare technique (no concrete target): a statically
    hard-blocked technique gets its own reason, and the password reset lists the
    account classes it is refused against in every scan policy.
    """
    rel = (relation or "").strip().lower()
    if rel in _HARD_BLOCKED_RELATIONS:
        return _hard_blocked_reason(rel)
    if rel == _FCP_RELATION:
        return _FCP_PROTECTED_ACCOUNTS_NOTE
    return ""


_FCP_PROTECTED_ACCOUNTS_NOTE = (
    "ADscan never resets the password of a computer account, the krbtgt account, "
    "a managed service account or an Entra ID sync account, in any scan policy. "
    "Running systems depend on those passwords and the previous value cannot be "
    "put back, so ADscan maps the path and reports it without running the reset. "
    "You can confirm who holds the right by reading the account's ACL with Get-Acl."
)


def safety_abstention_notes(
    relation: str,
    target_kind: str | None = None,
    *,
    target: Mapping[str, Any] | None = None,
) -> dict[str, str] | None:
    """Return graph/step ``details`` notes for a safety-abstained step, or None.

    The single place that decides whether a step is a safety abstention and what
    marker + client-safe reason to stamp. Every stamping site (the persisted
    graph edge notes AND the per-path ``steps_for_ui`` builders in
    ``attack_graph_service``/``attack_graph_core``) routes through this so a
    hard-blocked technique can never be stamped ``"dangerous"`` in one place and
    ``"dangerous_destructive"`` in another.

    Args:
        relation: The BloodHound/ACL relationship name (case-insensitive).
        target_kind: The target's graph node kind or ``$``-suffixed name (only
            matters for ForceChangePassword; the statically hard-blocked
            techniques are hard-blocked regardless of target).
        target: The target object (graph node or step identity), forwarded to
            :func:`classify_destructive`.

    Returns:
        ``{"blocked_kind": "dangerous_destructive", "reason": …,
        "client_safe_reason": …}`` when the step is a hard-blocked safety
        abstention, plus ``protected_account_class`` for a password reset
        refused because of its target; ``None`` otherwise (the caller keeps its
        own default).
    """
    verdict = classify_destructive(relation, target_kind, target=target)
    if not verdict.hard_blocked:
        return None
    notes = {
        "blocked_kind": DANGEROUS_DESTRUCTIVE_MARKER,
        "reason": verdict.client_safe_reason,
        "client_safe_reason": verdict.client_safe_reason,
    }
    if (relation or "").strip().lower() in _PASSWORD_RESET_RELATIONS:
        account_class = classify_password_dependent_account(target_kind, target)
        if account_class:
            notes[PROTECTED_ACCOUNT_CLASS_KEY] = account_class
    return notes


def safety_abstention_statement(client_safe_reason: str | None) -> str:
    """Return the full client-facing statement for a safety-abstained step.

    Combines the fixed framing (:data:`SAFETY_ABSTENTION_LEAD`) — which presents
    the abstention as a deliberate protective decision — with the specific,
    engine-produced ``client_safe_reason`` (from :func:`classify_destructive`).
    The reason is never re-authored here; this only frames it.

    Args:
        client_safe_reason: The verdict's ``client_safe_reason`` for the blocked
            step (may be empty).

    Returns:
        A single client-safe sentence pair. When no reason is supplied, only the
        framing lead is returned.
    """
    reason = str(client_safe_reason or "").strip()
    if reason:
        return f"{SAFETY_ABSTENTION_LEAD} {reason}"
    return SAFETY_ABSTENTION_LEAD


def is_internal_engineering_reason(text: str | None) -> bool:
    """Return True when ``text`` is an internal, engineering-register reason.

    Screens a candidate reason string against every ``support_reason`` authored
    in the attack-step catalog and the support registry (see
    ``attack_step_support_registry.internal_support_reasons``). Those strings
    explain ADscan's automation coverage to a developer; a client reading one in
    a deliverable gets a capability-gap confession instead of a finding.

    Best-effort by design: if the registry cannot be imported (a trimmed
    deployment), nothing is screened rather than raising inside a renderer.
    """
    candidate = str(text or "").strip().casefold()
    if not candidate:
        return False
    try:
        from adscan_internal.services.attack_step_support_registry import (  # noqa: PLC0415
            internal_support_reasons,
        )

        return candidate in internal_support_reasons()
    except Exception:  # noqa: BLE001 - never break a render over the screen.
        return False


def client_safe_step_reason(details: dict | None) -> str:
    """Return the step's reason text that is safe to print to a client, or "".

    ``client_safe_reason`` is the ONLY key a producer promises to author as
    client-facing prose (:func:`safety_abstention_notes`,
    :func:`classify_destructive`). The generic ``reason`` key carries whatever
    the engine had — usually the engineering-register ``support_reason`` — so it
    is read only for a safety abstention, where
    :func:`safety_abstention_notes` writes the same authored sentence into both
    keys and older persisted graphs may carry only ``reason``.

    Whatever survives that is still screened by
    :func:`is_internal_engineering_reason`, so an internal string cannot reach a
    deliverable even if a future producer writes one into the wrong key.

    Args:
        details: A step/edge ``details`` (or graph ``notes``) mapping.

    Returns:
        A client-safe sentence, or ``""`` when the step has none.
    """
    if not isinstance(details, dict):
        return ""
    candidates = [details.get("client_safe_reason")]
    blocked_kind = str(details.get("blocked_kind") or "").strip().lower()
    if blocked_kind == DANGEROUS_DESTRUCTIVE_MARKER:
        candidates.append(details.get("reason"))
    for candidate in candidates:
        text = str(candidate or "").strip()
        if text and not is_internal_engineering_reason(text):
            return text
    return ""


def non_execution_statement(details: dict | None) -> str:
    """Return the client-facing sentence for a step that did not execute, or "".

    The single mapping every client surface (PDF report, web platform) uses, so
    the two can never disagree about what ADscan claims:

    - hard-blocked safety abstention (``blocked_kind`` is
      :data:`DANGEROUS_DESTRUCTIVE_MARKER`) → :data:`SAFETY_ABSTENTION_LEAD`
      plus the authored reason. This is the ONLY route to the safety framing;
      a bare reason string never reaches it.
    - any other non-execution marker (``unsupported``, the opt-in-only
      ``dangerous``) → :data:`NOT_EXERCISED_STATEMENT`, plus a client-safe
      reason when the producer authored one.
    - no marker at all → ``""`` (the step is theoretical; the narrative already
      says so and needs no trailing sentence).

    Args:
        details: A step/edge ``details`` (or graph ``notes``) mapping.

    Returns:
        A complete, client-safe sentence, or ``""``.
    """
    if not isinstance(details, dict):
        return ""
    blocked_kind = str(details.get("blocked_kind") or "").strip().lower()
    if not blocked_kind:
        return ""
    reason = client_safe_step_reason(details)
    if blocked_kind == DANGEROUS_DESTRUCTIVE_MARKER:
        return safety_abstention_statement(reason)
    if reason:
        return f"{NOT_EXERCISED_STATEMENT} {reason}"
    return NOT_EXERCISED_STATEMENT


def safety_abstention_disruption_clause(relations: Iterable[str] | None) -> str:
    """Return the "Running it would have ..." clause for abstained techniques.

    Args:
        relations: The technique keys of the steps ADscan abstained from, as
            :func:`path_safety_abstention_relations` returns them (a relation
            name, or ``<relation>.<account class>`` for a password reset refused
            because of its target). Several routes commonly share ONE technique,
            in which case that technique's specific clause is returned.

    Returns:
        A verb phrase completing "Running them would have ...". A mixed set of
        techniques, an unrecognised technique or an empty set resolves to
        :data:`GENERIC_DISRUPTION_CLAUSE` rather than a guessed mechanism.
    """
    distinct = {
        normalized
        for raw in (relations or ())
        if (normalized := str(raw or "").strip().lower())
    }
    if len(distinct) != 1:
        return GENERIC_DISRUPTION_CLAUSE
    return _HARD_BLOCKED_DISRUPTION_CLAUSES.get(
        distinct.pop(), GENERIC_DISRUPTION_CLAUSE
    )


def step_is_safety_abstention(step: object) -> bool:
    """Return True when ONE step was hard-refused for safety.

    The step-granularity half of :func:`path_is_safety_abstention`, and the one
    definition both use. A renderer that badges an individual hop needs it: a
    withheld step must read as restraint ("Not Executed for Safety"), never as
    the neutral ``attempted`` the bare ``blocked`` token degrades to, or the card
    contradicts its own prose one line apart.

    Delegates to ``adscan_core.reporting.execution_status``, where the web
    ingestion reads the same predicate when it stores a path's status.
    """
    return _shared_step_is_safety_abstention(step)


def _iter_safety_abstained_steps(path: object) -> Iterable[Mapping]:
    """Yield the steps of ``path`` that were hard-refused for safety."""
    if not isinstance(path, Mapping):
        return
    steps = path.get("steps")
    if not isinstance(steps, Sequence) or isinstance(steps, (str, bytes)):
        return
    for step in steps:
        if step_is_safety_abstention(step):
            yield step  # type: ignore[misc]


def path_is_safety_abstention(path: object) -> bool:
    """Return True when a path carries a step ADscan hard-refused for safety.

    The ONE predicate for "did ADscan confirm this route and deliberately not
    execute it". Both the engine-stamped KPI count
    (``exposure_score_service.compute_exposure_kpis`` ->
    ``path_axis[<class>]["safety_withheld"]``) and the report's display bucket
    (``attack_path_render.group_attack_paths_by_status`` -> ``safety_blocked``)
    call it, so the headline figure and the section that details those routes
    can never disagree about which routes they are.

    A safety abstention is DISTINCT from a bare ``blocked`` status: ADscan is an
    exposure-validation product and never attributes a non-execution to a
    control in the client's environment, so a ``blocked`` path with no safety
    marker is reported as ``attempted``, never as restraint.
    """
    for _step in _iter_safety_abstained_steps(path):
        return True
    return False


#: Where in a chain the withheld step sits. The STATUS token is deliberately
#: position-blind (one token, ``blocked``: this repo already carries three status
#: vocabularies and a compound token would deepen that), so the POSITION is a
#: separate fact the client-facing PROSE reads, because the two cases are
#: different stories and only one of them may be told as "the route stops at the
#: act we declined".
SAFETY_ABSTENTION_TERMINAL = "terminal"
SAFETY_ABSTENTION_MID_CHAIN = "mid_chain"


def safety_abstention_position(path: object) -> str:
    """Return where a path's withheld step sits, or ``""`` when none is marked.

    :data:`SAFETY_ABSTENTION_TERMINAL` when the LAST actionable step of the chain
    is the withheld one: the strongest and most precise story, because everything
    the route needed was established and only the disruptive final act was
    declined. :data:`SAFETY_ABSTENTION_MID_CHAIN` when the withheld step sits
    earlier: the hops beyond it were never walked, so narrating that route as one
    ADscan took to its end would overclaim.

    Structural / context hops (``MemberOf`` and friends) are not actionable
    steps, so a trailing one does not demote a terminal abstention to mid-chain.
    """
    if not isinstance(path, Mapping):
        return ""
    steps = path.get("steps")
    if not isinstance(steps, Sequence) or isinstance(steps, (str, bytes)):
        return ""
    actionable: list[Mapping] = [
        step
        for step in steps
        if isinstance(step, Mapping)
        and str(step.get("status") or "").strip().lower() != "structural"
    ]
    if not actionable:
        return ""
    withheld = [
        index
        for index, step in enumerate(actionable)
        if step_is_safety_abstention(step)
    ]
    if not withheld:
        return ""
    if withheld[-1] == len(actionable) - 1:
        return SAFETY_ABSTENTION_TERMINAL
    return SAFETY_ABSTENTION_MID_CHAIN


def path_safety_abstention_reason(path: object) -> str:
    """Return the client-safe reason a path was NOT executed for safety, or "".

    The step carries the engine-produced ``client_safe_reason`` (see
    :func:`safety_abstention_notes`); this returns it verbatim so a render can
    surface it without re-authoring the sentence. Resolution goes through
    :func:`client_safe_step_reason`, which screens out any engineering-register
    reason before it can reach a deliverable.
    """
    for step in _iter_safety_abstained_steps(path):
        return client_safe_step_reason(dict(step.get("details") or {}))
    return ""


def _abstention_technique_key(step: Mapping) -> str:
    """Return the technique key one safety-abstained step is described by.

    The relation name, except for a password reset, whose disruption depends on
    WHICH account it would have reset: ``forcechangepassword.krbtgt`` and its
    siblings. The computer case keeps the bare relation key, which is also what
    a step stamped before the account class existed resolves to.
    """
    relation = str(
        step.get("relation") or step.get("action") or step.get("edge") or ""
    ).strip()
    if relation.lower() not in _PASSWORD_RESET_RELATIONS:
        return relation
    details = step.get("details") if isinstance(step.get("details"), Mapping) else {}
    account_class = classify_password_dependent_account(
        None, step_target_identity(details)
    )
    if account_class and account_class != PROTECTED_ACCOUNT_COMPUTER:
        return f"{_FCP_RELATION}.{account_class}"
    return relation


def path_safety_abstention_relations(paths: Iterable[object] | None) -> list[str]:
    """Return the technique key of every safety-abstained step in ``paths``.

    Feeds :func:`safety_abstention_disruption_clause`, which needs the set of
    techniques withheld rather than any one path. A key is the relation name, or
    ``<relation>.<account class>`` for a password reset refused because of its
    target (see :func:`_abstention_technique_key`).
    """
    relations: list[str] = []
    for path in paths or ():
        for step in _iter_safety_abstained_steps(path):
            relation = _abstention_technique_key(step)
            if relation:
                relations.append(relation)
    return relations
