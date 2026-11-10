"""Resolve the target of a password reset to its directory object, then classify it.

The destructive-action policy (``destructive_action_policy``) decides whether a
password reset is refused in every mode, and for the accounts a running system
depends on (krbtgt, managed service accounts, Entra ID sync accounts) that
decision needs the object's structural signals: its SID, object class, account
type, distinguished name, description. An execution entry point usually holds
only a sAMAccountName, so this module looks the account up in the workspace
attack graph first and hands the classifier the node.

It lives apart from the policy module on purpose: the policy module is bundled
into the appliance web backend, and the graph loader it would need here is
engine code that must never be.

Best-effort by construction. When the graph is missing or the account is not in
it, the classifier still receives the name, which carries the reserved
``krbtgt`` / ``krbtgt_<n>`` names, the ``MSOL_<hex>`` sync-account pattern and
the ``$`` suffix of a machine account. A lookup failure can only fall back to
fewer signals, never to an unguarded reset.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from adscan_core import telemetry
from adscan_core.rich_output import print_exception, print_info_debug
from adscan_internal.services.destructive_action_policy import (
    DestructiveVerdict,
    classify_destructive,
)

__all__ = [
    "FALLBACK_EXCLUDED_BY_SCAN_POLICY",
    "FALLBACK_NO_RESET_RIGHT",
    "FALLBACK_PASSWORD_DEPENDENT_ACCOUNT",
    "HeldSecret",
    "PASSWORD_RESET_RELATION",
    "PasswordResetFallback",
    "RESET_GRANTING_RELATIONS",
    "held_secret_for_account",
    "password_reset_fallback",
    "password_reset_verdict",
    "relation_grants_password_reset",
    "resolve_password_reset_target",
]

#: The relation every password-setting path is classified as.
PASSWORD_RESET_RELATION = "forcechangepassword"

#: Relations whose right includes the Reset-Password extended right. GenericAll
#: and Owns (ownership lets the owner grant itself full control) carry it;
#: AllExtendedRights is every control-access right; ForceChangePassword is the
#: right itself. GenericWrite, WriteAccountRestrictions and AddKeyCredentialLink
#: are property writes and do NOT: the DC refuses a reset through them.
RESET_GRANTING_RELATIONS: frozenset[str] = frozenset(
    {"genericall", "owns", "allextendedrights", PASSWORD_RESET_RELATION}
)

#: Why a password reset is not offered (``PasswordResetFallback.reason``).
FALLBACK_NO_RESET_RIGHT = "no_reset_right"
FALLBACK_EXCLUDED_BY_SCAN_POLICY = "excluded_by_scan_policy"
FALLBACK_PASSWORD_DEPENDENT_ACCOUNT = "password_dependent_account"


def _candidate_labels(account: str, domain: str, label: str | None) -> list[str]:
    """Return the graph labels an account may be stored under, best first."""
    candidates: list[str] = []
    text = str(label or "").strip()
    if text:
        candidates.append(text)
    name = str(account or "").strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    realm = str(domain or "").strip()
    if name and realm:
        candidates.append(f"{name}@{realm}".upper())
    seen: set[str] = set()
    ordered: list[str] = []
    for candidate in candidates:
        key = candidate.upper()
        if key not in seen:
            seen.add(key)
            ordered.append(candidate)
    return ordered


def resolve_password_reset_target(
    shell: Any,
    *,
    domain: str,
    account: str,
    label: str | None = None,
) -> dict[str, Any] | None:
    """Return the attack-graph node for ``account`` in ``domain``, or None.

    Args:
        shell: Active shell (used to load the workspace graph).
        domain: The domain the account lives in (the reset's target domain).
        account: The account's sAMAccountName (``DOMAIN\\`` / ``@realm`` tolerated).
        label: The graph label when the caller already has it (an attack-path
            step's ``to``), tried first.
    """
    try:
        from adscan_internal.services.attack_graph_service import (  # noqa: PLC0415
            get_node_by_label,
        )
    except Exception as exc:  # noqa: BLE001 - classification falls back to the name.
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None
    for candidate in _candidate_labels(account, domain, label):
        try:
            node = get_node_by_label(shell, domain, label=candidate)
        except Exception as exc:  # noqa: BLE001 - best-effort lookup.
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            return None
        if isinstance(node, dict):
            return node
    print_info_debug(
        "password-reset target not found in the attack graph; classifying by name"
    )
    return None


def password_reset_verdict(
    shell: Any,
    *,
    domain: str,
    account: str,
    target_kind: str | None = None,
    label: str | None = None,
    target: dict[str, Any] | None = None,
) -> DestructiveVerdict:
    """Classify a password reset of ``account`` against the destructive policy.

    The one call every password-setting entry point makes before it resets or
    sets anything. ``target`` short-circuits the graph lookup when the caller
    already holds the node.
    """
    node = target if isinstance(target, dict) else None
    if node is None and shell is not None:
        node = resolve_password_reset_target(
            shell, domain=domain, account=account, label=label
        )
    identity: dict[str, Any] = {"samaccountname": str(account or "").strip()}
    if label:
        identity["label"] = label
    if node:
        identity.update(node)
    return classify_destructive(PASSWORD_RESET_RELATION, target_kind, target=identity)


def relation_grants_password_reset(relation: str | None) -> bool:
    """Whether an ACL relation carries the right to reset the target's password."""
    return str(relation or "").strip().lower() in RESET_GRANTING_RELATIONS


@dataclass(frozen=True)
class PasswordResetFallback:
    """Whether a password reset may be offered as an alternative technique.

    Attributes:
        allowed: True when the reset may be offered (it still passes the
            ForceChangePassword choke point and its consent before it runs).
        reason: Empty when allowed, otherwise one of the ``FALLBACK_*`` values.
    """

    allowed: bool
    reason: str = ""


def password_reset_fallback(
    shell: Any,
    *,
    grants_reset: bool,
    domain: str,
    account: str,
) -> PasswordResetFallback:
    """Decide whether a branch may offer a password reset of ``account``.

    The ONE decision for every branch that reaches ForceChangePassword through a
    different relation (the GenericAll / Owns user menu, the shadow-credentials
    fallback). Three terms, all required:

    1. the edge grants the reset right (``grants_reset``, from
       :func:`relation_grants_password_reset`);
    2. the scan policy enables ``step:forcechangepassword``: a policy that
       switches resets off (Audit, Production-sensitive) never gets one through
       the GenericAll switch. An interactive run keeps deciding live: with no
       policy, or a policy that enables resets, the reset is offered and the
       choke point asks the operator;
    3. the destructive-action policy does not refuse this account (krbtgt, a
       managed service account, an Entra ID sync account, a computer).

    Not offering a technique is not a refusal, so nothing is recorded here; the
    choke point ``run_exploit_force_change_password`` refuses and records if a
    reset is ever attempted anyway.
    """
    if not grants_reset:
        return PasswordResetFallback(False, FALLBACK_NO_RESET_RIGHT)
    from adscan_internal.services.scan_policy_enforcement import (  # noqa: PLC0415
        relation_excluded,
    )

    if relation_excluded(shell, PASSWORD_RESET_RELATION):
        return PasswordResetFallback(False, FALLBACK_EXCLUDED_BY_SCAN_POLICY)
    if password_reset_verdict(shell, domain=domain, account=account).hard_blocked:
        return PasswordResetFallback(False, FALLBACK_PASSWORD_DEPENDENT_ACCOUNT)
    return PasswordResetFallback(True)


@dataclass(frozen=True)
class HeldSecret:
    """A secret the session already holds for an account (never printed).

    Attributes:
        secret: The password or NT hash.
        kind: ``"password"`` or ``"nt_hash"``.
    """

    secret: str = field(repr=False)
    kind: str = "password"

    @property
    def is_hash(self) -> bool:
        return self.kind == "nt_hash"


def _strip(value: Any) -> str:
    from adscan_core.sensitive import strip_sensitive_markers  # noqa: PLC0415

    return strip_sensitive_markers(str(value or "")).strip()


def _looks_like_nt_hash(value: str) -> bool:
    text = value.split(":")[-1] if ":" in value else value
    return len(text) == 32 and all(c in "0123456789abcdefABCDEF" for c in text)


def held_secret_for_account(
    shell: Any, *, domain: str, account: str
) -> Optional[HeldSecret]:
    """The previous secret of ``account`` the session holds, or None.

    Answers two questions a password reset asks before it runs, from ONE place:
    is the reset needed at all (when the credential is already held, it gains
    nothing and breaks whatever already signs in with it, the scan's own
    session included), and, when a reset happens anyway, can its previous value
    be put back afterwards. Reads the domain credential store only: a host-local
    credential is a different principal.

    Lives here, beside the destructive-target classifier, and not in
    ``destructive_action_policy``: that policy classifies what the TARGET is and
    is bundled into the web backend with no session state, while this reads
    what the SESSION holds right now.

    Args:
        shell: The session shell (``domains_data`` credential store).
        domain: The domain the account lives in.
        account: Its sAMAccountName (``DOMAIN\\`` / ``@realm`` tolerated).

    Returns:
        The held password (preferred) or NT hash, or None.
    """
    name = str(account or "").strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    if not name or not domain:
        return None
    data = (getattr(shell, "domains_data", {}) or {}).get(domain)
    if not isinstance(data, dict):
        return None
    wanted = name.lower()
    creds = data.get("credentials")
    stored = ""
    if isinstance(creds, dict):
        for user, secret in creds.items():
            if _strip(user).lower() == wanted:
                stored = _strip(secret)
                break
    if stored and not _looks_like_nt_hash(stored):
        return HeldSecret(secret=stored, kind="password")
    meta = data.get("credentials_meta")
    record = None
    if isinstance(meta, dict):
        for user, value in meta.items():
            if _strip(user).lower() == wanted and isinstance(value, dict):
                record = value
                break
    if isinstance(record, dict):
        password = _strip(record.get("password"))
        if password and not _looks_like_nt_hash(password):
            return HeldSecret(secret=password, kind="password")
    if stored:
        return HeldSecret(secret=stored, kind="nt_hash")
    if isinstance(record, dict):
        nt_hash = _strip(record.get("nt_hash"))
        if nt_hash and _looks_like_nt_hash(nt_hash):
            return HeldSecret(secret=nt_hash, kind="nt_hash")
    return None
