"""Engine half of the revert-right registry: one probe per token, read-only.

Each token of :mod:`adscan_core.scan_policy.revert_rights` is established by the
probe registered against it here (:func:`register_revert_right_probe`). A probe
gathers facts from the environment and hands them to the pure decision of the
registry, so the gate, the checklist and the report read one answer:

* **domain / forest tokens** (``directory_probe``): the account's transitive
  group SIDs, as a domain controller of its HOME domain computes them
  (``tokenGroups``, read with the scan's own credential, so the cleanup secret
  never leaves the store for this) or, when that read is unavailable, as the
  collected membership snapshot resolves them. Roles come from SIDs: Domain
  Admins and BUILTIN\\Administrators of the account's own domain, Enterprise
  Admins of its forest root. Never from a group's name, never from what the
  operator says the account is.
* **CA tokens** (``ca_probe``): what the CA itself answers to three read-only
  CSRA calls made AS the account (``GetMyRoles``, role separation,
  ``GetOfficerRights``; ``SMBMachine.get_ca_reversal_facts_dcom``). The sign-in
  goes through the guarded SMB transport like every other one.

Nothing here writes. Facts are memoized for the session (a CA's facts per
account, an account's SIDs per home domain); a verdict that could not be
established is never memoized, so the next call asks again.

Extension: register a probe for a new token with
:func:`register_revert_right_probe`. A token of an existing scope can reuse
``directory_probe`` or ``ca_probe`` as they stand.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping, Optional

from adscan_core import telemetry
from adscan_core.rich_output import print_exception, print_info_debug
from adscan_core.scan_policy.revert_rights import (
    REASON_PROBE_FAILED,
    SCOPE_CA,
    SCOPE_DOMAIN,
    SCOPE_FOREST,
    STATE_UNDETERMINABLE,
    RevertRight,
    RightVerdict,
    decide_ca_right,
    decide_directory_right,
    directory_roles,
    is_ca_access_denied,
    registered_revert_rights,
    revert_right,
)
from adscan_internal.rich_output import mark_sensitive

#: How long an established CA fact set / SID set is reused within a session.
#: Every scan re-verifies at its start; this only spares repeated reads in one run.
_FACT_TTL_SECONDS = 1800.0
_SID_MEMO_ATTR = "_revert_right_sid_memo"
_CA_MEMO_ATTR = "_revert_right_ca_memo"


@dataclass(frozen=True)
class ProbeTarget:
    """What a probe resolves against.

    Attributes:
        scope: ``domain`` / ``forest`` / ``ca``.
        target: The domain, the forest root, or the CA key (``host\\name``).
        domain: The domain that owns the target (for a CA, the CA host's domain;
            for a forest token, the forest root).
        ca_name / ca_host: Set for a CA target.
    """

    scope: str
    target: str
    domain: str
    ca_name: str = ""
    ca_host: str = ""


@dataclass(frozen=True)
class ProbeAccount:
    """The account a probe asks about. ``candidate`` carries the secret, CA probes only.

    ``candidate`` is a ``revert_credentials.RevertCandidate``, the only object
    allowed to hold the cleanup secret outside the store.
    """

    principal: str
    home_domain: str = ""
    candidate: Any = None


ProbeFn = Callable[[Any, RevertRight, ProbeTarget, ProbeAccount], RightVerdict]
_PROBES: dict[str, ProbeFn] = {}


def register_revert_right_probe(token: str, probe: ProbeFn) -> None:
    """Bind the probe that establishes ``token``. One probe per token."""
    if revert_right(token) is None:
        raise ValueError(f"unknown revert right {token!r}: register it in revert_rights first")
    _PROBES[str(token)] = probe


def registered_probe(token: str) -> Optional[ProbeFn]:
    return _PROBES.get(str(token or ""))


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _memo(shell: Any, attr: str) -> dict:
    memo = getattr(shell, attr, None)
    if not isinstance(memo, dict):
        memo = {}
        try:
            setattr(shell, attr, memo)
        except Exception:  # noqa: BLE001 - a read-only shell just recomputes
            pass
    return memo


def forget_probe_memo(shell: Any) -> None:
    """Drop every memoized fact (an explicit re-check, or a new account)."""
    for attr in (_SID_MEMO_ATTR, _CA_MEMO_ATTR):
        try:
            setattr(shell, attr, {})
        except Exception:  # noqa: BLE001
            pass


def probe_revert_right(
    shell: Any, token: str, target: ProbeTarget, account: ProbeAccount
) -> RightVerdict:
    """Establish one right on one target for one account. Never raises."""
    right = revert_right(token)
    probe = registered_probe(token)
    if right is None or probe is None:
        return RightVerdict(
            str(token), target.scope, target.target, STATE_UNDETERMINABLE, REASON_PROBE_FAILED,
            account.principal, (), _now_iso(),
        )
    try:
        return probe(shell, right, target, account)
    except Exception as exc:  # noqa: BLE001 - an unestablished right is not undoable
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return RightVerdict(
            right.token, right.scope, target.target, STATE_UNDETERMINABLE, REASON_PROBE_FAILED,
            account.principal, (), _now_iso(),
        )


# ── directory: the account's group SIDs, from directory data ─────────────────


def _snapshot_group_sids(shell: Any, principal: str, home: str) -> tuple[Optional[list[str]], bool]:
    """``(sids, found)`` from the collected membership snapshot of ``home``."""
    from adscan_internal.services.attack_graph_service import (  # noqa: PLC0415
        _expand_group_ancestors,
    )
    from adscan_internal.services.membership_snapshot import (  # noqa: PLC0415
        load_membership_snapshot,
    )

    snapshot = load_membership_snapshot(shell, home)
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("user_to_groups"), dict):
        return None, False
    label_to_sid = snapshot.get("label_to_sid") or {}
    if not isinstance(label_to_sid, dict):
        return None, False
    label = f"{principal.strip().upper()}@{home.strip().upper()}"
    direct = snapshot["user_to_groups"].get(label)
    if direct is None:
        return [], False
    group_to_parents = snapshot.get("group_to_parents") or {}
    cache: dict[str, set[str]] = {}
    groups: set[str] = set()
    for group in direct or ():
        group_label = str(group or "").strip().upper()
        if not group_label:
            continue
        groups.add(group_label)
        groups.update(_expand_group_ancestors(home, group_label, group_to_parents, cache))
    return [str(label_to_sid.get(g) or "") for g in groups if label_to_sid.get(g)], True


_READER_ATTR = "_revert_right_directory_reader"


def set_directory_reader(shell: Any, domain: str, username: str, secret: str) -> None:
    """The scan credential that reads the account's ``tokenGroups`` in ``domain``.

    Only for a caller that holds the scan credential without having stored it
    in ``domains_data`` (the doctor). Kept on a private shell attribute, never
    persisted. A scan reads with the credential it already stored.
    """
    readers = _memo(shell, _READER_ATTR)
    if username and secret:
        readers[str(domain or "").strip().lower()] = (username, secret)


def _live_group_sids(shell: Any, principal: str, home: str) -> Optional[list[str]]:
    """``tokenGroups`` of the account read on a DC of ``home`` with the scan's credential."""
    from adscan_internal.cli.ldap import get_principal_token_group_sids  # noqa: PLC0415

    reader = _memo(shell, _READER_ATTR).get(home.strip().lower())
    if reader:
        return get_principal_token_group_sids(
            shell,
            domain=home,
            target_samaccountname=principal,
            auth_username=reader[0],
            auth_password=reader[1],
            timeout=60,
        )
    return get_principal_token_group_sids(
        shell, domain=home, target_samaccountname=principal, timeout=60
    )


def account_group_sids(
    shell: Any, principal: str, home: str
) -> tuple[Optional[list[str]], bool, str]:
    """``(sids, found, source)`` for ``principal`` in its home domain. Memoized per session."""
    key = (principal.strip().lower(), home.strip().lower())
    memo = _memo(shell, _SID_MEMO_ATTR)
    cached = memo.get(key)
    if cached is not None and time.monotonic() - cached[0] < _FACT_TTL_SECONDS:
        return cached[1], cached[2], cached[3]
    sids: Optional[list[str]] = None
    found = False
    source = ""
    try:
        live = _live_group_sids(shell, principal, home)
    except Exception as exc:  # noqa: BLE001 - fall back to the collected snapshot
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        live = None
    if live is not None:
        sids, found, source = live, True, "token_groups"
    else:
        try:
            snap, snap_found = _snapshot_group_sids(shell, principal, home)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            snap, snap_found = None, False
        if snap is not None:
            sids, found, source = snap, snap_found, "membership_snapshot"
    if sids is not None and found:
        memo[key] = (time.monotonic(), sids, found, source)
    print_info_debug(
        "revert-right sids "
        f"principal={mark_sensitive(principal, 'user')} home={mark_sensitive(home, 'domain')} "
        f"found={found} source={source or 'none'} count={len(sids or [])}"
    )
    return sids, found, source


def _home_candidates(shell: Any, account: ProbeAccount, target_domain: str) -> list[str]:
    """Where to look the account up: its stated home, else the target and its forest."""
    from adscan_core.scan_policy.revert_permission import ANY_DOMAIN  # noqa: PLC0415
    from adscan_internal.services.forest_topology import (  # noqa: PLC0415
        known_forest_root,
    )

    home = str(account.home_domain or "").strip().lower()
    if home and home != ANY_DOMAIN:
        return [home]
    out = [target_domain.lower()]
    root = known_forest_root(shell, target_domain)
    if root and root not in out:
        out.append(root)
    for name in (getattr(shell, "domains_data", None) or {}):
        n = str(name or "").strip().lower()
        if n and n not in out and root and known_forest_root(shell, n) == root:
            out.append(n)
    return out


@dataclass(frozen=True)
class DirectoryFacts:
    """What the directory says about one account in one target domain."""

    found: bool
    directory_data: bool
    same_forest: Optional[bool]
    roles: frozenset[str]
    home_domain: str
    forest_root: str
    source: str


def directory_facts(shell: Any, account: ProbeAccount, target_domain: str) -> DirectoryFacts:
    """The account's roles in ``target_domain``, from its SIDs. Never raises.

    The account is looked up in its stated home domain, or, when it was given
    without one, in the target and then the other known domains of the target's
    forest. Roles are read from SIDs (``revert_rights.directory_roles``).
    """
    from adscan_internal.services.forest_topology import (  # noqa: PLC0415
        domain_sid,
        resolve_forest_root,
        same_forest,
    )

    target_domain = str(target_domain or "").strip().lower()
    principal = str(account.principal or "").strip()
    if not principal or not target_domain:
        return DirectoryFacts(False, False, None, frozenset(), "", "", "")
    sids: Optional[list[str]] = None
    found = False
    source = ""
    home = ""
    for candidate in _home_candidates(shell, account, target_domain):
        sids, found, source = account_group_sids(shell, principal, candidate)
        if found:
            home = candidate
            break
    if not found:
        home = (_home_candidates(shell, account, target_domain) or [target_domain])[0]
    shared = same_forest(shell, home, target_domain)
    root = resolve_forest_root(shell, target_domain) or (target_domain if shared else "")
    home_sid = domain_sid(shell, home)
    target_sid = domain_sid(shell, target_domain)
    root_sid = domain_sid(shell, root) if root else ""
    roles = directory_roles(
        sids or (),
        home_domain_sid=home_sid,
        target_domain_sid=target_sid,
        forest_root_sid=root_sid,
        same_forest=bool(shared),
    )
    # Enough data to answer: the account's SIDs, the target's SID, and the forest
    # root's SID whenever the account is not of the target domain itself.
    directory_data = sids is not None and bool(target_sid) and (
        home_sid == target_sid or bool(root_sid)
    )
    return DirectoryFacts(found, bool(directory_data), shared, roles, home, root, source)


def directory_probe(
    shell: Any, right: RevertRight, target: ProbeTarget, account: ProbeAccount
) -> RightVerdict:
    """Domain / forest tokens: roles from the account's SIDs, decided by the registry."""
    facts = directory_facts(shell, account, target.domain)
    return decide_directory_right(
        right,
        target=target.target,
        principal=str(account.principal or "").strip(),
        same_forest=facts.same_forest,
        directory_data=facts.directory_data,
        principal_found=facts.found,
        roles=facts.roles,
        checked_at=_now_iso(),
        detail={
            "home_domain": facts.home_domain,
            "forest_root": facts.forest_root,
            "source": facts.source,
        },
    )


# ── CA: what the CA itself answers, as the account ───────────────────────────


def _error_text(err: Any) -> str:
    if err is None:
        return ""
    code = getattr(err, "error_code", None)
    text = str(err) or repr(err)
    return f"{text} (0x{int(code) & 0xffffffff:08x})" if isinstance(code, int) else text


async def _read_ca_facts(smb_config: Any, ca_name: str) -> tuple[Optional[dict], Any]:
    from adscan_internal.services.smb_transport import (  # noqa: PLC0415
        smb_machine_with_fallback,
    )

    async with smb_machine_with_fallback(smb_config) as machine:
        return await machine.get_ca_reversal_facts_dcom(ca_name)


def ca_facts(shell: Any, target: ProbeTarget, account: ProbeAccount) -> dict[str, Any]:
    """The four facts for one CA and one account, read once per session.

    Returns ``{"reachable", "roles", "role_separation", "officer_rights_enabled",
    "errors", "refused"}``; a value the CA did not give is ``None``, never a
    negative. ``refused`` names the reads the CA itself answered with access
    denied (E_ACCESSDENIED), which is an answer, unlike any other failure.
    """
    key = (target.target.lower(), str(account.principal or "").lower())
    memo = _memo(shell, _CA_MEMO_ATTR)
    cached = memo.get(key)
    if cached is not None and time.monotonic() - cached[0] < _FACT_TTL_SECONDS:
        return cached[1]
    facts: dict[str, Any] = {
        "reachable": False,
        "roles": None,
        "role_separation": None,
        "officer_rights_enabled": None,
        "errors": {},
        "refused": [],
    }
    candidate = account.candidate
    if candidate is None:
        facts["errors"]["account"] = "no usable credential for the account"
        return facts
    from adscan_internal.models.domain import resolve_dc_ip  # noqa: PLC0415
    from adscan_internal.services.adcs.certificate_revocation import (  # noqa: PLC0415
        smb_config_for_candidate,
    )
    from adscan_internal.services.async_bridge import run_async_sync  # noqa: PLC0415
    from adscan_internal.services.domain_posture import get_posture  # noqa: PLC0415

    domains_data = getattr(shell, "domains_data", {}) or {}
    domain_data = domains_data.get(target.domain) or {}
    try:
        posture = get_posture(domains_data, domain=target.domain)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        posture = None
    smb_config = smb_config_for_candidate(
        candidate,
        ca_host=target.ca_host,
        dc_ip=resolve_dc_ip(domain_data) if domain_data else None,
        posture=posture,
    )
    if smb_config is None:
        facts["errors"]["account"] = "the account's credential kind cannot sign in to the CA"
        return facts
    try:
        raw, err = run_async_sync(_read_ca_facts(smb_config, target.ca_name))
    except Exception as exc:  # noqa: BLE001 - unreachable is an honest unknown
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        raw, err = None, exc
    if raw is None:
        facts["errors"]["interface"] = _error_text(err)
    else:
        facts["reachable"] = True
        facts["roles"] = raw.get("roles")
        facts["role_separation"] = raw.get("role_separation")
        facts["officer_rights_enabled"] = raw.get("officer_rights_enabled")
        for name in ("roles", "role_separation", "officer_rights"):
            error = raw.get(f"{name}_error")
            if error is not None:
                facts["errors"][name] = _error_text(error)
                if is_ca_access_denied(getattr(error, "error_code", None)):
                    # The CA's own answer (E_ACCESSDENIED), not a failed read.
                    facts["refused"].append(name)
    memo[key] = (time.monotonic(), facts)
    print_info_debug(
        "revert-right ca "
        f"ca={mark_sensitive(target.target, 'hostname')} "
        f"principal={mark_sensitive(account.principal, 'user')} reachable={facts['reachable']} "
        f"roles={facts['roles']!r} role_separation={facts['role_separation']!r} "
        f"officer_restricted={facts['officer_rights_enabled']!r} refused={sorted(facts['refused'])} "
        "errors="
        + mark_sensitive(
            "; ".join(f"{k}: {v}" for k, v in sorted(facts["errors"].items())) or "none",
            "detail",
        )
    )
    return facts


def ca_probe(
    shell: Any, right: RevertRight, target: ProbeTarget, account: ProbeAccount
) -> RightVerdict:
    """CA tokens: the four facts, decided by the registry."""
    facts = ca_facts(shell, target, account)
    errors = dict(facts.get("errors") or {})
    if account.principal and "account" in errors:
        # No usable credential to ask the CA with: unknown, and not the CA's fault.
        return RightVerdict(
            right.token, right.scope, target.target, STATE_UNDETERMINABLE, REASON_PROBE_FAILED,
            account.principal, (), _now_iso(),
            {"ca_name": target.ca_name, "ca_host": target.ca_host, "errors": errors},
        )
    return decide_ca_right(
        right,
        target=target.target,
        principal=account.principal,
        reachable=bool(facts.get("reachable")),
        roles_bits=facts.get("roles"),
        role_separation=facts.get("role_separation"),
        officer_rights_enabled=facts.get("officer_rights_enabled"),
        roles_refused="roles" in (facts.get("refused") or ()),
        checked_at=_now_iso(),
        detail={
            "ca_name": target.ca_name,
            "ca_host": target.ca_host,
            "domain": target.domain,
            "errors": dict(facts.get("errors") or {}),
        },
    )


for _right in registered_revert_rights():
    if _right.scope in (SCOPE_DOMAIN, SCOPE_FOREST):
        register_revert_right_probe(_right.token, directory_probe)
    elif _right.scope == SCOPE_CA:
        register_revert_right_probe(_right.token, ca_probe)


def tokens_for_scope(scope: str, tokens: Iterable[str] | None = None) -> list[str]:
    """Registered tokens of one scope that have a probe."""
    wanted = None if tokens is None else {str(t) for t in tokens}
    return [
        r.token
        for r in registered_revert_rights()
        if r.scope == scope and r.token in _PROBES and (wanted is None or r.token in wanted)
    ]


def verdicts_as_dicts(verdicts: Iterable[RightVerdict]) -> list[Mapping[str, Any]]:
    return [v.to_dict() for v in verdicts]


def session_ca_role_separation(shell: Any, *, ca_host: str, ca_name: str) -> Optional[int]:
    """The role-separation flag the cleanup account's CA probe read in this run.

    Reuses what :func:`ca_facts` already asked the CA, never a new sign-in. Only
    a fact memoized in this session and still within its freshness window
    counts, so a reading from an earlier run never stands in for this one. The
    probe only asks CAs the engagement scope covers
    (``cleanup_capability.in_scope_cas``), so a value found here is in scope by
    construction.

    Returns:
        1 or 0 when the CA answered definitively for some account, ``None``
        when no fresh fact holds a definitive answer, or when two accounts read
        different answers (the CA would then have changed mid-run).
    """
    from adscan_core.scan_policy.revert_rights import (  # noqa: PLC0415
        ca_key,
        role_separation_state,
    )

    wanted = ca_key(ca_host, ca_name).lower()
    memo = getattr(shell, _CA_MEMO_ATTR, None)
    if not isinstance(memo, dict):
        return None
    values: set[int] = set()
    now = time.monotonic()
    for key, cached in memo.items():
        if not (isinstance(key, tuple) and key and str(key[0]).lower() == wanted):
            continue
        if not (isinstance(cached, tuple) and len(cached) == 2):
            continue
        stamped, facts = cached
        if not isinstance(facts, Mapping) or now - float(stamped) >= _FACT_TTL_SECONDS:
            continue
        state = role_separation_state(facts.get("role_separation"))
        if state is not None:
            values.add(1 if state else 0)
    return values.pop() if len(values) == 1 else None


__all__ = [
    "ProbeAccount",
    "ProbeTarget",
    "account_group_sids",
    "ca_facts",
    "ca_probe",
    "directory_probe",
    "forget_probe_memo",
    "probe_revert_right",
    "register_revert_right_probe",
    "registered_probe",
    "session_ca_role_separation",
    "set_directory_reader",
    "tokens_for_scope",
    "verdicts_as_dicts",
]
