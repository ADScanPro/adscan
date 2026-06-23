"""Credential privilege-role resolution and consumer-facing picker.

The ADscan credential store keeps secrets as a flat
``{username: secret_string}`` mapping inside
``domains_data[domain]["credentials"]``. That format predates any notion
of "which of these can actually act as a local admin on this host" and
is consumed by dozens of call sites that assume the value is the secret
string itself.

This module provides a single high-quality picker for any consumer that
needs the **best** credential to use as a local administrator on a target
host. The picker is the only correct way to choose a credential for
post-compromise actions like SMB ``\\C$\\`` byte reads, schtask payload
drops, lsass dumps, etc. — never iterate ``credentials.items()`` and
take the first one.

Single source of truth: privilege classification (DA / EA / RID 500 /
LAV) is derived **at read time** from the canonical AD attack graph and
identity-risk store. Writers no longer push role hints into
``credentials_meta`` — the legacy ``tag_credential_privilege_role``,
``tag_credential_local_admin_host`` and ``set_credential_enabled``
helpers were removed in Phase 2 of the credentials cleanup.

The sibling ``credentials_meta`` mapping is still used for the two
truly-non-derivable signals: ``secret_kind`` (how to interpret the
secret string) and ``aes256_key`` / ``aes128_key`` / ``kerberos_keys``
(extra Kerberos material captured during DCSync).
"""

from __future__ import annotations

from enum import Enum
from typing import Any, MutableMapping

from adscan_core import telemetry


class CredentialPrivilegeRole(str, Enum):
    """Privilege classification of a stored credential.

    These are evidence-driven labels — not BloodHound edges. Tier-0
    membership detected via group enumeration is one source; RID 500
    from an NTDS dump is another; verified SMB ``Pwn3d!`` access on a
    host is a third. The picker resolves them via :data:`ROLE_PRIORITY`.
    """

    BUILTIN_ADMINISTRATOR = "builtin_administrator"  # RID 500 — DC local admin
    DOMAIN_ADMIN = "domain_admin"                    # member of Domain Admins (512)
    ENTERPRISE_ADMIN = "enterprise_admin"            # member of Enterprise Admins (519)
    LOCAL_ADMIN_VERIFIED = "local_admin_verified"    # SMB Pwn3d! confirmed
    KRBTGT = "krbtgt"                                # RID 502 — never logs in but
                                                     # NT/AES keys enable Golden
                                                     # Ticket and Silver Ticket
                                                     # forging. UAC is set to
                                                     # ACCOUNTDISABLE by design;
                                                     # the account is fully
                                                     # operational.
    KERBEROASTABLE = "kerberoastable"
    ASREP_ROASTABLE = "asrep_roastable"
    STANDARD = "standard"


class CredentialKind(str, Enum):
    """How to interpret the secret string when authenticating."""

    PASSWORD = "password"
    NT_HASH = "nt_hash"
    AES256_KEY = "aes256_key"
    AES128_KEY = "aes128_key"
    CCACHE_PATH = "ccache_path"


# Higher value = stronger admin claim.
# Domain-wide roles (DA, EA, BUILTIN\Administrator RID 500) always outrank
# host-specific local admin — DA credentials work on every machine in the
# domain, while LOCAL_ADMIN_VERIFIED is scoped to one host.  This ordering
# matters for flag collection: after a DCSync we have Administrator+hash and
# want that used for C$ PTH, not the narrower verified-admin account.
ROLE_PRIORITY: dict[CredentialPrivilegeRole, int] = {
    CredentialPrivilegeRole.DOMAIN_ADMIN: 300,
    CredentialPrivilegeRole.ENTERPRISE_ADMIN: 250,
    CredentialPrivilegeRole.BUILTIN_ADMINISTRATOR: 200,
    CredentialPrivilegeRole.LOCAL_ADMIN_VERIFIED: 100,
    # KRBTGT sits below admin tiers because it cannot authenticate as a
    # user — but above the kerberoast/asrep/standard pool because its
    # material unlocks Golden/Silver tickets which trump local admin in
    # blast radius. Kept out of `_LOCAL_ADMIN_TIERS` so the local-admin
    # picker never returns it.
    CredentialPrivilegeRole.KRBTGT: 70,
    CredentialPrivilegeRole.KERBEROASTABLE: 30,
    CredentialPrivilegeRole.ASREP_ROASTABLE: 30,
    CredentialPrivilegeRole.STANDARD: 0,
}

# Roles considered "admin-capable" — only these are returned by the
# local-admin picker. The picker's host-specific tier (LAV with
# matching host) is checked first, then this list in order.
_LOCAL_ADMIN_TIERS: tuple[CredentialPrivilegeRole, ...] = (
    CredentialPrivilegeRole.DOMAIN_ADMIN,
    CredentialPrivilegeRole.ENTERPRISE_ADMIN,
    CredentialPrivilegeRole.BUILTIN_ADMINISTRATOR,
)

# Within a tier prefer cleartext, then NT hash, then AES keys, then ccache.
_KIND_PREFERENCE: tuple[CredentialKind, ...] = (
    CredentialKind.PASSWORD,
    CredentialKind.NT_HASH,
    CredentialKind.AES256_KEY,
    CredentialKind.AES128_KEY,
    CredentialKind.CCACHE_PATH,
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _domain_data(shell: Any, domain: str) -> dict[str, Any] | None:
    """Return the per-domain bucket from ``shell.domains_data``."""
    domains = getattr(shell, "domains_data", None)
    if not isinstance(domains, MutableMapping):
        return None
    bucket = domains.get(domain)
    return bucket if isinstance(bucket, MutableMapping) else None


def _meta_bucket(domain_data: MutableMapping[str, Any]) -> dict[str, Any]:
    """Return (creating if needed) the ``credentials_meta`` sub-mapping."""
    meta = domain_data.get("credentials_meta")
    if not isinstance(meta, dict):
        meta = {}
        domain_data["credentials_meta"] = meta
    return meta


def _normalize_user(user: str) -> str:
    return (user or "").strip().lower()


def _looks_like_nt_hash(value: str) -> bool:
    """Detect NT hash form (32 hex) or LM:NT (32:32 hex)."""
    if not value:
        return False
    s = value.strip()
    if len(s) == 32 and all(c in "0123456789abcdefABCDEF" for c in s):
        return True
    if len(s) == 65 and s[32] == ":":
        left, right = s[:32], s[33:]
        return all(
            c in "0123456789abcdefABCDEF" for c in left + right
        )
    return False


def _infer_secret_kind(secret: str) -> CredentialKind:
    """Best-effort detection when no metadata is stored."""
    if _looks_like_nt_hash(secret or ""):
        return CredentialKind.NT_HASH
    return CredentialKind.PASSWORD


# ---------------------------------------------------------------------------
# Public read/write API
# ---------------------------------------------------------------------------


def get_credential_meta(
    shell: Any, *, domain: str, username: str
) -> dict[str, Any]:
    """Return a defensive copy of the metadata for ``username``.

    Defaults are filled for any missing key so callers never have to
    branch on absence. Returns an empty-default dict if the credential
    itself does not exist.
    """
    domain_data = _domain_data(shell, domain)
    if domain_data is None:
        return _default_meta()
    meta_map = domain_data.get("credentials_meta") or {}
    raw = meta_map.get(_normalize_user(username)) if isinstance(meta_map, dict) else None
    if not isinstance(raw, dict):
        return _default_meta()
    out = _default_meta()
    out.update(raw)
    return out


def _default_meta() -> dict[str, Any]:
    return {
        "secret_kind": None,
    }


def set_credential_kerberos_material(
    shell: Any,
    *,
    domain: str,
    username: str,
    aes256_key: str | None = None,
    aes128_key: str | None = None,
    kerberos_keys: tuple[tuple[str, str], ...] = (),
) -> None:
    """Persist additional Kerberos key material for ``username``.

    Kept separate from the primary credential string (NT hash / password)
    because the existing storage contract is a flat ``{user: secret}``
    map. AES256/AES128 keys and the full kerberos_keys tuple unlock
    pass-the-key, Golden Ticket, and Silver Ticket workflows; they are
    surfaced via metadata so consumers like the Golden Ticket forging
    flow can pick the strongest key without re-running DCSync.

    All values default to None / empty — passing the same field twice
    is idempotent and last-write-wins.
    """
    try:
        domain_data = _domain_data(shell, domain)
        if domain_data is None:
            return
        meta_map = _meta_bucket(domain_data)
        key = _normalize_user(username)
        if not key:
            return
        current = meta_map.get(key)
        if not isinstance(current, dict):
            current = _default_meta()
        if aes256_key:
            current["aes256_key"] = aes256_key
        if aes128_key:
            current["aes128_key"] = aes128_key
        if kerberos_keys:
            # Normalize to a list-of-pairs JSON-friendly shape.
            current["kerberos_keys"] = [
                [str(k_type), str(k_value)] for k_type, k_value in kerberos_keys
            ]
        meta_map[key] = current
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)


def set_credential_secret_kind(
    shell: Any,
    *,
    domain: str,
    username: str,
    secret_kind: CredentialKind,
) -> None:
    """Record only the secret_kind for username.

    Useful when a writer knows how to interpret the secret string
    (eg. AS-REP roast cracking returns a password regardless of the
    target's privilege).
    """
    try:
        domain_data = _domain_data(shell, domain)
        if domain_data is None:
            return
        meta_map = _meta_bucket(domain_data)
        key = _normalize_user(username)
        if not key:
            return
        current = meta_map.get(key)
        if not isinstance(current, dict):
            current = _default_meta()
        current["secret_kind"] = secret_kind.value
        meta_map[key] = current
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)


def set_credential_origin(
    shell: Any,
    *,
    domain: str,
    username: str,
    origin: str,
) -> None:
    """Record the provenance ``origin`` for ``username``'s credential.

    ``origin`` is the machine-readable source label for how this credential
    entered the store (for example ``kerberoast``, ``dcsync``, ``spray``,
    ``authenticated_scan`` for the scan's own STARTING credential, or
    ``user_provided`` for a manual ``creds save``). It is persisted into
    ``credentials_meta[username]["credential_origin"]`` so the ``creds show``
    Provenance column and the compromise SSOT can read it back.

    Two of these origins identify a self-introduced credential — the scan
    input or a manually entered one — and are excluded from the
    compromised-credential counters via
    :data:`adscan_internal.services.session_compromise_state_service.NON_COMPROMISE_ORIGINS`,
    while the credential remains a fully owned principal for attack-path
    discovery.

    Writes a JSON-safe string. Idempotent (last-write-wins); never raises.
    """
    try:
        normalized_origin = str(origin or "").strip()
        if not normalized_origin:
            return
        domain_data = _domain_data(shell, domain)
        if domain_data is None:
            return
        meta_map = _meta_bucket(domain_data)
        key = _normalize_user(username)
        if not key:
            return
        current = meta_map.get(key)
        if not isinstance(current, dict):
            current = _default_meta()
        current["credential_origin"] = normalized_origin
        meta_map[key] = current
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)


# ---------------------------------------------------------------------------
# Graph-driven role resolvers (canonical AD source of truth)
# ---------------------------------------------------------------------------


def _safe_get_identity_risk_record(
    shell: Any, *, domain: str, username: str
) -> Any:
    """Return the ADscan identity-risk record for ``username`` or None.

    Wraps :func:`adscan_internal.services.identity_risk_service.get_identity_risk_record`
    in a defensive try/except so callers in lightweight test contexts
    (where the service module or workspace dirs are absent) silently
    fall through. Never raises.
    """
    try:
        from adscan_internal.services.identity_risk_service import (
            get_identity_risk_record,
        )
    except Exception:  # noqa: BLE001
        return None
    try:
        return get_identity_risk_record(
            shell, domain=domain, samaccountname=username
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return None


def _safe_find_user_node(
    shell: Any, *, domain: str, username: str
) -> dict[str, Any] | None:
    """Locate the User node for ``username`` in the attack graph or None."""
    try:
        from adscan_internal.services.high_value import (
            _find_user_node_in_attack_graph,
        )
    except Exception:  # noqa: BLE001
        return None
    try:
        node = _find_user_node_in_attack_graph(
            shell, domain=domain, samaccountname=username
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return None
    return node if isinstance(node, dict) else None


def _safe_load_attack_graph(shell: Any, domain: str) -> dict[str, Any] | None:
    """Load the attack graph dict for ``domain`` or None on any failure."""
    try:
        from adscan_internal.services.attack_graph_service import (
            load_attack_graph,
        )
    except Exception:  # noqa: BLE001
        return None
    try:
        graph = load_attack_graph(shell, domain)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return None
    return graph if isinstance(graph, dict) else None


def _node_object_id(node: dict[str, Any]) -> str:
    """Best-effort SID/objectid extraction from an attack-graph node."""
    if not isinstance(node, dict):
        return ""
    raw = (
        node.get("objectId")
        or node.get("objectid")
        or node.get("id")
    )
    if not raw:
        props = node.get("properties")
        if isinstance(props, dict):
            raw = (
                props.get("objectid")
                or props.get("objectId")
                or props.get("sid")
            )
    return str(raw or "").strip()


def _rid_from_sid(sid: str) -> int | None:
    """Return the RID portion of a SID, or None when unparseable."""
    if not sid or "-" not in sid:
        return None
    tail = sid.rsplit("-", 1)[-1]
    try:
        return int(tail)
    except (TypeError, ValueError):
        return None


def _user_admin_to_host(
    graph: dict[str, Any] | None,
    *,
    user_node: dict[str, Any] | None,
    target_host: str,
) -> bool:
    """Return True when an ``AdminTo`` edge exists from user to ``target_host``.

    The host is matched by IP, FQDN, or hostname against any of the
    common label / property fields populated by the native collector.
    """
    if not isinstance(graph, dict) or not isinstance(user_node, dict):
        return False
    target = (target_host or "").strip().lower()
    if not target:
        return False

    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    if not isinstance(nodes_map, dict) or not nodes_map:
        return False

    user_id = _node_object_id(user_node)
    user_node_id = next(
        (nid for nid, n in nodes_map.items() if n is user_node), ""
    )

    host_ids: set[str] = set()
    for nid, node in nodes_map.items():
        if not isinstance(node, dict):
            continue
        kind = str(node.get("kind") or "")
        if kind != "Computer":
            continue
        candidates: list[str] = []
        label = str(node.get("label") or "")
        if label:
            candidates.append(label)
            candidates.append(label.split(".", 1)[0])
            candidates.append(label.split("@", 1)[0])
        props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
        for key in ("name", "dnshostname", "samaccountname", "ip", "ipaddress"):
            val = props.get(key)
            if isinstance(val, str) and val:
                candidates.append(val)
                candidates.append(val.split(".", 1)[0])
        if any(c.strip().lower() == target for c in candidates if c):
            host_ids.add(str(nid))

    if not host_ids:
        return False

    edges = graph.get("edges")
    if not isinstance(edges, list):
        return False
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        relation = str(edge.get("relation") or "").strip().lower()
        if relation != "admintto" and relation != "adminto":
            continue
        src = str(edge.get("source") or "")
        tgt = str(edge.get("target") or "")
        if tgt not in host_ids:
            continue
        if user_node_id and src == user_node_id:
            return True
        if user_id and src == user_id:
            return True
    return False


def _resolve_privilege_role_from_graph(
    shell: Any,
    *,
    domain: str,
    username: str,
    target_host: str | None = None,
    graph: dict[str, Any] | None = None,
    user_node: dict[str, Any] | None = None,
    risk_record: Any = None,
) -> CredentialPrivilegeRole:
    """Compute the privilege role of ``username`` from canonical AD data.

    Sources, in order of evaluation:

        1. RID == 500 from the user's SID in the attack graph
           → :attr:`CredentialPrivilegeRole.BUILTIN_ADMINISTRATOR`.
        2. RID == 502 → :attr:`CredentialPrivilegeRole.KRBTGT`.
        3. ADscan identity-risk-snapshot ``reasons``:

           * ``"domain_admins"``          → ``DOMAIN_ADMIN``
           * ``"enterprise_admins"``      → ``ENTERPRISE_ADMIN``
           * ``"builtin_administrators"`` → ``BUILTIN_ADMINISTRATOR``

        4. ``AdminTo`` edge from this user to ``target_host`` (when
           ``target_host`` is provided) → ``LOCAL_ADMIN_VERIFIED``.
        5. Otherwise → :attr:`CredentialPrivilegeRole.STANDARD`.

    Multiple matches resolve to the highest-priority via
    :data:`ROLE_PRIORITY`. Pure read; never raises (returns ``STANDARD``
    on any internal error).
    """
    try:
        if user_node is None:
            user_node = _safe_find_user_node(
                shell, domain=domain, username=username
            )
        candidates: list[CredentialPrivilegeRole] = []

        sid = _node_object_id(user_node) if user_node else ""
        rid = _rid_from_sid(sid)
        if rid == 500:
            candidates.append(CredentialPrivilegeRole.BUILTIN_ADMINISTRATOR)
        elif rid == 502:
            candidates.append(CredentialPrivilegeRole.KRBTGT)

        if risk_record is None:
            risk_record = _safe_get_identity_risk_record(
                shell, domain=domain, username=username
            )
        reasons: tuple[str, ...] = ()
        if isinstance(risk_record, dict):
            raw_reasons = risk_record.get("reasons") or ()
            reasons = tuple(str(r).strip().lower() for r in raw_reasons)
        else:
            raw_reasons = getattr(risk_record, "reasons", None)
            if raw_reasons:
                reasons = tuple(str(r).strip().lower() for r in raw_reasons)
        if "domain_admins" in reasons:
            candidates.append(CredentialPrivilegeRole.DOMAIN_ADMIN)
        if "enterprise_admins" in reasons:
            candidates.append(CredentialPrivilegeRole.ENTERPRISE_ADMIN)
        if "builtin_administrators" in reasons:
            candidates.append(CredentialPrivilegeRole.BUILTIN_ADMINISTRATOR)

        if target_host and user_node is not None:
            if graph is None:
                graph = _safe_load_attack_graph(shell, domain)
            if _user_admin_to_host(
                graph, user_node=user_node, target_host=target_host
            ):
                candidates.append(CredentialPrivilegeRole.LOCAL_ADMIN_VERIFIED)

        if not candidates:
            return CredentialPrivilegeRole.STANDARD
        return max(candidates, key=lambda r: ROLE_PRIORITY.get(r, 0))
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return CredentialPrivilegeRole.STANDARD


def _resolve_is_enabled(
    shell: Any,
    *,
    domain: str,
    username: str,
    user_node: dict[str, Any] | None = None,
) -> bool:
    """Return the best-available enabled signal for the AD account.

    Order:

        1. krbtgt (RID 502) is always treated as enabled — the
           ACCOUNTDISABLE bit is set by design and the account is
           fully operational for ticket forging.
        2. Attack-graph node property ``enabled`` (BloodHound-style;
           the native collector populates it).
        3. Default ``True``.

    Never raises.
    """
    try:
        if user_node is None:
            user_node = _safe_find_user_node(
                shell, domain=domain, username=username
            )
        if user_node is not None:
            sid = _node_object_id(user_node)
            if _rid_from_sid(sid) == 502:
                return True
            props = user_node.get("properties")
            if isinstance(props, dict) and "enabled" in props:
                return bool(props.get("enabled"))
        return True
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return True


# ---------------------------------------------------------------------------
# Picker
# ---------------------------------------------------------------------------


def pick_credential_for_local_admin(
    shell: Any,
    *,
    domain: str,
    target_host: str | None = None,
    require_cleartext: bool = False,
) -> tuple[str, str, CredentialKind] | None:
    """Return the best ``(username, secret, secret_kind)`` for local admin.

    Privilege classification is computed from the **canonical AD attack
    graph** (RID, identity-risk reasons, ``AdminTo`` edges) at read time
    via :func:`_resolve_privilege_role_from_graph`. ``credentials_meta``
    is consulted only for ``secret_kind`` (how to interpret the secret
    string); the legacy role / host / enabled hints were removed in
    Phase 2.

    Priority order (descending):

        1. ``LOCAL_ADMIN_VERIFIED`` resolved against ``target_host`` —
           most specific evidence (priority 1000).
        2. ``DOMAIN_ADMIN``.
        3. ``ENTERPRISE_ADMIN``.
        4. ``BUILTIN_ADMINISTRATOR`` (RID 500).
        5. ``None`` — no admin credential available.

    Within each tier, prefer cleartext password > NT hash > AES256 key >
    AES128 key > ccache path.

    Hard filters:
        * ``is_enabled`` (graph-driven) must be True.
        * If ``require_cleartext=True``, accounts whose only available
          secret is a hash / key / ccache are excluded.
        * KRBTGT is never returned (out of ``_LOCAL_ADMIN_TIERS``).

    Returns:
        ``(username, secret, kind)`` triple or ``None``.
    """
    domain_data = _domain_data(shell, domain)
    if domain_data is None:
        return None
    creds_map = domain_data.get("credentials") or {}
    if not isinstance(creds_map, dict) or not creds_map:
        return None
    meta_map = domain_data.get("credentials_meta") or {}
    if not isinstance(meta_map, dict):
        meta_map = {}

    # Cache the per-domain graph once so we don't re-read JSON per credential.
    graph_cache = _safe_load_attack_graph(shell, domain)

    candidates: list[tuple[int, int, str, str, CredentialKind]] = []

    for raw_user, raw_secret in creds_map.items():
        if not isinstance(raw_user, str) or not isinstance(raw_secret, str):
            continue
        secret = raw_secret
        if not secret:
            continue
        meta = meta_map.get(_normalize_user(raw_user))
        meta = meta if isinstance(meta, dict) else {}

        user_node = _safe_find_user_node(
            shell, domain=domain, username=raw_user
        )
        risk_record = _safe_get_identity_risk_record(
            shell, domain=domain, username=raw_user
        )

        # Graph-only role resolution.
        role = _resolve_privilege_role_from_graph(
            shell,
            domain=domain,
            username=raw_user,
            target_host=target_host,
            graph=graph_cache,
            user_node=user_node,
            risk_record=risk_record,
        )

        host_specific_lav = (
            role is CredentialPrivilegeRole.LOCAL_ADMIN_VERIFIED
            and bool(target_host)
        )

        if role not in _LOCAL_ADMIN_TIERS and not host_specific_lav:
            continue

        # Enabled filter — graph-driven.
        if not _resolve_is_enabled(
            shell,
            domain=domain,
            username=raw_user,
            user_node=user_node,
        ):
            continue

        # secret_kind from meta or inference.
        stored_kind = meta.get("secret_kind")
        try:
            kind = (
                CredentialKind(stored_kind)
                if stored_kind
                else _infer_secret_kind(secret)
            )
        except ValueError:
            kind = _infer_secret_kind(secret)

        if require_cleartext and kind is not CredentialKind.PASSWORD:
            continue

        if host_specific_lav:
            # Host-specific boost: still capped below DOMAIN_ADMIN (300) so
            # a DA credential is always preferred over a host-scoped local admin.
            priority = ROLE_PRIORITY[CredentialPrivilegeRole.LOCAL_ADMIN_VERIFIED] + 50  # 150
        elif role in _LOCAL_ADMIN_TIERS:
            priority = ROLE_PRIORITY[role]
        else:
            continue

        try:
            kind_score = -_KIND_PREFERENCE.index(kind)
        except ValueError:
            kind_score = -len(_KIND_PREFERENCE)

        candidates.append((priority, kind_score, raw_user, secret, kind))

    if not candidates:
        return None

    # Demote principals the target host has already denied a NETWORK logon
    # (ground truth from a prior probe) so a logon-capable credential is
    # auto-picked over a known-dead one — e.g. a DA denied network logon on the
    # DC (SeDenyNetworkLogonRight) no longer wins over another logon-capable DA /
    # local admin. The denied principal is RETAINED (last resort), so flags never
    # ends with zero candidates. The flags SMB byte-read is a network logon, so
    # the "network" denial bucket applies. host=None → order unchanged.
    if target_host:
        from adscan_internal.services.credential_store_service import (  # noqa: PLC0415
            is_logon_denied,
        )

        domains_data = getattr(shell, "domains_data", {}) or {}

        def _capable(row: tuple) -> int:
            return (
                0
                if is_logon_denied(
                    domains_data, domain, principal=row[2], host=target_host
                )
                else 1
            )

    else:

        def _capable(row: tuple) -> int:  # noqa: ARG001
            return 1

    # capable first (1 > 0), then priority, then kind preference — all descending.
    candidates.sort(key=lambda row: (_capable(row), row[0], row[1]), reverse=True)
    _prio, _kscore, user, secret, kind = candidates[0]
    return user, secret, kind


__all__ = [
    "CredentialPrivilegeRole",
    "CredentialKind",
    "ROLE_PRIORITY",
    "get_credential_meta",
    "set_credential_kerberos_material",
    "set_credential_origin",
    "set_credential_secret_kind",
    "pick_credential_for_local_admin",
]
