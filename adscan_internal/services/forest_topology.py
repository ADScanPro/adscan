"""Which forest a domain belongs to, and which in-scope domains share one.

The cleanup account's reach is bounded by the forest: an Enterprise Admin of a
forest root administers every domain of ITS forest and nothing across a forest
trust. So the capability checklist is sectioned by forest, and the per-domain
verdict needs to know whether the account and the domain share one.

Sources, most authoritative first, never guessed from a name alone:

1. ``domains_data[<domain>]["forest_dns_name"]``, recorded the first time the
   forest was established (below), so a later process reads it for free.
2. The trust SSOT ``domains_data[<d>]["trusts"]``: domains linked by a trust that
   carries the ``WITHIN_FOREST`` flag are one forest; its root is the member every
   other member's DNS name ends with.
3. The pre-authentication CLDAP netlogon ping (``forest_identity``): the same
   datagram a domain-joined workstation sends to locate a DC, whose reply carries
   ``DnsForestName``. Recorded under (1) once answered.

When none answers, the forest is unknown (``None``) and every consumer treats it
as such: an unknown forest is never read as "same forest".
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from adscan_core import telemetry
from adscan_core.rich_output import print_exception, print_info_debug

#: ``domains_data[<domain>]`` key holding the forest root's DNS name.
FOREST_KEY = "forest_dns_name"
_ASKED_ATTR = "_forest_root_pinged"


def _norm(value: Any) -> str:
    return str(value or "").strip().rstrip(".").lower()


def _domains_data(shell: Any) -> Mapping[str, Any]:
    data = getattr(shell, "domains_data", None)
    return data if isinstance(data, Mapping) else {}


def _entry(shell: Any, domain: str) -> Mapping[str, Any] | None:
    name = _norm(domain)
    for key, value in _domains_data(shell).items():
        if _norm(key) == name and isinstance(value, Mapping):
            return value
    return None


def _within_forest_partners(shell: Any, domain: str) -> set[str]:
    """Every known domain linked to ``domain`` by a WITHIN_FOREST trust, transitively."""
    data = _domains_data(shell)
    edges: dict[str, set[str]] = {}
    for key, entry in data.items():
        if not isinstance(entry, Mapping):
            continue
        source = _norm(key)
        for trust in entry.get("trusts") or ():
            if not isinstance(trust, Mapping):
                continue
            flags = {str(f).strip().upper() for f in (trust.get("attribute_flags") or ())}
            target = _norm(trust.get("target_domain"))
            if target and "WITHIN_FOREST" in flags:
                edges.setdefault(source, set()).add(target)
                edges.setdefault(target, set()).add(source)
    seen = {_norm(domain)}
    stack = [_norm(domain)]
    while stack:
        current = stack.pop()
        for partner in edges.get(current, ()):
            if partner not in seen:
                seen.add(partner)
                stack.append(partner)
    return seen


def _root_of_group(group: Iterable[str]) -> str | None:
    """The member every other member's DNS name ends with, or ``None``."""
    members = sorted({_norm(d) for d in group if _norm(d)}, key=len)
    for candidate in members:
        if all(m == candidate or m.endswith("." + candidate) for m in members):
            return candidate
    return None


def known_forest_root(shell: Any, domain: str) -> str | None:
    """The forest root from recorded data only (no network). ``None`` when unknown."""
    entry = _entry(shell, domain)
    recorded = _norm((entry or {}).get(FOREST_KEY))
    if recorded:
        return recorded
    group = _within_forest_partners(shell, domain)
    if len(group) > 1:
        return _root_of_group(group)
    return None


def _record_forest(shell: Any, domain: str, forest: str) -> None:
    entry = _entry(shell, domain)
    if isinstance(entry, dict) and forest:
        entry[FOREST_KEY] = forest


def resolve_forest_root(shell: Any, domain: str, *, allow_network: bool = True) -> str | None:
    """The forest root of ``domain``, recorded data first, then the CLDAP ping.

    Never raises. The ping is pre-authentication and one datagram; an answer is
    recorded under ``domains_data[<domain>]["forest_dns_name"]``.
    """
    known = known_forest_root(shell, domain)
    if known or not allow_network:
        return known
    # One ping per domain per session: an unanswered ping is not retried on every
    # call (it is never persisted either, so the next session asks again).
    asked = getattr(shell, _ASKED_ATTR, None)
    if not isinstance(asked, set):
        asked = set()
        try:
            setattr(shell, _ASKED_ATTR, asked)
        except Exception:  # noqa: BLE001
            pass
    if _norm(domain) in asked:
        return None
    asked.add(_norm(domain))
    try:
        from adscan_core.environment_ledger import SOURCE_NAME_ONLY  # noqa: PLC0415
        from adscan_internal.models.domain import resolve_dc_ip  # noqa: PLC0415
        from adscan_internal.services.async_bridge import run_async_sync  # noqa: PLC0415
        from adscan_internal.services.forest_identity import (  # noqa: PLC0415
            resolve_forest_identity,
        )

        entry = _entry(shell, domain) or {}
        dc_ip = resolve_dc_ip(entry) if entry else None
        if not dc_ip:
            return None
        identity = run_async_sync(resolve_forest_identity(_norm(domain), dc_ip))
        if identity is None or identity.source == SOURCE_NAME_ONLY:
            return None
        forest = _norm(identity.forest_dns_name)
        _record_forest(shell, domain, forest)
        print_info_debug(f"forest-topology domain={domain} forest={forest} via=cldap")
        return forest or None
    except Exception as exc:  # noqa: BLE001 - an unknown forest is an honest answer
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


def same_forest(
    shell: Any, first: str, second: str, *, allow_network: bool = True
) -> bool | None:
    """Whether two domains share a forest; ``None`` when that cannot be established."""
    a, b = _norm(first), _norm(second)
    if not a or not b:
        return None
    if a == b:
        return True
    root_a = resolve_forest_root(shell, a, allow_network=allow_network)
    root_b = resolve_forest_root(shell, b, allow_network=allow_network)
    if not root_a or not root_b:
        return None
    return root_a == root_b


def group_by_forest(
    shell: Any, domains: Iterable[str], *, allow_network: bool = True
) -> dict[str, list[str]]:
    """``{forest root: [domains]}``; a domain whose forest is unknown is its own key."""
    groups: dict[str, list[str]] = {}
    for domain in domains:
        name = _norm(domain)
        if not name:
            continue
        root = resolve_forest_root(shell, name, allow_network=allow_network) or name
        groups.setdefault(root, [])
        if name not in groups[root]:
            groups[root].append(name)
    return {root: sorted(members) for root, members in sorted(groups.items())}


def domain_sid(shell: Any, domain: str) -> str:
    """The domain's SID from the recorded data, or ``""``."""
    entry = _entry(shell, domain) or {}
    sid = str(entry.get("domain_sid") or "").strip()
    if sid:
        return sid
    try:
        from adscan_internal.services.membership_snapshot import (  # noqa: PLC0415
            load_membership_snapshot,
        )

        snapshot = load_membership_snapshot(shell, _norm(domain))
        if isinstance(snapshot, Mapping):
            return str(snapshot.get("domain_sid") or "").strip()
    except Exception as exc:  # noqa: BLE001 - absence is the honest answer
        telemetry.capture_exception(exc)
    return ""


__all__ = [
    "FOREST_KEY",
    "domain_sid",
    "group_by_forest",
    "known_forest_root",
    "resolve_forest_root",
    "same_forest",
]
