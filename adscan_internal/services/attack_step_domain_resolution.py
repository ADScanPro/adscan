"""Single source of truth for the two domain axes of an attack-STEP execution.

Every attack-step branch answers the same two questions before it authenticates:

- **SOURCE axis** — which forest owns the executing credential, so the credential's
  own AS-REQ / TGT mint goes to *that* forest's KDC. A cross-forest ESC (an owned
  principal in forest A holding enrollment rights on a template in trusted forest B)
  mints ``user@A`` against A's KDC, never B's.
- **TARGET axis** — which domain the action authenticates *into* (the realm of the
  object being acted upon). For a same-forest step this equals the path's domain;
  for a genuine cross-forest path it is the trusted domain the target object lives
  in, when ADscan actually collected that domain.

Historically these two axes were re-derived ad hoc in every branch, and many
branches dropped one of them and fell back to the single path ``domain`` — which
breaks cross-forest paths silently. Two correct-but-partial mechanisms already
existed: ``_resolve_esc_auth_context`` (source axis, ESC actions) and
``_node_domain`` (target axis, ACE relations); roasting grew its own parsers
(``_label_realm`` / ``_resolve_roast_target_domain``). This module is the shared
home those mechanisms fold into.

**Scope boundary — this SSOT resolves DOMAINS and their KDCs, nothing else.**
``source_kdc`` / ``target_kdc`` are the KDC IPs of a *domain* (resolved via the
``resolve_dc_ip`` SSOT and the cross-forest KDC SSOT — never a raw
``.get("pdc")``). Resolving a specific target *HOST*'s reachable IP (the
multi-homed member server a host-execution relation such as ``adminto`` /
``canrdp`` connects to) is ``host_address_resolver.resolve_host_address``'s job, a
SEPARATE concern. A host-execution branch takes ``source_domain`` + ``source_kdc``
from here (which forest mints the credential's TGT) and the target computer's
reachable IP from ``resolve_host_address`` at the branch. Do NOT make this SSOT
resolve host addresses.

**Well-known / broad-indeterminate SOURCE labels.** When ``from_label`` is a
well-known "all principals" group (Everyone / Authenticated Users / BUILTIN Users,
carrying a synthetic ``@WELLKNOWN`` / ``properties.domain="wellknown"``) or a broad
domain group with indeterminate membership (Domain Users / Domain Computers), the
source domain is NOT derivable from the label — the true source forest is the home
forest of whichever owned credential the actor SSOT ends up selecting, knowable
only after that selection. So ``resolve_step_domains`` returns
``source_domain = path_domain`` for these (byte-identical to today, where nothing
threads a source domain). The real well-known source-forest resolution belongs to
the actor SSOT in a later phase; this module never invents a source domain from a
well-known label, and never returns the ``"wellknown"`` placeholder.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adscan_internal.models.domain import resolve_dc_ip
from adscan_internal.services.cross_forest_kdc import (
    resolve_auth_kdc_for_cross_forest,
)

__all__ = [
    "StepDomains",
    "resolve_step_domains",
    "label_realm",
    "node_domain_raw",
    "normalize_domain_placeholder",
    "resolve_source_domain_and_kdc",
    "resolve_target_domain",
    "resolve_target_kdc",
]

# Synthetic placeholder domains carried by well-known / global principals. These
# are NOT real domains (there is no ``domains_data["wellknown"]``), so any caller
# that treats one as a realm and keys ``domains_data`` by it gets nothing. Compared
# case-insensitively; the collector writes ``"WELLKNOWN"`` on the node, ``_node_domain``
# lowercases it to ``"wellknown"``.
_PLACEHOLDER_DOMAINS: frozenset[str] = frozenset({"wellknown"})


@dataclass(frozen=True)
class StepDomains:
    """The resolved SOURCE and TARGET domains (and their KDCs) for one attack step.

    ``source_domain`` / ``source_kdc``:
        The forest that owns the executing credential and the KDC that receives its
        AS-REQ / TGT mint. For a same-forest step this equals ``path_domain`` and the
        target realm's DC. For a well-known / broad-indeterminate source label the
        source domain is NOT derivable here and falls back to ``path_domain``; the
        true source forest is the selected owned credential's domain, resolved by the
        actor SSOT in a later phase.

    ``target_domain`` / ``target_kdc``:
        The DOMAIN the action authenticates INTO, and that domain's DC. This is the
        realm of the object being acted upon — the path domain in the same-forest
        case, a collected trusted domain in a real cross-forest path. Resolving a
        specific target HOST's reachable IP (for host-execution relations) is
        ``host_address_resolver.resolve_host_address``'s job, NOT this SSOT's.
    """

    source_domain: str
    source_kdc: str | None
    target_domain: str
    target_kdc: str | None


def label_realm(value: str | None) -> str:
    """Return the realm qualifier of a principal label, or ``""`` when absent.

    ``PAXMOMVUA@awjom.zojij`` -> ``awjom.zojij``; ``AWJOM\\user`` -> ``AWJOM``;
    a bare ``user`` -> ``""``. Only extracts; the caller decides whether the realm
    is a collected domain worth targeting.
    """
    name = (value or "").strip()
    if "@" in name:
        return name.split("@", 1)[1].strip()
    if "\\" in name:
        return name.split("\\", 1)[0].strip()
    return ""


def node_domain_raw(node: dict[str, Any] | None) -> str | None:
    """Return a graph node's ``properties.domain`` lowercased, or ``None``.

    RAW graph truth — the synthetic ``"wellknown"`` placeholder is NOT normalized
    here (a caller that wants the placeholder collapsed to a concrete domain runs
    :func:`normalize_domain_placeholder` on top). This is the exact behaviour ACE's
    ``_node_domain`` has always had; the target-domain ladder in this module applies
    the placeholder normalization itself.
    """
    if not isinstance(node, dict):
        return None
    props = node.get("properties")
    if not isinstance(props, dict):
        return None
    value = props.get("domain")
    if isinstance(value, str) and value.strip():
        return value.strip().lower()
    return None


def normalize_domain_placeholder(domain: str | None, *, fallback: str) -> str:
    """Return ``domain`` unless it is a synthetic placeholder, then ``fallback``.

    Well-known SIDs (Everyone / Authenticated Users) carry ``domain="wellknown"``,
    a synthetic marker that is NOT a real domain. Any attempt to key
    ``domains_data["wellknown"]`` yields nothing, so this collapses the placeholder
    to the concrete ``fallback`` (the path domain) before it reaches a lookup.
    """
    value = str(domain or "").strip()
    if not value or value.lower() in _PLACEHOLDER_DOMAINS:
        return str(fallback or "").strip()
    return value


def _normalize_account(value: str | None) -> str:
    """Return the bare sAMAccountName of a principal label (``DOMAIN\\``/``@`` stripped)."""
    name = (value or "").strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name.strip().lower()


def _has_stored_credential(shell: Any, *, domain: str, username: str) -> bool:
    """Return whether ``username`` has a stored credential in ``domain``.

    Lazily imports the credential-store SSOT so this leaf module stays free of a
    module-level dependency on the heavier services graph.
    """
    from adscan_internal.services.credential_store_service import (
        get_stored_domain_credential_for_user,
    )

    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return False
    return bool(
        get_stored_domain_credential_for_user(
            domains_data, domain=domain, username=username
        )
    )


def resolve_source_domain_and_kdc(
    shell: Any,
    *,
    target_domain: str,
    exec_username: str | None,
    raw_principal_label: str | None = None,
) -> tuple[str, str]:
    """Resolve the ``(source_domain, source_kdc)`` for an execution credential.

    The SOURCE axis: which forest mints the credential's TGT. Same-forest is the
    common case (source equals ``target_domain``), but cross-forest execution is
    real — an owned principal in forest A acting against forest B mints against A's
    KDC, or B's KDC rejects it.

    The source realm is derived, in order:

    1. An explicit ``@realm`` / ``REALM\\`` qualifier on ``raw_principal_label``
       that differs from ``target_domain`` AND names a domain ADscan actually
       collected. A well-known ``@WELLKNOWN`` qualifier is never a collected domain,
       so it never matches — the well-known source stays on the ``target_domain``
       fallback (its true forest is the selected owned credential's, resolved later).
    2. Otherwise, the forest that holds ``exec_username``'s stored credential when
       that forest is NOT ``target_domain``.
    3. ``target_domain`` itself (same-forest).

    The KDC is resolved via the cross-forest SSOT so the source realm's DC receives
    the AS-REQ; same-forest, that is the target domain's PDC (identical to prior
    behaviour). Never reads a raw ``.get("pdc")``/``.get("dc_ip")`` for the primary
    resolution — only the historical last-resort fallback below preserves the exact
    legacy string.
    """
    target = (target_domain or "").strip()
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        domains_data = {}

    source_domain = target

    # 1. An explicit realm qualifier on the principal label that diverges.
    qualified_realm = label_realm(raw_principal_label)
    if qualified_realm and qualified_realm.lower() != target.lower():
        # Only trust a realm qualifier that names a domain ADscan actually knows.
        if any(
            isinstance(k, str) and k.lower() == qualified_realm.lower()
            for k in domains_data
        ):
            source_domain = qualified_realm

    # 2. Otherwise, find the forest that holds this principal's credential when it
    #    is NOT the target domain.
    if source_domain.lower() == target.lower() and exec_username:
        normalized = _normalize_account(exec_username)
        for candidate_domain, candidate_data in domains_data.items():
            if not isinstance(candidate_domain, str) or not isinstance(
                candidate_data, dict
            ):
                continue
            if candidate_domain.lower() == target.lower():
                continue
            if _has_stored_credential(
                shell, domain=candidate_domain, username=normalized
            ):
                source_domain = candidate_domain
                break

    source_kdc = str(
        resolve_auth_kdc_for_cross_forest(
            domains_data, auth_domain=source_domain, target_domain=target
        )
        or (
            domains_data.get(target, {}).get("pdc")
            if isinstance(domains_data.get(target), dict)
            else ""
        )
        or ""
    )
    return source_domain, source_kdc


def resolve_target_domain(
    shell: Any,
    *,
    to_label: str | None,
    node_domain: str | None = None,
    path_domain: str,
) -> str | None:
    """Resolve the domain the TARGET object lives in for a step.

    Preference order:

    1. ``node_domain`` — the graph node's own ``properties.domain`` (graph truth),
       when supplied and not a synthetic placeholder. A ``"wellknown"`` placeholder
       is collapsed to ``path_domain``.
    2. The realm qualifier of ``to_label`` — ``path_domain`` when it is absent or
       matches ``path_domain`` (single-domain / same-forest, byte-identical to the
       roast behaviour); the trusted domain's canonical (stored-casing) name when it
       names a DIFFERENT realm ADscan actually collected (a real cross-forest path);
       ``None`` when the realm was named but never collected (the caller then records
       an honest "not collected" outcome instead of acting on the wrong domain).

    Returns ``None`` ONLY for the "named-but-uncollected foreign realm" case reached
    via the label ladder — the roasting contract. When ``node_domain`` supplies a
    concrete domain the result is always a concrete domain.
    """
    path = str(path_domain or "").strip()

    # 1. Graph node truth (used by ACE relations), placeholder-normalized.
    if node_domain is not None:
        normalized = normalize_domain_placeholder(node_domain, fallback=path)
        if normalized:
            return normalized

    # 2. Label realm ladder (the roasting contract).
    realm = label_realm(to_label)
    if not realm or realm.lower() == path.lower():
        return path
    domains_data = getattr(shell, "domains_data", None)
    if isinstance(domains_data, dict):
        for candidate_domain in domains_data:
            if (
                isinstance(candidate_domain, str)
                and candidate_domain.lower() == realm.lower()
            ):
                return candidate_domain  # preserve stored casing
    return None


def resolve_target_kdc(shell: Any, *, target_domain: str | None) -> str | None:
    """Return the KDC IP of ``target_domain`` via the ``resolve_dc_ip`` SSOT.

    ``None`` when the domain is unknown / has no resolvable DC. Never reads a raw
    ``.get("pdc")``/``.get("dc_ip")`` — the fallback chain lives inside
    ``resolve_dc_ip``.
    """
    domain = str(target_domain or "").strip()
    if not domain:
        return None
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return None
    record = domains_data.get(domain)
    if not isinstance(record, dict):
        return None
    return resolve_dc_ip(record)


def resolve_step_domains(
    shell: Any,
    *,
    from_label: str | None,
    to_label: str | None,
    path_domain: str,
    to_node: dict[str, Any] | None = None,
    exec_username: str | None = None,
) -> StepDomains:
    """Resolve both domain axes (source + target) and their KDCs for one step.

    Composes the two ladders: ``resolve_source_domain_and_kdc`` (source forest that
    mints the credential's TGT) and ``resolve_target_domain`` /
    ``resolve_target_kdc`` (the domain the action authenticates into). ``to_node``,
    when a graph node with ``properties.domain``, feeds the target ladder's
    graph-truth preference; otherwise the label realm is used. The synthetic
    ``"wellknown"`` placeholder is normalized to ``path_domain`` (source AND target),
    so no caller ever keys ``domains_data["wellknown"]``.

    A target realm named on the label but never collected yields
    ``target_domain = path_domain`` here (the composed resolver keeps a concrete
    domain for downstream KDC resolution); callers that need the roasting
    "not-collected -> None" distinction call ``resolve_target_domain`` directly.
    """
    path = str(path_domain or "").strip()

    source_domain, source_kdc = resolve_source_domain_and_kdc(
        shell,
        target_domain=path,
        exec_username=exec_username,
        raw_principal_label=from_label,
    )

    resolved_target = resolve_target_domain(
        shell,
        to_label=to_label,
        node_domain=node_domain_raw(to_node),
        path_domain=path,
    )
    target_domain = resolved_target or path
    target_kdc = resolve_target_kdc(shell, target_domain=target_domain)

    return StepDomains(
        source_domain=source_domain,
        source_kdc=source_kdc or None,
        target_domain=target_domain,
        target_kdc=target_kdc,
    )
