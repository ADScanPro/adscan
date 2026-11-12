"""Engagement scope SSOT: is this domain one the scan may act against?

ONE question, answered here and nowhere else, consulted at the execution seams
every attack step passes through before it runs:

* the attack-path executor's per-step loop
  (``cli/attack_path_execution.py``), and its readiness overlay, so a route
  whose next step leaves the scope is never offered to run;
* the post-compromise cross-domain escalation drain
  (``services/cross_domain_escalation.py``), which fires escalations outside
  any attack path;
* the two cross-domain technique runners themselves (``run_raise_child`` and
  ``run_cross_org_tgt_delegation_step``), so a manual command cannot reach past
  the scope either.

The collection has its own seam, :func:`collection_host_verdict`: the
multi-domain flow collects each domain separately, so a domain's collection
connects only to hosts that domain owns (a CA hosted in the parent domain, a
DC of another domain the forest Configuration NC lists, an SQL host another
domain's SPN names). A host of another domain is collected with that domain,
and only when it is in scope; from elsewhere it stays mapped from directory
data and is reported as not checked.

Scope is contractual. It is settled before collection by the trust-scope
decision (the request's trusted-domain setting, the scan policy, or the
operator) and recorded here, in memory on the shell and in the workspace
``scope.json`` for disclosure. No surface asks per step whether to cross it: the
operator widens the scope before the scan, never mid-route.

Verdict ladder for one domain (first match wins):

1. no domain at all (it could not be determined) -> OUT;
2. the synthetic well-known placeholder -> IN (it is not a domain);
3. an origin (the domain the scan targets, or one the trust decision started
   from) -> IN;
4. a recorded trust decision -> its answer (an explicit exclusion always wins);
5. the domain the route itself was computed for -> IN (computing a route there
   needed that domain enumerated, which was itself a scope decision);
6. a policy that follows trusts on its own (``scope_expansion = automatic``,
   Lab / CTF only) -> IN;
7. otherwise -> OUT: a domain nobody put in scope is not in scope.

An attack step is checked on BOTH axes the step-domain SSOT
(``attack_step_domain_resolution``) defines: the acting object and the target.
Either one outside the scope keeps the step from running, whatever the object
is (the domain itself, a user, group, computer, certificate authority...).
"""

from __future__ import annotations

import os
import re
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from dataclasses import fields as dataclass_fields
from typing import Any, Callable, Iterable, Iterator, Mapping

from adscan_core import telemetry
from adscan_core.reporting.engagement_scope import (
    NOT_EXECUTED_OUTSIDE_SCOPE,
    domains_named,
    scope_note,
)
from adscan_core.rich_output import print_exception, print_info, print_info_debug
from adscan_core.scan_policy import settings as policy_settings
from adscan_internal.rich_output import mark_sensitive

#: Shell attribute holding this session's scope record (never ``domains_data``:
#: it is session state, not workspace data).
_RECORD_ATTR = "_engagement_scope_record"
#: Shell attribute holding the (relation, to) keys already announced.
_ANNOUNCED_ATTR = "_engagement_scope_announced"

SCOPE_FILENAME = "scope.json"

#: Verdict bases.
BASIS_UNDETERMINED = "undetermined"
BASIS_PLACEHOLDER = "not_a_domain"
BASIS_ORIGIN = "origin"
BASIS_SELECTED = "selected"
BASIS_EXCLUDED = "excluded"
BASIS_PATH_DOMAIN = "path_domain"
BASIS_POLICY_AUTOMATIC = "policy_automatic"
BASIS_NOT_CONFIRMED = "not_confirmed"

_PLACEHOLDERS = frozenset({"wellknown"})
_DN_DC = re.compile(r"(?i)\bDC=([^,]+)")


@dataclass(frozen=True)
class ScopeVerdict:
    """Whether one domain is in the engagement scope, and why."""

    domain: str
    in_scope: bool
    basis: str


@dataclass(frozen=True)
class StepScopeVerdict:
    """The scope verdict for one attack step (both axes)."""

    allowed: bool
    source: ScopeVerdict
    target: ScopeVerdict

    @property
    def out_of_scope_domain(self) -> str:
        """The first domain that keeps the step from running ("" when allowed)."""
        for verdict in (self.target, self.source):
            if not verdict.in_scope:
                return verdict.domain
        return ""


# ── The record ─────────────────────────────────────────────────────────────


def _norm(value: Any) -> str:
    return str(value or "").strip().rstrip(".").lower()


def _record(shell: Any) -> dict[str, Any]:
    record = getattr(shell, _RECORD_ATTR, None)
    if not isinstance(record, dict):
        record = {"origin_domains": [], "entries": {}, "decided_by": "", "withheld": []}
        try:
            setattr(shell, _RECORD_ATTR, record)
        except Exception:  # noqa: BLE001 - a frozen double still gets an answer
            pass
    return record


def _workspace_dir(shell: Any) -> str:
    for attr in ("current_workspace_dir", "current_workspace"):
        value = getattr(shell, attr, None)
        if isinstance(value, (str, os.PathLike)) and str(value):
            return os.fspath(value)
    return ""


def record_trust_scope_decision(
    shell: Any,
    *,
    source_domain: str,
    entries: Iterable[Any],
    decided_by: str,
) -> None:
    """Record one trust-scope decision and write the workspace ``scope.json``.

    Successive decisions in the same session MERGE: a domain offered again takes
    the new answer, a domain not offered keeps the earlier one, and a domain the
    session already put in scope stays in scope when a later decision merely
    leaves it unselected because it was already enumerated (the pivot flow).

    Args:
        shell: The session shell.
        source_domain: The domain the trust enumeration started from (always in
            scope: the scan was pointed at it, or reached it in scope).
        entries: ``collector.scope.ScopeEntry`` rows, one per offered domain.
        decided_by: Who settled it (``adscan_core.reporting.engagement_scope``
            ``DECIDED_BY_*``).
    """
    record = _record(shell)
    origin = _norm(source_domain)
    if origin and origin not in record["origin_domains"]:
        record["origin_domains"].append(origin)
    stored: dict[str, dict[str, Any]] = record["entries"]
    for entry in entries or ():
        row = asdict(entry) if not isinstance(entry, Mapping) else dict(entry)
        name = _norm(row.get("domain"))
        if not name:
            continue
        previous = stored.get(name)
        keep_in = bool(previous and previous.get("in_scope") is True)
        row["in_scope"] = bool(row.get("in_scope")) or keep_in or name == origin
        stored[name] = row
    if decided_by:
        record["decided_by"] = str(decided_by)
    _save(shell)


def _save(shell: Any) -> None:
    """Write the session record to ``<workspace>/scope.json`` (best effort)."""
    workspace = _workspace_dir(shell)
    if not workspace:
        return
    try:
        from adscan_internal.services.collector.scope import (  # noqa: PLC0415
            ScopeEntry,
            ScopeResult,
            save_scope,
        )

        record = _record(shell)
        fields = {f.name for f in dataclass_fields(ScopeEntry)}
        entries = [
            ScopeEntry(**{k: v for k, v in row.items() if k in fields})
            for row in record["entries"].values()
        ]
        save_scope(
            ScopeResult(entries=entries),
            os.path.join(workspace, SCOPE_FILENAME),
            extra={
                "origin_domains": list(record["origin_domains"]),
                "decided_by": record.get("decided_by") or "",
                "withheld": list(record["withheld"]),
            },
        )
    except Exception as exc:  # noqa: BLE001 - disclosure never breaks the scan
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def origin_domains(shell: Any) -> list[str]:
    """The domains the scan targets (always in scope)."""
    names = list(_record(shell)["origin_domains"])
    primary = _norm(getattr(shell, "domain", None))
    if primary and primary not in names:
        names.append(primary)
    return names


def _known_domains(shell: Any) -> list[str]:
    """Every AD domain the session knows of, from recorded data only.

    A recorded forest root counts (``forest_topology.FOREST_KEY``): it is a real
    domain even when nothing of it was collected, and without it a host of the
    root (``ca.<root>``) seen from a child's records matched no known suffix and
    was attributed to the child, so the child's checks contacted it.
    """
    from adscan_internal.services.forest_topology import FOREST_KEY  # noqa: PLC0415

    known: list[str] = []
    domains_data = getattr(shell, "domains_data", None)
    if isinstance(domains_data, Mapping):
        known.extend(_norm(k) for k in domains_data.keys())
        for entry in domains_data.values():
            if isinstance(entry, Mapping) and entry.get(FOREST_KEY):
                known.append(_norm(entry.get(FOREST_KEY)))
    known.extend(_record(shell)["entries"].keys())
    known.extend(origin_domains(shell))
    return [d for d in domains_named(known) if d not in _PLACEHOLDERS]


# ── The verdict ────────────────────────────────────────────────────────────


def domain_scope_verdict(
    shell: Any, domain: str | None, *, path_domain: str | None = None
) -> ScopeVerdict:
    """Return whether ``domain`` is in the engagement scope (see module ladder)."""
    name = _norm(domain)
    if not name:
        return ScopeVerdict("", False, BASIS_UNDETERMINED)
    if name in _PLACEHOLDERS:
        return ScopeVerdict(name, True, BASIS_PLACEHOLDER)
    if name in origin_domains(shell):
        return ScopeVerdict(name, True, BASIS_ORIGIN)
    recorded = _record(shell)["entries"].get(name)
    if isinstance(recorded, Mapping):
        if recorded.get("in_scope") is True:
            return ScopeVerdict(name, True, BASIS_SELECTED)
        return ScopeVerdict(name, False, BASIS_EXCLUDED)
    if path_domain and name == _norm(path_domain):
        return ScopeVerdict(name, True, BASIS_PATH_DOMAIN)
    try:
        if policy_settings.expands_scope_automatically(shell):
            return ScopeVerdict(name, True, BASIS_POLICY_AUTOMATIC)
    except Exception as exc:  # noqa: BLE001 - unknown policy: not confirmed
        telemetry.capture_exception(exc)
    return ScopeVerdict(name, False, BASIS_NOT_CONFIRMED)


def domain_in_engagement_scope(
    shell: Any, domain: str | None, *, path_domain: str | None = None
) -> bool:
    """Boolean form of :func:`domain_scope_verdict`."""
    return domain_scope_verdict(shell, domain, path_domain=path_domain).in_scope


def _domain_from_dn(dn: Any) -> str:
    parts = _DN_DC.findall(str(dn or ""))
    return ".".join(p.strip().lower() for p in parts if p.strip())


def _longest_known_suffix(name: str, known: list[str]) -> str:
    best = ""
    for domain in known:
        if (name == domain or name.endswith("." + domain)) and len(domain) > len(best):
            best = domain
    return best


def object_domain(
    shell: Any,
    *,
    label: str | None,
    path_domain: str,
    dn: str | None = None,
    dnshostname: str | None = None,
) -> str | None:
    """The domain an attack-graph object belongs to, or ``None`` if undeterminable.

    Mirrors the step-domain SSOT (``attack_step_domain_resolution``): graph truth
    first (the object's distinguished name), then the label's realm, with a bare
    account name belonging to the route's own domain. On top of it, a dotted
    label or DNS host name (a computer, a domain object) is matched to the
    longest known domain suffix, so a host of the parent domain is never read as
    a host of the child the route was computed for.
    """
    from_dn = _domain_from_dn(dn)
    if from_dn:
        return from_dn
    known = _known_domains(shell)
    path = _norm(path_domain)
    text = str(label or "").strip()
    if "@" in text:
        realm = _norm(text.split("@", 1)[1])
        if not realm or realm in _PLACEHOLDERS:
            return path or None
        return _longest_known_suffix(realm, known) or realm
    if "\\" in text:
        netbios = _norm(text.split("\\", 1)[0])
        return _domain_for_netbios(shell, netbios, known)
    host = _norm(dnshostname)
    if host:
        matched = _longest_known_suffix(host, known)
        if matched:
            return matched
        return host.split(".", 1)[1] if "." in host else (path or None)
    lowered = _norm(text)
    if lowered and "." in lowered:
        matched = _longest_known_suffix(lowered, known)
        if matched:
            return matched
    return path or None


def _domain_for_netbios(shell: Any, netbios: str, known: list[str]) -> str | None:
    if not netbios:
        return None
    domains_data = getattr(shell, "domains_data", None)
    if isinstance(domains_data, Mapping):
        for name, data in domains_data.items():
            if not isinstance(data, Mapping):
                continue
            for key in ("netbios", "netbios_domain"):
                if _norm(data.get(key)) == netbios:
                    return _norm(name)
    for domain in known:
        if domain.split(".", 1)[0] == netbios:
            return domain
    return None


def step_scope_verdict(
    shell: Any,
    *,
    path_domain: str,
    from_label: str | None,
    to_label: str | None,
    details: Mapping[str, Any] | None = None,
) -> StepScopeVerdict:
    """Check one attack step on both axes: the acting object and the target."""
    details = details if isinstance(details, Mapping) else {}
    source_domain = object_domain(
        shell,
        label=from_label,
        path_domain=path_domain,
        dn=details.get("source_dn"),
        dnshostname=details.get("source_dnshostname"),
    )
    target_domain = object_domain(
        shell,
        label=to_label,
        path_domain=path_domain,
        dn=details.get("target_dn"),
        dnshostname=details.get("target_dnshostname"),
    )
    source = domain_scope_verdict(shell, source_domain, path_domain=path_domain)
    target = domain_scope_verdict(shell, target_domain, path_domain=path_domain)
    return StepScopeVerdict(
        allowed=source.in_scope and target.in_scope, source=source, target=target
    )


# ── Collection: which hosts a domain's collection may contact ──────────────

#: Collection host verdict reasons.
HOST_OWNED_BY_COLLECTING_DOMAIN = "owned_by_collecting_domain"
HOST_IN_OTHER_DOMAIN = "host_in_other_domain"
HOST_OUTSIDE_SCOPE = NOT_EXECUTED_OUTSIDE_SCOPE

#: Shell attribute holding the (collecting domain, host) pairs already announced.
_HOST_ANNOUNCED_ATTR = "_engagement_scope_host_announced"


@dataclass(frozen=True)
class CollectionHostVerdict:
    """Whether the collection of one domain may open a connection to a host."""

    host: str
    host_domain: str
    collecting_domain: str
    allowed: bool
    reason: str


def _is_ip_literal(value: str) -> bool:
    import ipaddress  # noqa: PLC0415

    try:
        ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return False
    return True


def host_owner_domain(
    shell: Any,
    host: str | None,
    *,
    collecting_domain: str,
    host_dn: str | None = None,
) -> str:
    """The AD domain that owns ``host``, as seen from ``collecting_domain``'s data.

    Graph truth first: the host's distinguished name, when the caller has it.
    Otherwise its DNS name is matched to the longest KNOWN domain suffix, so a
    host of the parent domain is never read as a host of the child collecting
    it. A DNS name under no known domain (a disjoint DNS namespace), an IP
    literal or a bare name came from the collecting domain's own records and is
    attributed to it.
    """
    collecting = _norm(collecting_domain)
    from_dn = _domain_from_dn(host_dn)
    if from_dn:
        return from_dn
    name = _norm(host)
    if not name or "." not in name or _is_ip_literal(name):
        return collecting
    known = list(dict.fromkeys([*_known_domains(shell), *([collecting] if collecting else [])]))
    return _longest_known_suffix(name, known) or collecting


def collection_host_verdict(
    shell: Any,
    *,
    host: str | None,
    collecting_domain: str,
    host_dn: str | None = None,
) -> CollectionHostVerdict:
    """May the collection of ``collecting_domain`` connect to ``host``?

    The multi-domain flow collects every domain on its own, so a domain's
    collection opens connections ONLY to hosts that domain owns. A host owned by
    another domain is read when that domain is collected, and only if it is in
    the engagement scope; from here it stays mapped from directory data and is
    never contacted. Collecting a domain is itself the scope decision for its
    own hosts. The one exception, trust relationships, is read from the
    collecting domain's own DC and never reaches this check.
    """
    collecting = _norm(collecting_domain)
    owner = host_owner_domain(
        shell, host, collecting_domain=collecting, host_dn=host_dn
    )
    host_text = str(host or "").strip()
    if not owner or owner == collecting:
        return CollectionHostVerdict(
            host_text, owner or collecting, collecting, True, HOST_OWNED_BY_COLLECTING_DOMAIN
        )
    reason = (
        HOST_IN_OTHER_DOMAIN if domain_in_engagement_scope(shell, owner) else HOST_OUTSIDE_SCOPE
    )
    return CollectionHostVerdict(host_text, owner, collecting, False, reason)


def collection_host_skip_line(verdict: CollectionHostVerdict, what: str, *, marked: bool = True) -> str:
    """The operator line for a host a domain's collection did not contact."""
    from rich.markup import escape  # noqa: PLC0415

    def _m(value: str, kind: str) -> str:
        return mark_sensitive(escape(value), kind) if marked else escape(value)

    host = _m(verdict.host, "hostname")
    owner = _m(verdict.host_domain, "domain")
    collecting = _m(verdict.collecting_domain, "domain")
    if verdict.reason == HOST_UNDETERMINED:
        tail = (
            "the domain of that host could not be determined, so it was not "
            "contacted; it stays mapped from directory data."
        )
    elif verdict.reason == HOST_OUTSIDE_SCOPE:
        tail = (
            f"{owner} is outside the engagement scope, so it was not contacted; "
            "it stays mapped from directory data."
        )
    else:
        tail = (
            f"it belongs to {owner}, so it is checked when that domain is "
            f"collected, not from {collecting}; it stays mapped from directory data."
        )
    return f"{escape(what)} on {host} not checked: {tail}"


def note_collection_host_skipped(
    shell: Any, verdict: CollectionHostVerdict, *, what: str
) -> None:
    """Announce a host the collection did not contact (once per domain and host)."""
    key = (verdict.collecting_domain, _norm(verdict.host), verdict.reason)
    announced = getattr(shell, _HOST_ANNOUNCED_ATTR, None)
    if not isinstance(announced, set):
        announced = set()
        try:
            setattr(shell, _HOST_ANNOUNCED_ATTR, announced)
        except Exception:  # noqa: BLE001
            pass
    first = key not in announced
    announced.add(key)
    if first:
        print_info(collection_host_skip_line(verdict, what))
    print_info_debug(
        "collection-host skip: "
        f"what={mark_sensitive(what, 'detail')} reason={verdict.reason} "
        f"host={mark_sensitive(verdict.host, 'hostname')} "
        f"owner={mark_sensitive(verdict.host_domain or '?', 'domain')} "
        f"collecting={mark_sensitive(verdict.collecting_domain, 'domain')}"
    )


# ── Linked SQL servers: the far side of a link is another host ──────────────

#: The linked server's host has no domain anyone can determine (an empty data
#: source, or a bare name or IP the inventory does not resolve): never
#: contacted, never assumed in scope.
HOST_UNDETERMINED = "host_domain_undetermined"

#: The domain whose collection is running in this context ("" outside one).
#: ``asyncio.to_thread`` and task creation copy it, so a collector's worker
#: threads see the domain they collect for.
_COLLECTING_DOMAIN: ContextVar[str] = ContextVar("adscan_collecting_domain", default="")

#: The session shell the MSSQL transport consults (dependency inversion: the
#: transport never receives a shell), held weakly so it ends with the session.
#: ``None`` outside a session (lab scripts, unit tests): there is no engagement
#: to hold a query to.
_SCOPE_SHELL_REF: Callable[[], Any] | None = None


@contextmanager
def collecting_domain_context(domain: str) -> Iterator[None]:
    """Mark the code inside as the collection of ``domain``."""
    token = _COLLECTING_DOMAIN.set(_norm(domain))
    try:
        yield
    finally:
        _COLLECTING_DOMAIN.reset(token)


def current_collecting_domain() -> str:
    """The domain being collected in this context, ``""`` outside a collection."""
    return _COLLECTING_DOMAIN.get()


def register_scope_shell(shell: Any) -> None:
    """Bind this session's shell to the transport seams that consult the scope."""
    import weakref  # noqa: PLC0415

    global _SCOPE_SHELL_REF  # noqa: PLW0603 - one session per process
    if shell is None:
        _SCOPE_SHELL_REF = None
        return
    try:
        _SCOPE_SHELL_REF = weakref.ref(shell)
    except TypeError:
        _SCOPE_SHELL_REF = lambda: shell  # noqa: E731 - unweakrefable double


def _scope_shell() -> Any:
    ref = _SCOPE_SHELL_REF
    return ref() if ref is not None else None


def linked_server_gate_active() -> bool:
    """Whether queries through a linked server are held to an engagement."""
    return _scope_shell() is not None


def linked_server_host(data_source: str | None) -> str:
    """The host a linked server's ``data_source`` names, without provider or instance.

    ``tcp:sql02.corp.example,1433`` and ``SQL02\\INST`` become ``sql02.corp.example``
    and ``sql02``. IPv6 literals are kept intact.
    """
    host = str(data_source or "").strip()
    if not host:
        return ""
    if ":" in host and host.count(":") == 1:
        prefix, _, rest = host.partition(":")
        if prefix.isalpha() and rest:
            host = rest
    host = host.split("\\", 1)[0].split(",", 1)[0]
    return host.strip().rstrip(".").lower()


#: Shell attribute caching the inventory index per domain and graph version.
_INVENTORY_ATTR = "_engagement_scope_inventory_index"

#: Verdict reason of a linked host the scope allows.
HOST_IN_SCOPE = "in_engagement_scope"


def _inventory_index(shell: Any, domain: str) -> Any:
    """The domain's computer inventory as the alias-aware asset index (cached).

    Built from the workspace ``attack_graph.json`` of ``domain`` through
    ``affected_assets_struct`` (sAMAccountName, name, DNS name, short name, IP),
    and rebuilt only when that file changes. ``None`` when there is none.
    """
    workspace = _workspace_dir(shell)
    name = _norm(domain)
    if not workspace or not name:
        return None
    path = os.path.join(workspace, "domains", name, "attack_graph.json")
    try:
        stamp = os.stat(path).st_mtime_ns
    except OSError:
        return None
    cache = getattr(shell, _INVENTORY_ATTR, None)
    if not isinstance(cache, dict):
        cache = {}
        try:
            setattr(shell, _INVENTORY_ATTR, cache)
        except Exception:  # noqa: BLE001 - a frozen double rebuilds every time
            pass
    cached = cache.get(name)
    if isinstance(cached, tuple) and cached[0] == stamp:
        return cached[1]
    try:
        from adscan_internal.services.affected_assets_struct import (  # noqa: PLC0415
            load_asset_index,
        )

        index = load_asset_index(workspace, name)
    except Exception as exc:  # noqa: BLE001 - unresolved stays undeterminable
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None
    cache[name] = (stamp, index)
    return index


def resolve_linked_server_host(
    shell: Any, host: str, *, inventory_domain: str | None
) -> tuple[str, str]:
    """Resolve a bare name or IP to ``(dns_name, domain)`` through an inventory.

    Looks the token up in ``inventory_domain``'s computer inventory, alias-aware
    (sAMAccountName, name, short name, IP). Only a directory object counts: a
    node with a distinguished name, whose domain is read from that DN (graph
    truth). A placeholder for a host seen only as a link target, or no match,
    returns ``("", "")``.
    """
    index = _inventory_index(shell, inventory_domain or "")
    if index is None:
        return "", ""
    node = index.lookup(host, f"{host}$")
    if node is None or str(getattr(node, "kind", "")).lower() != "computer":
        return "", ""
    owner = _domain_from_dn(getattr(node, "dn", ""))
    if not owner:
        return "", ""
    fqdn = _norm(getattr(node, "fqdn", "")) or _norm(getattr(node, "name", ""))
    return (fqdn if "." in fqdn else ""), owner


def linked_server_target_verdict(
    shell: Any,
    *,
    data_source: str | None,
    collecting_domain: str | None = None,
) -> CollectionHostVerdict:
    """May a query run on the FAR side of a linked server whose data source is this?

    A query sent ``AT [link]`` or through ``OPENQUERY`` executes on the linked
    host and makes it accept a sign-in through the link, so it is a contact with
    that host. Reading the links of an instance (``sys.servers``) is not, and
    stays allowed like reading a trust.

    The engagement SCOPE decides, for a collection's read-only probes and for an
    attack step alike. Ownership does not: a linked server is reachable only
    through the instance that links to it, so no other domain's collection will
    ever probe it (the same reasoning as the trust exception).

    The host's domain comes from its DNS name (:func:`object_domain`). A bare
    name or an IP is resolved through ``collecting_domain``'s computer inventory
    (the domain whose instance holds the link), and a resolved host takes the
    domain of its directory object. Anything still unresolved has no
    determinable domain, and is neither in scope nor contacted.
    """
    collecting = _norm(collecting_domain)
    host = linked_server_host(data_source)
    owner = ""
    if host and "." in host and not _is_ip_literal(host):
        owner = _norm(
            object_domain(shell, label=None, path_domain=collecting, dnshostname=host)
        )
    elif host:
        fqdn, owner = resolve_linked_server_host(shell, host, inventory_domain=collecting)
        host = fqdn or host
    if not owner:
        return CollectionHostVerdict(host, "", collecting, False, HOST_UNDETERMINED)
    if not domain_in_engagement_scope(shell, owner):
        return CollectionHostVerdict(host, owner, collecting, False, HOST_OUTSIDE_SCOPE)
    return CollectionHostVerdict(host, owner, collecting, True, HOST_IN_SCOPE)


def linked_server_query_refusal(
    *, data_source: str | None, inventory_domain: str | None = None
) -> CollectionHostVerdict | None:
    """The transport-level check for one query through a link (``None``: allowed).

    Consulted by the MSSQL transport for every query that names a linked server,
    whatever built it, so a new caller cannot reach past a link the scope keeps
    closed. ``inventory_domain`` is the domain whose inventory resolves a bare
    name or IP: the collecting domain inside a collection, else the domain of
    the instance holding the link. Without a session shell there is no
    engagement to hold the query to, and it runs.
    """
    shell = _scope_shell()
    if shell is None:
        return None
    verdict = linked_server_target_verdict(
        shell,
        data_source=data_source,
        collecting_domain=current_collecting_domain() or inventory_domain or None,
    )
    return None if verdict.allowed else verdict


def scope_entry(shell: Any, domain: str | None) -> Mapping[str, Any] | None:
    """The recorded trust-scope row for ``domain`` (``None`` when not recorded)."""
    row = _record(shell)["entries"].get(_norm(domain))
    return row if isinstance(row, Mapping) else None


# ── Refusal ────────────────────────────────────────────────────────────────


def outside_scope_line(action: str, target: str, domain: str, *, marked: bool = True) -> str:
    """The operator line for a step the scope kept from running.

    ``marked`` wraps the domain and target for the telemetry sanitizer (the
    terminal line); the persisted execution event takes the plain form.
    """
    from rich.markup import escape  # noqa: PLC0415

    def _m(value: str, kind: str) -> str:
        return mark_sensitive(escape(value), kind) if marked else value

    where = _m(domain, "domain") if domain else "a domain that could not be determined"
    subject = f"{escape(action)} on {_m(target, 'node')}" if target else escape(action)
    return (
        f"{subject} not executed: {where} is outside the engagement scope. "
        "Widen the scope before the scan (trusted-domain setting) to assess it."
    )


def refuse_outside_scope(
    shell: Any,
    *,
    relation: str,
    out_domain: str,
    surface: str,
    path_domain: str = "",
    from_label: str = "",
    to_label: str = "",
    source_domain: str = "",
    step_status: str | None = None,
    event_recorder: Callable[[str, dict[str, Any]], None] | None = None,
) -> None:
    """Keep one step from running because it leaves the engagement scope.

    One operator line per (relation, target), the edge note every surface reads
    (``not_executed_reason = outside_engagement_scope``, status unchanged so the
    route stays mapped), and a ``withheld`` row in ``scope.json`` for the report.
    Never raises.
    """
    action = str(relation or "").strip() or "This step"
    target = str(to_label or "").strip()
    key = (action.lower(), target.lower(), _norm(out_domain))
    announced = getattr(shell, _ANNOUNCED_ATTR, None)
    if not isinstance(announced, set):
        announced = set()
        try:
            setattr(shell, _ANNOUNCED_ATTR, announced)
        except Exception:  # noqa: BLE001
            pass
    first = key not in announced
    announced.add(key)
    # An attack path the operator launched never stops in silence, so that
    # surface prints on every refusal; elsewhere a repeat is collapsed.
    if first or surface == "attack_path":
        print_info(outside_scope_line(action, target, _norm(out_domain)))
    if first:
        withheld = _record(shell)["withheld"]
        withheld.append(
            {
                "source_domain": _norm(source_domain or path_domain),
                "target_domain": _norm(out_domain),
                "technique": action.lower(),
                "from": str(from_label or "").strip(),
                "to": target,
                "surface": surface,
            }
        )
        _save(shell)
    print_info_debug(
        "engagement-scope refuse: "
        f"relation={mark_sensitive(action, 'detail')} surface={surface} "
        f"domain={mark_sensitive(_norm(out_domain) or '?', 'domain')} first={first}"
    )
    if path_domain and from_label and target and relation:
        try:
            from adscan_internal.services.attack_graph_service import (  # noqa: PLC0415
                update_edge_status_by_labels,
            )

            update_edge_status_by_labels(
                shell,
                path_domain,
                from_label=str(from_label),
                relation=relation,
                to_label=target,
                status=str(step_status or "theoretical").strip().lower() or "theoretical",
                notes=scope_note(_norm(out_domain)),
            )
        except Exception as exc:  # noqa: BLE001 - the note never breaks the scan
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
    if event_recorder is not None:
        try:
            event_recorder(
                outside_scope_line(action, target, _norm(out_domain), marked=False),
                {"reason": NOT_EXECUTED_OUTSIDE_SCOPE, **scope_note(_norm(out_domain))},
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)


def gate_cross_domain_technique(
    shell: Any,
    *,
    technique: str,
    source_domain: str,
    target_domain: str,
    surface: str,
) -> bool:
    """Seam for a technique runner acting from one domain INTO another.

    Returns True when both domains are in the engagement scope; otherwise
    refuses (one line, a ``withheld`` record) and returns False so the runner
    returns its own "nothing done" result.
    """
    for domain in (target_domain, source_domain):
        verdict = domain_scope_verdict(shell, domain)
        if not verdict.in_scope:
            # The escalation edge joins the two domain objects; noting it lets the
            # shared status derivation split every route that crosses it.
            refuse_outside_scope(
                shell,
                relation=technique,
                out_domain=verdict.domain or _norm(domain),
                surface=surface,
                path_domain=_norm(source_domain),
                from_label=str(source_domain or "").strip().upper(),
                source_domain=source_domain,
                to_label=str(target_domain or "").strip().upper(),
            )
            return False
    return True


__all__ = (
    "BASIS_EXCLUDED",
    "BASIS_NOT_CONFIRMED",
    "BASIS_ORIGIN",
    "BASIS_PATH_DOMAIN",
    "BASIS_POLICY_AUTOMATIC",
    "BASIS_SELECTED",
    "BASIS_UNDETERMINED",
    "HOST_IN_OTHER_DOMAIN",
    "HOST_IN_SCOPE",
    "HOST_UNDETERMINED",
    "HOST_OUTSIDE_SCOPE",
    "HOST_OWNED_BY_COLLECTING_DOMAIN",
    "CollectionHostVerdict",
    "ScopeVerdict",
    "StepScopeVerdict",
    "domain_in_engagement_scope",
    "domain_scope_verdict",
    "collecting_domain_context",
    "collection_host_skip_line",
    "collection_host_verdict",
    "gate_cross_domain_technique",
    "current_collecting_domain",
    "host_owner_domain",
    "linked_server_gate_active",
    "linked_server_host",
    "linked_server_query_refusal",
    "linked_server_target_verdict",
    "note_collection_host_skipped",
    "object_domain",
    "origin_domains",
    "outside_scope_line",
    "record_trust_scope_decision",
    "refuse_outside_scope",
    "resolve_linked_server_host",
    "register_scope_shell",
    "scope_entry",
    "step_scope_verdict",
)
