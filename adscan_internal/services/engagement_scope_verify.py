"""Whole-scope verification: what a recorded asset scope resolves to.

One function, :func:`verify_asset_scope`, explains the scope a session runs
under BEFORE anything is contacted. It is built on the engine's own resolution
pass and verdicts (``engagement_scope``), so it shows exactly what a scan will
enforce; there is no second resolver and no second matcher here.

What it reads: the engine's resolution of each entry, the computers of the
directory the workspace already holds (the domain's graph store), and forward
name lookups through the host-address SSOT (the workspace inventory, then a
DNS query to the domain's resolver). It sends nothing to a target, and nothing
at all to a denied address (the socket guard is armed like for any other
lookup). There is no reverse lookup in the stack's host-address SSOT, so
"which names does this address have" is answered from the directory and from
the forward lookups only.

Two levels, stated in the result:

* ``name_resolution``: no directory has been read. Names are resolved; nothing
  can be said about which computers an address, an account, a SID or a unit
  covers, and the three counts over the known computers are empty.
* ``directory``: the collection has read the directory. Every entry is matched
  to the objects it names and the counts are complete.

The result is plain data (dicts, lists, strings, numbers): the REPL renders
it, an unattended run prints its one-line summary, the scan-end stamp records
the per-entry rows with the run, and the web can serve it as it is.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Iterable, Mapping

from adscan_core import engagement_scope_model as asset_model
from adscan_core import telemetry
from adscan_core.reporting import engagement_scope as wording
from adscan_core.rich_output import print_exception, print_info_debug
from adscan_internal.services import engagement_scope as es

VERIFY_FORMAT = 1
#: Labels and addresses named per entry or issue (the counts stay exact).
VERIFY_LABELS_MAX = 8
#: Issue rows of one kind named in the result (the count stays exact).
VERIFY_ISSUES_MAX = 50

_COMPUTER = "computer"
_ACCOUNT_KINDS = frozenset({"user", "group", "gmsa", "msa", "foreignsecurityprincipal"})
_CA_KINDS = ("EnterpriseCA",)
_VERIFICATION_ATTR = "_asset_scope_verification"


class _Known:
    """One computer of a directory the workspace holds."""

    __slots__ = ("name", "domain", "dn", "sid", "sam", "os", "addresses", "state", "reason", "entry", "dc")

    def __init__(self, identity: Any, os_name: str) -> None:
        self.name = str(identity.fqdn or "").lower()
        self.domain = str(identity.domain or "").lower()
        self.dn = str(identity.dn or "")
        self.sid = str(identity.object_id or "").upper()
        self.sam = str(identity.samaccountname or "").lower()
        self.os = os_name
        self.addresses: tuple[str, ...] = ()
        self.state = ""
        self.reason = ""
        self.entry = ""
        self.dc = False


def _directory_computers(shell: Any, domain: str) -> tuple[list[_Known], list[str]] | None:
    """The computers of ``domain`` the workspace holds, and the hosts of its
    certification authorities. ``None`` when its directory has not been read."""
    try:
        from adscan_internal.services.graph_runtime import graph_store_for  # noqa: PLC0415

        store = graph_store_for(shell, domain, create=False)
    except Exception as exc:  # noqa: BLE001 - an unreadable store is "not read"
        print_info_debug(f"scope verification: store unavailable ({type(exc).__name__})")
        return None
    if store is None:
        return None
    try:
        if not es._directory_objects_complete(store):  # noqa: SLF001
            return None
        computers: list[_Known] = []
        for record in store.iter_objects(kinds=("computer",)):
            identity = es._identity_from_record(shell, record)  # noqa: SLF001
            if identity.kind != _COMPUTER or not identity.fqdn:
                continue
            props = getattr(record, "properties", None) or {}
            os_name = str(props.get("operatingsystem") or props.get("os") or "") if isinstance(props, Mapping) else ""
            computers.append(_Known(identity, os_name))
        ca_hosts: list[str] = []
        for record in store.iter_objects(kinds=_CA_KINDS):
            props = getattr(record, "properties", None) or {}
            host = str(props.get("dnshostname") or "").lower() if isinstance(props, Mapping) else ""
            if host and host not in ca_hosts:
                ca_hosts.append(host)
        return computers, ca_hosts
    except Exception as exc:  # noqa: BLE001 - reported, and the domain reads as not read
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


class _AddressIndex:
    """Which address entries cover an address: exact lookups by prefix length."""

    def __init__(self) -> None:
        self._nets: dict[tuple[int, int], dict[int, list[str]]] = {}

    def add(self, entry: asset_model.ScopeEntry) -> None:
        try:
            if entry.type == asset_model.TYPE_RANGE:
                first, _, last = entry.value.partition("-")
                nets = list(
                    ipaddress.summarize_address_range(
                        ipaddress.ip_address(first.strip()), ipaddress.ip_address(last.strip())
                    )
                )
            else:
                nets = [ipaddress.ip_network(entry.value, strict=False)]
        except ValueError:
            return
        for net in nets:
            bucket = self._nets.setdefault((net.version, net.prefixlen), {})
            bucket.setdefault(int(net.network_address), []).append(entry.id)

    def covering(self, address: str, *, narrower_than: int | None = None) -> list[str]:
        """Entry ids whose network holds ``address`` (optionally only the ones
        broader than a prefix length)."""
        try:
            addr = asset_model.unmap_address(ipaddress.ip_address(address))
        except ValueError:
            return []
        bits = 32 if addr.version == 4 else 128
        value = int(addr)
        out: list[str] = []
        for (version, prefix), bucket in self._nets.items():
            if version != addr.version or (narrower_than is not None and prefix >= narrower_than):
                continue
            shift = bits - prefix
            hit = bucket.get((value >> shift) << shift if shift else value)
            if hit:
                out.extend(hit)
        return out


def _dn_ancestors(dn: str) -> Iterable[str]:
    parts = [p.strip() for p in asset_model._split_dn(dn)]  # noqa: SLF001
    for index in range(1, len(parts)):
        yield ",".join(parts[index:]).casefold()


def _label_of(identity: Any) -> str:
    return str(
        getattr(identity, "fqdn", "")
        or getattr(identity, "upn", "")
        or getattr(identity, "samaccountname", "")
        or getattr(identity, "dn", "")
        or getattr(identity, "object_id", "")
        or ""
    )


def verify_asset_scope(
    shell: Any = None,
    *,
    refresh: bool = True,
    max_labels: int = VERIFY_LABELS_MAX,
    entries_fresh: bool = False,
) -> dict[str, Any] | None:
    """Explain the recorded asset scope: what each entry resolves to, and what
    the entries say together.

    Args:
        shell: The session (``None``: the registered one).
        refresh: Run the engine's resolution pass and look the known computers'
            names up first (name lookups and workspace reads; never a contact
            with a target). ``False`` reads what the session already knows (the
            scan-end stamp).
        max_labels: Labels and addresses named per entry and per issue.
        entries_fresh: The entries were resolved a moment ago (the scope was
            just recorded): the resolution pass is not run a second time.

    Returns:
        ``None`` without an asset scope. Otherwise plain data::

            {"format": 1, "usable": bool, "errors": [str],
             "revision": int, "digest": str, "mode": str, "dc_access": str,
             "level": "name_resolution" | "directory" | "mixed",
             "level_statement": str,
             "domains": [{"domain", "level", "computers"}],
             "entry_counts": {"allow", "deny", "matched", "matched_nothing",
                              "deny_matched_nothing", "not_confirmed"},
             "entries": [ {id, side, type, value, origin, status, outcome, cause,
                           matched: {computers, accounts, other}, labels,
                           labels_omitted, addresses, addresses_omitted, names,
                           domains, candidates, pin, notes, statement,
                           computer_names} ],
             "issues": [ {kind, severity, entries, labels, count, statement} ],
             "counts": {known_computers, inside, excluded, not_confirmed,
                        directory_only},
             "host_states": {computer name: "inside"|"excluded"|"not_confirmed"|"directory_only"},
             "names_not_looked_up": int,
             "summary": str}

        ``entries[*].computer_names`` and ``host_states`` list every matched
        computer (for the scan-end stamp); a renderer shows ``labels``.
    """
    shell = es._session(shell)  # noqa: SLF001
    state = es._asset_state(shell)  # noqa: SLF001
    if state is None:
        return None
    if state.broken:
        return {
            "format": VERIFY_FORMAT,
            "usable": False,
            "errors": list(es.asset_scope_errors(shell)),
            "entries": [],
            "issues": [],
            "counts": {},
            "entry_counts": {},
            "summary": "Scope check: the recorded scope cannot be used; no host is contacted.",
        }
    if refresh and not entries_fresh:
        es.resolve_asset_scope(shell)
        state = es._asset_state(shell)  # noqa: SLF001
        if state is None or state.broken:
            return verify_asset_scope(shell, refresh=False, max_labels=max_labels)
    scope = state.scope
    view = es._domain_view(shell, state)  # noqa: SLF001
    in_scope = [d for d in view.known if es.domain_in_engagement_scope(shell, d)]

    # The computers the workspace holds, per domain.
    known: list[_Known] = []
    ca_hosts: dict[str, str] = {}
    domain_rows: list[dict[str, Any]] = []
    for domain in in_scope:
        listed = _directory_computers(shell, domain)
        if listed is None:
            domain_rows.append(
                {"domain": domain, "level": wording.VERIFY_LEVEL_NAME_RESOLUTION, "computers": 0}
            )
            continue
        computers, cas = listed
        if refresh and computers:
            es.prepare_scope_targets(shell, [c.name for c in computers], domain=domain)
        known.extend(computers)
        for host in cas:
            ca_hosts.setdefault(host, domain)
        domain_rows.append(
            {"domain": domain, "level": wording.VERIFY_LEVEL_DIRECTORY, "computers": len(computers)}
        )
    read = [row for row in domain_rows if row["level"] == wording.VERIFY_LEVEL_DIRECTORY]
    level = (
        wording.VERIFY_LEVEL_DIRECTORY
        if read and len(read) == len(domain_rows)
        else wording.VERIFY_LEVEL_MIXED
        if read
        else wording.VERIFY_LEVEL_NAME_RESOLUTION
    )
    state = es._asset_state(shell) or state  # noqa: SLF001

    # Each known computer: its addresses and the engine's own verdict.
    by_name: dict[str, _Known] = {}
    by_sid: dict[str, _Known] = {}
    at_address: dict[str, list[_Known]] = {}
    host_states: dict[str, str] = {}
    counts = {"known_computers": len(known), "inside": 0, "excluded": 0, "not_confirmed": 0, "directory_only": 0}
    for computer in known:
        by_name[computer.name] = computer
        if computer.sid:
            by_sid[computer.sid] = computer
        computer.addresses = tuple(sorted(state.current_of(computer.name) or state.addresses_of(computer.name)))
        for address in computer.addresses:
            at_address.setdefault(address, []).append(computer)
        verdict = es.host_scope_verdict(
            shell,
            host=computer.name,
            domain=computer.domain,
            host_dn=computer.dn or None,
            host_sid=computer.sid or None,
        )
        computer.reason = verdict.reason
        computer.entry = verdict.entry_id
        if verdict.allowed:
            computer.state = "inside"
        elif verdict.reason == es.ASSET_REASON_DC_DIRECTORY_ONLY:
            computer.state = "directory_only"
        elif verdict.outcome is es.ScopeOutcome.UNDETERMINED:
            computer.state = "not_confirmed"
        else:
            computer.state = "excluded"
        counts[computer.state] += 1
        host_states[computer.name] = computer.state

    # What each entry matched.
    sides = {e.id: "allow" for e in scope.allow}
    sides.update({e.id: "deny" for e in scope.deny})
    everything = (*scope.allow, *scope.deny)
    addr_index = {"allow": _AddressIndex(), "deny": _AddressIndex()}
    suffixes: dict[str, list[str]] = {}
    subtrees: dict[str, list[str]] = {}
    matched_computers: dict[str, list[_Known]] = {}
    other_objects: dict[str, list[Any]] = {}
    for entry in everything:
        if entry.type in asset_model.ADDRESS_TYPES:
            addr_index[sides[entry.id]].add(entry)
        elif entry.type == asset_model.TYPE_DNS_SUFFIX:
            suffixes.setdefault(entry.value, []).append(entry.id)
        elif entry.type == asset_model.TYPE_DN and not (state.resolution.get(entry.id) or {}).get("leaf"):
            subtrees.setdefault(entry.value.casefold(), []).append(entry.id)

    matched_names: dict[str, set[str]] = {}

    def _match(entry_id: str, computer: _Known) -> None:
        seen = matched_names.setdefault(entry_id, set())
        if computer.name not in seen:
            seen.add(computer.name)
            matched_computers.setdefault(entry_id, []).append(computer)

    for computer in known:
        for address in computer.addresses:
            for side in ("allow", "deny"):
                for entry_id in addr_index[side].covering(address):
                    _match(entry_id, computer)
        if suffixes:
            labels = computer.name.split(".")
            for index in range(1, len(labels)):
                for entry_id in suffixes.get(".".join(labels[index:]), ()):
                    _match(entry_id, computer)
        if subtrees and computer.dn:
            for ancestor in _dn_ancestors(computer.dn):
                for entry_id in subtrees.get(ancestor, ()):
                    _match(entry_id, computer)
    for entry in everything:
        row = state.resolution.get(entry.id) or {}
        for identity in row.get("identities") or ():
            sid = str(getattr(identity, "object_id", "") or "").upper()
            name = str(getattr(identity, "fqdn", "") or "").lower()
            computer = by_sid.get(sid) or by_name.get(name)
            if computer is not None:
                _match(entry.id, computer)
            else:
                other_objects.setdefault(entry.id, []).append(identity)

    collected = {row["domain"] for row in read}
    rows: list[dict[str, Any]] = []
    for entry in everything:
        rows.append(
            _entry_row(
                shell,
                state,
                entry,
                sides[entry.id],
                matched_computers.get(entry.id, []),
                other_objects.get(entry.id, []),
                level=level,
                collected=collected,
                in_scope=in_scope,
                max_labels=max_labels,
            )
        )

    issues = _issues(
        shell,
        state,
        scope,
        rows,
        known,
        at_address,
        addr_index,
        matched_computers,
        ca_hosts,
        in_scope,
        max_labels=max_labels,
    )
    entry_counts = {
        "allow": len(scope.allow),
        "deny": len(scope.deny),
        "matched": sum(
            1 for r in rows if r["outcome"] in (wording.ENTRY_MATCHED, wording.ENTRY_MATCHED_EXCLUDED)
        ),
        "matched_nothing": sum(1 for r in rows if r["outcome"] == wording.ENTRY_MATCHED_NOTHING),
        "deny_matched_nothing": sum(
            1 for r in rows if r["outcome"] == wording.ENTRY_MATCHED_NOTHING and r["side"] == "deny"
        ),
        "not_confirmed": sum(1 for r in rows if r["outcome"] == wording.ENTRY_MATCHED_NOT_CONFIRMED),
    }
    result: dict[str, Any] = {
        "format": VERIFY_FORMAT,
        "usable": True,
        "errors": list(es.asset_scope_errors(shell)),
        "revision": int((es.asset_scope_block(shell) or {}).get("revision") or 0),
        "digest": scope.digest(),
        "mode": "allow_and_deny" if scope.allow and scope.deny else "allow" if scope.allow else "deny",
        "dc_access": scope.dc_access,
        "level": level,
        "level_statement": wording.scope_verification_level_statement(level),
        "domains": domain_rows,
        "entry_counts": entry_counts,
        "entries": rows,
        "issues": issues,
        "counts": counts,
        "host_states": host_states,
        "names_not_looked_up": es.names_not_looked_up(shell),
    }
    result["summary"] = wording.scope_verification_summary(result)
    try:
        setattr(shell, _VERIFICATION_ATTR, result)
    except Exception:  # noqa: BLE001 - a frozen double keeps no copy
        pass
    return result


def last_verification(shell: Any = None) -> dict[str, Any] | None:
    """The result of the session's latest :func:`verify_asset_scope` (a read)."""
    held = getattr(es._session(shell), _VERIFICATION_ATTR, None)  # noqa: SLF001
    return held if isinstance(held, dict) else None


def _entry_row(
    shell: Any,
    state: Any,
    entry: asset_model.ScopeEntry,
    side: str,
    computers: list[_Known],
    others: list[Any],
    *,
    level: str,
    collected: set[str],
    in_scope: list[str],
    max_labels: int,
) -> dict[str, Any]:
    resolution = state.resolution.get(entry.id) or {}
    is_address = entry.type in asset_model.ADDRESS_TYPES
    # A name the directory does not hold keeps a reading of itself (so a deny
    # by name still applies): it is an object only with a SID or a DN. One that
    # merely resolves is listed by its addresses.
    resolved_only = [
        i for i in others if not (getattr(i, "object_id", "") or getattr(i, "dn", ""))
    ]
    others = [i for i in others if getattr(i, "object_id", "") or getattr(i, "dn", "")]
    status = "" if is_address else str(resolution.get("status") or es.RESOLUTION_PENDING)
    accounts = sum(1 for i in others if str(getattr(i, "kind", "") or "").lower() in _ACCOUNT_KINDS)
    other_hosts = [i for i in others if str(getattr(i, "kind", "") or "").lower() in ("", _COMPUTER)]
    matched = {
        "computers": len(computers) + len(other_hosts),
        "accounts": accounts,
        "other": len(others) - accounts - len(other_hosts),
    }
    labels = [c.name for c in computers] + [_label_of(i) for i in others]
    addresses: list[str] = []
    for computer in computers:
        addresses.extend(a for a in computer.addresses if a not in addresses)
    for identity in (*others, *resolved_only):
        addresses.extend(a for a in getattr(identity, "addresses", ()) or () if a not in addresses)
    names: list[str] = []
    if entry.type == asset_model.TYPE_IP:
        # Address to names: what the directory and the forward lookups say.
        names = sorted(state.names_of(entry.value))
    domains = sorted({c.domain for c in computers} | {str(getattr(i, "domain", "") or "") for i in others} - {""})
    notes: list[str] = []
    total = sum(matched.values())
    cause = ""
    if total:
        outcome = wording.ENTRY_MATCHED_EXCLUDED if side == "deny" else wording.ENTRY_MATCHED
        if status == es.RESOLUTION_PENDING and not is_address:
            # Resolved by name only so far; the directory may still say more.
            outcome, cause = wording.ENTRY_MATCHED_NOT_CONFIRMED, wording.CAUSE_DIRECTORY_NOT_READ
    elif status == es.RESOLUTION_AMBIGUOUS:
        outcome, cause = wording.ENTRY_MATCHED_NOT_CONFIRMED, wording.CAUSE_AMBIGUOUS_ENTRY
    elif addresses and not is_address and side == "deny":
        # It resolves, and no computer of the directory is behind it: the
        # address itself is excluded.
        outcome = wording.ENTRY_MATCHED_EXCLUDED
        notes.append("resolves_without_directory_object")
    elif is_address:
        if names:
            outcome = wording.ENTRY_MATCHED_EXCLUDED if side == "deny" else wording.ENTRY_MATCHED
        elif level == wording.VERIFY_LEVEL_DIRECTORY:
            outcome = wording.ENTRY_MATCHED_NOTHING
        else:
            outcome, cause = wording.ENTRY_MATCHED_NOT_CONFIRMED, wording.CAUSE_DIRECTORY_NOT_READ
    elif status == es.RESOLUTION_UNRESOLVABLE or (
        entry.type in (asset_model.TYPE_DNS_SUFFIX, asset_model.TYPE_DN) and level == wording.VERIFY_LEVEL_DIRECTORY
    ):
        outcome = wording.ENTRY_MATCHED_NOTHING
    else:
        outcome = wording.ENTRY_MATCHED_NOT_CONFIRMED
        cause = (
            wording.CAUSE_NAME_NOT_RESOLVED
            if collected and set(in_scope) <= collected
            else wording.CAUSE_DIRECTORY_NOT_READ
        )
    if entry.type == asset_model.TYPE_IP and side == "allow":
        notes.append("covers_this_address_only")
    if entry.type in (asset_model.TYPE_FQDN, asset_model.TYPE_SHORT_HOST) and not addresses:
        notes.append("name_without_address")
    row: dict[str, Any] = {
        "id": entry.id,
        "side": side,
        "type": entry.type,
        "value": entry.value,
        "origin": entry.origin,
        "status": status,
        "outcome": outcome,
        "cause": cause,
        "matched": matched,
        "labels": labels[:max_labels],
        "labels_omitted": max(0, len(labels) - max_labels),
        "addresses": addresses[:max_labels],
        "addresses_omitted": max(0, len(addresses) - max_labels),
        "names": names[:max_labels],
        "domains": domains,
        "candidates": [str(c) for c in resolution.get("candidates") or ()][:max_labels],
        "notes": notes,
        "computer_names": [c.name for c in computers],
    }
    # An address or a name behind which the directory holds exactly one
    # computer: pinning the entry to that object makes it follow a rename or a
    # new address.
    if (
        entry.type in (asset_model.TYPE_IP, asset_model.TYPE_FQDN, asset_model.TYPE_SHORT_HOST)
        and len(computers) == 1
        and not others
        and computers[0].sid
    ):
        row["pin"] = {"value": computers[0].sid, "label": computers[0].name}
    row["statement"] = wording.entry_outcome_note(row)
    return row


def _issue(
    kind: str,
    severity: str,
    statement: str,
    *,
    entries: Iterable[str] = (),
    labels: Iterable[str] = (),
    count: int = 0,
    max_labels: int = VERIFY_LABELS_MAX,
) -> dict[str, Any]:
    named = list(dict.fromkeys(labels))
    return {
        "kind": kind,
        "severity": severity,
        "entries": list(dict.fromkeys(entries))[:max_labels],
        "labels": named[:max_labels],
        "count": count or len(named),
        "statement": statement,
    }


def _issues(
    shell: Any,
    state: Any,
    scope: asset_model.AssetScope,
    rows: list[dict[str, Any]],
    known: list[_Known],
    at_address: Mapping[str, list[_Known]],
    addr_index: Mapping[str, _AddressIndex],
    matched_computers: Mapping[str, list[_Known]],
    ca_hosts: Mapping[str, str],
    in_scope: list[str],
    *,
    max_labels: int,
) -> list[dict[str, Any]]:
    out: dict[str, list[dict[str, Any]]] = {}

    def _add(issue: dict[str, Any]) -> None:
        out.setdefault(issue["kind"], []).append(issue)

    by_id = {row["id"]: row for row in rows}
    # 1. An exclusion that matched nothing: the dangerous one (a typo leaves
    #    the host the client wanted excluded under another name).
    for row in rows:
        if row["outcome"] != wording.ENTRY_MATCHED_NOTHING:
            continue
        deny = row["side"] == "deny"
        _add(
            _issue(
                wording.ISSUE_DENY_MATCHED_NOTHING if deny else wording.ISSUE_ALLOW_MATCHED_NOTHING,
                "error" if deny else "warning",
                wording.entry_outcome_note(row),
                entries=[row["id"]],
                labels=[row["value"]],
                max_labels=max_labels,
            )
        )
    # 2. Domain controllers and certificate servers the scope keeps out.
    from adscan_core.dc_topology import resolve_domain_controllers  # noqa: PLC0415

    domains_data = getattr(shell, "domains_data", None) or {}
    for domain in in_scope:
        data = domains_data.get(domain) if isinstance(domains_data, Mapping) else None
        if not isinstance(data, Mapping):
            continue
        records = resolve_domain_controllers(data).dcs
        closed = []
        for record in records:
            host = record.fqdn or record.aliases[0]
            verdict = es.host_scope_verdict(
                shell, host=host, domain=domain, contact=es.Contact("ldap")
            )
            if not verdict.allowed and verdict.reason == es.ASSET_REASON_DENIED:
                closed.append((host, verdict.entry_id))
        for host, entry_id in closed:
            every = len(closed) == len(records)
            _add(
                _issue(
                    wording.ISSUE_DIRECTORY_SERVER_EXCLUDED,
                    "error" if every else "warning",
                    (
                        f"Every domain controller of {domain} is excluded, so its directory "
                        "cannot be read and the domain is not assessed."
                        if every
                        else "An excluded domain controller is never contacted: the directory "
                        f"of {domain} is read through the others, and nothing is checked on this one."
                    ),
                    entries=[entry_id] if entry_id else [],
                    labels=[host],
                    max_labels=max_labels,
                )
            )
    by_name = {c.name: c for c in known}
    for host, domain in ca_hosts.items():
        computer = by_name.get(host)
        if computer is not None and computer.state in ("excluded", "not_confirmed"):
            _add(
                _issue(
                    wording.ISSUE_DIRECTORY_SERVER_EXCLUDED,
                    "warning",
                    (
                        "This certificate server is not contacted, so its enrolment "
                        "services and the settings read from the server itself are not "
                        f"checked for {domain}; certificate templates are still read from the directory."
                    ),
                    entries=[computer.entry] if computer.entry else [],
                    labels=[host],
                    max_labels=max_labels,
                )
            )
    # 3. An object on both lists (the exclusion wins).
    allow_ids = {e.id for e in scope.allow}
    both: dict[str, set[str]] = {}
    for entry_id, computers in matched_computers.items():
        for computer in computers:
            both.setdefault(computer.name, set()).add(entry_id)
    for name, ids in both.items():
        allowed_by = sorted(i for i in ids if i in allow_ids)
        denied_by = sorted(i for i in ids if i not in allow_ids)
        if allowed_by and denied_by:
            _add(
                _issue(
                    wording.ISSUE_ALLOW_AND_DENY,
                    "warning",
                    "Listed on both lists: the exclusion wins, and it is not contacted.",
                    entries=[*denied_by, *allowed_by],
                    labels=[name],
                    max_labels=max_labels,
                )
            )
    # 4. A host with several known addresses of which the allow-list names
    #    some (the second-interface case).
    if scope.allow:
        for computer in known:
            if len(computer.addresses) < 2:
                continue
            covered = [a for a in computer.addresses if addr_index["allow"].covering(a)]
            if not covered or len(covered) == len(computer.addresses):
                continue
            named = any(
                by_id[i]["type"] not in asset_model.ADDRESS_TYPES
                for i in both.get(computer.name, ())
                if i in allow_ids
            )
            if named:
                continue
            missing = [a for a in computer.addresses if a not in covered]
            _add(
                _issue(
                    wording.ISSUE_PARTIAL_HOST,
                    "warning",
                    (
                        f"{len(covered)} of its {len(computer.addresses)} known addresses are on "
                        "the allow list. It is contacted at those only; list it by name or by "
                        "its computer object to cover it at every address."
                    ),
                    entries=[i for a in covered for i in addr_index["allow"].covering(a)],
                    labels=[computer.name, *missing],
                    count=1,
                    max_labels=max_labels,
                )
            )
    # 5. An address several computers hold.
    for address, holders in at_address.items():
        names = sorted({c.name for c in holders})
        if len(names) > 1:
            _add(
                _issue(
                    wording.ISSUE_SHARED_ADDRESS,
                    "info",
                    (
                        f"{len(names)} computers are known at this address. An exclusion of one "
                        "of them keeps ADscan away from the address for all of them."
                    ),
                    labels=[address, *names],
                    count=len(names),
                    max_labels=max_labels,
                )
            )
    # 6. An entry a broader one of the same list already covers.
    for side, entries in (("allow", scope.allow), ("deny", scope.deny)):
        for entry in entries:
            if entry.type not in (asset_model.TYPE_IP, asset_model.TYPE_CIDR):
                continue
            try:
                net = ipaddress.ip_network(entry.value, strict=False)
            except ValueError:
                continue
            broader = [
                i
                for i in addr_index[side].covering(str(net.network_address), narrower_than=net.prefixlen)
                if i != entry.id
            ]
            if broader:
                _add(
                    _issue(
                        wording.ISSUE_SHADOWED,
                        "info",
                        "A broader entry of the same list already covers this one.",
                        entries=[entry.id, *broader],
                        labels=[entry.value],
                        max_labels=max_labels,
                    )
                )
    ordered: list[dict[str, Any]] = []
    for kind in wording.ISSUE_ORDER:
        found = out.get(kind) or []
        ordered.extend(found[:VERIFY_ISSUES_MAX])
        if len(found) > VERIFY_ISSUES_MAX:
            ordered.append(
                _issue(
                    kind,
                    found[0]["severity"],
                    f"{len(found) - VERIFY_ISSUES_MAX} more of the same kind are not listed.",
                    count=len(found) - VERIFY_ISSUES_MAX,
                    max_labels=max_labels,
                )
            )
    return ordered


__all__ = ["VERIFY_FORMAT", "last_verification", "verify_asset_scope"]
