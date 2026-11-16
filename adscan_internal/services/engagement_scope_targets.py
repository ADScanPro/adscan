"""Call-site helper: tell the engagement scope about a batch of hosts, once.

A scope verdict is a read of what the session already knows (see
``engagement_scope.py``): it never resolves a name and never reads the
directory. So a seam that is about to judge a LIST of hosts tells the session
about the list first, in one call:

* the name-to-address pairs the seam already holds are reported
  (:func:`engagement_scope.note_host_addresses_batch`), so an entry naming a
  host covers the address the seam will connect to, and no lookup is repeated;
* the names are then prepared (:func:`engagement_scope.prepare_scope_targets`),
  which looks up what is still missing: an address for a name nobody resolved,
  and the host's place in the directory when the scope holds an entry only a
  directory record can settle.

One call per batch, never per item: the per-name work is one lookup, and a
verdict asked afterwards costs a few dictionary probes. A seam that holds the
address, the DN and the SID of each target passes them to the verdict and needs
none of this.

This module adds no rule of its own. Whether a host may be contacted is decided
by ``engagement_scope`` alone.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable

from adscan_core import telemetry
from adscan_core.rich_output import print_exception


def prepare_targets_for_scope(
    shell: Any,
    targets: Iterable[Any],
    *,
    key: Callable[[Any], Any] = str,
    address: Callable[[Any], Any] | None = None,
    domain: str | None = None,
) -> None:
    """Tell the session what it needs to judge ``targets``, in one call.

    Call it once, right before ``partition_targets_in_scope`` (or a
    single-target gate), with the same ``key`` and ``address`` the partition
    gets. Nothing happens, at the cost of one attribute read, when no asset
    scope is recorded.

    Never raises: when the session cannot be told, the verdicts that follow
    answer "not confirmed" for what it does not know, so the seam contacts
    less, never more.

    Args:
        shell: The session (``None`` uses the registered one).
        targets: The batch the seam is about to judge.
        key: The host name (or address) of a target, as the partition reads it.
        address: The address the seam will connect to for a target, when held.
        domain: The domain the targets were listed for, when known.
    """
    try:
        from adscan_internal.services.engagement_scope import (  # noqa: PLC0415
            asset_scope_recorded,
            note_host_addresses_batch,
            prepare_scope_targets,
        )

        if not asset_scope_recorded(shell):
            return
        names: dict[str, None] = {}
        held: dict[str, list[str]] = {}
        for target in targets or ():
            name = str(key(target) or "").strip()
            if not name:
                continue
            names[name] = None
            if address is None:
                continue
            connect = str(address(target) or "").strip()
            if connect and connect.lower() != name.lower():
                held.setdefault(name, []).append(connect)
        if held:
            note_host_addresses_batch(shell, held)
        if names:
            prepare_scope_targets(shell, list(names), domain=domain)
    except Exception as exc:  # noqa: BLE001 - unprepared targets stay "not confirmed"
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def _known_domain_names(shell: Any) -> set[str]:
    """The domains the session knows, lower-cased (empty when there is none)."""
    names: set[str] = set()
    current = str(getattr(shell, "domain", "") or "").strip().rstrip(".").lower()
    if current:
        names.add(current)
    domains_data = getattr(shell, "domains_data", None)
    if isinstance(domains_data, dict):
        names.update(
            str(name).strip().rstrip(".").lower() for name in domains_data if str(name or "").strip()
        )
    return names


def report_resolved_addresses(
    resolved: Any, *, shell: Any = None
) -> None:
    """Tell the engagement scope EVERY address a resolver saw for each host name.

    ``resolved`` is ``{host name: [addresses]}``. The one call every resolver
    makes with what it found (all of it, not the one address a caller ends up
    connecting to): the host resolver's DNS layer, the DNS discovery of the
    domain controllers, the collector's bulk resolution. The scope judges a
    host in every way it can be read and knows the addresses of a name only
    when a resolver reported them. A domain controller in particular is one
    only at a recorded or reported address: reached at an address nobody
    reported it is judged as an ordinary host, so a directory read through an
    unreported interface would be refused under an allow-list.

    The name of a DOMAIN is never reported as a host. Its A records are its
    domain controllers' addresses, and reporting them under the domain's name
    would make each address read as held by a second host nobody listed, which
    takes the allowance away from the controller a scope names.

    One attribute read when no asset scope is recorded. Never raises: a lookup
    must not fail because its report did.
    """
    try:
        from adscan_internal.services.engagement_scope import (  # noqa: PLC0415
            asset_scope_recorded,
            note_host_addresses_batch,
        )

        if not asset_scope_recorded(shell):
            return
        if shell is None:
            from adscan_internal.services.engagement_scope_principals import (  # noqa: PLC0415
                session_shell,
            )

            shell = session_shell()
        domains = _known_domain_names(shell) if shell is not None else set()
        pairs: dict[str, list[str]] = {}
        for host, addresses in (resolved or {}).items():
            name = str(host or "").strip().rstrip(".")
            found = [str(a).strip() for a in addresses or () if str(a or "").strip()]
            if not name or not found or name.lower() in domains:
                continue
            pairs.setdefault(name, []).extend(found)
        if pairs:
            # ``shell`` may still be None here: the engine then uses its own session.
            note_host_addresses_batch(shell, pairs)
    except Exception as exc:  # noqa: BLE001 - the verdicts stay fail-closed
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


# ── A long fan-out: each chunk is prepared, each host judged before its contact ──

#: Hosts prepared together, ahead of the workers that will contact them.
FANOUT_CHUNK_SIZE = 64
#: A chunk is prepared again when a worker reaches it later than this. Shorter
#: than the scope's evidence window (15 minutes), so a sweep that outlasts the
#: window never leaves it to the socket guard to notice.
FANOUT_REFRESH_SECONDS = 600.0


def fanout_scope_gate(
    shell: Any,
    items: Iterable[Any],
    *,
    surface: str,
    key: Callable[[Any], Any] = str,
    address: Callable[[Any], Any] | None = None,
    domain: str | None = None,
    contact: Any = None,
    chunk_size: int = FANOUT_CHUNK_SIZE,
    refresh_seconds: float = FANOUT_REFRESH_SECONDS,
    on_held: Callable[[Any, Any], None] | None = None,
) -> Callable[[Any], bool] | None:
    """The ``before_item`` check of a host fan-out, or ``None`` without an asset scope.

    Pass the result to ``run_stoppable_fanout`` / ``run_stoppable_thread_fanout``.
    The list was partitioned before the sweep started; that answer is from the
    start of the sweep. A sweep over many hosts can run longer than what the
    session knows stays current, and the scope can be replaced while it runs,
    so each host is judged again when a worker is about to contact it:

    * the chunk of hosts the worker has reached is prepared once (and again if
      the sweep comes back to it late), so the session's knowledge of those
      hosts is current when they are judged;
    * the host's verdict is then read. A host the scope keeps out now is not
      contacted: the pool marks it held, and the refusal joins the scope record
      under ``surface``.

    The gate adds no rule: the verdict is ``engagement_scope.host_scope_verdict``
    with the same ``key``, ``address``, ``domain`` and ``contact`` the seam's
    partition used. A gate that cannot ask keeps the host out.

    An item is found in its chunk by identity, then by its host name, so a
    fan-out that asks with an equal value (a host string rebuilt from a pair)
    still prepares a whole chunk and never one host at a time. ``on_held`` is
    told each item kept out, with its verdict (a fan-out outside the pool words
    the host with it: see :func:`host_contact_gate`).
    """
    import threading  # noqa: PLC0415
    import time  # noqa: PLC0415

    from adscan_internal.services import engagement_scope as es  # noqa: PLC0415

    if not es.asset_scope_recorded(shell):
        return None
    ordered = list(items or ())
    position = {id(item): index for index, item in enumerate(ordered)}
    by_name: dict[str, int] = {}
    for index, item in enumerate(ordered):
        by_name.setdefault(_host_key(key, item), index)
    size = max(1, int(chunk_size))
    prepared_at: dict[int, float] = {}
    lock = threading.Lock()

    def _prepare_chunk_of(item: Any) -> None:
        index = position.get(id(item))
        if index is None:
            index = by_name.get(_host_key(key, item))
        chunk = ordered[index - index % size : index - index % size + size] if index is not None else [item]
        number = (index // size) if index is not None else -1 - len(prepared_at)
        with lock:
            last = prepared_at.get(number)
            if last is not None and time.monotonic() - last < refresh_seconds:
                return
            prepare_targets_for_scope(shell, chunk, key=key, address=address, domain=domain)
            prepared_at[number] = time.monotonic()

    def _admit(item: Any) -> bool:
        _prepare_chunk_of(item)
        host = str(key(item) or "")
        verdict = es.host_scope_verdict(
            shell,
            host=host,
            connect_address=(str(address(item) or "") or None) if address is not None else None,
            domain=domain,
            contact=contact,
        )
        if verdict.allowed:
            return True
        try:
            es.record_scope_refusals(shell, [(item, verdict)], surface=surface, domain=domain, key=key)
        except Exception as exc:  # noqa: BLE001 - the record never changes who is kept out
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
        if on_held is not None:
            try:
                on_held(item, verdict)
            except Exception as exc:  # noqa: BLE001 - telling the caller never lets the host through
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
        return False

    return _admit


def _host_key(key: Callable[[Any], Any], item: Any) -> str:
    try:
        return str(key(item) or "").strip().lower()
    except Exception:  # noqa: BLE001 - an item the key cannot read has no name
        return ""


# ── Fan-outs outside the shared pool, and target lists handed to a child ────

#: What a fan-out writes for a host the scope excludes (a result row, a note).
HELD_EXCLUDED_TEXT = "outside the engagement scope"
#: The same, for a host the scope could not place.
HELD_UNCONFIRMED_TEXT = "not confirmed inside the engagement scope"


class HostContactGate:
    """One fan-out's hold on the engagement scope, asked host by host.

    For a fan-out that does not run through the shared stoppable pool (a
    sequential loop, a thread pool of its own, an ``asyncio.gather``, one child
    process per host). Built by :func:`host_contact_gate`; the fan-out calls
    :meth:`admits` for each host immediately before that host's contact (from an
    event loop: ``await asyncio.to_thread(gate.admits, item)``).

    It is the pool's gate (:func:`fanout_scope_gate`) with what a fan-out of
    its own needs on top: it is never ``None`` (without an asset scope every
    host is admitted at the cost of one attribute read), it remembers who was
    kept out and why, and it tells the operator once per host.
    """

    def __init__(self, *, what: str, key: Callable[[Any], Any]) -> None:
        import threading  # noqa: PLC0415

        self._what = what
        self._key = key
        self._admit: Callable[[Any], bool] | None = None
        self._lock = threading.Lock()
        self._held: dict[str, tuple[Any, Any]] = {}

    @property
    def active(self) -> bool:
        """Whether an asset scope is recorded (otherwise every host is admitted)."""
        return self._admit is not None

    def admits(self, item: Any) -> bool:
        """Whether ``item`` may be contacted NOW. Ask right before the contact."""
        if self._admit is None:
            return True
        try:
            return bool(self._admit(item))
        except Exception as exc:  # noqa: BLE001 - a gate that cannot ask keeps the host out
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            return False

    __call__ = admits

    def _note_held(self, item: Any, verdict: Any) -> None:
        name = _host_key(self._key, item)
        with self._lock:
            first = name not in self._held
            self._held[name] = (item, verdict)
        if not first or not self._what:
            return
        from adscan_core.rich_output import print_info  # noqa: PLC0415
        from adscan_internal.services.engagement_scope import (  # noqa: PLC0415
            asset_refusal_line,
        )

        print_info(asset_refusal_line(self._what, str(self._key(item) or ""), verdict))

    @property
    def held(self) -> list[Any]:
        """The items kept out so far (one per host, in the order they were met)."""
        with self._lock:
            return [item for item, _verdict in self._held.values()]

    def held_reason(self, item: Any) -> str:
        """How a held host reads in a result: excluded, or not confirmed. Empty if admitted."""
        with self._lock:
            entry = self._held.get(_host_key(self._key, item))
        if entry is None:
            return ""
        from adscan_internal.services.engagement_scope import ScopeOutcome  # noqa: PLC0415

        undetermined = getattr(entry[1], "outcome", None) is ScopeOutcome.UNDETERMINED
        return HELD_UNCONFIRMED_TEXT if undetermined else HELD_EXCLUDED_TEXT


def host_contact_gate(
    shell: Any,
    items: Iterable[Any],
    *,
    surface: str,
    what: str,
    key: Callable[[Any], Any] = str,
    address: Callable[[Any], Any] | None = None,
    domain: str | None = None,
    contact: Any = None,
) -> HostContactGate:
    """The per-host scope check of a fan-out that does not use the shared pool.

    ``items`` is the list the fan-out is about to work through (already
    partitioned at its start); ``surface``, ``key``, ``address``, ``domain`` and
    ``contact`` are the ones that partition used, and ``what`` is its operator
    wording. The fan-out then asks ``gate.admits(item)`` right before each
    host's contact. A host kept out is recorded under ``surface``, announced
    once, and listed in ``gate.held``: the fan-out reports it as outside the
    scope (:meth:`HostContactGate.held_reason`), never as offline, not checked
    or access denied.
    """
    gate = HostContactGate(what=what, key=key)
    gate._admit = fanout_scope_gate(  # noqa: SLF001 - the gate's own builder
        shell,
        items,
        surface=surface,
        key=key,
        address=address,
        domain=domain,
        contact=contact,
        on_held=gate._note_held,  # noqa: SLF001
    )
    return gate


def subprocess_targets_in_scope(
    shell: Any,
    targets: Iterable[Any],
    *,
    surface: str,
    what: str,
    key: Callable[[Any], Any] = str,
    address: Callable[[Any], Any] | None = None,
    domain: str | None = None,
    contact: Any = None,
) -> Any:
    """Split the targets of a CHILD PROCESS, immediately before it starts.

    No in-process check sees what a child process connects to (the socket guard
    covers this process only), and nothing reads a target file again after it
    is written. So the list handed to a tool is prepared and partitioned HERE,
    by the function that starts the tool, right before it builds the command or
    writes the file, never by an earlier step: only ``.allowed`` reaches the
    argument list or the file, and each refusal is recorded under ``surface``.
    A tool started once per host calls this once per start (one target each).

    A tool that takes a RANGE also gets the scope's exclusions in its own
    exclude mechanism: ``engagement_scope.scanner_exclusions``.

    Returns the engine's ``ScopePartition`` (``allowed``, ``refused``).
    """
    from adscan_internal.services.engagement_scope import (  # noqa: PLC0415
        partition_targets_in_scope,
    )

    listed = list(targets or ())
    prepare_targets_for_scope(shell, listed, key=key, address=address, domain=domain)
    return partition_targets_in_scope(
        shell,
        listed,
        key=key,
        address=address,
        surface=surface,
        what=what,
        domain=domain,
        contact=contact,
    )


def subprocess_host_in_scope(
    shell: Any,
    host: Any,
    *,
    surface: str,
    what: str,
    address: str | None = None,
    domain: str | None = None,
    contact: Any = None,
) -> bool:
    """Whether ONE host may be handed to a child process, asked right before it starts.

    The single-target form of :func:`subprocess_targets_in_scope`: for a tool
    started against one host (a client launched on a host, an exploit script
    run against a domain controller). False: the tool is not started, the
    operator was told once and the refusal is recorded under ``surface``.
    An empty host is not a target: nothing to hand over, so True.
    """
    name = str(host or "").strip()
    if not name:
        return True
    connect = str(address or "").strip()
    split = subprocess_targets_in_scope(
        shell,
        [name],
        surface=surface,
        what=what,
        address=(lambda _host: connect) if connect else None,
        domain=domain,
        contact=contact,
    )
    return not split.refused


def subprocess_dc_in_scope(
    shell: Any,
    domain: str,
    *,
    surface: str,
    what: str,
    contact: Any = None,
) -> bool:
    """Whether the domain's recorded domain controller may be handed to a child process.

    For a tool that is pointed at "the DC of ``domain``" (its recorded PDC):
    the controller is named the way the session records it (FQDN, with its
    address as the connect address) and asked about through
    :func:`subprocess_host_in_scope`. ``contact`` describes what the tool opens
    there; left out, it is ordinary host work. True when no controller is
    recorded (there is nothing to hand over).
    """
    domains_data = getattr(shell, "domains_data", None)
    domain_data = (domains_data.get(domain) if isinstance(domains_data, dict) else None) or {}
    fqdn = str(domain_data.get("pdc_hostname_fqdn") or "").strip()
    short = str(domain_data.get("pdc_hostname") or "").strip()
    address = str(domain_data.get("pdc") or "").strip()
    host = fqdn or (f"{short}.{domain}" if short and "." not in short else short) or address
    return subprocess_host_in_scope(
        shell,
        host,
        surface=surface,
        what=what,
        address=address or None,
        domain=str(domain or "").strip() or None,
        contact=contact,
    )


def subprocess_target_file_in_scope(
    shell: Any,
    path: str,
    *,
    surface: str,
    what: str,
    domain: str | None = None,
    contact: Any = None,
) -> str | None:
    """A target FILE for a child process, holding in-scope hosts only, written right now.

    For a tool that reads its hosts from a file (``-target-file``, ``-iL``).
    The file ``path`` may have been written long before, under another scope,
    and nothing reads it again once the tool runs. So its entries are read,
    prepared and partitioned HERE, immediately before the tool starts, and the
    in-scope ones are written to a sibling file (``<path>.in-scope``) that the
    tool is handed instead.

    Returns the path to hand to the tool: ``path`` itself when no asset scope is
    recorded (the command is the one it always was), the sibling file under a
    scope, or ``None`` when the file cannot be read or holds no in-scope host
    (the tool is then not started).
    """
    from adscan_internal.services.engagement_scope import (  # noqa: PLC0415
        asset_scope_recorded,
    )

    if not asset_scope_recorded(shell):
        return path
    try:
        with open(path, encoding="utf-8") as handle:
            entries = [
                line.strip() for line in handle if line.strip() and not line.strip().startswith("#")
            ]
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None
    allowed = subprocess_targets_in_scope(
        shell, entries, surface=surface, what=what, domain=domain, contact=contact
    ).allowed
    if not allowed:
        return None
    scoped_path = f"{path}.in-scope"
    with open(scoped_path, "w", encoding="utf-8") as handle:
        handle.write("".join(f"{entry}\n" for entry in allowed))
    return scoped_path


__all__ = [
    "FANOUT_CHUNK_SIZE",
    "FANOUT_REFRESH_SECONDS",
    "HELD_EXCLUDED_TEXT",
    "HELD_UNCONFIRMED_TEXT",
    "HostContactGate",
    "fanout_scope_gate",
    "host_contact_gate",
    "prepare_targets_for_scope",
    "report_resolved_addresses",
    "subprocess_dc_in_scope",
    "subprocess_host_in_scope",
    "subprocess_target_file_in_scope",
    "subprocess_targets_in_scope",
]
