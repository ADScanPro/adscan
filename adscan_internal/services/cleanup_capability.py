"""The cleanup-account capability check: what the account can undo, here, now.

Builds the block :mod:`adscan_core.reporting.reversal_capability` renders, from
the engagement scope and the revert-right registry, and persists it so a later
process (the report, the web ingestion) reads the same answer.

Scope-driven (founder decision, 2026-11-11). The in-scope domains come from the
engagement-scope SSOT (``engagement_scope.domain_in_engagement_scope``), are
grouped by forest (``forest_topology``), and each forest is checked with the
cleanup account configured for it. Per domain, every registered domain token;
per in-scope forest root, every forest token; per CA a domain owns and the scope
covers, every CA token. Out-of-scope domains, forests and CAs produce nothing.

Every row is established by the token's registered probe
(``revert_right_probes``), read-only. The directory rows read the account's
group SIDs from directory data (never a group name). The CA rows sign in to the
CA AS the cleanup account and read what the CA says (the only reads here that
use its secret, through the revert cascade, the store's single reader).

Called by: the ``cleanup_credential check`` command, the start of ``adscan ci``
and ``adscan start`` once the directory is collected, ``adscan doctor`` for the
web scan form, and the report disclosure (which reads the persisted block).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Optional

from adscan_core import telemetry
from adscan_core.reporting.reversal_capability import (
    REVERSAL_CAPABILITY_KEY,
    build_reversal_capability_block,
    checklist_text_lines,
    reversal_capability_view,
)
from adscan_core.rich_output import print_exception, print_info, print_info_debug
from adscan_core.scan_policy.model import ENV_NOT_REVERSIBLE, ENV_REVERTED_WHEN_PERMITTED
from adscan_core.scan_policy.revert_rights import (
    NEED_BACKSTOP,
    NEED_REQUIRED,
    SCOPE_CA,
    SCOPE_DOMAIN,
    SCOPE_FOREST,
    RightVerdict,
    ca_key,
)
from adscan_internal.rich_output import mark_sensitive

_PLACEHOLDER_DOMAINS = frozenset({"wellknown", ""})

#: The changes nobody can undo, with the kind each is declared by. Worded for
#: the checklist row ("Nobody can undo <subject>").
_NOBODY_SUBJECTS: tuple[tuple[str, str], ...] = (
    ("password_changed", "a password reset"),
    ("ca_private_key_exfiltrated", "a copy of a CA's private key"),
)


def _norm(value: Any) -> str:
    return str(value or "").strip().rstrip(".").lower()


def token_needs() -> dict[str, str]:
    """``{token: required|backstop}`` from the change-kind declarations. Required wins."""
    from adscan_internal.services.safeguard_profile import (  # noqa: PLC0415
        BACKSTOP_REVERT_RIGHTS,
        CLEANUP_ACCOUNT_REVERT_RIGHTS,
    )

    needs: dict[str, str] = {token: NEED_BACKSTOP for token in BACKSTOP_REVERT_RIGHTS.values()}
    for token in CLEANUP_ACCOUNT_REVERT_RIGHTS.values():
        needs[token] = NEED_REQUIRED
    return needs


def in_scope_domains(shell: Any) -> list[str]:
    """The run's domains the engagement scope covers (never a placeholder)."""
    from adscan_internal.services.engagement_scope import (  # noqa: PLC0415
        domain_in_engagement_scope,
    )

    out: list[str] = []
    domains_data = getattr(shell, "domains_data", None) or {}
    names = [*domains_data.keys(), getattr(shell, "domain", None)]
    for name in names:
        domain = _norm(name)
        if domain in _PLACEHOLDER_DOMAINS or domain in out:
            continue
        try:
            if domain_in_engagement_scope(shell, domain):
                out.append(domain)
        except Exception as exc:  # noqa: BLE001 - an unreadable scope adds no rows
            telemetry.capture_exception(exc)
    return sorted(out)


def in_scope_cas(shell: Any, domain: str) -> list[dict[str, str]]:
    """Enterprise CAs a domain OWNS and the scope covers: ``{key, name, host, domain}``.

    The forest-wide configuration partition lists every CA of the forest under
    each domain's collection, so a CA is kept only for the domain that owns its
    host (``engagement_scope.collection_host_verdict``).
    """
    from adscan_internal.services.engagement_scope import (  # noqa: PLC0415
        collection_host_verdict,
    )

    found: dict[str, dict[str, str]] = {}

    def _add(name: Any, host: Any) -> None:
        ca_name = str(name or "").split("@", 1)[0].strip()
        ca_host = str(host or "").strip()
        if not ca_name or not ca_host:
            return
        verdict = collection_host_verdict(shell, host=ca_host, collecting_domain=domain)
        if not verdict.allowed:
            return
        key = ca_key(ca_host, ca_name)
        found.setdefault(key, {"key": key, "name": ca_name, "host": ca_host, "domain": domain})

    try:
        from adscan_internal.services.local_graph_service import (  # noqa: PLC0415
            LocalGraphService,
        )

        for record in LocalGraphService(shell)._inventory_records(  # noqa: SLF001
            domain, "adcs_enterprise_cas.json"
        ):
            _add(record.get("name"), record.get("dns_hostname"))
    except Exception as exc:  # noqa: BLE001 - fall back to the domain record
        telemetry.capture_exception(exc)
    entry = (getattr(shell, "domains_data", None) or {}).get(domain) or {}
    if isinstance(entry, Mapping):
        _add(entry.get("ca"), entry.get("adcs_fqdn") or entry.get("adcs"))
        # Read by the doctor, which collects nothing (``doctor._read_cleanup_check_inputs``).
        for ca in entry.get("enterprise_cas") or ():
            if isinstance(ca, Mapping):
                _add(ca.get("name"), ca.get("dns_hostname"))
    return [found[k] for k in sorted(found)]


def _account_for(domains: Iterable[str]) -> tuple[str, str]:
    """``(principal, home)`` of the cleanup account configured for these domains."""
    from adscan_internal.services.cleanup_credential_loader import (  # noqa: PLC0415
        cleanup_account_identity,
    )

    for domain in domains:
        identity = cleanup_account_identity(domain)
        if identity is not None:
            return identity[0], identity[1]
    return "", ""


def _cleanup_candidate(shell: Any, domain: str) -> Any:
    """The cleanup account as a revert candidate (the only holder of its secret)."""
    from adscan_internal.services.revert_credentials import (  # noqa: PLC0415
        ROLE_CLEANUP,
        ROLE_CLEANUP_SAVED,
        revert_candidates,
    )

    for candidate in revert_candidates(
        shell, domain=domain, purpose="revert_right_probe", include_privileged=False
    ):
        if candidate.role in (ROLE_CLEANUP, ROLE_CLEANUP_SAVED):
            return candidate
    return None


def _locate_home(shell: Any, principal: str, home: str, domains: Iterable[str]) -> str:
    """Where the account lives when it was given without a domain, from directory data."""
    from adscan_core.scan_policy.revert_permission import ANY_DOMAIN  # noqa: PLC0415
    from adscan_internal.services.revert_right_probes import (  # noqa: PLC0415
        account_group_sids,
    )

    if home and home != ANY_DOMAIN:
        return _norm(home)
    for domain in domains:
        _sids, found, _source = account_group_sids(shell, principal, domain)
        if found:
            return _norm(domain)
    return ""


def policy_accepts_not_reversible(shell: Any) -> Optional[bool]:
    """Whether the run's scan policy accepts a change nobody can undo. ``None``: no policy.

    The ONE source for the checklist's "nobody can undo" rows, so ``ci``,
    ``start``, the doctor (the web scan form) and the report cannot disagree.
    The doctor runs before a policy is chosen, so it states the rule rather than
    a verdict it does not have; it never assumes the permissive built-in.
    """
    from adscan_core.scan_policy import gate  # noqa: PLC0415

    policy = gate.active_policy(shell)
    if policy is None or not hasattr(policy, "permits_change_class"):
        return None
    try:
        return bool(policy.permits_change_class(ENV_NOT_REVERSIBLE))
    except Exception as exc:  # noqa: BLE001 - an unreadable policy states no verdict
        telemetry.capture_exception(exc)
        return None


def _policy_parts(
    shell: Any, verdicts: list[RightVerdict]
) -> tuple[str, list[str], list[str], Optional[bool]]:
    """``(policy name, now running, turned off by the policy, accepts not-reversible)``."""
    from adscan_core.scan_policy import gate  # noqa: PLC0415
    from adscan_core.scan_policy.policy import policy_display_name  # noqa: PLC0415
    from adscan_core.scan_policy.registry import load_registry  # noqa: PLC0415

    policy = gate.active_policy(shell)
    accepts = policy_accepts_not_reversible(shell)
    if policy is None or not hasattr(policy, "definition"):
        return "", [], [], accepts
    permitted = {v.token for v in verdicts if v.permitted}
    reg = load_registry()
    running: list[str] = []
    off: list[str] = []
    for check in reg.checks:
        if check.environment_change != ENV_REVERTED_WHEN_PERMITTED or not check.revert_rights:
            continue
        if not all(token in permitted for token in check.revert_rights):
            continue
        title = check.title or check.check_id
        if check.check_id in policy.effective_ids:
            running.append(title)
        elif check.check_id in policy.excluded_ids:
            off.append(title)
    try:
        name = policy_display_name(policy.definition)
    except Exception:  # noqa: BLE001
        name = ""
    return name, running, off, accepts


def directory_collected(shell: Any, domain: str) -> bool:
    """Whether ``domain``'s directory has been read: its SID is known.

    Before collection the domain SID is unknown, so the account's roles cannot be
    read from SIDs and its CAs are not listed: a checklist built then is a
    snapshot of nothing, not an answer. The SID is recorded by the collector (in
    the membership snapshot) and by the doctor's own LDAP read.
    """
    from adscan_internal.services.forest_topology import domain_sid  # noqa: PLC0415

    try:
        return bool(domain_sid(shell, domain))
    except Exception as exc:  # noqa: BLE001 - unknown means not collected
        telemetry.capture_exception(exc)
        return False


def any_in_scope_domain_collected(shell: Any) -> bool:
    """Whether at least one in-scope domain's directory has been read."""
    return any(directory_collected(shell, d) for d in in_scope_domains(shell))


def block_is_stale(shell: Any, block: Any) -> bool:
    """Whether a persisted block predates the directory data now held.

    True when a domain row reads "could not read the account's memberships yet"
    while that domain's directory has since been collected: the block was taken
    before collection and is not the run's answer.
    """
    from adscan_core.scan_policy.revert_rights import (  # noqa: PLC0415
        REASON_NO_DIRECTORY_DATA,
    )

    if not isinstance(block, Mapping):
        return True
    for verdict in block.get("verdicts") or ():
        if not isinstance(verdict, Mapping):
            continue
        if (
            verdict.get("scope") == SCOPE_DOMAIN
            and verdict.get("reason") == REASON_NO_DIRECTORY_DATA
            and directory_collected(shell, str(verdict.get("target") or ""))
        ):
            return True
    return False


def check_cleanup_capability(
    shell: Any,
    *,
    refresh: bool = False,
    allow_network: bool = True,
    persist: Optional[bool] = None,
) -> dict[str, Any]:
    """Establish, read-only, what the cleanup account can undo in scope.

    Args:
        shell: The session shell.
        refresh: Drop memoized facts first (an explicit re-check).
        allow_network: False for a renderer that must not touch the network
            (forest lookups then use recorded data only).
        persist: Record the block for the report and the web. ``None`` (default)
            records it only once an in-scope domain's directory has been read, so
            a snapshot taken before collection never becomes the run's answer.

    Returns:
        The block (see ``build_reversal_capability_block``). Never raises.
    """
    from adscan_internal.services.cleanup_credential_loader import (  # noqa: PLC0415
        cleanup_account_supplied,
        install_forest_resolver,
    )
    from adscan_internal.services.forest_topology import (  # noqa: PLC0415
        group_by_forest,
        same_forest,
    )
    from adscan_internal.services.revert_right_probes import (  # noqa: PLC0415
        ProbeAccount,
        ProbeTarget,
        forget_probe_memo,
        probe_revert_right,
        tokens_for_scope,
    )

    checked_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    try:
        install_forest_resolver(shell)
        if refresh:
            forget_probe_memo(shell)
        domains = in_scope_domains(shell)
        forests_map = group_by_forest(shell, domains, allow_network=allow_network)
        verdicts: list[RightVerdict] = []
        forests: list[dict[str, Any]] = []
        for root, members in forests_map.items():
            principal, home = _account_for([*members, root])
            home = _locate_home(shell, principal, home, [*members, root]) if principal else ""
            account = ProbeAccount(principal, home)
            for domain in members:
                for token in tokens_for_scope(SCOPE_DOMAIN):
                    verdicts.append(
                        probe_revert_right(shell, token, ProbeTarget(SCOPE_DOMAIN, domain, domain), account)
                    )
            root_in_scope = root in members
            if root_in_scope:
                for token in tokens_for_scope(SCOPE_FOREST):
                    verdicts.append(
                        probe_revert_right(shell, token, ProbeTarget(SCOPE_FOREST, root, root), account)
                    )
            cas: list[dict[str, Any]] = []
            for domain in members:
                for ca in in_scope_cas(shell, domain):
                    candidate = _cleanup_candidate(shell, domain) if principal else None
                    ca_account = ProbeAccount(principal, home, candidate)
                    target = ProbeTarget(
                        SCOPE_CA, ca["key"], domain, ca_name=ca["name"], ca_host=ca["host"]
                    )
                    for token in tokens_for_scope(SCOPE_CA):
                        verdicts.append(probe_revert_right(shell, token, target, ca_account))
                    cas.append({**ca, "holders": []})
            in_forest: Optional[bool] = None
            if principal and home:
                in_forest = same_forest(shell, home, root, allow_network=allow_network)
            forests.append(
                {
                    "root": root,
                    "root_in_scope": root_in_scope,
                    "principal": principal,
                    "account_in_forest": in_forest,
                    "domains": members,
                    "cas": cas,
                }
            )
        policy_name, running, off, accepts = _policy_parts(shell, verdicts)
        nobody = [
            {"subject": subject, "kind": kind, "policy_accepts": accepts}
            for kind, subject in _NOBODY_SUBJECTS
        ]
        block = build_reversal_capability_block(
            forests=forests,
            verdicts=verdicts,
            token_needs=token_needs(),
            checked_at=checked_at,
            nobody=nobody,
            policy_name=policy_name,
            now_running=running,
            turned_off_by_policy=off,
            cleanup_account_supplied=cleanup_account_supplied(),
        )
        if persist is None:
            persist = any(directory_collected(shell, d) for d in domains)
        if persist:
            _persist(shell, domains, block)
        return block
    except Exception as exc:  # noqa: BLE001 - the check is a disclosure, never a blocker
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return build_reversal_capability_block(
            forests=[], verdicts=[], token_needs={}, checked_at=checked_at
        )


def _persist(shell: Any, domains: Iterable[str], block: Mapping[str, Any]) -> None:
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return
    wanted = {_norm(d) for d in domains}
    for key, bucket in domains_data.items():
        if _norm(key) in wanted and isinstance(bucket, dict):
            bucket[REVERSAL_CAPABILITY_KEY] = dict(block)


def print_cleanup_capability(shell: Any, block: Mapping[str, Any]) -> None:
    """Print the checklist (never a prompt: ``ci`` is unattended). Never raises."""
    try:
        from rich.table import Table  # noqa: PLC0415

        from adscan_core.rich_output import print_table  # noqa: PLC0415

        view = reversal_capability_view(block)
        if not view.get("forests"):
            print_info(
                "No in-scope domain is known yet, so what the cleanup account can undo "
                "is checked once the directory is collected."
            )
            return
        for forest in view["forests"]:
            title = f"What the cleanup account can undo in {forest['root']}"
            table = Table(title=mark_sensitive(title, "domain"))
            for column in ("Where", "Changes", "Can it undo them"):
                table.add_column(column)
            for row in forest["rows"]:
                answer = row["answer_label"]
                if row.get("reason_text"):
                    answer = f"{answer} ({row['reason_text']})"
                table.add_row(
                    mark_sensitive(row["place"], "domain"), row["subject"], answer
                )
            print_table(table)
            for line in forest["lines"]:
                print_info(mark_sensitive(line, "detail"))
        for row in view["nobody_rows"]:
            print_info(row["text"])
        for line in view["lines"]:
            print_info(line)
        print_info_debug("cleanup-capability " + " | ".join(checklist_text_lines(view)))
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def check_and_print(shell: Any, *, refresh: bool = False) -> dict[str, Any]:
    """Run the check and print it. The one entry the CLI surfaces call."""
    block = check_cleanup_capability(shell, refresh=refresh)
    print_cleanup_capability(shell, block)
    _remember_printed(shell, block)
    return block


#: Shell attribute: a COMPLETE checklist (read after collection) was printed this session.
PRINTED_ATTR = "_cleanup_capability_printed"
#: Shell attribute: the text of the last checklist printed (to print a change only).
_LAST_PRINTED_ATTR = "_cleanup_capability_last_printed"
#: Shell attribute: the "checked once the directory is collected" line was printed.
_DEFERRED_ATTR = "_cleanup_capability_deferred_noted"


def _remember_printed(shell: Any, block: Mapping[str, Any]) -> None:
    try:
        setattr(shell, _LAST_PRINTED_ATTR, checklist_text_lines(reversal_capability_view(block)))
        setattr(shell, PRINTED_ATTR, True)
    except Exception:  # noqa: BLE001 - a read-only shell just prints again
        pass


def _note_deferred(shell: Any) -> None:
    if getattr(shell, _DEFERRED_ATTR, False):
        return
    print_info(
        "What the cleanup account can undo is checked once the directory is collected, "
        "before any change is made."
    )
    try:
        setattr(shell, _DEFERRED_ATTR, True)
    except Exception:  # noqa: BLE001
        pass


def print_once(shell: Any, *, force: bool = False) -> None:
    """Print the checklist at the start of a scan and before the first attack step.

    ``force`` re-checks even when it was already printed (the start of a scan:
    every scan re-verifies). A checklist is printed only once the directory is
    collected; before that, one line says when it will be. Never raises.
    """
    try:
        if not force and getattr(shell, PRINTED_ATTR, False):
            return
        print_when_a_cleanup_account_is_set(shell)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def print_when_a_cleanup_account_is_set(shell: Any) -> bool:
    """At the start of ``ci`` / ``start`` and before the first attack step: check and print.

    Does nothing without a cleanup account. Before any in-scope domain's
    directory is read, prints one line instead of a checklist of unknowns (and
    records nothing). Returns True when a complete checklist was printed. Never
    prompts, never raises.
    """
    try:
        from adscan_internal.services.cleanup_credential_loader import (  # noqa: PLC0415
            cleanup_account_supplied,
        )

        if not cleanup_account_supplied():
            return False
        if not any_in_scope_domain_collected(shell):
            _note_deferred(shell)
            return False
        check_and_print(shell, refresh=True)
        return True
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False


def refresh_after_collection(shell: Any, domain: str) -> None:
    """Once ``domain``'s directory is collected: establish, record and show the checklist.

    The point where the checklist is complete for that domain: its SID, its
    memberships and the CAs it owns are known. Called by the collection seam
    BEFORE the AD CS confirmations, so the operator reads what can be undone
    before any certificate step. Records the block for the report and the web,
    and prints it when it differs from what was last printed (a second domain
    of the run adds its rows). Does nothing without a cleanup account or for a
    domain outside the engagement scope. Never raises.
    """
    try:
        from adscan_internal.services.cleanup_credential_loader import (  # noqa: PLC0415
            cleanup_account_supplied,
        )
        from adscan_internal.services.engagement_scope import (  # noqa: PLC0415
            domain_in_engagement_scope,
        )

        if not cleanup_account_supplied():
            return
        if not domain_in_engagement_scope(shell, _norm(domain)):
            return
        block = check_cleanup_capability(shell, persist=True)
        lines = checklist_text_lines(reversal_capability_view(block))
        if lines and lines != getattr(shell, _LAST_PRINTED_ATTR, None):
            print_cleanup_capability(shell, block)
            _remember_printed(shell, block)
    except Exception as exc:  # noqa: BLE001 - a disclosure never blocks collection
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def capability_block_for_report(shell: Any) -> Optional[dict[str, Any]]:
    """The block the report and the web read: the run's FINAL answer, or ``None``.

    The newest recorded block, unless none was recorded or it predates the
    directory data now held (``block_is_stale``); then, with a cleanup account,
    it is established now (read-only) and recorded. Never raises.
    """
    from adscan_core.reporting.reversal_capability import (  # noqa: PLC0415
        merge_reversal_capability,
    )

    try:
        from adscan_internal.services.cleanup_credential_loader import (  # noqa: PLC0415
            cleanup_account_supplied,
        )

        block = merge_reversal_capability(getattr(shell, "domains_data", None))
        if (block is None or block_is_stale(shell, block)) and cleanup_account_supplied():
            block = check_cleanup_capability(shell)
        return block
    except Exception as exc:  # noqa: BLE001 - disclosure states what it has
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


__all__ = [
    "any_in_scope_domain_collected",
    "block_is_stale",
    "capability_block_for_report",
    "check_and_print",
    "directory_collected",
    "policy_accepts_not_reversible",
    "refresh_after_collection",
    "check_cleanup_capability",
    "in_scope_cas",
    "in_scope_domains",
    "PRINTED_ATTR",
    "print_cleanup_capability",
    "print_once",
    "print_when_a_cleanup_account_is_set",
    "token_needs",
]
