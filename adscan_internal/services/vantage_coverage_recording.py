"""Record a privilege the assessment proved but could not exercise.

The client-facing wording lives in the shared SSOT
:mod:`adscan_core.reporting.vantage_coverage`. This module is the thin,
shell-aware recording seam: it humanizes the principal label, derives the
domain DN the verification command needs, merges the new record into whatever
the domain already carried, and persists the block.

It exists so the OBSERVING seam (the one that watched the ports stay silent)
stays a one-line call, and so no caller has to know the block is a union that
must be read before it is written.
"""

from __future__ import annotations

from typing import Any

from adscan_core import telemetry
from adscan_core.rich_output import print_exception, print_info_debug


def domain_dn_from_domain(domain: str) -> str:
    """Return the distinguished name of *domain*, or ``""``.

    ``cicada.htb`` becomes ``DC=cicada,DC=htb``. Purely mechanical, so a
    verification command can name a real object instead of a placeholder.
    """
    parts = [p for p in str(domain or "").strip().strip(".").split(".") if p]
    if not parts:
        return ""
    return ",".join(f"DC={p}" for p in parts)


def _humanize(label: str, domain: str) -> str:
    """Return the client-facing form of a principal label.

    Routes through the humanization SSOT so a deliverable never shows a raw
    SID, a shouting UPN or the synthetic well-known realm qualifier. Degrades to
    the label as given if the humanizer cannot be reached, which is better than
    recording nothing.
    """
    try:
        from adscan_core.reporting.principal_display import (  # noqa: PLC0415
            humanize_principal_for_prose,
        )

        return (
            humanize_principal_for_prose(label=label, report_domain=domain) or label
        )
    except Exception as exc:  # noqa: BLE001 - a label read is best-effort
        telemetry.capture_exception(exc)
        return label


def record_unexercisable_privilege(
    shell: Any,
    domain: str,
    *,
    protocol: str,
    holder: str,
    host: str = "",
    reachable_ports: str = "",
    unreachable_ports: str = "",
    target: str = "",
) -> None:
    """Persist one unexercised-privilege record for *domain*.

    Args:
        shell: The pentest shell (used only to resolve the technical report).
        domain: The domain the privilege is held over.
        protocol: A key of
            :data:`adscan_core.reporting.vantage_coverage.VANTAGE_PROTOCOLS`.
        holder: The principal that holds the privilege, as a raw label; it is
            humanized here.
        host: The host the attempt went to (a domain controller).
        reachable_ports: What DID answer, in the client's terms (e.g. ``"135"``).
        unreachable_ports: What did not (e.g. ``"49152-65535"``).
        target: What the privilege is held over; defaults to *domain*.

    Best-effort and idempotent per ``(protocol, holder, target)``: the SSOT
    de-duplicates, so a retried step records one declaration, not three. Never
    raises into the caller, because a scan must not fail over its own coverage
    note.
    """
    try:
        from adscan_core.reporting.technical_report import (  # noqa: PLC0415
            read_vantage_coverage,
            record_vantage_coverage,
        )
        from adscan_core.reporting.vantage_coverage import (  # noqa: PLC0415
            build_vantage_coverage,
        )

        existing = read_vantage_coverage(shell, domain) or {}
        prior = existing.get("entries")
        entries: list[Any] = list(prior) if isinstance(prior, list) else []
        entries.append(
            {
                "protocol": protocol,
                "holder": _humanize(holder, domain),
                "target": target or domain,
                "host": host,
                "domain_dn": domain_dn_from_domain(domain),
                "reachable_ports": reachable_ports,
                "unreachable_ports": unreachable_ports,
            }
        )
        record_vantage_coverage(
            shell, domain, coverage=build_vantage_coverage(entries=entries)
        )
        print_info_debug(
            f"vantage-coverage: recorded unexercisable {protocol} privilege "
            f"for domain={domain!r}"
        )
    except Exception as exc:  # noqa: BLE001 - a coverage note is best-effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


__all__ = ["domain_dn_from_domain", "record_unexercisable_privilege"]
