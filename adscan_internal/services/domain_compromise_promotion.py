"""Single source of truth for promoting a domain to ``pwned`` state.

Multiple code paths discover that the engagement has reached "domain
compromise" — Domain Admin group membership, krbtgt hash extraction,
NTDS dump, etc. Before this module each of those paths duplicated the
same telemetry / session-state / victory-hint / CTF-trigger sequence,
which was both error-prone and hard to evolve.

Call :func:`promote_to_pwned` from every such path. It is idempotent —
the second call for the same domain returns ``False`` and is a no-op.
"""

from __future__ import annotations

import time
from enum import StrEnum
from typing import Any

import rich.box

from adscan_internal import (
    print_info_debug,
    telemetry,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.session_compromise_state_service import (
    mark_session_domain_compromised,
)


class CompromiseEvidence(StrEnum):
    """What proves the domain is compromised.

    The string value is recorded in telemetry, so do not rename
    casually — downstream dashboards filter on these.
    """

    DOMAIN_ADMIN_MEMBERSHIP = "domain_admin_membership"
    KRBTGT_HASH_EXTRACTED = "krbtgt_hash_extracted"
    TIER0_HASH_EXTRACTED = "tier0_hash_extracted"
    TIER0_PASSWORD_OBTAINED = "tier0_password_obtained"
    DCSYNC_RIGHTS_GRANTED = "dcsync_rights_granted"
    NTDS_DUMP = "ntds_dump"


def is_full_ntds_replicated(shell, domain: str) -> bool:
    """True once a full DCSync ("all") has replicated this domain's NTDS.

    Set by ``run_dcsync`` (via :func:`mark_full_ntds_replicated`) only on a
    successful "all" run. The post-compromise pipeline (CTF *and* audit) reads
    this to run the full replication EXACTLY ONCE: it dumps "all" when this is
    False (the compromise was reached without a full dump — e.g. DA-group
    membership, or an ESC8 DC-account targeted dump that only extracted the DA)
    and skips it when True (an attack-path DCSync step already dumped "all").
    """
    dd = getattr(shell, "domains_data", {}) or {}
    return bool((dd.get(domain) or {}).get("dcsync_all_done"))


def mark_full_ntds_replicated(shell, domain: str) -> None:
    """Record that the full NTDS ("all") has been replicated for ``domain``.

    Single source of truth for the ``dcsync_all_done`` marker consumed by
    :func:`is_full_ntds_replicated`. Best-effort: never raises.
    """
    dd = getattr(shell, "domains_data", None)
    if isinstance(dd, dict):
        try:
            dd.setdefault(domain, {})["dcsync_all_done"] = True
        except Exception:  # noqa: BLE001
            pass


def promote_to_pwned(
    shell,
    *,
    domain: str,
    evidence: CompromiseEvidence,
    username: str,
    credential: str | None,
    evidence_ref: str | None = None,
    compromise_summary: str | None = None,
    ctf_actions: set[str] | None = None,
) -> bool:
    """Mark ``domain`` as pwned and run the standard side-effects.

    Args:
        shell: The ADscan shell instance.
        domain: Domain key in ``shell.domains_data``.
        evidence: What proves the compromise. Stored in telemetry.
        username: Username that produced the evidence (DA member, krbtgt
            owner, etc.).
        credential: The credential value, if any (password, NT hash,
            ccache path). Stored in the CTF post-compromise context so
            queued actions can use it. Sensitive.
        evidence_ref: Optional path to the artifact that proves it
            (e.g. NTDS dump file inside the workspace).
        compromise_summary: Optional pre-rendered Rich summary string
            for the "Domain Compromised" panel. When ``None`` a
            default summary is built.
        ctf_actions: Optional set of CTF post-compromise actions to
            queue when ``shell.type == "ctf"``. Defaults to
            ``{"flags"}``. Pass e.g. ``{"flags", "dcsync"}`` for the
            full DA-membership flow.

    Returns:
        ``True`` if this call promoted the domain, ``False`` if it was
        already in ``pwned`` state (idempotent no-op).
    """
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        print_info_debug(
            f"[domain_compromise] shell has no domains_data; cannot promote {domain}"
        )
        return False
    entry = domains_data.get(domain)
    if not isinstance(entry, dict):
        print_info_debug(
            f"[domain_compromise] domain {domain!r} not found in domains_data"
        )
        return False

    if entry.get("auth") == "pwned":
        return False

    entry["auth"] = "pwned"

    # 1. Telemetry — match the legacy payload at adscan.py:21931.
    summary_text: str | None = compromise_summary
    try:
        from adscan_internal.cli.common import build_lab_event_fields

        duration_seconds: float | None = None
        duration_minutes: float | None = None
        if getattr(shell, "scan_start_time", None):
            duration_seconds = max(0.0, time.monotonic() - shell.scan_start_time)
            duration_minutes = round(duration_seconds / 60.0, 2)

        properties: dict[str, Any] = {
            "scan_mode": getattr(shell, "scan_mode", None),
            "duration_minutes": duration_minutes,
            "type": getattr(shell, "type", None),
            "auto": getattr(shell, "auto", None),
            "evidence": str(evidence),
        }
        try:
            properties.update(build_lab_event_fields(shell=shell, include_slug=True))
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
        telemetry.capture("domain_compromise", properties)

        if (
            hasattr(shell, "_scan_compromise_time")
            and shell._scan_compromise_time is None
        ):
            shell._scan_compromise_time = time.monotonic()
        mark_session_domain_compromised(shell)

        if hasattr(shell, "_session_victories"):
            try:
                shell._session_victories.append("domain_compromise")
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)

        if summary_text is None:
            marked_domain = mark_sensitive(domain, "domain")
            if duration_minutes is not None:
                summary_text = (
                    f"Domain [bold]{marked_domain}[/bold] compromised in "
                    f"[bold green]{duration_minutes:.2f} minute(s)[/bold green]."
                )
            else:
                summary_text = (
                    f"Domain [bold]{marked_domain}[/bold] has been compromised."
                )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)

    # 2. Record technical event for the report writer.
    try:
        from adscan_internal.reporting_compat import (
            load_optional_report_service_attr,
        )

        record_technical_event = load_optional_report_service_attr(
            "record_technical_event",
            action="Technical event sync",
            debug_printer=print_info_debug,
        )
        if callable(record_technical_event):
            try:
                record_technical_event(
                    shell,
                    domain,
                    event_type="domain_compromise",
                    message=f"Domain compromise via {evidence}",
                    details={
                        "username": username,
                        "domain": domain,
                        "evidence": str(evidence),
                        "evidence_ref": evidence_ref,
                    },
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)

    # 3. Victory hint + GitHub star CTA — defined in adscan.py at module
    # level. Imported lazily to avoid a circular import at package load.
    try:
        import adscan as _adscan_module  # type: ignore[import-not-found]
    except Exception:  # noqa: BLE001
        _adscan_module = None  # type: ignore[assignment]

    if _adscan_module is not None:
        should_show = getattr(_adscan_module, "should_show_victory_hint", None)
        show_explicit = getattr(_adscan_module, "show_victory_hint_explicit", None)
        try:
            if (
                callable(should_show)
                and callable(show_explicit)
                and should_show("da_compromise", "explicit")
            ):
                show_explicit(
                    victory_type="da_compromise",
                    title="🎯 Major Win: Domain Admin Compromised!",
                    message=(
                        "[bold green]You've just proven full domain compromise."
                        "[/bold green]\n\n"
                        "Domain Admin access confirmed. This is the finding your "
                        "client is paying you to discover.\n\n"
                        "[bold]Next step:[/bold] Document it before the engagement "
                        "window closes.\n"
                        "Generate a board-ready report → "
                        "[link=https://adscanpro.com/pro?utm_source=cli&"
                        "utm_medium=victory_da_compromise]"
                        "adscanpro.com/pro[/link]"
                    ),
                )
            # The session-exit rating -> star funnel owns the single star ask at
            # peak goodwill for value-moment sessions (Hormozi give:ask — one
            # primary ask). Suppress the inline star here when that funnel will
            # run this session; keep it for the paths the funnel does not cover
            # (non-interactive runs, or a repeat session already rated).
            from adscan_internal.services.session_rating import (
                rating_funnel_will_run,
                show_github_star_cta,
            )

            if not rating_funnel_will_run(shell, value_tier="domain_compromise"):
                show_github_star_cta(
                    shell,
                    trigger="domain_compromise",
                    extra_props={"evidence": str(evidence)},
                )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)

    # 4. Insert derived edge in the attack graph.
    # TODO(adscan): add a clean primitive in attack_graph_service —
    # ``upsert_domain_compromise_derived_edge(shell, domain, source_user,
    # evidence, evidence_ref)`` — and call it from here. For now the
    # graph is updated by the existing path-state machinery downstream.

    # 5. Post-compromise hook. The caller's action set drives BOTH the CTF and
    # the audit branch: "dcsync" requests a full DCSync ("all") of the domain
    # credential database. It is set by paths that have NOT already dumped the
    # NTDS (DA-group membership) and omitted by the secretsdump-driven paths
    # (krbtgt / Tier-0 hash already extracted) so neither mode replicates twice.
    post_compromise_actions = set(ctf_actions) if ctf_actions else {"flags"}
    if getattr(shell, "type", None) == "ctf":
        try:
            shell._ctf_queue_post_compromise_actions(
                domain,
                username,
                credential or "",
                actions=post_compromise_actions,
                compromise_summary=summary_text,
            )
            shell._ctf_execute_post_compromise_actions(domain)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
    else:
        # Non-CTF: render the compromise panel here so callers do not
        # have to. Matches the legacy presentation in adscan.py:22011.
        if summary_text:
            try:
                from adscan_internal.rich_output import print_panel

                print_panel(
                    summary_text,
                    title="[bold green]Domain Compromised[/bold green]",
                    border_style="green",
                    box=rich.box.ROUNDED,
                    padding=(1, 2),
                    expand=False,
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)

        # Audit post-compromise hook (symmetric with the CTF branch above).
        # QUEUE — do not run inline: promote_to_pwned frequently fires mid
        # attack-path execution (e.g. DCSync as a terminal step), and the
        # audit pipeline re-runs the attack-path engine, which must not run
        # re-entrantly. A safe checkpoint drains the queue (graph re-collection
        # AS the obtained DA + host credential-harvesting campaign).
        if getattr(shell, "type", None) == "audit":
            try:
                # DCSync-"all" is decided STATE-driven inside the executor
                # (is_full_ntds_replicated), not by the caller — so it runs once
                # regardless of which compromise path fired. See post_da.py.
                shell._queue_audit_post_compromise_actions(
                    domain, username, credential or ""
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)

    return True


__all__ = ["CompromiseEvidence", "promote_to_pwned"]
