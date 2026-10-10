"""Collection-stage ESC9 / ESC10 (implicit certificate mapping) active confirmation.

Runs during ADCS collection, right after the passive detector produces the
``ADCSESC9`` / ``ADCSESC10`` candidate edges and BEFORE the graph is consumed by
attack-path computation / the report. It mirrors the ESC14 / ESC15 confirmation
phases: a non-destructive active probe that gates the edge on a real verdict, so
the client report never shows an unverified ESC9/10 edge as a flat CRITICAL on a
domain controller where it is not exploitable.

ESC9/10's existence condition is the DOMAIN's certificate-binding posture (whether
the DCs still honour the WEAK implicit UPN-from-subject mapping a no-SID certificate
relies on), which is invisible to passive LDAP. This phase reads it two ways
(Option C — registry first, behavioral fallback):

1. ``StrongCertificateBindingEnforcement`` (SCBE) on every domain controller, via
   the SHARED observation SSOT :func:`observe_domain_scbe` (memoized per scan, so it
   reuses the read ESC14's confirmation already performed). Full (== 2) everywhere
   -> the edges are removed and a positive control recorded; SCBE < 2 -> the edges
   are kept CONFIRMED (weak binding present).
2. only when the registry read is INDETERMINATE (UNKNOWN), a behavioral canary
   (:func:`confirm_esc9_vulnerable`): enroll ONE self no-SID certificate from the
   ESC9 template and PKINIT as self. A Kerberos code-66 refusal upgrades the verdict
   to effective HARDENED (basis=behavioral); a PKINIT success upgrades it to WEAK.
   The behavioral verdict drives THIS phase only; it is never written back into the
   shared SCBE memo, so the registry observation ESC14 relies on is uncontaminated.

Posture guardrail: an edge is REMOVED only on an OBSERVED hardened verdict. An
absence / unreachable read / opt-out / no credential, and a clock-skew
``KDC_ERR_CLIENT_NOT_TRUSTED`` from the canary, all stay confirmation-pending —
never removed, never a flat critical.

Opt-out: ``ADSCAN_NO_ESC9_CONFIRM=1`` skips the active probe entirely; the edges
then fall to confirmation-pending (honest data gap), never a flat critical, never
silently dropped.
"""

from __future__ import annotations

from typing import Any, Optional

from adscan_internal import telemetry
from adscan_core.rich_output import (
    mark_sensitive,
    print_exception,
    print_info_debug,
    print_info_verbose,
    print_success,
)
from adscan_internal.services.adcs.esc14_confirmation import (
    ScbeBasis,
    ScbeState,
    ScbeVerdict,
)
from adscan_internal.services.adcs.esc9_confirmation import (
    Esc9ApplyResult,
    apply_esc9_confirmation_to_graph,
    esc9_confirmation_disabled,
    graph_has_esc9_edges,
)
from adscan_internal.services.adcs.scbe_observation import (
    observe_domain_scbe,
    resolve_reading_credential,
)

_ESC9_RELATIONS = ("ADCSESC9", "ADCSESC10")


def run_esc9_confirmation_phase(
    shell: Any,
    domain: str,
    *,
    credential: Any = None,
    dc_ip: Optional[str] = None,
    auth_domain: Optional[str] = None,
    auth_kdc: Optional[str] = None,
) -> None:
    """Confirm every ESC9/10 candidate for ``domain`` and gate its graph edges.

    Best-effort: any failure is captured and swallowed — a confirmation error must
    never abort collection, and it leaves the edges confirmation-pending (the safe,
    honest default) rather than dropping them.
    """
    try:
        from adscan_internal.services.attack_graph_service import (
            load_attack_graph,
            save_attack_graph,
        )

        graph = load_attack_graph(shell, domain)
        if not isinstance(graph, dict) or not graph_has_esc9_edges(graph):
            return  # no ESC9/10 candidate in this domain

        marked_domain = mark_sensitive(domain, "domain")

        if esc9_confirmation_disabled():
            scbe = _pending_verdict(
                "active ESC9 confirmation opted out (ADSCAN_NO_ESC9_CONFIRM)"
            )
            result = apply_esc9_confirmation_to_graph(graph, scbe)
            save_attack_graph(shell, domain, graph)
            print_info_verbose(
                f"ESC9 confirmation skipped for {marked_domain} (opt-out); "
                f"{result.pending} candidate(s) left confirmation-pending."
            )
            return

        # Option C: registry first via the shared SCBE observation SSOT.
        scbe = observe_domain_scbe(
            shell,
            domain,
            credential=credential,
            dc_ip=dc_ip,
            auth_domain=auth_domain,
            auth_kdc=auth_kdc,
        )

        # Behavioral fallback ONLY when the registry read was indeterminate. A
        # definite registry verdict (WEAK / HARDENED) is used as-is — the canary
        # would only issue a certificate for no new information.
        if scbe.state is ScbeState.UNKNOWN:
            behavioral = _run_behavioral_canary(
                shell,
                domain,
                graph,
                credential=credential,
                dc_ip=dc_ip,
                auth_domain=auth_domain,
                auth_kdc=auth_kdc,
            )
            if behavioral is not None:
                scbe = behavioral

        result = apply_esc9_confirmation_to_graph(graph, scbe)
        save_attack_graph(shell, domain, graph)

        if scbe.state is ScbeState.HARDENED and result.removed:
            # Every ESC9/10 edge is decided by the single domain-wide SCBE verdict,
            # so a HARDENED verdict removes them all (confirmed == pending == 0). The
            # implicit-mapping existence condition is absent domain-wide: record the
            # verified control. NEVER a closed_by_configuration edge — SCBE is ESC9's
            # existence condition, not an orthogonal avenue.
            _emit_hardened_positive(shell, domain, scbe)
            print_success(
                f"ESC9 / ESC10 not exploitable on {marked_domain}: the domain "
                "controllers enforce strong certificate binding (KB5014754), so a "
                "certificate with no SID extension is refused. Candidate dismissed "
                "and recorded as a verified control."
            )
        elif result.confirmed:
            print_success(
                f"ESC9 / ESC10 CONFIRMED on {marked_domain}: a domain controller "
                "accepts weak certificate binding, so a certificate with no SID "
                "extension authenticates via the implicit mapping."
            )
        _report_counts(marked_domain, result)
    except Exception as exc:  # noqa: BLE001 — never break collection
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            f"[esc9-confirm] confirmation phase failed for "
            f"{mark_sensitive(domain, 'domain')}: {exc}"
        )


def _report_counts(marked_domain: str, result: Esc9ApplyResult) -> None:
    """Emit the per-run ESC9/10 confirmation tally at verbose level."""
    print_info_verbose(
        f"ESC9 confirmation for {marked_domain}: {result.removed} hardened edge(s) "
        f"removed, {result.confirmed} confirmed, {result.pending} confirmation-pending."
    )


def _pending_verdict(reason: str) -> ScbeVerdict:
    """Build an UNKNOWN SCBE verdict carrying ``reason`` (opt-out path)."""
    return ScbeVerdict(state=ScbeState.UNKNOWN, reason=reason)


def _run_behavioral_canary(
    shell: Any,
    domain: str,
    graph: dict[str, Any],
    *,
    credential: Any,
    dc_ip: Optional[str],
    auth_domain: Optional[str],
    auth_kdc: Optional[str],
) -> Optional[ScbeVerdict]:
    """Behavioral SCBE observation when the registry read was indeterminate.

    Enrolls a self no-SID certificate from an ESC9 template and PKINITs as self.
    Returns a behavioral :class:`ScbeVerdict` (HARDENED on a code-66 refusal, WEAK on
    a PKINIT success) or ``None`` when no definite observation could be made (keeps
    the edges confirmation-pending). Best-effort: any failure returns ``None``.
    """
    try:
        username, secret = resolve_reading_credential(shell, domain, credential)
        if not username or not secret:
            return None  # no enrolling credential: stay pending (data gap)

        template_cns = _collect_esc9_template_cns(graph)
        if not template_cns:
            return None  # template name unresolved: stay pending

        # Clock-sync guard BEFORE the PKINIT canary. PKINIT validates the signed
        # authenticator against the DC's REAL time, so a drifted host clock would
        # fail with KDC_ERR_CLIENT_NOT_TRUSTED (clock skew, NOT hardening). Step the
        # host clock physically first so a code-66 refusal is attributable to strong
        # binding, not drift. Best-effort (never raises).
        _ensure_clock_synced(shell, domain, dc_ip)

        for template_cn in template_cns:
            verdict = _confirm_one_canary(
                shell,
                domain=domain,
                template_cn=template_cn,
                username=username,
                secret=secret,
                dc_ip=dc_ip,
                auth_domain=auth_domain,
                auth_kdc=auth_kdc,
            )
            if verdict is not None and verdict.state in (
                ScbeState.HARDENED,
                ScbeState.WEAK,
            ):
                return verdict
        return None  # every canary was indeterminate: stay pending
    except Exception as exc:  # noqa: BLE001 — data gap => stay pending
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            f"[esc9-confirm] behavioral canary failed for "
            f"{mark_sensitive(domain, 'domain')}: {exc}"
        )
        return None


def _collect_esc9_template_cns(graph: dict[str, Any]) -> list[str]:
    """Return the distinct ESC9/10 template enrollment CNs from the graph edges.

    ESC9/10 derived edges carry the abused CertTemplate(s) under
    ``notes.vulnerable_resources`` (see ``collector/persistence``), exactly like
    ESC15. A canary enrolls from any one of them; one successful canary observes the
    domain-wide binding posture.
    """
    edges = graph.get("edges")
    if not isinstance(edges, list):
        return []
    seen: list[str] = []
    for edge in edges:
        if (
            not isinstance(edge, dict)
            or str(edge.get("relation") or "").strip() not in _ESC9_RELATIONS
        ):
            continue
        notes = edge.get("notes")
        if not isinstance(notes, dict):
            continue
        for resource in notes.get("vulnerable_resources") or []:
            if not isinstance(resource, dict):
                continue
            if str(resource.get("kind") or "").strip() != "CertTemplate":
                continue
            cn = str(resource.get("name") or "").strip()
            if cn and cn not in seen:
                seen.append(cn)
    return seen


def _confirm_one_canary(
    shell: Any,
    *,
    domain: str,
    template_cn: str,
    username: str,
    secret: str,
    dc_ip: Optional[str],
    auth_domain: Optional[str],
    auth_kdc: Optional[str],
) -> Optional[ScbeVerdict]:
    """Run the self no-SID canary against one template; return a behavioral verdict.

    Returns a behavioral :class:`ScbeVerdict` for a definite outcome, or ``None`` for
    an indeterminate one (CA unreachable, request denied/pending, or a non-66 PKINIT
    failure). Never raises.
    """
    from adscan_internal.services.adcs.esc_enrollment import confirm_esc9_vulnerable
    from adscan_internal.services.adcs.esc_types import (
        EscConfig,
        map_esc9_confirm_result,
    )
    from adscan_internal.services.async_bridge import run_async_sync

    ca_target = _resolve_publishing_ca(shell, domain, template_cn)
    if ca_target is None:
        return None  # CA unreachable: indeterminate -> stay pending
    ca_name, ca_host, ca_fqdn = ca_target

    domain_data = getattr(shell, "domains_data", {}).get(domain, {})
    if not isinstance(domain_data, dict):
        domain_data = {}
    resolved_dc_ip = str(dc_ip or domain_data.get("pdc") or "")
    min_key_size = _resolve_template_min_key_size(shell, domain, template_cn)

    config = EscConfig(
        esc=9,
        domain=domain,
        auth_domain=str(auth_domain or domain),
        dc_ip=resolved_dc_ip,
        auth_kdc=str(auth_kdc or resolved_dc_ip),
        ca_host=ca_host,
        ca_name=ca_name,
        template=template_cn,
        username=username,
        password=secret,
        # Subject = self: NO target_upn, NO on_behalf_of. Non-destructive.
        workspace_dir=_resolve_workspace_dir(shell, domain),
        shell=shell,
        ca_fqdn=ca_fqdn,
        dc_fqdn=domain_data.get("dc_fqdn") or domain_data.get("pdc_hostname") or None,
        min_key_size=min_key_size,
    )

    result = run_async_sync(confirm_esc9_vulnerable(config))
    decision = map_esc9_confirm_result(result)
    if decision.is_positive_control:  # hardened
        return ScbeVerdict(
            state=ScbeState.HARDENED,
            reason=decision.reason,
            basis=ScbeBasis.BEHAVIORAL,
        )
    if decision.is_proven:  # confirmed_vulnerable (weak binding)
        return ScbeVerdict(
            state=ScbeState.WEAK,
            reason=decision.reason,
            basis=ScbeBasis.BEHAVIORAL,
        )
    return None  # indeterminate


def _ensure_clock_synced(shell: Any, domain: str, dc_ip: Optional[str]) -> None:
    """Physically step the host clock to the DC before the PKINIT canary (best-effort)."""
    try:
        from adscan_internal.models.domain import resolve_dc_ip
        from adscan_internal.services.dc_time import do_ensure_clock_synced_fresh

        domain_data = getattr(shell, "domains_data", {}).get(domain, {})
        if not isinstance(domain_data, dict):
            domain_data = {}
        resolved = str(dc_ip or resolve_dc_ip(domain_data) or "").strip()
        if not resolved:
            return
        do_ensure_clock_synced_fresh(shell, domain, resolved)
    except Exception as exc:  # noqa: BLE001 — clock sync is best-effort
        telemetry.capture_exception(exc)
        print_info_debug(f"[esc9-confirm] clock sync before canary failed: {exc}")


def _resolve_publishing_ca(
    shell: Any, domain: str, template_cn: str
) -> Optional[tuple[str, str, Optional[str]]]:
    """Resolve a reachable CA that publishes ``template_cn`` (CA-resolution SSOT)."""
    try:
        from adscan_internal.cli.attack_path_execution import (
            _resolve_reachable_publishing_ca,
        )

        return _resolve_reachable_publishing_ca(shell, domain, template_cn)
    except Exception as exc:  # noqa: BLE001 — resolution failure => data gap
        telemetry.capture_exception(exc)
        print_info_debug(f"[esc9-confirm] CA resolution failed: {exc}")
        return None


def _resolve_template_min_key_size(
    shell: Any, domain: str, template_cn: str
) -> Optional[int]:
    """Best-effort read of the template's minimal key size."""
    try:
        from adscan_internal.cli.adcs_exploitation import (
            _resolve_template_min_key_size as _r,
        )

        return _r(shell, domain, template_cn)
    except Exception:  # noqa: BLE001
        return None


def _resolve_workspace_dir(shell: Any, domain: str) -> str:
    """Resolve the ESC confirmation workspace dir (reuses the executor SSOT)."""
    try:
        from adscan_internal.cli.attack_path_execution import (
            _resolve_workspace_dir as _r,
        )

        return _r(shell, domain)
    except Exception:  # noqa: BLE001
        return str(getattr(shell, "current_workspace_dir", "") or "")


def _emit_hardened_positive(shell: Any, domain: str, scbe: ScbeVerdict) -> None:
    """Record the SCBE-hardened positive control for an ESC9/10 hardened verdict."""
    try:
        from adscan_internal.services.positive_control_evidence import (
            emit_esc9_hardened_positive,
        )

        emit_esc9_hardened_positive(shell, domain, scbe=scbe.scbe, reason=scbe.reason)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


__all__ = ["run_esc9_confirmation_phase"]
