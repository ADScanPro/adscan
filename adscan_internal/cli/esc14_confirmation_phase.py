"""Collection-stage ESC14 (weak explicit certificate mapping) active confirmation.

Runs during ADCS collection, right after the passive detector produces the
``ADCSESC14`` candidate edges and BEFORE the graph is consumed by attack-path
computation / the report. It mirrors the ESC15 confirmation phase: a
non-destructive active probe that gates the edge on a real verdict, so the client
report never shows an unverified ESC14 edge as a flat CRITICAL.

The passive detector flags a template shape plus its enrollment principals; it does
NOT establish either real ESC14 existence condition. This phase reads BOTH, entirely
with READS (no certificate issued):

1. ``StrongCertificateBindingEnforcement`` (SCBE) on every domain controller over
   aiosmb Remote Registry (the previously-unused
   :meth:`CertificateMappingService.read_dc_binding_state`). Full (== 2) everywhere
   -> the SCBE-gated edges (variants B/C/D and implicit mappings) are removed and a
   positive control recorded. A variant A (write-access) edge is EXEMPT: it plants a
   strong explicit mapping that SCBE Full does not close, so it is kept CONFIRMED
   under Full enforcement (write access alone suffices at every SCBE level,
   lab-proven on a patched DC) and the positive control is suppressed when such an
   edge survives.
2. when a DC still accepts weak mappings (SCBE < 2), condition #2 — read from
   production SSOTs, never hand-rolled:
   * variant A: the executor's ``_resolve_esc9_puppet_user`` resolves a
     ``role=puppet`` target off the edge (the collector's write-ACL + group-closure
     result), i.e. a controlling principal can WRITE that target's
     altSecurityIdentities;
   * variants B/C/D:
     ``AltSecurityIdentitiesService.find_users_with_weak_altsecurityidentities``
     finds a reachable account already carrying a weak-form mapping over LDAP.

   A WEAK DC with neither condition #2 established stays confirmation-pending — SCBE
   < 2 alone is never a flat CONFIRMED.

Opt-out: ``ADSCAN_NO_ESC14_CONFIRM=1`` skips the active reads entirely; the edges
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
    Esc14ApplyResult,
    Esc14WeakMappingTarget,
    ScbeState,
    ScbeVerdict,
    apply_esc14_confirmation_to_graph,
    esc14_confirmation_disabled,
    graph_has_esc14_edges,
)
from adscan_internal.services.adcs.scbe_observation import (
    observe_domain_scbe,
    resolve_reading_credential,
)


def run_esc14_confirmation_phase(
    shell: Any,
    domain: str,
    *,
    credential: Any = None,
    dc_ip: Optional[str] = None,
    auth_domain: Optional[str] = None,
    auth_kdc: Optional[str] = None,
) -> None:
    """Confirm every ESC14 candidate for ``domain`` and gate its graph edges.

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
        if not isinstance(graph, dict) or not graph_has_esc14_edges(graph):
            return  # no ESC14 candidate in this domain

        marked_domain = mark_sensitive(domain, "domain")
        username, secret = resolve_reading_credential(shell, domain, credential)

        # Opt-out / no usable credential: never read, leave every edge pending.
        if esc14_confirmation_disabled():
            self_verdict = _pending_verdict(
                "active ESC14 confirmation opted out (ADSCAN_NO_ESC14_CONFIRM)"
            )
            self_reason = "opt-out"
        elif not username or not secret:
            self_verdict = _pending_verdict(
                "no usable domain credential to read DC binding enforcement (data gap)"
            )
            self_reason = "no credential"
        else:
            self_verdict = None
            self_reason = ""

        if self_verdict is not None:
            result = apply_esc14_confirmation_to_graph(
                graph,
                self_verdict,
                domain_has_weak_mapping=False,
                has_write_access=lambda _edge: False,
            )
            save_attack_graph(shell, domain, graph)
            print_info_verbose(
                f"ESC14 confirmation skipped for {marked_domain} ({self_reason}); "
                f"{result.pending} candidate(s) left confirmation-pending."
            )
            return

        # Read + classify SCBE via the shared observation SSOT (memoized per scan,
        # so ESC9/10's later confirmation reuses this read rather than probing the
        # DC registry twice). The resulting ScbeVerdict is byte-identical to the
        # previous inline read + classify_scbe_state here.
        scbe = observe_domain_scbe(
            shell,
            domain,
            credential=credential,
            dc_ip=dc_ip,
            auth_domain=auth_domain,
            auth_kdc=auth_kdc,
        )

        # Condition #2 is only consulted when a DC still accepts weak mappings.
        # A hardened / unknown SCBE decides the edges on its own, so skip the extra
        # LDAP read + puppet resolution.
        weak_mapping_targets: list[Esc14WeakMappingTarget] = []
        if scbe.state is ScbeState.WEAK:
            weak_mapping_targets = _resolve_weak_mapping_targets(
                shell,
                domain=domain,
                username=username,
                secret=secret,
                dc_ip=dc_ip,
                auth_domain=str(auth_domain or domain),
                auth_kdc=auth_kdc,
            )

        def _has_write_access(edge: dict[str, Any]) -> bool:
            return _edge_has_write_access(edge, domain)

        # A variant-A edge plants a STRONG explicit mapping the KDC honors even under
        # SCBE Full (lab-proven on a patched DC), so write access alone confirms it at
        # every SCBE level — no no-SID-extension / ESC9-shaped template is required.
        result = apply_esc14_confirmation_to_graph(
            graph,
            scbe,
            domain_has_weak_mapping=bool(weak_mapping_targets),
            has_write_access=_has_write_access,
            weak_mapping_targets=tuple(weak_mapping_targets),
        )
        save_attack_graph(shell, domain, graph)

        if scbe.state is ScbeState.HARDENED and not result.confirmed and not result.pending:
            # Record the control ONLY when EVERY ESC14 edge was removed. A variant-A
            # (write-access) edge plants a STRONG explicit mapping that SCBE Full does
            # not close, so it is KEPT as CONFIRMED (write access alone suffices at
            # every SCBE level, lab-proven). A kept variant-A edge therefore survives
            # in result.confirmed; declaring ESC14 "not exploitable" and recording a
            # verified control while such an edge lives would be the false negative
            # the Exposure-Validation doctrine forbids (SCBE Full does not cover it).
            _emit_hardened_positive(shell, domain, scbe)
            print_success(
                f"ESC14 not exploitable on {marked_domain}: every domain controller "
                "enforces strong certificate binding (KB5014754 Full), so weak "
                "explicit mappings are refused. Candidate dismissed and recorded as "
                "a verified control."
            )
        elif result.confirmed:
            if scbe.state is ScbeState.HARDENED:
                print_success(
                    f"ESC14 CONFIRMED on {marked_domain}: a controlling principal can "
                    "plant a strong certificate mapping (variant A) the KDC honors "
                    "even under strong certificate binding enforcement (Full)."
                )
            else:
                print_success(
                    f"ESC14 CONFIRMED on {marked_domain}: a domain controller accepts "
                    "weak explicit certificate mappings and an abusable mapping or "
                    "write access was verified."
                )
        _report_counts(marked_domain, result)
    except Exception as exc:  # noqa: BLE001 — never break collection
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            f"[esc14-confirm] confirmation phase failed for "
            f"{mark_sensitive(domain, 'domain')}: {exc}"
        )


def _report_counts(marked_domain: str, result: Esc14ApplyResult) -> None:
    """Emit the per-run ESC14 confirmation tally at verbose level."""
    print_info_verbose(
        f"ESC14 confirmation for {marked_domain}: {result.removed} hardened edge(s) "
        f"removed, {result.confirmed} confirmed, {result.pending} confirmation-pending."
    )


def _pending_verdict(reason: str) -> ScbeVerdict:
    """Build an UNKNOWN SCBE verdict carrying ``reason`` (opt-out / no-credential)."""
    return ScbeVerdict(state=ScbeState.UNKNOWN, reason=reason)


def _edge_has_write_access(edge: dict[str, Any], domain: str) -> bool:
    """Condition #2(a): does this ESC14 edge carry proven altSecurityIdentities write?

    Reuses the executor's ``_resolve_esc9_puppet_user`` SSOT: the collector only
    stamps a ``role=puppet`` target resource onto a writer-mediated edge when it has
    already proven (via the write-ACL + group-closure resolution) that a controlling
    principal can write that target's identity attributes. A resolved puppet is that
    proof; its absence means the edge is enrollment-sourced with no established write
    access.
    """
    try:
        from adscan_internal.cli.attack_path_execution import _resolve_esc9_puppet_user

        notes = edge.get("notes")
        if not isinstance(notes, dict):
            return False
        return _resolve_esc9_puppet_user(notes, domain) is not None
    except Exception as exc:  # noqa: BLE001 — resolution failure => not established
        telemetry.capture_exception(exc)
        print_info_debug(f"[esc14-confirm] puppet resolution failed: {exc}")
        return False


def _resolve_weak_mapping_targets(
    shell: Any,
    *,
    domain: str,
    username: str,
    secret: str,
    dc_ip: Optional[str],
    auth_domain: str,
    auth_kdc: Optional[str],
) -> list[Esc14WeakMappingTarget]:
    """Condition #2(b): the reachable accounts carrying a weak altSecurityIdentities.

    Reuses the ``AltSecurityIdentitiesService`` SSOT over a posture-aware LDAP
    connection and classifies each weak mapping into its B/C/D variant via the
    variant SSOT, so every confirmed ESC14 edge carries the FULL set of open
    avenues (not just a boolean) and the executor can dispatch any of them against
    the real account the mapping names. Best-effort: any failure returns ``[]``
    (the conservative, honest direction — a data gap keeps the edge pending, never
    a false confirm). ``low_privileged_only=False`` because a weak mapping on a
    PRIVILEGED account is the most dangerous ESC14 target, not one to filter out.
    """
    try:
        from adscan_internal.services.altsecurityidentities_service import (
            AltSecurityIdentitiesService,
        )
        from adscan_internal.services.adcs.esc14_variants import (
            ESC14_VICTIM_ATTRIBUTE,
            classify_weak_binding,
            extract_victim_match_value,
        )
        from adscan_internal.services.domain_posture import get_posture
        from adscan_internal.services.ldap_transport_service import (
            ADscanLDAPConfig,
            ADscanLDAPConnection,
        )
        from adscan_internal.models.domain import resolve_dc_ip

        domain_data = getattr(shell, "domains_data", {}).get(domain, {})
        if not isinstance(domain_data, dict):
            domain_data = {}
        resolved_dc_ip = str(dc_ip or resolve_dc_ip(domain_data) or "").strip()
        if not resolved_dc_ip:
            return []

        config = ADscanLDAPConfig(
            domain=domain,
            dc_ip=resolved_dc_ip,
            use_ldaps=True,
            use_kerberos=False,
            username=username,
            password=secret,  # NT hash is accepted here via the canonical PtH path
            auth_domain=auth_domain,
            auth_kdc=str(auth_kdc or "").strip() or None,
            posture_snapshot=get_posture(
                getattr(shell, "domains_data", None), domain=domain
            ),
        )
        with ADscanLDAPConnection(config) as conn:
            users = AltSecurityIdentitiesService().find_users_with_weak_altsecurityidentities(
                connection=conn,
                domain=domain,
                shell=shell,
                enabled_only=True,
                low_privileged_only=False,
            )

        targets: list[Esc14WeakMappingTarget] = []
        for user in users:
            for weak_value in user.weak_mappings:
                variant = classify_weak_binding(weak_value)
                if variant is None:
                    continue
                match_value = extract_victim_match_value(variant, weak_value)
                if not match_value:
                    continue  # unparseable mapping: fail honest, never guess a value
                targets.append(
                    Esc14WeakMappingTarget(
                        variant=variant.value,
                        samaccountname=user.samaccountname,
                        distinguished_name=user.distinguished_name,
                        weak_binding=weak_value,
                        victim_attribute=ESC14_VICTIM_ATTRIBUTE[variant],
                        match_value=match_value,
                        is_tier0=bool(user.is_tier0 or user.is_high_value),
                    )
                )

        print_info_debug(
            f"[esc14-confirm] weak altSecurityIdentities enumeration for "
            f"{mark_sensitive(domain, 'domain')}: "
            f"{len(users)} weak-mapped account(s), {len(targets)} abusable variant(s)"
        )
        return targets
    except Exception as exc:  # noqa: BLE001 — data gap => not established
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            f"[esc14-confirm] weak-mapping enumeration failed for "
            f"{mark_sensitive(domain, 'domain')}: {exc}"
        )
        return []


def _emit_hardened_positive(shell: Any, domain: str, scbe: ScbeVerdict) -> None:
    """Record the SCBE-Full positive control for a hardened ESC14 verdict."""
    try:
        from adscan_internal.services.positive_control_evidence import (
            emit_esc14_hardened_positive,
        )

        emit_esc14_hardened_positive(
            shell, domain, scbe=scbe.scbe, reason=scbe.reason
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


__all__ = ["run_esc14_confirmation_phase"]
