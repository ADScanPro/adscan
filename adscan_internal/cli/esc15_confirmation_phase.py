"""Collection-stage ESC15 (EKUwu / CVE-2024-49019) active confirmation phase.

Runs during ADCS collection, right after the passive detector produces the
``ADCSESC15`` candidate edges and BEFORE the graph is consumed by attack-path
computation / the report. It mirrors the ESC8 web-enrollment probe and the
GetCASecurity DCOM read that collection already performs: a non-destructive
active probe that gates the edge on a real verdict, so the client report never
shows an unverified ``Authenticated Users -> domain`` ESC15 edge as a flat
CRITICAL (the CA patch state for CVE-2024-49019 is invisible to passive LDAP).

The confirmation enrolls ONE self-subject certificate with a canary application
policy and inspects the issued cert — no PKINIT, no on-behalf-of, no privileged
identity (``confirm_esc15_vulnerable``). The issued canary cert is a durable
credential in the client PKI, so revocation + the environment-change ledger are
inherited from ``request_certificate_native`` via ``EscConfig.shell``.

Opt-out: ``ADSCAN_NO_ESC15_CONFIRM=1`` skips the active issuance entirely; the
edge then falls to confirmation-pending (honest data gap), never a flat
critical, never silently dropped.
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
from adscan_internal.services.adcs.esc15_confirmation import (
    Esc15CollectionAction,
    Esc15TemplateRef,
    apply_esc15_verdicts_to_graph,
    classify_esc15_collection_action,
    collect_esc15_template_refs,
    esc15_confirmation_disabled,
    esc15_edge_notes_update,
)


def run_esc15_confirmation_phase(
    shell: Any,
    domain: str,
    *,
    credential: Any = None,
    dc_ip: Optional[str] = None,
    auth_domain: Optional[str] = None,
    auth_kdc: Optional[str] = None,
) -> None:
    """Confirm every ESC15 candidate for ``domain`` and gate its graph edge.

    Best-effort: any failure is captured and swallowed — a confirmation error
    must never abort collection, and it leaves the edge confirmation-pending
    (the safe, honest default) rather than dropping it.
    """
    try:
        from adscan_internal.services.attack_graph_service import (
            load_attack_graph,
            save_attack_graph,
        )

        graph = load_attack_graph(shell, domain)
        if not isinstance(graph, dict):
            return
        refs = collect_esc15_template_refs(graph)
        if not refs:
            return  # no ESC15 candidate in this domain

        marked_domain = mark_sensitive(domain, "domain")
        username, secret = _resolve_enrolling_credential(shell, domain, credential)

        # Opt-out or no usable enrolling credential (e.g. a Kerberos-only /
        # ccache-only scan the native cert request cannot use): never issue a
        # cert, leave every ESC15 edge confirmation-pending.
        if esc15_confirmation_disabled():
            reason = "active ESC15 confirmation opted out (ADSCAN_NO_ESC15_CONFIRM)"
            _apply_all_pending(graph, refs, reason)
            save_attack_graph(shell, domain, graph)
            print_info_verbose(
                f"ESC15 confirmation skipped for {marked_domain} (opt-out); "
                f"{len(refs)} candidate(s) left confirmation-pending."
            )
            return
        if not username or not secret:
            reason = "no password / NT-hash credential available to enroll (data gap)"
            _apply_all_pending(graph, refs, reason)
            save_attack_graph(shell, domain, graph)
            print_info_debug(
                f"[esc15-confirm] no enrolling credential for {marked_domain}; "
                f"{len(refs)} candidate(s) left confirmation-pending."
            )
            return

        verdicts: dict[str, Esc15CollectionAction] = {}
        notes_by_template: dict[str, dict[str, Any]] = {}
        hardened_templates: list[str] = []
        for ref in refs:
            action, notes, hardened_cn = _confirm_one_template(
                shell,
                domain=domain,
                ref=ref,
                username=username,
                secret=secret,
                dc_ip=dc_ip,
                auth_domain=auth_domain,
                auth_kdc=auth_kdc,
            )
            verdicts[ref.object_id] = action
            if action is not Esc15CollectionAction.REMOVE_HARDENED:
                notes_by_template[ref.object_id] = notes
            elif hardened_cn is not None:
                hardened_templates.append(hardened_cn)

        removed, marked = apply_esc15_verdicts_to_graph(
            graph, verdicts, notes_by_template=notes_by_template
        )
        save_attack_graph(shell, domain, graph)

        # A hardened CA has NO ESC15 exposure — record the verified control
        # (the graph edge is gone; this is the separate positive-control store).
        for template_cn in hardened_templates:
            _emit_hardened_positive(shell, domain, template_cn)

        print_info_verbose(
            f"ESC15 confirmation for {marked_domain}: "
            f"{removed} hardened edge(s) removed, {marked} edge(s) marked "
            "(confirmed/pending)."
        )
    except Exception as exc:  # noqa: BLE001 — never break collection
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            f"[esc15-confirm] confirmation phase failed for "
            f"{mark_sensitive(domain, 'domain')}: {exc}"
        )


def _apply_all_pending(
    graph: dict[str, Any], refs: list[Esc15TemplateRef], reason: str
) -> None:
    """Mark every ESC15 edge confirmation-pending (opt-out / no-credential path)."""
    verdicts = {ref.object_id: Esc15CollectionAction.KEEP_PENDING for ref in refs}
    notes_by_template = {
        ref.object_id: esc15_edge_notes_update(
            Esc15CollectionAction.KEEP_PENDING, verdict="skipped", reason=reason
        )
        for ref in refs
    }
    apply_esc15_verdicts_to_graph(graph, verdicts, notes_by_template=notes_by_template)


def _resolve_enrolling_credential(
    shell: Any, domain: str, credential: Any
) -> tuple[Optional[str], Optional[str]]:
    """Return ``(username, secret)`` for the enrolling principal.

    ``secret`` is a password OR an NT hash (``request_certificate_native``
    detects the format). A Kerberos/ccache-only credential yields no secret here,
    so the confirmation is left as a data gap (pending) rather than guessed.
    """
    username = getattr(credential, "username", None)
    secret = getattr(credential, "password", None)
    domain_data = getattr(shell, "domains_data", {}).get(domain, {})
    if not isinstance(domain_data, dict):
        domain_data = {}
    if not username:
        username = domain_data.get("username")
    if not secret:
        secret = domain_data.get("password") or domain_data.get("nt_hash")
    return (
        str(username).strip() if username else None,
        str(secret) if secret else None,
    )


def _confirm_one_template(
    shell: Any,
    *,
    domain: str,
    ref: Esc15TemplateRef,
    username: str,
    secret: str,
    dc_ip: Optional[str],
    auth_domain: Optional[str],
    auth_kdc: Optional[str],
) -> tuple[Esc15CollectionAction, dict[str, Any], Optional[str]]:
    """Confirm one ESC15 template; return ``(action, notes_update, hardened_cn)``.

    ``hardened_cn`` is the template CN when the verdict is hardened (so the caller
    can emit the positive control), else ``None``.
    """
    from adscan_internal.services.adcs.esc_enrollment import confirm_esc15_vulnerable
    from adscan_internal.services.adcs.esc_types import (
        EscConfig,
        map_esc15_confirm_result,
    )
    from adscan_internal.services.async_bridge import run_async_sync

    template_cn = ref.cn
    if not template_cn:
        template_cn = _resolve_untyped_template_cn(shell, domain)
    if not template_cn:
        return (
            Esc15CollectionAction.KEEP_PENDING,
            esc15_edge_notes_update(
                Esc15CollectionAction.KEEP_PENDING,
                verdict="skipped",
                reason="ESC15 template name could not be resolved (data gap)",
            ),
            None,
        )

    ca_target = _resolve_publishing_ca(shell, domain, template_cn)
    if ca_target is None:
        return (
            Esc15CollectionAction.KEEP_PENDING,
            esc15_edge_notes_update(
                Esc15CollectionAction.KEEP_PENDING,
                verdict="skipped",
                reason=(
                    "no reachable certification authority publishing the template "
                    "(CA unreachable; data gap)"
                ),
            ),
            None,
        )
    ca_name, ca_host, ca_fqdn = ca_target

    domain_data = getattr(shell, "domains_data", {}).get(domain, {})
    if not isinstance(domain_data, dict):
        domain_data = {}
    resolved_dc_ip = str(dc_ip or domain_data.get("pdc") or "")
    template_eku_oids = _resolve_template_eku_oids(shell, domain, template_cn)
    min_key_size = _resolve_template_min_key_size(shell, domain, template_cn)

    config = EscConfig(
        esc=15,
        domain=domain,
        auth_domain=str(auth_domain or domain),
        dc_ip=resolved_dc_ip,
        auth_kdc=str(auth_kdc or resolved_dc_ip),
        ca_host=ca_host,
        ca_name=ca_name,
        template=template_cn,
        username=username,
        password=secret,
        # Subject = self: NO target_upn, NO on-behalf-of. Non-destructive.
        workspace_dir=_resolve_workspace_dir(shell, domain),
        shell=shell,
        ca_fqdn=ca_fqdn,
        dc_fqdn=domain_data.get("dc_fqdn") or domain_data.get("pdc_hostname") or None,
        min_key_size=min_key_size,
    )

    result = run_async_sync(
        confirm_esc15_vulnerable(config, template_eku_oids=template_eku_oids)
    )
    decision = map_esc15_confirm_result(result)
    action = classify_esc15_collection_action(decision.verdict)
    evidence = result.evidence if isinstance(result.evidence, dict) else {}
    canary_oid = evidence.get("canary_oid")

    if action is Esc15CollectionAction.REMOVE_HARDENED:
        return (action, {}, template_cn)

    notes = esc15_edge_notes_update(
        action,
        verdict=decision.verdict,
        reason=decision.reason,
        canary_oid=str(canary_oid) if canary_oid else None,
    )
    if action is Esc15CollectionAction.KEEP_CONFIRMED:
        print_success(
            f"ESC15 CONFIRMED on {mark_sensitive(domain, 'domain')} "
            f"(template {mark_sensitive(template_cn, 'service')}): the CA honours "
            "application-policy injection (EKUwu / CVE-2024-49019)."
        )
    return (action, notes, None)


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
        print_info_debug(f"[esc15-confirm] CA resolution failed: {exc}")
        return None


def _resolve_template_eku_oids(shell: Any, domain: str, template_cn: str) -> list[str]:
    """Best-effort read of the template's EKU OIDs (for canary selection)."""
    try:
        from adscan_internal.cli.adcs_exploitation import _resolve_template_eku_oids as _r

        return list(_r(shell, domain, template_cn) or [])
    except Exception:  # noqa: BLE001
        return []


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
        from adscan_internal.cli.attack_path_execution import _resolve_workspace_dir as _r

        return _r(shell, domain)
    except Exception:  # noqa: BLE001
        return str(getattr(shell, "current_workspace_dir", "") or "")


def _resolve_untyped_template_cn(shell: Any, domain: str) -> Optional[str]:
    """Resolve a template CN for an ESC15 edge that carried no vulnerable resource."""
    try:
        from adscan_internal.cli.attack_path_execution import (
            _resolve_adcs_template_candidates,
        )

        domain_data = getattr(shell, "domains_data", {}).get(domain, {})
        if not isinstance(domain_data, dict):
            domain_data = {}
        candidates = _resolve_adcs_template_candidates(
            shell,
            domain=domain,
            exec_username=str(domain_data.get("username") or ""),
            password=str(domain_data.get("password") or ""),
            esc_number="15",
            details={},
            to_label=None,
            domain_data=domain_data,
        )
        return candidates[0] if candidates else None
    except Exception:  # noqa: BLE001
        return None


def _emit_hardened_positive(shell: Any, domain: str, template_cn: str) -> None:
    """Record the patched-CA positive control for a hardened ESC15 verdict."""
    try:
        from adscan_internal.services.positive_control_evidence import (
            emit_esc15_hardened_positive,
        )

        emit_esc15_hardened_positive(
            shell,
            domain,
            template=template_cn,
            reason=(
                "the CA stripped the injected application policy from the issued "
                "certificate"
            ),
        )
        print_success(
            f"ESC15 not exploitable on {mark_sensitive(domain, 'domain')} "
            f"(template {mark_sensitive(template_cn, 'service')}): the CA strips "
            "injected application policies (CVE-2024-49019 patched). Candidate "
            "dismissed and recorded as a verified control."
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


__all__ = ["run_esc15_confirmation_phase"]
