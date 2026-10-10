"""Pre-flight Rich UX panel and confirmation for ESC exploitation flows."""
from __future__ import annotations
from typing import TYPE_CHECKING
from rich.box import ROUNDED
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from adscan_internal.rich_output import mark_sensitive

if TYPE_CHECKING:
    from adscan_internal.services.adcs.esc_types import EscConfig, EscStep

_AMBER = "#FF9500"
_STEEL = "#4A9EBA"
_CRIMSON = "#DC2626"
_MUTED = "grey50"

_ESC_TITLES = {
    2:  "ESC2 — Any Purpose EKU (Enrollment Agent chain)",
    4:  "ESC4 — Write Access on Certificate Template",
    6:  "ESC6 — CA-level SubjectAltName Flag (EDITF_ATTRIBUTESUBJECTALTNAME2)",
    7:  "ESC7 — ManageCA → Enable SubCA → Issue Certificate",
    9:  "ESC9 — No-Security-Extension via UPN Manipulation",
    14: "ESC14 — AltSecurityIdentities Write",
    15: "ESC15 — Application Policy Injection (Enrollment Agent)",
}

_ESC15_CONFIRM_TITLE = "ESC15 — EKUwu Confirmation (non-destructive)"
_ESC15_SCHANNEL_TITLE = "ESC15 — EKUwu via Schannel (method A)"


def build_esc15_schannel_steps(config: "EscConfig") -> list["EscStep"]:
    """Steps for ESC15 method A (Schannel / PassTheCert).

    One certificate, one template, no enrollment agent: inject the Client
    Authentication application policy with SAN UPN = target, bind to LDAPS over
    Schannel as the target (no PKINIT), then grant DCSync to the controlled
    principal. The DCSync ACE is a durable change recorded in the
    environment-change ledger.
    """
    from adscan_internal.services.adcs.esc_types import EscStep

    return [
        EscStep(
            "Request client-auth cert",
            f"Enroll in {config.template} with the Client Authentication "
            f"application policy and SAN UPN = {config.target_upn}",
        ),
        EscStep(
            "Schannel LDAPS bind",
            f"Present the certificate over LDAPS (SASL EXTERNAL) to authenticate "
            f"as {config.target_upn} — no PKINIT",
        ),
        EscStep(
            "Grant DCSync (LDAP write)",
            "As the target, add replication rights for the controlled principal "
            "to the domain object's DACL",
            destructive=True,
            rollback_label="Remove the replication ACEs from the domain DACL",
        ),
    ]


def build_esc15_confirm_steps(config: "EscConfig") -> list["EscStep"]:
    """Steps for the NON-DESTRUCTIVE ESC15 (EKUwu) confirmation.

    Enrolls ONE certificate for the enrolling user themselves (subject = self)
    with a canary application policy, then inspects the issued certificate. No
    privileged identity is minted: no on-behalf-of, no SAN target, no PKINIT.
    """
    from adscan_internal.services.adcs.esc_types import EscStep

    return [
        EscStep(
            "Confirm EKUwu (non-destructive)",
            f"Enroll a self-subject certificate in {config.template} with a canary "
            "application policy and inspect the issued certificate for it — no "
            "privileged identity is minted",
        ),
    ]


def build_esc_steps(config: "EscConfig") -> list["EscStep"]:
    from adscan_internal.services.adcs.esc_types import EscStep
    n = config.esc
    if n == 6:
        return [
            EscStep("Request certificate", f"Enroll in {config.template} with UPN SAN = {config.target_upn}"),
            EscStep("PKINIT authenticate", "Exchange PFX for NT hash via UnPAC-the-hash"),
        ]
    if n == 2:
        return [
            EscStep("Request agent cert", f"Enroll in {config.template} as enrollment agent"),
            EscStep("Request on-behalf-of cert", f"Use agent cert to enroll on behalf of {config.target_upn}"),
            EscStep("PKINIT authenticate", "Exchange PFX for NT hash via UnPAC-the-hash"),
        ]
    if n == 15:
        return [
            EscStep("Request cert with appPolicy OID", f"Enroll in {config.template} with enrollment-agent application policy"),
            EscStep("Request on-behalf-of cert", f"Use cert to enroll on behalf of {config.target_upn}"),
            EscStep("PKINIT authenticate", "Exchange PFX for NT hash via UnPAC-the-hash"),
        ]
    if n == 4:
        return [
            EscStep("Snapshot template", f"Save current attributes of {config.template}"),
            EscStep("Mutate template flags", f"Enable ENROLLEE_SUPPLIES_SUBJECT on {config.template}", destructive=True, rollback_label="Restore template"),
            EscStep("Request certificate", f"Enroll with UPN SAN = {config.target_upn}"),
            EscStep("Restore template", f"Revert {config.template} to original state", rollback_label="Rollback"),
            EscStep("PKINIT authenticate", "Exchange PFX for NT hash via UnPAC-the-hash"),
        ]
    if n == 7:
        return [
            EscStep("Enable SubCA template", "Add SubCA to certificateTemplates on EnterpriseCA", destructive=True, rollback_label="Disable SubCA"),
            EscStep("Request SubCA cert", f"Enroll in SubCA with UPN = {config.target_upn}"),
            EscStep("Issue pending request", "Approve pending request via ManageCA right"),
            EscStep("Retrieve certificate", "Download issued certificate"),
            EscStep("Disable SubCA template", "Remove SubCA from certificateTemplates (rollback)", rollback_label="Rollback"),
            EscStep("PKINIT authenticate", "Exchange PFX for NT hash via UnPAC-the-hash"),
        ]
    if n == 9:
        return [
            EscStep("Add shadow credentials", f"Write msDS-KeyCredentialLink on {config.target_account}", destructive=True, rollback_label="Remove shadow credentials"),
            EscStep("Get target NT hash", f"PKINIT as {config.target_account} via shadow creds"),
            EscStep("Change UPN", f"Set {config.target_account} UPN → {config.target_upn}", destructive=True, rollback_label="Restore UPN"),
            EscStep("Request certificate", f"Enroll as {config.target_account} in {config.template}"),
            EscStep("Restore UPN", f"Revert {config.target_account} UPN to original", rollback_label="Rollback"),
            EscStep("Remove shadow credentials", f"Clear msDS-KeyCredentialLink on {config.target_account}", rollback_label="Rollback"),
            EscStep("PKINIT authenticate", f"Authenticate as {config.target_upn} via UnPAC-the-hash"),
        ]
    if n == 14:
        variant = str(getattr(config, "esc14_variant", "A") or "A").strip().upper()
        if variant in {"B", "C", "D"}:
            return _build_esc14_weak_mapping_steps(config, variant)
        # Variant A: ADscan writes the TARGET's altSecurityIdentities directly.
        return [
            EscStep("Create machine account", "Add computer account via MachineAccountQuota", destructive=True, rollback_label="Delete computer account"),
            EscStep("Request Machine certificate", "Enroll computer account in Machine template"),
            EscStep("Compute X509IssuerSerial", "Extract issuer+serial from cert DER"),
            EscStep("Write altSecurityIdentities", f"Set X509 binding on {config.target_account}", destructive=True, rollback_label="Clear altSecurityIdentities"),
            EscStep("PKINIT authenticate", f"Authenticate as {config.target_account}"),
        ]
    return []


#: Per-variant victim attribute and the weak mapping each B/C/D run satisfies.
_ESC14_VARIANT_META = {
    "B": ("mail", "the target's RFC822 (email) altSecurityIdentities mapping"),
    "C": ("cn", "the target's X509IssuerSubject altSecurityIdentities mapping"),
    "D": ("dNSHostName", "the target's X509SubjectOnly altSecurityIdentities mapping"),
}


def _build_esc14_weak_mapping_steps(config: "EscConfig", variant: str) -> list["EscStep"]:
    """Steps for ESC14 variants B/C/D (satisfy the target's EXISTING weak mapping).

    Unlike variant A, ADscan NEVER touches the target here. It creates a throwaway
    victim machine account, sets the victim's ``mail`` (B) / ``cn`` (C) /
    ``dNSHostName`` (D) to the value the target's weak ``altSecurityIdentities``
    mapping matches, enrolls a certificate as the victim, and the DC maps the
    issued certificate to the target. Both destructive writes are on the throwaway
    victim and are reversible: the victim account is deleted and its attribute is
    restored, through the environment-change ledger.
    """
    from adscan_internal.services.adcs.esc_types import EscStep

    default_attr, mapping_phrase = _ESC14_VARIANT_META.get(
        variant, ("mail", "the target's weak altSecurityIdentities mapping")
    )
    attribute = (config.esc14_victim_attribute or "").strip() or default_attr
    match_value = (config.esc14_match_value or "").strip()
    target = config.target_account or config.target_upn or "the target"

    if match_value:
        write_description = (
            f"Set the throwaway victim's {attribute} to {match_value}, matching "
            f"{mapping_phrase}"
        )
    else:
        write_description = (
            f"Set the throwaway victim's {attribute} to match {mapping_phrase}"
        )

    return [
        EscStep(
            "Create victim machine account",
            "Add a throwaway computer account via MachineAccountQuota",
            destructive=True,
            rollback_label="Delete victim computer account",
        ),
        EscStep(
            f"Set victim {attribute}",
            write_description,
            destructive=True,
            rollback_label=f"Restore the victim's original {attribute}",
        ),
        EscStep(
            "Request certificate as victim",
            f"Enroll the victim in {config.template or 'User'}; the DC maps the "
            f"issued certificate to {target}",
        ),
        EscStep("PKINIT authenticate", f"Authenticate as {target}"),
    ]


def print_esc_preflight(
    config: "EscConfig", steps: list["EscStep"], *, title_override: str | None = None
) -> bool:
    from adscan_core.rich_output import _get_console, confirm_ask
    console = _get_console()

    has_destructive = any(s.destructive for s in steps)
    border = _CRIMSON if has_destructive else _AMBER
    title_text = title_override or _ESC_TITLES.get(config.esc, f"ESC{config.esc}")

    grid = Table.grid(padding=(0, 1))
    grid.add_column(style=_MUTED, justify="right", min_width=16)
    grid.add_column()

    if config.target_upn:
        grid.add_row("Impersonating", Text(mark_sensitive(config.target_upn, "user"), style=f"bold {_STEEL}"))
    grid.add_row("Executing as", Text(mark_sensitive(config.username, "user"), style="bold"))
    if config.template:
        grid.add_row("Template", Text(config.template, style=f"bold {_AMBER}"))
    if config.target_account:
        grid.add_row("Modifying", Text(mark_sensitive(config.target_account, "user"), style=f"bold {_AMBER}"))
    grid.add_row("CA", Text(f"{config.ca_name} @ {config.ca_host}", style=_MUTED))

    step_table = Table.grid(padding=(0, 1))
    step_table.add_column(style=_MUTED, width=3)
    step_table.add_column(min_width=30)
    step_table.add_column(width=22)

    for i, step in enumerate(steps, 1):
        if step.destructive:
            badge = Text("⚠ DESTRUCTIVE", style=f"bold {_AMBER}")
        elif step.rollback_label and not step.destructive:
            badge = Text("↩ rollback", style=_STEEL)
        else:
            badge = Text("read-only", style=_MUTED)
        step_table.add_row(f"{i}", step.label, badge)

    from rich.console import Group
    body = Group(grid, Text(""), Text("  Steps", style=f"bold {_MUTED}"), step_table, Text(""))
    if has_destructive:
        body = Group(body, Text(
            "  All destructive changes are registered to the environment ledger and "
            "restored automatically on failure.",
            style=_MUTED,
        ))

    title = Text.assemble(
        Text.from_markup(f"[bold {_CRIMSON}]⚡[/] "),
        (title_text, "bold"),
    )
    console.print(Panel(body, title=title, border_style=border, box=ROUNDED, padding=(0, 1)))
    return confirm_ask("  Proceed?", default=True)
