"""Single entry point for all ADCS ESC exploitation flows."""

from __future__ import annotations

from adscan_internal.services.async_bridge import run_async_sync
from adscan_internal.services.adcs.esc_types import EscConfig, EscResult
from adscan_internal.services.adcs.esc_preflight import (
    _ESC15_CONFIRM_TITLE,
    _ESC15_SCHANNEL_TITLE,
    build_esc15_confirm_steps,
    build_esc15_schannel_steps,
    build_esc_steps,
    print_esc_preflight,
)
from adscan_internal.services.adcs.esc_enrollment import (
    confirm_esc15_vulnerable,
    run_esc2,
    run_esc6,
    run_esc13,
    run_esc15,
    run_esc15_schannel,
)
from adscan_internal.services.adcs.esc_template_write import run_esc4
from adscan_internal.services.adcs.esc_ca_manage import run_esc7
from adscan_internal.services.adcs.esc_principal_write import run_esc9, run_esc10, run_esc14
from adscan_internal.services.adcs.esc_relay import run_esc8, run_esc8_krb, run_esc11


async def run_esc(config: EscConfig) -> EscResult:
    """Run the appropriate ESC exploitation flow after showing the pre-flight panel."""
    steps = build_esc_steps(config)
    if not print_esc_preflight(config, steps):
        return EscResult(success=False, esc=config.esc, error="Aborted by user")

    n = config.esc
    if n == 2:
        return await run_esc2(config)
    if n == 4:
        return await run_esc4(config)
    # ESC5 (CA-key theft + offline forge) is dispatched to the working
    # adcs_golden_cert implementation from the attack-path executor, not through
    # this enrollment runner. It stays gated behind ledger disclosure — see
    # esc_enrollment.py and BACKLOG.md § "ESC5 (CA key theft + offline forge)".
    if n == 6:
        return await run_esc6(config)
    if n == 7:
        return await run_esc7(config)
    if n == 8:
        if config.use_kerberos:
            return await run_esc8_krb(config)
        return await run_esc8(config)
    if n == 9:
        return await run_esc9(config)
    if n == 10:
        return await run_esc10(config)
    if n == 11:
        return await run_esc11(config)
    if n == 13:
        return await run_esc13(config)
    if n == 14:
        return await run_esc14(config)
    if n == 15:
        return await run_esc15(config)

    return EscResult(
        success=False, esc=config.esc, error=f"ESC{config.esc} not implemented"
    )


def run_esc_sync(config: EscConfig) -> EscResult:
    """Synchronous wrapper for use from attack_path_execution.py."""
    return run_async_sync(run_esc(config))


async def run_esc15_confirm(
    config: EscConfig, *, template_eku_oids: list[str] | None = None
) -> EscResult:
    """Run the NON-DESTRUCTIVE ESC15 (EKUwu) confirmation after its pre-flight.

    Keeps the per-ESC consent gate (``print_esc_preflight``) — the confirmation
    still enrolls a certificate, so the operator confirms it — but shows the
    non-destructive confirm steps, not the full on-behalf-of exploit steps. The
    actual proof runs through ``confirm_esc15_vulnerable``; the full ``run_esc15``
    exploit is untouched and stays the default via ``run_esc``.
    """
    steps = build_esc15_confirm_steps(config)
    if not print_esc_preflight(config, steps, title_override=_ESC15_CONFIRM_TITLE):
        return EscResult(success=False, esc=15, error="Aborted by user")
    return await confirm_esc15_vulnerable(config, template_eku_oids=template_eku_oids)


def run_esc15_confirm_sync(
    config: EscConfig, *, template_eku_oids: list[str] | None = None
) -> EscResult:
    """Synchronous wrapper for the ESC15 confirm-mode (attack_path_execution.py)."""
    return run_async_sync(
        run_esc15_confirm(config, template_eku_oids=template_eku_oids)
    )


async def run_esc15_schannel_flow(config: EscConfig) -> EscResult:
    """Run ESC15 method A (Schannel / PassTheCert) after its pre-flight panel.

    Keeps the per-ESC consent gate (``print_esc_preflight``) — the flow enrolls a
    certificate and grants DCSync — showing the method-A steps (cert request,
    Schannel LDAPS bind, DCSync grant), then runs ``run_esc15_schannel``.
    """
    steps = build_esc15_schannel_steps(config)
    if not print_esc_preflight(config, steps, title_override=_ESC15_SCHANNEL_TITLE):
        return EscResult(success=False, esc=15, error="Aborted by user")
    return await run_esc15_schannel(config)


def run_esc15_schannel_sync(config: EscConfig) -> EscResult:
    """Synchronous wrapper for ESC15 method A (attack_path_execution.py)."""
    return run_async_sync(run_esc15_schannel_flow(config))
