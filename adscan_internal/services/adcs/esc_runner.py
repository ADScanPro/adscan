"""Single entry point for all ADCS ESC exploitation flows."""

from __future__ import annotations

from adscan_internal.services.async_bridge import run_async_sync
from adscan_internal.services.adcs.esc_types import EscConfig, EscResult
from adscan_internal.services.adcs.esc_preflight import (
    build_esc_steps,
    print_esc_preflight,
)
from adscan_internal.services.adcs.esc_enrollment import (
    run_esc2,
    run_esc6,
    run_esc13,
    run_esc15,
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
