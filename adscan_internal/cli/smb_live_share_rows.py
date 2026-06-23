"""Live-source adapter for the premium SMB share-exposure surface.

The interactive authenticated share-enum (``creds select`` → ``run_auth_shares``)
runs ALWAYS live, per current user: each host's :class:`ShareViewSet` already
carries the credential's *effective* per-share access (share ACL ∩ NTFS via
SMB2 MaximalAccess), computed by the native path
(:func:`smb_shares_native._probe_share_access` →
``query_effective_root_access_on_machine`` →
``resolve_effective_share_permissions``).

This adapter is the single, narrow seam that turns those live
:class:`ShareView` records into the row schema consumed by
:func:`adscan_core.output._attack_paths.render_smb_exposed_resources_panel`
and :func:`adscan_internal.cli.share_exposure_phase._split_share_rows`.

It is the *one* place the live permission vocabulary
(``READ``/``WRITE``/``WRITE_DAC``/``READ_CONTROL``/``EXECUTE``) is translated
into the renderer's capitalized vocabulary (``Read``/``Write``/``Full
Control``). Pure logic, no network — fully L1-testable.

This adapter NEVER touches the collector graph. The graph-first share path was
reverted (commit ``94b08f85``); the interactive flow is live per-user only.
"""

from __future__ import annotations

from typing import Any

from adscan_internal.services.smb_exclusion_policy import (
    GLOBAL_SMB_EXCLUDED_DRIVE_SHARES,
    GLOBAL_SMB_EXCLUDED_SHARE_NAMES,
)

# ── Live → renderer label translation (the one fragile seam) ──────────────────
#
# Live vocabulary (from ``smb_shares_native._translate_maximal_access`` /
# ``_effective_access_to_labels``):
#     READ, WRITE, WRITE_DAC, READ_CONTROL, EXECUTE
# Renderer vocabulary (consumed by ``render_smb_exposed_resources_panel`` and
# ``_split_share_rows``):
#     Read, Write, Full Control
#
# Rules (owner-specified):
#   * READ                 → Read
#   * WRITE / WRITE_DAC     → Write
#   * full control          → Full Control
#
# "Full control" on the live path is NOT a distinct token: a GENERIC_ALL grant
# sets READ + WRITE + WRITE_DAC simultaneously (see
# ``_translate_maximal_access``). So a live set that carries all three rights
# is the effective "full control" case and collapses to the renderer's
# ``Full Control`` label. READ_CONTROL / EXECUTE carry no exposure semantics
# for this surface and are dropped (they never gate Step 1/Step 2).
_LIVE_WRITE_LABELS = frozenset({"WRITE", "WRITE_DAC"})


def _translate_live_permissions(live_permissions: list[str] | None) -> set[str]:
    """Translate live permission labels into the renderer's access vocabulary.

    Args:
        live_permissions: ``ShareView.live_permissions`` — a list drawn from
            ``READ``/``WRITE``/``WRITE_DAC``/``READ_CONTROL``/``EXECUTE``.

    Returns:
        A set drawn from ``{"Read", "Write", "Full Control"}``. A grant that
        carries READ + (WRITE or WRITE_DAC) AND an explicit WRITE_DAC (the
        GENERIC_ALL signature) collapses to ``{"Full Control"}``; otherwise the
        individual ``Read``/``Write`` labels are emitted.
    """
    perms = {str(p or "").strip().upper() for p in (live_permissions or [])}
    perms.discard("")

    has_read = "READ" in perms
    has_write = bool(_LIVE_WRITE_LABELS & perms)
    # GENERIC_ALL sets READ + WRITE + WRITE_DAC together — that is the only way
    # WRITE_DAC appears alongside both READ and WRITE on the live path, so it is
    # the reliable "full control" signature.
    is_full_control = has_read and "WRITE" in perms and "WRITE_DAC" in perms

    if is_full_control:
        return {"Full Control"}

    access: set[str] = set()
    if has_read:
        access.add("Read")
    if has_write:
        access.add("Write")
    return access


# Admin / system shares whose name flags ``admin_share`` for schema parity with
# ``collect_share_exposures_from_graph``. The renderer filters these out of the
# visible table via ``is_globally_excluded_smb_share``, so the flag is carried
# for schema completeness only.
_ADMIN_SHARE_NAMES_CASEFOLD: frozenset[str] = frozenset(
    name.casefold()
    for name in (GLOBAL_SMB_EXCLUDED_SHARE_NAMES + GLOBAL_SMB_EXCLUDED_DRIVE_SHARES)
)


def _is_admin_share(share_name: str) -> bool:
    """Return ``True`` for administrative / system shares (C$, ADMIN$, IPC$, …)."""
    return str(share_name or "").strip().casefold() in _ADMIN_SHARE_NAMES_CASEFOLD


def build_live_share_rows(
    view_sets: list[Any],
    *,
    domain_data: dict[str, Any],
    current_principal_label: str,
) -> list[dict[str, Any]]:
    """Build premium share-exposure rows from LIVE per-user share views.

    For every accessible :class:`ShareView` across all hosts, emit one row in
    the schema ``render_smb_exposed_resources_panel`` and ``_split_share_rows``
    consume::

        {
            "host": str,
            "share": str,
            "access": set[str],            # {"Read", "Write", "Full Control"}
            "principals": set[str],        # {current_principal_label}
            "impact_rank": int,            # 3 when the host is the DC, else 1
            "admin_share": bool,
        }

    Access is the credential's *effective* access (share ACL ∩ NTFS, SMB2
    MaximalAccess), already computed by the native live probe — no MxAc work is
    done here. A share with no effective access (empty translated set) is
    dropped: it is not an exposure for this credential.

    Args:
        view_sets: The :class:`ShareViewSet` objects ``run_native_shares_view``
            returned, one per enumerated host (in LIVE mode).
        domain_data: ``shell.domains_data[domain]`` — used only to resolve the
            DC IP for Tier-0 ``impact_rank`` styling.
        current_principal_label: The display label for the authenticating
            principal (already ``mark_sensitive``-wrapped by the caller). Drives
            the renderer's "Effective for" column.

    Returns:
        A list of row dicts. Empty when no host exposed any accessible share.
    """
    from adscan_internal.models.domain import resolve_dc_ip  # noqa: PLC0415

    dc_ip = (resolve_dc_ip(domain_data) or "").strip()

    rows: list[dict[str, Any]] = []
    for view_set in view_sets:
        if view_set is None:
            continue
        host = str(getattr(view_set, "host", "") or "").strip()
        if not host:
            continue
        is_dc = bool(dc_ip) and host == dc_ip
        impact_rank = 3 if is_dc else 1

        for view in getattr(view_set, "views", []) or []:
            # Only shares the live probe could actually open carry effective
            # access — a denied / unprobed share is not an exposure for us.
            if not getattr(view, "live_accessible", False):
                continue
            access = _translate_live_permissions(getattr(view, "live_permissions", []))
            if not access:
                continue
            share_name = str(getattr(view, "name", "") or "").strip()
            if not share_name:
                continue
            rows.append(
                {
                    "host": host,
                    "share": share_name,
                    "access": access,
                    "principals": {current_principal_label},
                    "impact_rank": impact_rank,
                    "admin_share": _is_admin_share(share_name),
                }
            )

    return rows


__all__ = ["build_live_share_rows"]
