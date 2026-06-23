"""Single source of truth for resolving a mass-auth sweep's credential.

Every operation that authenticates as ONE domain principal across MANY hosts —
the SMB privilege/access sweep, the WinRM and MSSQL (Windows-auth) sweeps, the
RDP login sweep, the SMB/MSSQL collectors, share enumeration — must route its
credential through :func:`resolve_sweep_credential` BEFORE it builds per-host
configs. The result is a reuse-ready, lockout-safe credential that every per-host
config shares.

The problem this fixes (validated 2026-06-16 on the Cyberzaintza audit)
====================================================================
Passing a plaintext password / NT hash straight into N per-host transport
configs makes each host mint its OWN TGT from the secret (``kerberos-password://``
→ a fresh AS-REQ per connection — see ``smb_transport._build_smb_url``). At
1-2k hosts that is:

* **Slow / noisy** — 1-2k AS-REQs hammering the single PDC instead of one.
* **A domain-lockout hazard** — the dangerous part for a customer audit. A
  wrong / rotated / must-change credential becomes N failed pre-auths =
  N ``badPwdCount`` increments = near-instant lockout of the principal across
  the domain. (Relying on the on-disk canonical ccache for reuse does NOT help
  here: if the first mint fails, hosts 2..N each retry the mint with the secret
  and amplify the lockout just the same.)

The fix
=======
Pre-mint ONE TGT for the principal up front via the existing SSOT
:func:`adscan_internal.services.kerberos_ticket_service.ensure_user_ccache`
(posture-aware: AES etype + correct salt when AES is enforced), then hand every
per-host config that single ccache. The secret touches the wire exactly once
(one AS-REQ); each host does only a cheap TGS for its service SPN. A failed
mint **aborts the sweep** (``aborted=True``) rather than falling back to
per-host password auth — fail once, never N times. This keeps the documented
Kerberos-first policy (``auth_plan.KERBEROS_FIRST_POLICY``) and works for hosts
where NTLM is disabled (they "just work" over Kerberos).

Exemptions (used as-is, never re-minted)
========================================
* **Capability-bearing / scoped artifacts** — an explicitly-supplied ccache:
  an ESC13 PAC-injected TGT, or an S4U2Proxy / RBCD / silver service ticket.
  Re-minting would destroy the synthetic SID / impersonation. This mirrors the
  carve-out in ``ensure_user_ccache`` and ``_kerberos_ccache_guard``.
* **Non-Kerberos credentials** — local-account secrets, MSSQL SQL-auth logins,
  or AES-key-only credentials have no domain TGT to pre-mint and pass through
  unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adscan_core import telemetry
from adscan_core.rich_output import print_info_debug
from adscan_internal.rich_output import mark_sensitive

__all__ = ["SweepCredential", "resolve_sweep_credential"]


@dataclass(frozen=True)
class SweepCredential:
    """A sweep credential resolved into reuse-ready, lockout-safe form.

    Exactly one of two shapes is meaningful:

    * **Pre-minted Kerberos** — ``ccache_path`` is set, the secret fields are
      cleared, ``use_kerberos`` is ``True``. Every per-host config reuses this
      one ccache.
    * **Passthrough** — a secret field is populated (non-Kerberos / AES-only /
      fallback). The caller authenticates per host as before.

    When ``aborted`` is ``True`` the caller MUST NOT start the sweep: the
    pre-mint failed and proceeding would spray the secret across hosts.
    """

    ccache_path: str | None = None
    password: str | None = None
    nt_hash: str | None = None
    aes_key: str | None = None
    use_kerberos: bool = False
    aborted: bool = False
    abort_reason: str | None = None
    notes: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        """``True`` when the sweep may proceed (not aborted)."""
        return not self.aborted


def _looks_like_ccache(value: str | None) -> bool:
    return bool((value or "").strip().lower().endswith(".ccache"))


def resolve_sweep_credential(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str | None = None,
    nt_hash: str | None = None,
    aes_key: str | None = None,
    ccache_path: str | None = None,
    auth_domain: str | None = None,
    kdc_ip: str | None = None,
    allow_password_fallback: bool = False,
) -> SweepCredential:
    """Resolve a sweep's credential to a reuse-ready, lockout-safe form.

    Pre-mints ONE TGT for ``username`` (in ``auth_domain`` or ``domain``) when a
    password / NT hash is supplied, so every per-host config can reuse the same
    ccache. See the module docstring for the rationale.

    Args:
        shell: The active ``PentestShell`` (needed by ``ensure_user_ccache`` for
            the workspace path and credential registry). Any object exposing the
            same attributes works for tests.
        domain: Target domain of the hosts being swept.
        username: sAMAccountName of the principal to authenticate as.
        password: Plaintext password (a ``.ccache`` path landing here is treated
            as an explicit ccache; an NT hash is auto-routed by the transport).
        nt_hash: NT hash for pass-the-hash (used as the TGT mint secret).
        aes_key: AES-128/256 Kerberos key. Passed through (the pre-mint path
            mints from password / NT hash).
        ccache_path: An explicitly-supplied ccache — capability-bearing (ESC13)
            or scoped (S4U/RBCD/silver). Used as-is, never re-minted.
        auth_domain: Domain the credential belongs to, when it differs from the
            target ``domain`` (cross-domain). The TGT is minted here.
        kdc_ip: KDC IP for the AS-REQ. Falls back to the domain's PDC inside
            ``ensure_user_ccache`` when omitted.
        allow_password_fallback: When ``True``, a failed pre-mint passes the
            secret through per-host instead of aborting. Reserved for paths
            where Kerberos genuinely cannot apply; NOT lockout-safe.

    Returns:
        A :class:`SweepCredential`. Check ``.ok`` / ``.aborted`` before sweeping.
    """
    masked_user = mark_sensitive(username, "user")
    notes: list[str] = []

    # 1. Explicit ccache (incl. capability-bearing ESC13 PAC-TGT and scoped
    #    S4U/RBCD/silver service tickets) → use as-is, NEVER re-mint.
    explicit_ccache = (ccache_path or "").strip()
    pw = password
    if not explicit_ccache and _looks_like_ccache(pw):
        explicit_ccache = (pw or "").strip()
        pw = None
    if explicit_ccache:
        notes.append(
            "caller-supplied ccache used as-is (capability-bearing / scoped "
            "tickets are never re-minted)"
        )
        return SweepCredential(
            ccache_path=explicit_ccache,
            use_kerberos=True,
            notes=tuple(notes),
        )

    secret = (pw or "").strip() or (nt_hash or "").strip()

    # 2. No password / NT hash to mint from → passthrough (AES-only, or no
    #    usable secret at all; the transport handles those branches).
    if not secret:
        notes.append(
            "no password / NT-hash secret to pre-mint; credential passed through"
        )
        return SweepCredential(
            password=pw,
            nt_hash=nt_hash,
            aes_key=aes_key,
            use_kerberos=bool((aes_key or "").strip()),
            notes=tuple(notes),
        )

    # 3. Domain principal with a password / NT hash → pre-mint ONE TGT.
    mint_domain = (auth_domain or domain or "").strip()
    minted: str | None = None
    try:
        from adscan_internal.services.kerberos_ticket_service import (
            ensure_user_ccache,
        )

        minted = ensure_user_ccache(
            shell,
            user=username,
            domain=mint_domain,
            credential=secret,
            dc_ip=(kdc_ip or None),
        )
    except Exception as exc:  # noqa: BLE001 — best-effort; classified below
        telemetry.capture_exception(exc)
        notes.append(f"pre-mint raised: {exc}")

    if minted:
        print_info_debug(
            "[sweep_cred] pre-minted one TGT for the sweep: "
            f"user={masked_user} reused across all hosts (secret used once)"
        )
        notes.append(
            "pre-minted one TGT; per-host configs reuse this ccache (secret "
            "used once — lockout-safe)"
        )
        return SweepCredential(
            ccache_path=minted,
            use_kerberos=True,
            notes=tuple(notes),
        )

    # 4. Pre-mint failed.
    if allow_password_fallback:
        notes.append(
            "pre-mint failed; per-host secret fallback (allow_password_fallback) "
            "— NOT lockout-safe"
        )
        return SweepCredential(
            password=pw,
            nt_hash=nt_hash,
            aes_key=aes_key,
            notes=tuple(notes),
        )

    notes.append(
        "pre-mint failed; aborting sweep rather than spraying the secret across "
        "hosts (lockout-safe default)"
    )
    return SweepCredential(
        aborted=True,
        abort_reason=(
            "Kerberos TGT pre-mint failed; aborting the sweep to avoid spraying "
            "the credential across every host (domain-lockout protection). "
            "Verify the credential is valid, or re-run with an explicit ccache."
        ),
        notes=tuple(notes),
    )
