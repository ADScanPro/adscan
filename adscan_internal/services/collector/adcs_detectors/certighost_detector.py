"""Certighost (CVE-2026-54121) — CA chase-fallback DC-impersonation detector.

READ-ONLY. This detector inspects already-collected CA state and probe-derived
registry / OS values; it NEVER enrolls a certificate, never injects the
``cdc`` / ``rmd`` request attributes, never stands up a rogue DC responder and
never mutates the target environment. It emits a THEORETICAL finding only — the
exploit (minting a DC credential) is a deferred, lab-gated follow-up. Because
nothing is changed in the environment, there is no rollback to disclose.

What Certighost is
------------------
The CA "chase" fallback reads requester-supplied ``cdc`` (client DC to contact)
and ``rmd`` (remote machine object) request attributes and trusts a
client-supplied "DC" without verifying it is a real domain controller. A
low-privileged authenticated user can therefore point the CA at an attacker
host serving a forged DC identity and obtain a certificate that authenticates
AS a DC, then PKINIT -> DCSync -> full domain compromise. The avenue is only
reachable when the CA has ``EDITF_ENABLECHASECLIENTDC`` (``0x00100000``) set in
its policy ``EditFlags``. Microsoft patched it in July 2026 (the update adds
DC validation), so a CA whose host build is at or above the patch UBR is not
exploitable even with the flag set.

Detection inputs (all read-only; no enrollment)
-----------------------------------------------
1. An enterprise CA is present (the ADCS collector already knows this).
2. ``EDITF_ENABLECHASECLIENTDC`` state, read from the CA host CertSvc
   ``EditFlags`` via the shared CA registry probe.
3. The CA host OS build + UBR, read from the CA host ``CurrentVersion`` key via
   the same registry probe, compared against the per-OS patch table below.

Verdict logic (observe, never infer; never cache an absence)
------------------------------------------------------------
* Patched build (UBR >= the table threshold) -> NO finding (definitive negative).
* Unpatched + CA + chase flag SET -> emit a THEORETICAL ``certighost`` edge
  (high-confidence configuration, unproven exploit).
* Unpatched + CA + chase flag UNSET -> informational only, NO exploitable edge.
* Build or EditFlags unreadable -> UNKNOWN, NO finding, re-probe next run (never
  cache a false negative).
"""

from __future__ import annotations

from adscan_internal.services.collector.adcs_detectors._common import (
    make_certighost_edge,
)
from adscan_internal.services.collector.adcs_detectors._well_known import (
    AUTHENTICATED_USERS_SID,
)
from adscan_internal.services.collector.models import CollectorEdge, CollectorNode

# CVE identifier surfaced in the edge notes + catalog prose.
CERTIGHOST_CVE_ID = "CVE-2026-54121"

# Per-OS first-fixed UBR table for CVE-2026-54121 (July 2026 patch). Keyed by the
# OS ``(major, minor, build)`` triple; the value is the first UBR (Update Build
# Revision) that carries the fix. A CA host whose UBR is >= its build's threshold
# is PATCHED. Mirrors NetExec's ``enum_cve`` build/patch-level table verbatim.
#   Server 2012    (6, 2, 9200)   -> 26226
#   Server 2012 R2 (6, 3, 9600)   -> 23291
#   Server 2016    (10, 0, 14393) -> 9339
#   Server 2019    (10, 0, 17763) -> 9020
#   Server 2022    (10, 0, 20348) -> 5386
#   Server 2025    (10, 0, 26100) -> 33158
CERTIGHOST_PATCH_UBR_BY_BUILD: dict[int, int] = {
    9200: 26226,
    9600: 23291,
    14393: 9339,
    17763: 9020,
    20348: 5386,
    26100: 33158,
}


def certighost_patch_status(os_build_number: int | None, os_ubr: int | None) -> str:
    """Classify a CA host's patch state for Certighost.

    Returns one of:
      * ``"patched"``   — the UBR is at or above the build's first-fixed UBR.
      * ``"unpatched"`` — the UBR is below the build's first-fixed UBR.
      * ``"unknown"``   — the build/UBR is missing or the build is not in the
        patch table (an unexpected OS), so no honest verdict is possible.
    """
    if os_build_number is None or os_ubr is None:
        return "unknown"
    threshold = CERTIGHOST_PATCH_UBR_BY_BUILD.get(int(os_build_number))
    if threshold is None:
        return "unknown"
    return "patched" if int(os_ubr) >= threshold else "unpatched"


def detect_certighost(
    *,
    ca_node: CollectorNode,
    domain: str,
    editf_enablechaseclientdc_enabled: bool = False,
    edit_flags_readable: bool = False,
    os_build_number: int | None = None,
    os_ubr: int | None = None,
    os_major_version: int | None = None,
    os_minor_version: int | None = None,
) -> list[CollectorEdge]:
    """Return a theoretical ``certighost`` edge when the CA is exploitable.

    Read-only. An edge is emitted ONLY when the CA host is confirmed unpatched
    AND the ``EDITF_ENABLECHASECLIENTDC`` flag is confirmed set. Every other
    case (patched, flag unset, or any unreadable input) emits NO edge, so a
    probe that could not run never produces a false positive and an absence is
    never cached as a negative.
    """
    if ca_node.kind != "EnterpriseCA":
        return []

    # Need a definitive patch verdict AND a readable EditFlags value; anything
    # else stays UNKNOWN (no edge), to be re-probed on the next run.
    patch_status = certighost_patch_status(os_build_number, os_ubr)
    if patch_status != "unpatched":
        # "patched" is a definitive negative; "unknown" is a data gap. Neither
        # emits an exploitable edge.
        return []
    if not edit_flags_readable:
        return []
    if not editf_enablechaseclientdc_enabled:
        # Unpatched but the chase fallback is not enabled — informational only.
        return []

    notes = {
        "cve_id": CERTIGHOST_CVE_ID,
        "editf_enablechaseclientdc": True,
        "ca_patch_status": patch_status,
        "ca_os_build": os_build_number,
        "ca_os_ubr": os_ubr,
        "ca_os_major_version": os_major_version,
        "ca_os_minor_version": os_minor_version,
        "intent": "dc_impersonation_certificate",
        "requires": "domain_credentials",
        "read_only": True,
        "exploit_status": "theoretical",
    }
    return [
        make_certighost_edge(
            principal_sid=AUTHENTICATED_USERS_SID,
            ca_node=ca_node,
            notes=notes,
        )
    ]
