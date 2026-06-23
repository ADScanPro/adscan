"""Ambient-ccache principal guard — detect the ``$KRB5CCNAME`` hijack.

ADscan authenticates as a *specific* principal via the single-source-of-truth
``ensure_user_ccache`` (mints/loads a per-user ccache from the stored secret).
The historical defect this guard protects against:

When a transport config carried ``use_kerberos=True`` and a ``username`` but
*no* explicit credential material, the URL builder used to fall back to the
ambient ``$KRB5CCNAME`` / the domain's "active" ccache. ``kerbad`` then returned
the *first available TGT* in that cache (silently, with no error) — which after
a Domain-Admin step is the DA's ticket. The result: an operation requested "as
daenerys" actually authenticated as administrator, mis-attributing the whole
collection and its sessions to the wrong principal.

This module is the durable, centralized net. It is **read-only**: it parses the
ccache's primary principal and compares it (alias-aware) against the principal
the caller asked for. On mismatch it WARNS loudly and emits a structured
telemetry event so the operator can see the hijack in the recording. It never
mints, refreshes, or repairs anything — that is ``ensure_user_ccache``'s job,
and importing it here would invert the layering (transport -> service).

Call contract (enforced by the call sites, not by this module):

* Call ONLY on the AMBIENT / ``$KRB5CCNAME``-fallback path — i.e. when the
  transport resolved a ccache from the environment rather than from an
  explicitly-passed ``config.ccache_path``.
* Call ONLY when ``config.username`` is set (we have an expected principal to
  compare against; an unauthenticated/realm-only bind has nothing to check).
* NEVER call for an explicitly-passed ``config.ccache_path``. That is exactly
  where ESC13 capability-bearing PAC-TGTs and S4U / RBCD / silver
  ``ServiceTicket`` ccaches flow — their principal "mismatch" (the impersonated
  user, or a synthetic-SID principal) is INTENTIONAL. Warning or refusing on
  those would break the very chains this codebase is designed to execute.
"""

from __future__ import annotations

import os
from typing import Optional

from adscan_internal import print_warning, telemetry
from adscan_internal.rich_output import mark_sensitive, print_info_debug

# ---------------------------------------------------------------------------
# Escalation toggle
# ---------------------------------------------------------------------------
#
# This release is CONSERVATIVE: a principal mismatch WARNS + records telemetry,
# but the bind proceeds. We do not hard-refuse yet because a false positive
# (an alias we failed to normalize, a legitimate cross-realm UPN form) would
# block a real operation, and the re-ordered URL builders + the per-caller
# ``ensure_user_ccache`` migrations already remove the hijack at the source.
#
# TODO: escalate to refuse once validated — flip this to ``True`` (or wire it
# to an env var / config) in a future release. When ``True``,
# ``assert_ccache_principal_matches`` raises ``CcachePrincipalMismatchError``
# on a confirmed mismatch so the caller falls back to NTLM / surfaces a blocked
# reason instead of binding as the wrong principal.
_REFUSE_ON_MISMATCH = False


class CcachePrincipalMismatchError(RuntimeError):
    """Raised when the ambient ccache principal does not match the expected one.

    Only raised when ``_REFUSE_ON_MISMATCH`` is enabled. In the default
    (conservative) configuration the guard warns and returns without raising.
    """


def _normalize_principal_name(value: str) -> str:
    """Lowercase a principal, stripping any ``DOMAIN\\`` prefix / ``@REALM`` suffix.

    Alias-aware comparison: ``sAMAccountName``, ``DOMAIN\\sAMAccountName`` and
    ``user@REALM`` UPN forms all collapse to the bare lowercased account name so
    the three representations of the same principal compare equal.
    """
    name = str(value or "").strip()
    if not name:
        return ""
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    # Trailing ``$`` (machine account) is significant — keep it.
    return name.strip().lower()


def _normalize_realm(value: str) -> str:
    """Lowercase a realm for case-insensitive comparison (realms are case-insensitive)."""
    return str(value or "").strip().lower()


def read_ccache_primary_principal(
    ccache_path: str,
) -> Optional[tuple[str, str]]:
    """Return ``(cname, crealm)`` of the ccache's TGT principal, or ``None``.

    Reads the ccache via ``kerbad``'s ``CCACHE.from_file`` (the same parser the
    transport uses) and prefers the principal of an actual TGT
    (``get_all_tgt()``) over the stored ``primary_principal`` header — the TGT
    cname is the authoritative "who this cache authenticates as". Falls back to
    ``primary_principal`` when no TGT row is present (e.g. a TGS-only cache).

    Best-effort and never raises: any parse/IO error returns ``None`` so the
    guard degrades to a no-op rather than blocking a bind.
    """
    path = str(ccache_path or "").strip()
    if not path or not os.path.exists(path):
        return None
    try:
        from kerbad.common.ccache import CCACHE  # noqa: PLC0415

        ccache = CCACHE.from_file(path)
    except Exception as exc:  # noqa: BLE001 — best-effort read
        print_info_debug(
            f"ccache-guard: could not parse ccache "
            f"{mark_sensitive(path, 'path')}: {exc}"
        )
        return None

    # Prefer a real TGT row: its cname/crealm is who the cache authenticates as.
    # ``get_all_tgt()`` returns ``(tgt_rep, sessionkey)`` tuples; ``tgt_rep`` is
    # the native AS-REP dict with ``cname['name-string']`` (list) and ``crealm``.
    try:
        tgts = ccache.get_all_tgt()
    except Exception:  # noqa: BLE001
        tgts = []
    for tgt, _keystruct in tgts or []:
        try:
            cname = "/".join(tgt["cname"]["name-string"])
            crealm = str(tgt["crealm"])
        except (KeyError, TypeError):
            continue
        if cname:
            return cname, crealm

    # Fallback: the stored primary_principal header.
    principal = getattr(ccache, "primary_principal", None)
    if principal is not None:
        try:
            cname = principal.to_string("/")
            crealm = principal.realm.to_string() if principal.realm else ""
            if cname:
                return cname, crealm
        except Exception:  # noqa: BLE001
            return None
    return None


def assert_ccache_principal_matches(
    ccache_path: str,
    expected_username: str,
    expected_domain: str,
    *,
    source: str,
    context: str,
) -> bool:
    """Verify an ambient ccache authenticates as ``expected_username``.

    Read-only principal check for the ``$KRB5CCNAME`` / ambient-ccache fallback
    path. See the module docstring for the call contract — in particular this
    must NEVER be invoked for an explicitly-passed ``config.ccache_path`` (ESC13
    capability-bearing TGTs and S4U/RBCD service tickets flow there and their
    principal mismatch is intentional).

    Args:
        ccache_path: Path to the ambient ccache about to be used for the bind.
        expected_username: The principal the caller asked to authenticate as.
        expected_domain: The realm the caller asked for.
        source: Short tag for where the ccache came from (e.g. ``"env"``,
            ``"KRB5CCNAME"``) — recorded in telemetry.
        context: Short tag for the transport/operation (e.g. ``"smb_transport"``,
            ``"ldap_transport"``) — recorded in telemetry.

    Returns:
        ``True`` when the principal matches (or could not be determined — we do
        not block on an unreadable cache). ``False`` on a confirmed mismatch in
        the conservative (warn-only) configuration.

    Raises:
        CcachePrincipalMismatchError: On a confirmed mismatch ONLY when
            ``_REFUSE_ON_MISMATCH`` is enabled (off by default this release).
    """
    expected_user_norm = _normalize_principal_name(expected_username)
    if not expected_user_norm:
        # No expected principal to compare against — nothing to assert.
        return True

    principal = read_ccache_primary_principal(ccache_path)
    if principal is None:
        # Unreadable / absent cache: degrade to no-op (do not block the bind on
        # our own inability to parse — the transport will surface a real error).
        return True

    actual_cname, actual_crealm = principal
    actual_user_norm = _normalize_principal_name(actual_cname)
    if actual_user_norm == expected_user_norm:
        # Principal matches; realm is informational only (cross-realm UPNs are
        # legitimate, so a realm difference alone is not a mismatch).
        return True

    expected_realm_norm = _normalize_realm(expected_domain)
    actual_realm_norm = _normalize_realm(actual_crealm)

    masked_expected = mark_sensitive(expected_username, "user")
    masked_actual = mark_sensitive(actual_cname, "user")
    masked_domain = mark_sensitive(expected_domain, "domain")

    # WARN loudly — this is the daenerys-as-administrator hijack signature. The
    # masked detail lands in the (export-time-sanitized) session recording via
    # the _TeeConsole; the structured telemetry event below stays free of raw
    # principal names on purpose. No bracketed markers (Rich markup rule).
    print_warning(
        f"Kerberos credential mismatch: requested authentication as "
        f"{masked_expected} in {masked_domain}, but the ambient ccache "
        f"(source {source}) authenticates as {masked_actual}. The ambient "
        f"ticket binds as the WRONG principal; authenticating as the requested "
        f"user requires a per-user ccache (ensure_user_ccache). "
        f"Operation context: {context}."
    )

    try:
        telemetry.capture(
            "kerberos_ccache_principal_mismatch",
            {
                # Non-sensitive structural fields only — raw principal names are
                # NOT included (they would reach PostHog unsanitized).
                "context": context,
                "source": source,
                "expected_realm": expected_realm_norm,
                "actual_realm": actual_realm_norm,
                "realm_match": expected_realm_norm == actual_realm_norm,
                "refused": _REFUSE_ON_MISMATCH,
            },
        )
    except Exception as exc:  # noqa: BLE001 — telemetry is best-effort
        telemetry.capture_exception(exc)

    if _REFUSE_ON_MISMATCH:
        raise CcachePrincipalMismatchError(
            f"ambient ccache (source {source}) authenticates as a principal "
            f"other than the requested user ({context})"
        )
    return False


__all__ = [
    "CcachePrincipalMismatchError",
    "assert_ccache_principal_matches",
    "read_ccache_primary_principal",
]
