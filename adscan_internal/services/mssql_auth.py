"""MSSQL authentication SSOT — Kerberos-first, posture-aware NTLM fallback.

Every MSSQL connection point that may authenticate with a ``.ccache`` credential
(the login sweep, the authorization collector, and the interactive post-auth
workflow) resolves its NTLM fallback secret through the single function
:func:`resolve_mssql_ntlm_fallback_secret` in this module. Centralizing it here
guarantees no MSSQL surface can silently diverge into Kerberos-only auth and
then fail on an instance with no ``MSSQLSvc`` SPN.

The mechanics of *applying* the fallback live in
:class:`adscan_internal.integrations.mssql.native_backend.ImpacketMSSQLBackend`
(``execute_query(..., allow_ntlm_fallback=, ntlm_fallback_secret=)`` plus the
sticky ``ntlm_fallback_secret`` constructor arg). This module only decides
*whether* and *with which secret* a fallback should be attempted.
"""

from __future__ import annotations

from adscan_core.rich_output import print_info_debug


def resolve_mssql_ntlm_fallback_secret(
    shell,
    *,
    domain: str,
    username: str,
    wire_secret: str,
    password: str,
) -> str | None:
    """Resolve a password / NT hash for the NTLM fallback of a ccache-only auth.

    A Kerberos-only MSSQL connection sends a ``.ccache`` on the wire, which
    forecloses NTLM — so an instance with no ``MSSQLSvc`` SPN (Kerberos fails
    with ``KDC_ERR_S_PRINCIPAL_UNKNOWN``) is left unassessed. This returns a
    password / NT hash for the SAME principal so the backend can still try NTLM
    against those instances. Returns ``None`` (no fallback) when:

    - the wire secret is not a ccache (the primary attempt is already NTLM/SQL);
    - domain posture reports NTLM known-blocked (HIGH + ``DISABLED``) — never
      attempt NTLM the DC is known to reject;
    - only a ccache is available for the principal (no NTLM-usable secret).

    The principal's domain password / NT hash lives in the generic credential
    store — NOT a host-scoped service ticket or a local credential — so the
    canonical resolver (:func:`_get_stored_domain_credential_for_user`) is used,
    credential-store-first.

    Args:
        shell: The active :class:`PentestShell` (posture + credential store).
        domain: The target domain the principal belongs to.
        username: The connecting principal's sAMAccountName.
        wire_secret: The secret that will hit the wire on the primary attempt.
            When this is not a ``.ccache`` path there is nothing to fall back
            from (NTLM is already reachable) and ``None`` is returned.
        password: The in-hand secret for the principal (may itself be a ccache
            path). Preferred when it is a usable password / NT hash; otherwise
            the credential store is consulted.

    Returns:
        A password / NT hash usable for an NTLM bind, or ``None`` when no NTLM
        fallback should be attempted.
    """
    if not str(wire_secret or "").strip().lower().endswith(".ccache"):
        return None

    from adscan_internal.services.domain_posture import (
        ConstraintCategory,
        SignalConfidence,
        TriState,
        get_posture,
    )

    ntlm_state = get_posture(shell.domains_data, domain=domain).get(
        ConstraintCategory.NTLM_AUTHENTICATION
    )
    if (
        ntlm_state.confidence is SignalConfidence.HIGH
        and ntlm_state.effective_state is TriState.DISABLED
    ):
        print_info_debug(
            "[mssql_auth] NTLM known-blocked by posture — "
            "skipping ccache-only NTLM fallback"
        )
        return None

    # Prefer the in-hand secret when it is a usable password / NT hash; otherwise
    # fall back to the canonical credential-store resolver (covers the ccache-only
    # case where ``password`` is itself a ticket path).
    candidate = str(password or "").strip()
    if not candidate or candidate.lower().endswith(".ccache"):
        from adscan_internal.cli.attack_path_execution import (
            _get_stored_domain_credential_for_user,
        )

        candidate = (
            _get_stored_domain_credential_for_user(
                shell, domain=domain, username=username
            )
            or ""
        )
    candidate = str(candidate).strip()
    if not candidate or candidate.lower().endswith(".ccache"):
        return None
    return candidate
