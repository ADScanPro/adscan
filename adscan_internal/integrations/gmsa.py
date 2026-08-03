"""Native gMSA credential reader (LDAP path).

Reads the confidential ``msDS-ManagedPassword`` attribute over a sealed LDAP
channel and derives all credential types from the secret material:
  - NT hash  (MD4 of the raw UTF-16LE CurrentPassword)
  - AES-128-CTS-HMAC-SHA1-96 key
  - AES-256-CTS-HMAC-SHA1-96 key

The blob parsing and key derivation are NOT implemented here: they live in the
shared single source of truth
:mod:`adscan_internal.services.gmsa_managed_password`, which the LSA-dump path
(``DumpLSA`` recovering a cached ``_SC_GMSA_*`` secret) consumes as well. The
wire format is the same in both cases, so there is exactly one parser.

Important implementation detail:
  bloodyAD's ``msDS-ManagedPassword.B64ENCODED`` helper is already the extracted
  CurrentPassword bytes, not the full MSDS_MANAGEDPASSWORD_BLOB. The shared
  parser only unwraps the blob header when the bytes really are a blob, so both
  shapes are safe to pass in.
"""

from __future__ import annotations

import base64
import re

from adscan_internal.services.gmsa_managed_password import (
    GmsaCredentials,
    current_password_from_secret_material as _current_password_from_secret_material,
    derive_gmsa_keys as _derive_keys,
)

__all__ = [
    "GmsaCredentials",
    "fetch_gmsa_credentials_native",
    "render_confidential_channel_panel",
]


def _decode_base64_value(value: str) -> bytes | None:
    """Decode a base64 value after removing display whitespace."""
    normalized = re.sub(r"\s+", "", str(value or ""))
    if not normalized:
        return None

    try:
        return base64.b64decode(normalized, validate=False)
    except Exception:
        return None


def _extract_b64_blob(output: str) -> bytes | None:
    """Parse msDS-ManagedPassword base64 value from bloodyAD get object output.

    Supports both inline values and pretty-printed multi-line values:
      msDS-ManagedPassword: <base64>
      msDS-ManagedPassword.B64ENCODED: <base64>
      msDS-ManagedPassword.B64ENCODED:
        <base64-chunk-1>
        <base64-chunk-2>

    Note:
      bloodyAD's msDS-ManagedPassword.B64ENCODED is CurrentPassword, not the
      full MSDS_MANAGEDPASSWORD_BLOB.
    """
    lines = output.splitlines()

    for index, line in enumerate(lines):
        match = re.match(
            r"^\s*msDS-ManagedPassword(?:\.B64ENCODED)?\s*:\s*(.*)$",
            line,
            re.IGNORECASE,
        )
        if not match:
            continue

        inline_value = match.group(1).strip()
        if inline_value:
            decoded = _decode_base64_value(inline_value)
            if decoded is not None:
                return decoded
            continue

        collected_chunks: list[str] = []
        for next_line in lines[index + 1:]:
            stripped = next_line.strip()
            if not stripped:
                continue
            if ":" in stripped:
                break
            collected_chunks.append(stripped)

        if collected_chunks:
            return _decode_base64_value("".join(collected_chunks))

        return None

    return None


def _extract_decoded_secret_fields(output: str) -> tuple[str | None, str | None]:
    """Parse decoded helper fields emitted by newer bloodyAD builds.

    Returns:
        Tuple of ``(nt_hash, b64_current_password)``. Either field may be None.

    Important:
        msDS-ManagedPassword.B64ENCODED from bloodyAD is CurrentPassword bytes.
    """
    nt_hash: str | None = None
    b64_blob: str | None = None
    lines = output.splitlines()

    for index, line in enumerate(lines):
        nt_match = re.match(
            r"^\s*msDS-ManagedPassword\.NT\s*:\s*([0-9a-fA-F]{32})\s*$",
            line,
            re.IGNORECASE,
        )
        if nt_match:
            nt_hash = nt_match.group(1).strip().lower()
            continue

        b64_match = re.match(
            r"^\s*msDS-ManagedPassword\.B64ENCODED\s*:\s*(.*)$",
            line,
            re.IGNORECASE,
        )
        if not b64_match:
            continue

        inline_value = b64_match.group(1).strip()
        if inline_value:
            b64_blob = re.sub(r"\s+", "", inline_value)
            continue

        collected_chunks: list[str] = []
        for next_line in lines[index + 1:]:
            stripped = next_line.strip()
            if not stripped:
                continue
            if ":" in stripped:
                break
            collected_chunks.append(stripped)

        if collected_chunks:
            b64_blob = "".join(collected_chunks)

    return nt_hash, b64_blob


def render_confidential_channel_panel(account: str, dc_ip: str) -> None:
    """Render the educational panel for a failed confidential-channel gMSA read.

    The gMSA managed password (``msDS-ManagedPassword``) is a CONFIDENTIAL
    directory attribute. Active Directory only returns it over a sealed
    (encrypted) channel. When no sealed channel can be established, ADscan
    refuses to downgrade to an unsealed channel that could never return the
    secret. This panel explains that this is a Microsoft AD security control,
    not an ADscan limitation, and tells the operator exactly how to unblock it.

    Args:
        account: The gMSA sAMAccountName the read targeted (masked on render).
        dc_ip: The domain controller the read was attempted against (masked).
    """
    from rich.console import Group
    from rich.text import Text

    from adscan_core.output._log import BRAND_COLORS
    from adscan_internal import print_panel
    from adscan_internal.rich_output import mark_sensitive

    accent = BRAND_COLORS["info"]
    masked_account = mark_sensitive(account, "user")
    masked_dc = mark_sensitive(dc_ip, "ip")

    def _heading(label: str) -> Text:
        return Text(label, style=f"bold {accent}")

    def _body(text: str) -> Text:
        return Text(text, style="white")

    sections: list[Text] = []

    sections.append(_heading("What happened"))
    sections.append(
        _body(
            f"The gMSA managed password for {masked_account} could not be read: "
            f"no sealed (encrypted) channel to {masked_dc} was available."
        )
    )
    sections.append(Text(""))

    sections.append(_heading("Why (this is Active Directory behavior)"))
    sections.append(
        _body(
            "msDS-ManagedPassword is a CONFIDENTIAL attribute. Active Directory "
            "returns it only over a sealed channel: LDAPS (TLS on 636), or plain "
            "LDAP on 389 with GSS-API sign and seal. Over an unsealed channel the "
            "DC refuses the value with ERROR_DS_CONFIDENTIALITY_REQUIRED. This is "
            "a Microsoft security control, not an ADscan limitation."
        )
    )
    sections.append(Text(""))

    sections.append(_heading("Why ADscan did not just use plain LDAP"))
    sections.append(
        _body(
            "ADscan tried LDAPS and a sign and seal LDAP bind on 389. It "
            "deliberately refuses to downgrade a confidential read to an unsealed "
            "channel, because that read would always fail and could wrongly look "
            "like an ADscan bug or a permissions problem."
        )
    )
    sections.append(Text(""))

    sections.append(_heading("What you can do"))
    for step in (
        "Make sure LDAPS (TCP 636) is reachable to the DC. In a 636-filtered "
        "environment the sealed channel falls back to LDAP 389 with sign and seal.",
        "Provide a Kerberos or NTLM credential so the 389 bind can negotiate "
        "sign and seal. Anonymous and SIMPLE binds cannot seal the channel.",
        "Confirm the credential has rights to read the gMSA password "
        "(PrincipalsAllowedToRetrieveManagedPassword).",
    ):
        line = Text("  • ", style=accent)
        line.append(step, style="white")
        sections.append(line)

    print_panel(
        Group(*sections),
        title="🔒 gMSA Managed Password · Sealed Channel Required",
        border_style=BRAND_COLORS["warning"],
        expand=False,
    )


def fetch_gmsa_credentials_native(
    *,
    dc_ip: str,
    domain: str,
    username: str,
    password: str,
    target_account: str,
    target_domain: str,
    ccache_path: str | None = None,
    use_kerberos: bool = True,
    use_ldaps: bool = True,
    kerberos_target_hostname: str | None = None,
    auth_kdc: str | None = None,
) -> GmsaCredentials | None:
    """Read msDS-ManagedPassword via native badldap and derive all credential types.

    This replaces the bloodyAD subprocess path. The raw LDAP attribute returns
    the full MSDS_MANAGEDPASSWORD_BLOB which ``_current_password_from_secret_material``
    already handles (same as the bloodyAD B64ENCODED path).
    """
    from adscan_internal.rich_output import (
        print_info,
        print_info_debug,
        print_warning,
    )
    from adscan_internal.services.ldap_transport_service import (
        ADscanLDAPConfig,
        ADscanLDAPConnection,
        ConfidentialChannelUnavailableError,
        ConfidentialityMechanism,
    )

    sam = target_account.rstrip("$") + "$"
    effective_target_domain = (target_domain or domain).strip()

    config = ADscanLDAPConfig(
        domain=effective_target_domain,
        dc_ip=dc_ip,
        use_ldaps=use_ldaps,
        use_kerberos=use_kerberos,
        username=username,
        password=password,
        kerberos_target_hostname=kerberos_target_hostname if use_kerberos else None,
        auth_domain=domain,
        auth_kdc=auth_kdc,
        ccache_path=ccache_path,
        # msDS-ManagedPassword is a CONFIDENTIAL attribute: AD only returns it
        # over a sealed channel (LDAPS, or LDAP with GSS sign+seal). Setting this
        # forbids the transparent LDAPS(636)->plain-LDAP(389) downgrade from
        # falling back to an UNSEALED channel that can never return the secret.
        require_confidential=True,
    )

    print_info_debug(
        f"[gmsa] native LDAP fetch: dc={dc_ip} domain={effective_target_domain} "
        f"account={sam} use_kerberos={use_kerberos}"
    )

    base_dn = "DC=" + effective_target_domain.replace(".", ",DC=")

    sealing_mechanism: "ConfidentialityMechanism | None" = None
    try:
        with ADscanLDAPConnection(config) as conn:
            conn.search(
                search_base=base_dn,
                search_filter=f"(sAMAccountName={sam})",
                attributes=["msDS-ManagedPassword"],
            )
            entries = list(conn.entries)
            # Capture which mechanism sealed the channel before the
            # context manager exits and resets it. Used for the
            # positive-path note below when LDAPS was unavailable but a
            # sealed fallback (StartTLS / SASL sign+seal) still worked.
            sealing_mechanism = conn.mechanism
    except ConfidentialChannelUnavailableError as exc:
        # No sealed channel could be established. This is an Active Directory
        # security control, not an ADscan limitation: the gMSA secret is
        # unreadable over an unsealed channel by design. Render the educational
        # panel so the operator understands the AD requirement and how to unblock
        # it, then keep one debug line with the raw cause for diagnostics.
        print_info_debug(f"[gmsa] confidential channel unavailable for {sam}: {exc}")
        render_confidential_channel_panel(sam, dc_ip)
        return None
    except Exception as exc:
        print_warning(f"[gmsa] LDAP search failed for {sam}: {exc}")
        return None

    if not entries:
        print_info_debug(f"[gmsa] no results for {sam}")
        return None

    # Positive-path confidentiality note. When LDAPS (636) was unavailable
    # but the gMSA secret was still read over a sealed fallback channel
    # (StartTLS on 389, or GSS-API SASL sign+seal on 389), surface a brief
    # note so the operator knows the confidential attribute travelled
    # encrypted despite LDAPS being down — it is reassurance, not a warning.
    if sealing_mechanism in (
        ConfidentialityMechanism.STARTTLS,
        ConfidentialityMechanism.SASL_SEAL,
    ):
        _mech_label = (
            "StartTLS"
            if sealing_mechanism is ConfidentialityMechanism.STARTTLS
            else "GSS-API SASL sign+seal"
        )
        print_info(
            f"gMSA managed password read over a sealed channel "
            f"({_mech_label}) since LDAPS was unavailable"
        )

    entry = entries[0]
    attrs = entry.entry_attributes_as_dict
    raw_vals = (attrs or {}).get("msDS-ManagedPassword") if isinstance(attrs, dict) else None

    if not raw_vals:
        raw_vals = getattr(entry, "msDS-ManagedPassword", None) or []

    secret_bytes: bytes | None = None
    for val in (raw_vals if isinstance(raw_vals, list) else [raw_vals]):
        if isinstance(val, bytes) and val:
            secret_bytes = val
            break
        if isinstance(val, str) and val:
            try:
                secret_bytes = base64.b64decode(val)
                break
            except Exception:
                pass

    if secret_bytes is None:
        print_warning(
            f"[gmsa] msDS-ManagedPassword not returned for {sam} — "
            "insufficient permissions or account not a gMSA"
        )
        return None

    print_info_debug(f"[gmsa] native: raw blob size={len(secret_bytes)} bytes")

    try:
        current_password = _current_password_from_secret_material(secret_bytes)
    except Exception as exc:
        print_warning(f"[gmsa] failed to parse gMSA blob for {sam}: {exc}")
        return None

    try:
        nt_hash, aes128, aes256 = _derive_keys(current_password, sam, effective_target_domain)
    except Exception as exc:
        print_warning(f"[gmsa] failed to derive gMSA Kerberos keys for {sam}: {exc}")
        return None

    return GmsaCredentials(account=sam, nt_hash=nt_hash, aes128=aes128, aes256=aes256)
