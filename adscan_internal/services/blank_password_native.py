"""Native Kerberos blank-password check — replaces the legacy NetExec/SMB path.

Empirically validated against GOAD/Essos (2026-06-17):

* **kerbrute / gokrb5** rejects an empty password client-side ("client has
  neither a keytab nor a password set") and never sends the AS-REQ — a total
  false negative. That is why blank spraying historically shelled out to NetExec.
* **kerbad** mints a TGT for a genuinely blank-password account (PASSWD_NOTREQD +
  empty password) AND correctly rejects every other account with
  ``KDC_ERR_PREAUTH_FAILED`` — including a DONT_REQ_PREAUTH (AS-REP-roastable)
  account, because the client still sends a PA-ENC-TIMESTAMP whose (empty) key the
  KDC validates. So a successful TGT is a SOUND blank-password signal with no
  false positive on no-preauth accounts.

Requires the vendor fix in ``kerbad/common/creds.py`` that treats ``password==''``
as a valid (empty) credential (``is not None``), locked by
``tests/unit/vendor/test_kerbad_empty_password_key.py``.

A blank-password AS-REQ targets ``krbtgt/REALM`` (a TGT), so there is no service
SPN to normalise — the KDC IP is a sufficient target (the FQDN-SPN rule applies to
service tickets, not the AS-REQ).
"""

from __future__ import annotations

from typing import Optional

from adscan_core.rich_output import print_info_debug


async def check_blank_password(
    *,
    domain: str,
    username: str,
    kdc_ip: str,
    posture_snapshot: object | None = None,
    posture_sink: object | None = None,
) -> Optional[bool]:
    """Return whether ``username`` has an EMPTY password, via a native AS-REQ.

    Args:
        domain: Target realm (e.g. ``essos.local``).
        username: sAMAccountName to test.
        kdc_ip: KDC / DC address for the AS-REQ.
        posture_snapshot: Optional domain posture (AES-only / non-default salt).
        posture_sink: Optional posture signal sink.

    Returns:
        ``True``  — the account has a blank password (TGT minted).
        ``False`` — the KDC rejected the empty password (not blank / unknown / revoked).
        ``None``  — inconclusive (network, clock, or unclassified error): the caller
                    must NOT treat this as a verdict (no false positive/negative).
    """
    try:
        from kerbad.common.factory import KerberosClientFactory  # noqa: PLC0415
        from kerbad.protocol.errors import KerberosError  # noqa: PLC0415
    except ImportError:
        return None

    # The URL factory parses an empty password as "no secret", so build a
    # password-type credential with a placeholder, then force the EMPTY password
    # on the client before the AS-REQ.
    try:
        url = f"kerberos+password://{domain}\\{username}:placeholder@{kdc_ip}"
        client = KerberosClientFactory.from_url(url).get_client()
    except Exception:  # noqa: BLE001 — malformed principal/target is inconclusive
        return None
    client.credential.password = ""
    client.credential.nt_hash = None

    # Posture-aware salt: a no-op on standard-salt KDCs (AES key derivation
    # defaults to DOMAIN.UPPER+username, the standard salt), but REQUIRED on
    # hardened non-default-salt AES-only KDCs. Best-effort — get_TGT also
    # probe-firsts internally; this additionally emits the ETYPE-INFO2 posture
    # signal. Uses ``is not None`` gating, so the empty password passes.
    try:
        from adscan_internal.services.kerberos_transport import (  # noqa: PLC0415
            KerberosConfig,
            _probe_and_set_etype_info2_salt,
        )

        cfg = KerberosConfig(
            domain=domain,
            kdc_ip=kdc_ip,
            username=username,
            password="",
            posture_snapshot=posture_snapshot,
            posture_sink=posture_sink,
        )
        await _probe_and_set_etype_info2_salt(client, cfg)
    except Exception:  # noqa: BLE001 — salt probe is best-effort
        pass

    try:
        await client.with_clock_skew(client.get_TGT)
        print_info_debug(f"blank-password: TGT minted for {username} (empty password)")
        return True
    except KerberosError:
        # KDC_ERR_PREAUTH_FAILED / KDC_ERR_C_PRINCIPAL_UNKNOWN / CLIENT_REVOKED …
        # a definitive "this account does not have an empty password".
        return False
    except Exception as exc:  # noqa: BLE001 — network / clock / unclassified
        print_info_debug(f"blank-password: inconclusive for {username}: {exc}")
        return None
