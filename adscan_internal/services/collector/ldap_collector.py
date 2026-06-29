"""Single-pass LDAP collector that replaces native_collector and bloodhound_badldap_collector_service."""

from __future__ import annotations

import re
import time
import uuid
from typing import Any, Optional, TYPE_CHECKING

from adscan_internal import telemetry
from adscan_internal.rich_output import (
    mark_sensitive,
    print_info_debug,
    print_warning,
    print_warning_debug,
)
from adscan_internal.services.collector.acl_parser import ACLParser
from adscan_internal.services.collector.models import (
    CollectionResult,
    CollectorEdge,
    CollectorNode,
    DomainPolicy,
    PasswordSettingsObject,
)
from adscan_internal.services.collector.ldap_credentials import LDAPCredentials

if TYPE_CHECKING:
    from adscan_internal.services.domain_posture import DomainPosture
    from adscan_internal.services.posture_sink import PostureSink
from adscan_internal.services.collector.ldap_scope import LDAPCollectionScope
from adscan_internal.services.ldap_transport_service import (
    ADscanLDAPConfig,
    ADscanLDAPConnection,
    SD_FLAGS_DACL_CONTROL,
)
from adscan_internal.services.privileged_group_classifier import (
    is_tier_zero_group_sid,
    is_tier_zero_user_sid,
)

_RODC_GROUP_IDS = {516, 521}

_UAC_DISABLED = 0x00000002
_UAC_DONT_REQ_PREAUTH = 0x00400000
_UAC_TRUSTED_FOR_DELEGATION = 0x00080000
_UAC_TRUSTED_TO_AUTH = 0x01000000  # TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION (Protocol Transition)
_UAC_PWD_NEVER_EXPIRES = 0x00010000
_UAC_PWD_NOT_REQ = 0x00000020

# ---------------------------------------------------------------------------
# msDS-ReplAttributeMetaData parsing
# ---------------------------------------------------------------------------

# Password-policy-relevant attributes on the domain root object (DDP).
_DDP_PWD_ATTRS: frozenset[str] = frozenset({
    "minPwdLength", "maxPwdAge", "minPwdAge",
    "pwdProperties", "pwdHistoryLength",
    "lockoutThreshold", "lockoutDuration", "lockoutObservationWindow",
})

# Password-policy-relevant attributes on PSO objects (different LDAP names).
_PSO_PWD_ATTRS: frozenset[str] = frozenset({
    "msDS-MinimumPasswordLength", "msDS-MaximumPasswordAge", "msDS-MinimumPasswordAge",
    "msDS-PasswordHistoryLength", "msDS-PasswordComplexityEnabled",
    "msDS-LockoutThreshold", "msDS-LockoutDuration", "msDS-LockoutObservationWindow",
})

_REPL_ATTR_NAME_RE = re.compile(r"<pszAttributeName>(.+?)</pszAttributeName>")
_REPL_TIME_RE = re.compile(r"<ftimeLastOriginatingChange>(.+?)</ftimeLastOriginatingChange>")
_REPL_VER_RE = re.compile(r"<dwVersion>(\d+)</dwVersion>")


def _parse_repl_attr_metadata(
    blobs: list[Any],
    target_attrs: frozenset[str],
) -> tuple[tuple[str, str, int], ...]:
    """Extract per-attribute change metadata from msDS-ReplAttributeMetaData blobs.

    Each blob is one XML fragment describing one AD attribute. We filter to
    ``target_attrs`` and return a tuple of ``(attr_name, iso_timestamp, version)``
    sorted newest-first. ``version == 1`` means set at provisioning and never
    explicitly modified.
    """
    result: list[tuple[str, str, int]] = []
    for blob in blobs:
        text = blob if isinstance(blob, str) else (
            blob.decode("utf-8", errors="replace") if isinstance(blob, bytes) else str(blob)
        )
        name_m = _REPL_ATTR_NAME_RE.search(text)
        if not name_m:
            continue
        name = name_m.group(1).strip()
        if name not in target_attrs:
            continue
        time_m = _REPL_TIME_RE.search(text)
        if not time_m:
            continue
        ts = time_m.group(1).strip()
        ver_m = _REPL_VER_RE.search(text)
        ver = int(ver_m.group(1)) if ver_m else 1
        result.append((name, ts, ver))
    result.sort(key=lambda x: x[1], reverse=True)
    return tuple(result)


_COLLECT_ATTRS = [
    "objectSid",
    "objectGUID",
    "distinguishedName",
    "objectClass",
    "sAMAccountName",
    "sAMAccountType",
    "name",
    "dNSHostName",
    "userAccountControl",
    "primaryGroupID",
    "servicePrincipalName",
    "msDS-AllowedToDelegateTo",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "msDS-GroupMSAMembership",
    "sIDHistory",
    "adminCount",
    "ms-Mcs-AdmPwdExpirationTime",
    "lastLogon",
    "lastLogonTimestamp",
    "pwdLastSet",
    "whenCreated",
    "nTSecurityDescriptor",
    # Credential field enumeration (replaces nxc -M user-desc/get-unixUserPassword/get-userPassword/get-info-users)
    "description",
    "unixUserPassword",
    "userPassword",
    "info",
    # Host fingerprint & attack surface enrichment
    "operatingSystem",
    "operatingSystemVersion",
    "msDS-SupportedEncryptionTypes",
    "msDS-KeyCredentialLink",
    # Effective fine-grained password policy applied to the principal — used
    # by services/password_policy_compliance.py to resolve which policy
    # governs each user without re-querying LDAP. Constructed attribute,
    # only returned when the bind has read permission.
    "msDS-ResultantPSO",
]

_GPO_LINK_RE = re.compile(r"\[LDAP://[^,]*CN=\{([A-Fa-f0-9\-]+)\}", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Public helpers (exported for tests)
# ---------------------------------------------------------------------------


def _uac_enabled(uac: int | None) -> bool | None:
    """Return True if account is enabled, None if uac is None."""
    if uac is None:
        return None
    return not bool(uac & _UAC_DISABLED)


def _has_spn(spns: list[str]) -> bool:
    return bool(spns)


def _uac_dontreqpreauth(uac: int) -> bool:
    return bool(uac & _UAC_DONT_REQ_PREAUTH)


def _is_rodc_by_primary_group(pgid: int | None) -> bool:
    return pgid in _RODC_GROUP_IDS


def _account_name(username: str | None) -> str | None:
    if username is None:
        return None
    value = str(username).strip()
    if "\\" in value:
        return value.split("\\", 1)[1]
    if "@" in value:
        return value.split("@", 1)[0]
    return value


# ---------------------------------------------------------------------------
# Legacy kwargs → LDAPCredentials translation
# ---------------------------------------------------------------------------


def _legacy_kwargs_to_credentials(
    *,
    domain: str,
    dc_address: str,
    username: str | None,
    password: str | None,
    use_kerberos: bool,
    use_ldaps: bool,
    kerberos_target_hostname: str | None,
    auth_domain: str | None,
    auth_kdc: str | None,
    aes_key: str | None,
    ccache_path: str | None,
    posture_sink: Optional["PostureSink"] = None,
    posture_snapshot: Optional["DomainPosture"] = None,
) -> "LDAPCredentials":
    """Translate the legacy flat kwargs into the canonical ``LDAPCredentials``.

    Used to keep existing callers (orchestrator, tests, integrations) working
    while the rest of the codebase migrates to the factory API.
    """
    user = (username or "").strip()
    if use_kerberos:
        if ccache_path:
            return LDAPCredentials.for_kerberos_ccache(
                domain=domain,
                dc_ip=dc_address,
                username=user,
                ccache_path=ccache_path,
                kdc=auth_kdc,
                auth_domain=auth_domain,
                use_ldaps=use_ldaps,
                kerberos_target_hostname=kerberos_target_hostname,
                posture_sink=posture_sink,
                posture_snapshot=posture_snapshot,
            )
        if aes_key:
            return LDAPCredentials.for_kerberos_aes(
                domain=domain,
                dc_ip=dc_address,
                username=user,
                aes_key=aes_key,
                kdc=auth_kdc,
                auth_domain=auth_domain,
                use_ldaps=use_ldaps,
                kerberos_target_hostname=kerberos_target_hostname,
                posture_sink=posture_sink,
                posture_snapshot=posture_snapshot,
            )
        return LDAPCredentials.for_kerberos_password(
            domain=domain,
            dc_ip=dc_address,
            username=user,
            password=password or "",
            kdc=auth_kdc,
            auth_domain=auth_domain,
            use_ldaps=use_ldaps,
            kerberos_target_hostname=kerberos_target_hostname,
            posture_sink=posture_sink,
            posture_snapshot=posture_snapshot,
        )
    if not user and not password:
        return LDAPCredentials.anonymous(
            domain=domain,
            dc_ip=dc_address,
            use_ldaps=use_ldaps,
            kerberos_target_hostname=kerberos_target_hostname,
            posture_sink=posture_sink,
            posture_snapshot=posture_snapshot,
        )
    return LDAPCredentials.for_password(
        domain=domain,
        dc_ip=dc_address,
        username=user,
        password=password or "",
        use_ldaps=use_ldaps,
        auth_domain=auth_domain,
        auth_kdc=auth_kdc,
        kerberos_target_hostname=kerberos_target_hostname,
        posture_sink=posture_sink,
        posture_snapshot=posture_snapshot,
    )


def _replace_dataclass(obj: Any, **changes: Any) -> Any:
    """Thin wrapper around ``dataclasses.replace`` for non-frozen configs."""
    import dataclasses as _dc

    return _dc.replace(obj, **changes)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _attrs(entry: Any) -> dict[str, list[Any]]:
    raw = getattr(entry, "entry_raw_attributes", {}) or {}
    decoded = getattr(entry, "entry_attributes_as_dict", {}) or {}
    keys = set(raw) | set(decoded)
    result: dict[str, list[Any]] = {}
    _binary_keys = {"objectsid", "objectguid", "ntsecuritydescriptor", "sidhistory"}
    for key in keys:
        key_text = str(key)
        if key_text.casefold() in _binary_keys:
            values = raw.get(key)
        else:
            values = decoded.get(key)
        if values is None:
            values = raw.get(key, [])
        if not isinstance(values, (list, tuple, set)):
            values = [values]
        result[key_text] = [v for v in values if v is not None]
    return result


def _values(attrs: dict[str, list[Any]], name: str) -> list[Any]:
    for key, values in attrs.items():
        if key.casefold() == name.casefold():
            return [v for v in values if v is not None]
    return []


def _first(attrs: dict[str, list[Any]], name: str) -> Any:
    vals = _values(attrs, name)
    return vals[0] if vals else None


def _first_str(attrs: dict[str, list[Any]], name: str) -> str:
    val = _first(attrs, name)
    return str(val).strip() if val is not None else ""


def _int_attr(attrs: dict[str, list[Any]], name: str) -> int | None:
    val = _first(attrs, name)
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _decode_sid(raw: Any) -> str:
    """Decode a raw SID bytes or string into S-... format."""
    if isinstance(raw, bytes):
        try:
            from winacl.dtyp.sid import SID

            return str(SID.from_bytes(raw))
        except Exception:
            return raw.hex()
    return str(raw).strip() if raw else ""


def _decode_guid(raw: Any) -> str:
    if isinstance(raw, bytes):
        try:
            return str(uuid.UUID(bytes_le=raw))
        except (TypeError, ValueError):
            return raw.hex()
    return str(raw).strip() if raw else ""


def _raw_bytes(entry: Any, attr: str) -> bytes | None:
    raw = getattr(entry, "entry_raw_attributes", {}) or {}
    for key, values in raw.items():
        if str(key).casefold() == attr.casefold():
            return values[0] if values else None
    return None


def _parse_allowed_to_act_sd(
    sd_bytes: bytes,
    *,
    target_object_id: str,
) -> list[CollectorEdge]:
    """Parse RBCD ``msDS-AllowedToAct...`` SD bytes into ``AllowedToAct`` edges."""
    return _parse_trustee_sd_edges(
        sd_bytes,
        target_object_id=target_object_id,
        relation="AllowedToAct",
        method="msDS-AllowedToActOnBehalfOfOtherIdentity",
        notes={"delegation_type": "resource_based_constrained"},
    )


def _parse_gmsa_membership_sd(
    sd_bytes: bytes,
    *,
    target_object_id: str,
) -> list[CollectorEdge]:
    """Parse gMSA ``msDS-GroupMSAMembership`` SD bytes into read edges."""
    return _parse_trustee_sd_edges(
        sd_bytes,
        target_object_id=target_object_id,
        relation="ReadGMSAPassword",
        method="msDS-GroupMSAMembership",
        notes={"credential_type": "gmsa"},
    )


def _parse_trustee_sd_edges(
    sd_bytes: bytes,
    *,
    target_object_id: str,
    relation: str,
    method: str,
    notes: dict[str, Any],
) -> list[CollectorEdge]:
    """Parse an SD whose DACL trustees grant a relation to the target object."""
    if not sd_bytes or not target_object_id:
        return []
    try:
        from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR  # type: ignore
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_warning_debug(f"[ldap-collector] winacl unavailable for {method}: {exc}")
        return []

    try:
        sd = SECURITY_DESCRIPTOR.from_bytes(sd_bytes)
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_info_debug(f"[ldap-collector] Failed to parse {method} SD: {exc}")
        return []
    return _trustee_edges_from_descriptor(
        sd,
        target_object_id=target_object_id,
        relation=relation,
        method=method,
        notes=notes,
    )


def _allowed_to_act_edges_from_descriptor(
    sd: Any,
    *,
    target_object_id: str,
) -> list[CollectorEdge]:
    """Build ``AllowedToAct`` edges from a parsed RBCD security descriptor."""
    return _trustee_edges_from_descriptor(
        sd,
        target_object_id=target_object_id,
        relation="AllowedToAct",
        method="msDS-AllowedToActOnBehalfOfOtherIdentity",
        notes={"delegation_type": "resource_based_constrained"},
    )


def _trustee_edges_from_descriptor(
    sd: Any,
    *,
    target_object_id: str,
    relation: str,
    method: str,
    notes: dict[str, Any],
) -> list[CollectorEdge]:
    """Build collector edges from trustees in a parsed security descriptor."""
    dacl = getattr(sd, "Dacl", None)
    if not dacl:
        return []

    edges: list[CollectorEdge] = []
    seen: set[tuple[str, str]] = set()
    for ace in getattr(dacl, "aces", []) or []:
        trustee = _ace_trustee_sid(ace)
        if not trustee or trustee == target_object_id:
            continue
        key = (trustee, target_object_id)
        if key in seen:
            continue
        seen.add(key)
        edges.append(
            CollectorEdge(
                source_object_id=trustee,
                target_object_id=target_object_id,
                relation=relation,
                source="ldap",
                method=method,
                notes=notes,
            )
        )
    return edges


def _ace_trustee_sid(ace: Any) -> str:
    """Extract an ACE trustee SID from winacl ACE variants."""
    for attr_path in (
        ("Sid",),
        ("sid",),
        ("Ace", "Sid"),
        ("Ace", "sid"),
        ("ace", "Sid"),
        ("ace", "sid"),
    ):
        current = ace
        for attr in attr_path:
            current = getattr(current, attr, None)
            if current is None:
                break
        if current is not None:
            value = str(current).strip().upper()
            if value:
                return value
    return ""


def _is_tier_zero_group_sid(
    sid: str,
    *,
    name: str | None = None,
    distinguished_name: str | None = None,
) -> bool:
    return is_tier_zero_group_sid(
        sid,
        name=name,
        distinguished_name=distinguished_name,
    )


def _is_tier_zero_user_sid(sid: str) -> bool:
    return is_tier_zero_user_sid(sid)


def _str_values(attrs: dict[str, list[Any]], name: str) -> list[str]:
    return [str(v).strip() for v in _values(attrs, name) if str(v).strip()]


def _parse_enc_types(
    attrs: dict[str, list[Any]],
) -> tuple[int | None, bool | None]:
    """Parse msDS-SupportedEncryptionTypes into (enc_types, rc4_only).

    rc4_only is True when AES bits (0x38 = AES128|AES256|AES256-SK) are absent
    AND enc_types is explicitly non-zero. enc_types==0 means 'use OS default'
    which varies by forest functional level — treated as unknown (None).
    Returns (None, None) when the attribute is absent.
    """
    enc_types = _int_attr(attrs, "msDS-SupportedEncryptionTypes")
    if enc_types is None or enc_types == 0:
        return enc_types, None  # absent or default — cannot determine RC4-only
    rc4_only = (enc_types & 0x38) == 0  # no AES bits set
    return enc_types, rc4_only


def _set_if_nonempty(d: dict[str, Any], key: str, value: str) -> None:
    if value:
        d[key] = value


def _is_gmsa_account(attrs: dict[str, list[Any]], classes: set[str]) -> bool:
    """Return True when an LDAP entry is a group managed service account."""
    if "msds-groupmanagedserviceaccount" in classes:
        return True
    return bool(_values(attrs, "msDS-GroupMSAMembership"))


def _account_common_properties(
    attrs: dict[str, list[Any]],
    *,
    include_user_flags: bool,
    uac: int | None,
) -> dict[str, Any]:
    """Build shared User/gMSA account properties without changing node kind."""
    spns = _str_values(attrs, "servicePrincipalName")
    pwdlastset = _int_attr(attrs, "pwdLastSet")
    enc_types, rc4_only = _parse_enc_types(attrs)
    shadow_cred_keys = [
        k for k in _str_values(attrs, "msDS-KeyCredentialLink") if k.strip()
    ]
    props: dict[str, Any] = {
        "serviceprincipalnames": spns,
        "hasspn": _has_spn(spns),
        "pwdlastset": pwdlastset,
        "whencreated": _first_str(attrs, "whenCreated") or None,
        "allowedtodelegate": _str_values(attrs, "msDS-AllowedToDelegateTo"),
    }
    if include_user_flags:
        props.update(
            {
                "admincount": bool(_int_attr(attrs, "adminCount")),
                "pwdneverexpires": bool(uac and (uac & _UAC_PWD_NEVER_EXPIRES)),
                "passwordnotreqd": bool(uac and (uac & _UAC_PWD_NOT_REQ)),
                "dontreqpreauth": _uac_dontreqpreauth(uac or 0),
                "hasunconstrainedauth": bool(
                    uac and (uac & _UAC_TRUSTED_FOR_DELEGATION)
                ),
                "hastrustedtoauth": bool(
                    uac and (uac & _UAC_TRUSTED_TO_AUTH)
                ),
                "lastlogon": _int_attr(attrs, "lastLogonTimestamp")
                or _int_attr(attrs, "lastLogon"),
                "haslaps": _first(attrs, "ms-Mcs-AdmPwdExpirationTime") is not None,
            }
        )
        resultant_pso = _first_str(attrs, "msDS-ResultantPSO")
        if resultant_pso:
            props["resultantpso"] = resultant_pso
    if enc_types is not None:
        props["enc_types"] = enc_types
    if rc4_only:
        props["rc4_only"] = True
    if shadow_cred_keys:
        props["shadow_cred_count"] = len(shadow_cred_keys)
    _set_if_nonempty(props, "description", _first_str(attrs, "description"))
    return props


# ---------------------------------------------------------------------------
# Entry → CollectorNode
# ---------------------------------------------------------------------------


def _entry_to_node(entry: Any, domain: str) -> CollectorNode | None:
    attrs = _attrs(entry)
    classes = {str(v).lower() for v in _values(attrs, "objectClass")}

    raw_sid = _first(attrs, "objectSid")
    sid = _decode_sid(raw_sid).upper() if raw_sid else ""

    raw_guid = _first(attrs, "objectGUID")
    guid = _decode_guid(raw_guid).upper() if raw_guid else ""

    dn = _first_str(attrs, "distinguishedName")
    sam = _first_str(attrs, "sAMAccountName")
    raw_name = _first_str(attrs, "name") or sam or dn
    uac = _int_attr(attrs, "userAccountControl")
    primary_group_id = _int_attr(attrs, "primaryGroupID")
    enabled = _uac_enabled(uac)

    if _is_gmsa_account(attrs, classes):
        if not sid:
            return None
        name = f"{(sam or raw_name).upper()}@{domain.upper()}"
        props = _account_common_properties(attrs, include_user_flags=True, uac=uac)
        props.update(
            {
                "account_type": "gmsa",
                "is_gmsa": True,
                "is_smb_host": False,
                "primarygroupid": primary_group_id,
            }
        )
        return CollectorNode(
            object_id=sid,
            kind="User",
            name=name,
            domain=domain,
            samaccountname=sam,
            distinguished_name=dn,
            enabled=enabled,
            highvalue=_is_tier_zero_user_sid(sid),
            properties=props,
        )

    if "computer" in classes:
        dns_name = _first_str(attrs, "dNSHostName")
        short = sam.rstrip("$") if sam else raw_name
        name = (dns_name or f"{short}.{domain}").upper()
        spns = _str_values(attrs, "servicePrincipalName")
        pwdlastset = _int_attr(attrs, "pwdLastSet")
        enc_types, rc4_only = _parse_enc_types(attrs)
        shadow_cred_keys = [
            k for k in _str_values(attrs, "msDS-KeyCredentialLink") if k.strip()
        ]
        shadow_cred_count = len(shadow_cred_keys)
        enc_props: dict[str, Any] = {}
        _set_if_nonempty(enc_props, "os", _first_str(attrs, "operatingSystem"))
        _set_if_nonempty(
            enc_props, "os_version", _first_str(attrs, "operatingSystemVersion")
        )
        if enc_types is not None:
            enc_props["enc_types"] = enc_types
        if rc4_only:
            enc_props["rc4_only"] = True
        if shadow_cred_count > 0:
            enc_props["shadow_cred_count"] = shadow_cred_count
        cred_props: dict[str, Any] = {}
        _set_if_nonempty(cred_props, "description", _first_str(attrs, "description"))
        return CollectorNode(
            object_id=sid,
            kind="Computer",
            name=name,
            domain=domain,
            samaccountname=sam,
            distinguished_name=dn,
            enabled=enabled,
            highvalue=_is_rodc_by_primary_group(primary_group_id),
            properties={
                "dnshostname": dns_name or None,
                "primarygroupid": primary_group_id,
                "serviceprincipalnames": spns,
                "allowedtodelegate": _str_values(attrs, "msDS-AllowedToDelegateTo"),
                "hasspn": _has_spn(spns),
                "pwdlastset": pwdlastset,
                # lastLogonTimestamp is the RELIABLE staleness/activity signal for
                # a computer — independent of password rotation. pwdLastSet is NOT
                # a valid staleness proxy: legacy / pre-Win2000-compat / manual-
                # password machines (the Timeroast targets) keep an old pwdLastSet
                # while still actively logging on, so they would false-positive.
                # The User builder already maps this; the Computer builder omitted
                # it (computers came back 0/86 → stale-computer detection blind).
                "lastlogon": _int_attr(attrs, "lastLogonTimestamp")
                or _int_attr(attrs, "lastLogon"),
                "whencreated": _first_str(attrs, "whenCreated") or None,
                "unconstraineddelegation": bool(
                    uac and (uac & _UAC_TRUSTED_FOR_DELEGATION)
                ),
                "hastrustedtoauth": bool(
                    uac and (uac & _UAC_TRUSTED_TO_AUTH)
                ),
                **cred_props,
                **enc_props,
            },
        )

    if "group" in classes:
        name = f"{raw_name.upper()}@{domain.upper()}"
        cred_props = {}
        _set_if_nonempty(cred_props, "description", _first_str(attrs, "description"))
        return CollectorNode(
            object_id=sid,
            kind="Group",
            name=name,
            domain=domain,
            samaccountname=sam,
            distinguished_name=dn,
            highvalue=_is_tier_zero_group_sid(
                sid,
                name=raw_name,
                distinguished_name=dn,
            ),
            properties={
                **cred_props,
            },
        )

    if "user" in classes or "person" in classes:
        if not sid:
            return None
        name = f"{(sam or raw_name).upper()}@{domain.upper()}"
        props = _account_common_properties(attrs, include_user_flags=True, uac=uac)
        props["primarygroupid"] = primary_group_id
        _set_if_nonempty(
            props, "unix_user_password", _first_str(attrs, "unixUserPassword")
        )
        _set_if_nonempty(props, "user_password", _first_str(attrs, "userPassword"))
        _set_if_nonempty(props, "info_field", _first_str(attrs, "info"))
        return CollectorNode(
            object_id=sid,
            kind="User",
            name=name,
            domain=domain,
            samaccountname=sam,
            distinguished_name=dn,
            enabled=enabled,
            highvalue=_is_tier_zero_user_sid(sid),
            properties=props,
        )

    if "grouppolicycontainer" in classes:
        return CollectorNode(
            object_id=guid,
            kind="GPO",
            name=raw_name.upper(),
            domain=domain,
            distinguished_name=dn,
        )

    if "organizationalunit" in classes:
        return CollectorNode(
            object_id=guid,
            kind="OU",
            name=raw_name.upper(),
            domain=domain,
            distinguished_name=dn,
        )

    if "container" in classes and guid:
        return CollectorNode(
            object_id=guid,
            kind="Container",
            name=raw_name.upper(),
            domain=domain,
            distinguished_name=dn,
        )

    return None


def _deleted_entry_to_node(entry: Any, domain: str) -> CollectorNode | None:
    """Build a User node for a tombstoned (deleted) account.

    The object's SID is preserved across deletion (AD Recycle Bin), so this node
    keys on the SAME object_id it will have once restored — its ACL edges (parsed
    from the tombstone's nTSecurityDescriptor) therefore land on the right
    principal. The node carries ``tombstoned``/``deleted_dn``/``restore_dn`` so the
    execution layer reanimates it before running the technique the right allows.
    """
    attrs = _attrs(entry)
    raw_sid = _first(attrs, "objectSid")
    sid = _decode_sid(raw_sid).upper() if raw_sid else ""
    if not sid:
        return None

    deleted_dn = _first_str(attrs, "distinguishedName")
    sam = _first_str(attrs, "sAMAccountName")
    last_known_rdn = _first_str(attrs, "msDS-LastKnownRDN")
    last_known_parent = _first_str(attrs, "lastKnownParent")
    uac = _int_attr(attrs, "userAccountControl")
    display = sam or last_known_rdn or "DELETED"
    name = f"{display.upper()}@{domain.upper()}"
    restore_dn = (
        f"CN={last_known_rdn},{last_known_parent}"
        if last_known_rdn and last_known_parent
        else ""
    )

    props = _account_common_properties(attrs, include_user_flags=True, uac=uac)
    props["primarygroupid"] = _int_attr(attrs, "primaryGroupID")
    props["tombstoned"] = True
    props["deleted_dn"] = deleted_dn
    if restore_dn:
        props["restore_dn"] = restore_dn
    if last_known_rdn:
        props["last_known_rdn"] = last_known_rdn

    return CollectorNode(
        object_id=sid,
        kind="User",
        name=name,
        domain=domain,
        samaccountname=sam,
        distinguished_name=deleted_dn,
        enabled=_uac_enabled(uac),
        highvalue=_is_tier_zero_user_sid(sid),
        properties=props,
    )


# ---------------------------------------------------------------------------
# Collector class
# ---------------------------------------------------------------------------


class ADscanLDAPCollector:
    """Single-pass LDAP collector for BloodHound-style graph data.

    The collector is the single source of truth for **all** LDAP enumeration
    in ADscan — both authenticated and anonymous. Pass:

    * ``credentials=LDAPCredentials.for_password(...)`` (or any other factory)
      and ``scope=LDAPCollectionScope.full_authenticated()`` for the canonical
      authenticated path, or
    * ``credentials=LDAPCredentials.anonymous(...)`` and
      ``scope=LDAPCollectionScope.narrow_unauth()`` for the unauthenticated
      sweep used by ``unauth_enrichment_service``.

    Every collection phase has its own try/except → telemetry → debug log
    skip-on-fail behaviour, so a denied ACL read or a missing ADCS
    configuration never aborts the whole sweep.

    The legacy 11-kwarg signature (``domain=``, ``dc_address=``, ``username=``,
    …) is preserved for backward compatibility and translates internally to
    the new ``credentials`` + ``scope`` shape.
    """

    def __init__(self) -> None:
        # Set per-call so phase helpers can consult scope without changing
        # their signatures. None outside an active collect() call.
        self._active_scope: LDAPCollectionScope | None = None
        # Diagnostic breadcrumb: which sub-collection is in flight (sizes/counts
        # only). Set per-phase in the connection-scoped block; None when idle.
        self._active_phase: str | None = None

    def collect(
        self,
        *,
        # New canonical signature -------------------------------------------
        credentials: LDAPCredentials | None = None,
        scope: LDAPCollectionScope | None = None,
        # Legacy kwargs (deprecated — kept for backward compatibility) -----
        domain: str | None = None,
        dc_address: str | None = None,
        username: str | None = None,
        password: str | None = None,
        use_kerberos: bool | None = None,
        use_ldaps: bool = True,
        kerberos_target_hostname: str | None = None,
        auth_domain: str | None = None,
        auth_kdc: str | None = None,
        aes_key: str | None = None,
        ccache_path: str | None = None,
        collection_scope: str = "ctf",
        posture_sink: Optional["PostureSink"] = None,
        posture_snapshot: Optional["DomainPosture"] = None,
    ) -> CollectionResult:
        """Collect all AD objects for the domain and return a CollectionResult.

        Either provide ``credentials`` (preferred) or the legacy kwargs.
        ``scope`` defaults to :meth:`LDAPCollectionScope.full_authenticated`
        when omitted — every phase enabled, no caps.
        """
        if credentials is None:
            # Legacy path — translate the flat kwargs into a credentials
            # object via the appropriate factory. ``use_kerberos`` is the
            # discriminator: True → kerberos_*, False → password / hash.
            if not domain or not dc_address:
                raise ValueError(
                    "ADscanLDAPCollector.collect: pass either ``credentials`` "
                    "or both ``domain`` and ``dc_address``."
                )
            credentials = _legacy_kwargs_to_credentials(
                domain=domain,
                dc_address=dc_address,
                username=username,
                password=password,
                use_kerberos=bool(use_kerberos),
                use_ldaps=use_ldaps,
                kerberos_target_hostname=kerberos_target_hostname,
                auth_domain=auth_domain,
                auth_kdc=auth_kdc,
                aes_key=aes_key,
                ccache_path=ccache_path,
                posture_sink=posture_sink,
                posture_snapshot=posture_snapshot,
            )
        elif posture_sink is not None and credentials.posture_sink is None:
            # Caller passed both ``credentials`` AND ``posture_sink``: respect
            # the explicit sink by rebuilding the credentials with it. The
            # frozen dataclass forces this dance, but it stays cheap.
            import dataclasses as _dc

            credentials = _dc.replace(credentials, posture_sink=posture_sink)
        if posture_snapshot is not None and credentials.posture_snapshot is None:
            # Same dance for ``posture_snapshot``: honour the caller-provided
            # snapshot when ``credentials`` did not carry one.
            import dataclasses as _dc

            credentials = _dc.replace(credentials, posture_snapshot=posture_snapshot)
        if scope is None:
            scope = LDAPCollectionScope.full_authenticated()

        return self._collect_with(
            credentials=credentials,
            scope=scope,
            collection_scope_label=collection_scope,
        )

    def _collect_with(
        self,
        *,
        credentials: LDAPCredentials,
        scope: LDAPCollectionScope,
        collection_scope_label: str,
    ) -> CollectionResult:
        """Internal core — runs the seven phases gated by ``scope``."""
        config = credentials.to_transport_config(paged_size=scope.paged_size)
        # Normalise username (DOMAIN\user → user, user@dom → user) the same
        # way the legacy path did.
        if config.username:
            config = _replace_dataclass(config, username=_account_name(config.username))

        result = CollectionResult(
            domain=credentials.domain, collection_scope=collection_scope_label
        )
        print_info_debug(
            "[ldap-collector] starting "
            f"domain={mark_sensitive(credentials.domain, 'domain')} "
            f"dc={mark_sensitive(credentials.dc_ip, 'hostname')} "
            f"anon={credentials.is_anonymous} "
            f"acls={scope.acls} memberships={scope.group_memberships}"
        )
        self._active_scope = scope
        # Diagnostic breadcrumb (bracket-free). Records which sub-collection is
        # in flight so any 'Connection closed!' caught below (or in a per-phase
        # handler) can report the exact phase that died over the sealed channel.
        self._active_phase = None
        sealing_mechanism: object | None = None
        try:
            with ADscanLDAPConnection(config) as conn:
                acl_parser = ACLParser(domain=credentials.domain, connection=conn)
                if scope.domain_node:
                    self._active_phase = "domain_node"
                    self._collect_domain_node(conn, config, result, acl_parser)
                if scope.domain_policy:
                    self._active_phase = "domain_policy"
                    self._collect_domain_policy(conn, config, result)
                    self._collect_psos(conn, config, result)
                if scope.collects_objects:
                    self._active_phase = "objects_acls"
                    self._collect_objects(conn, config, result, acl_parser)
                    # Tombstoned (AD Recycle Bin) accounts: a deleted object with a
                    # writable ACE is a restore→foothold path neither this collector
                    # (it filters live objects) nor BloodHound surfaces. Reuses the
                    # SAME ACL parsing so a writable tombstone yields its real
                    # GenericWrite/GenericAll edge, with the node flagged tombstoned —
                    # the execution layer then restores it first (mirrors enable-first).
                    if scope.acls:
                        self._active_phase = "deleted_objects_acls"
                        self._collect_deleted_objects(conn, config, result, acl_parser)
                if scope.group_memberships:
                    self._active_phase = "group_memberships"
                    self._collect_group_memberships(conn, config, result)
                if scope.gpo_links:
                    self._active_phase = "gpo_links"
                    self._collect_gpo_links(conn, config, result)
                if scope.trusts:
                    self._active_phase = "trusts"
                    self._collect_trusts(conn, config, result)
                if scope.adcs:
                    self._active_phase = "adcs"
                    _adcs_t = time.monotonic()
                    self._collect_adcs(conn, credentials.domain, acl_parser, result)
                    result.adcs_elapsed = time.monotonic() - _adcs_t
                # Capture which confidentiality mechanism sealed the channel
                # BEFORE __exit__ resets it to None. Consumed by the operator
                # cleartext advisory (C.b) below.
                sealing_mechanism = conn.mechanism
        except Exception as exc:
            telemetry.capture_exception(exc)
            from adscan_internal.services.auth_error_classification import (
                is_unreachable_foreign_realm_error,
            )

            # A foreign/trust realm we cannot authenticate to (cross-forest
            # AES-only KDC, no shared trust key) is not a collector bug — it is
            # an out-of-reach domain. Surface ONE clean operator line (the
            # transport already collapsed the raw asn1/Kerberos traceback into a
            # typed ForeignRealmUnreachableError); everything else stays a debug
            # log so a default run is not noisy.
            if is_unreachable_foreign_realm_error(exc):
                print_warning(
                    "Skipped "
                    f"{mark_sensitive(credentials.domain, 'domain')}: not reachable "
                    "with the current credential (cross-realm Kerberos auth "
                    "unavailable)."
                )
            else:
                # Diagnostic (bracket-free). When the whole connection-scoped
                # block aborts, report which phase was in flight and the sealing
                # mechanism so a 'Connection closed!' here is attributable to the
                # sealed ACL/security-descriptor read rather than something else.
                print_info_debug(
                    "ldap-collector-seal: connection-scoped collection aborted "
                    f"phase={self._active_phase} "
                    f"sealing_mechanism={sealing_mechanism} "
                    f"nodes_so_far={len(result.nodes)} "
                    f"edges_so_far={len(result.edges)} "
                    f"error_type={type(exc).__name__}"
                )
                print_warning_debug(f"[ldap-collector] collection failed: {exc}")
        finally:
            self._active_scope = None
            self._active_phase = None
        self._maybe_advise_cleartext(credentials, config, sealing_mechanism)
        print_info_debug(
            "[ldap-collector] done "
            f"domain={mark_sensitive(credentials.domain, 'domain')} "
            f"nodes={len(result.nodes)} edges={len(result.edges)}"
        )
        return result

    @staticmethod
    def _maybe_advise_cleartext(
        credentials: LDAPCredentials,
        config: ADscanLDAPConfig,
        mechanism: object | None,
    ) -> None:
        """Surface the operator cleartext advisory for an authenticated enum read.

        Operator-only (C.b): when an AUTHENTICATED directory enumeration actually
        proceeded over a CLEARTEXT channel, the operator should know their traffic
        travelled in the clear and how to unblock a confidential channel. This is
        situational CLI output and NEVER records a technical finding.

        Gated so it never spams or fires on benign cases:

          * Only when the channel ended up CLEARTEXT.
          * Never for anonymous binds — cleartext is the expected, benign outcome
            there (anonymous rootDSE / unauth sweeps), not an operator concern.
          * Never for failure-eliciting probe contexts (``disable_self_heal``),
            which intentionally accept cleartext.
          * At most once per ``(domain, "ldap_enumeration")`` per run.
        """
        try:
            from adscan_internal.services.ldap_transport_service import (
                ConfidentialityMechanism,
            )

            if mechanism is not ConfidentialityMechanism.CLEARTEXT:
                return
            if credentials.is_anonymous:
                return
            if getattr(config, "disable_self_heal", False):
                return

            from adscan_internal.cli.ldap_confidentiality_advisory import (
                render_cleartext_ldap_advisory,
                should_advise_cleartext_once,
            )

            domain = credentials.domain or ""
            if not should_advise_cleartext_once(domain, "ldap_enumeration"):
                return
            render_cleartext_ldap_advisory(
                dc_ip=credentials.dc_ip,
                mechanism=mechanism,
                reason="LDAP enumeration / graph collection",
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(f"[ldap-collector] cleartext advisory skipped: {exc}")

    def _collect_domain_node(
        self,
        conn: ADscanLDAPConnection,
        config: ADscanLDAPConfig,
        result: CollectionResult,
        acl_parser: ACLParser,
    ) -> None:
        scope = self._active_scope
        want_acls = bool(scope and scope.acls)
        attributes = ["objectSid", "distinguishedName", "name"]
        if want_acls:
            attributes.append("nTSecurityDescriptor")
        try:
            conn.search(
                search_base=config.domain_dn,
                search_filter="(objectClass=domainDNS)",
                attributes=attributes,
                search_scope="BASE",
                controls=SD_FLAGS_DACL_CONTROL if want_acls else None,
            )
            entries = list(conn.entries)
            if not entries:
                return
            attrs = _attrs(entries[0])
            raw_sid = _first(attrs, "objectSid")
            sid = _decode_sid(raw_sid).upper() if raw_sid else config.domain.upper()
            node = CollectorNode(
                object_id=sid,
                kind="Domain",
                name=config.domain.upper(),
                domain=config.domain,
                distinguished_name=_first_str(attrs, "distinguishedName"),
                highvalue=True,
                properties={"domainsid": sid},
            )
            result.add_node(node)

            # Parse the Domain object DACL so the kill chain can terminate at
            # the Domain (DCSync via GetChanges/GetChangesAll, WriteDACL,
            # GenericAll, etc.). Without these edges every attack path stops
            # at a Tier-0 group instead of at domain compromise.
            if not want_acls:
                return
            sd_bytes = _raw_bytes(entries[0], "nTSecurityDescriptor")
            if not sd_bytes:
                print_warning_debug(
                    "[ldap-collector] domain node DACL not returned (insufficient rights or empty SD)"
                )
                return
            acl_edges = acl_parser.parse_sd(sd_bytes, node.object_id, node.kind)
            for edge in acl_edges:
                result.add_edge(edge)
            print_info_debug(
                f"[ldap-collector] domain node DACL parsed: {len(acl_edges)} edge(s) to Domain"
            )
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_warning_debug(f"[ldap-collector] _collect_domain_node failed: {exc}")

    def _collect_domain_policy(
        self,
        conn: ADscanLDAPConnection,
        config: ADscanLDAPConfig,
        result: CollectionResult,
    ) -> None:
        """Fetch domain password and account policy from the domain root object."""
        try:
            conn.search(
                search_base=config.domain_dn,
                search_filter="(objectClass=domainDNS)",
                attributes=[
                    "minPwdLength",
                    "lockoutThreshold",
                    "lockoutObservationWindow",
                    "maxPwdAge",
                    "pwdHistoryLength",
                    "pwdProperties",
                    "ms-DS-MachineAccountQuota",
                    # Per-attribute replication metadata — gives us the exact
                    # timestamp each password-policy attribute was last modified,
                    # which is far more precise than whenChanged (which includes
                    # any modification to the domain object, e.g. creationTime).
                    "msDS-ReplAttributeMetaData",
                ],
                search_scope="BASE",
            )
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_warning_debug(
                f"[ldap-collector] _collect_domain_policy failed: {exc}"
            )
            return

        entries = list(conn.entries)
        if not entries:
            return

        attrs = _attrs(entries[0])

        # NOTE: these mirror ``password_policy_compliance.ad_duration_to_days`` /
        # ``ad_duration_to_minutes`` but intentionally keep the local
        # "``0`` floors to ``0``" semantics that the offline DomainPolicy/PSO
        # models depend on (the canonical converter maps a sub-unit duration to
        # ``None``). TODO: unify once the collector models tolerate ``None`` for
        # zero-duration fields without changing audit output.
        def _100ns_to_days(raw: int | None) -> int | None:
            if not raw:
                return None
            return abs(raw) // (10_000_000 * 86_400)

        def _100ns_to_minutes(raw: int | None) -> int | None:
            if not raw:
                return None
            return abs(raw) // (10_000_000 * 60)

        repl_blobs = _values(attrs, "msDS-ReplAttributeMetaData")
        pwd_attrs = _parse_repl_attr_metadata(repl_blobs, _DDP_PWD_ATTRS)
        # Decode the ``pwdProperties`` bitmask: bit 0 (DOMAIN_PASSWORD_COMPLEX
        # = 0x1) controls whether the Default Domain Password Policy enforces
        # complexity ("must meet complexity requirements"). When the attribute
        # is unreadable / absent we record ``None`` so downstream consumers
        # can distinguish "not collected" from "explicitly disabled".
        pwd_props_raw = _int_attr(attrs, "pwdProperties")
        if pwd_props_raw is None:
            complexity_enabled: bool | None = None
        else:
            complexity_enabled = bool(pwd_props_raw & 0x1)
        result.domain_policy = DomainPolicy(
            min_pwd_length=_int_attr(attrs, "minPwdLength"),
            lockout_threshold=_int_attr(attrs, "lockoutThreshold"),
            lockout_window_minutes=_100ns_to_minutes(
                _int_attr(attrs, "lockoutObservationWindow")
            ),
            max_pwd_age_days=_100ns_to_days(_int_attr(attrs, "maxPwdAge")),
            pwd_history_length=_int_attr(attrs, "pwdHistoryLength"),
            machine_account_quota=_int_attr(attrs, "ms-DS-MachineAccountQuota"),
            complexity_enabled=complexity_enabled,
            pwd_attrs_when_changed=pwd_attrs,
            pwd_policy_last_changed=pwd_attrs[0][1] if pwd_attrs else None,
        )

    def _collect_psos(
        self,
        conn: ADscanLDAPConnection,
        config: ADscanLDAPConfig,
        result: CollectionResult,
    ) -> None:
        """Fetch fine-grained password policies (PSOs) from the Password Settings Container.

        PSOs override the Default Domain Password Policy for the principals
        listed in ``msDS-PSOAppliesTo``. They live under
        ``CN=Password Settings Container,CN=System,<domain_nc>`` — that
        container may be empty (no PSOs configured) or unreadable from a
        non-privileged bind. Both cases are non-fatal: we leave
        ``result.psos`` empty.
        """
        pso_container = f"CN=Password Settings Container,CN=System,{config.domain_dn}"
        try:
            conn.search(
                search_base=pso_container,
                search_filter="(objectClass=msDS-PasswordSettings)",
                attributes=[
                    "name",
                    "distinguishedName",
                    "msDS-PasswordSettingsPrecedence",
                    "msDS-MinimumPasswordLength",
                    "msDS-MaximumPasswordAge",
                    "msDS-MinimumPasswordAge",
                    "msDS-LockoutThreshold",
                    "msDS-LockoutObservationWindow",
                    "msDS-LockoutDuration",
                    "msDS-PasswordHistoryLength",
                    "msDS-PasswordComplexityEnabled",
                    "msDS-PasswordReversibleEncryptionEnabled",
                    "msDS-PSOAppliesTo",
                    "msDS-ReplAttributeMetaData",
                ],
                search_scope="SUBTREE",
            )
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_warning_debug(f"[ldap-collector] _collect_psos failed: {exc}")
            return

        entries = list(conn.entries)
        if not entries:
            return

        # NOTE: these mirror ``password_policy_compliance.ad_duration_to_days`` /
        # ``ad_duration_to_minutes`` but intentionally keep the local
        # "``0`` floors to ``0``" semantics that the offline DomainPolicy/PSO
        # models depend on (the canonical converter maps a sub-unit duration to
        # ``None``). TODO: unify once the collector models tolerate ``None`` for
        # zero-duration fields without changing audit output.
        def _100ns_to_days(raw: int | None) -> int | None:
            if not raw:
                return None
            return abs(raw) // (10_000_000 * 86_400)

        def _100ns_to_minutes(raw: int | None) -> int | None:
            if not raw:
                return None
            return abs(raw) // (10_000_000 * 60)

        def _bool_attr(attrs: dict, name: str) -> bool | None:
            val = _first(attrs, name)
            if val is None:
                return None
            if isinstance(val, bool):
                return val
            sval = str(val).strip().upper()
            if sval in {"TRUE", "1"}:
                return True
            if sval in {"FALSE", "0"}:
                return False
            return None

        for entry in entries:
            attrs = _attrs(entry)
            dn = _first_str(attrs, "distinguishedName")
            if not dn:
                continue
            applies_to = tuple(
                str(v).strip()
                for v in _values(attrs, "msDS-PSOAppliesTo")
                if str(v).strip()
            )
            pso_pwd_attrs = _parse_repl_attr_metadata(
                _values(attrs, "msDS-ReplAttributeMetaData"), _PSO_PWD_ATTRS
            )
            pso = PasswordSettingsObject(
                name=_first_str(attrs, "name"),
                distinguished_name=dn,
                precedence=_int_attr(attrs, "msDS-PasswordSettingsPrecedence"),
                min_pwd_length=_int_attr(attrs, "msDS-MinimumPasswordLength"),
                max_pwd_age_days=_100ns_to_days(
                    _int_attr(attrs, "msDS-MaximumPasswordAge")
                ),
                min_pwd_age_days=_100ns_to_days(
                    _int_attr(attrs, "msDS-MinimumPasswordAge")
                ),
                lockout_threshold=_int_attr(attrs, "msDS-LockoutThreshold"),
                lockout_observation_window_minutes=_100ns_to_minutes(
                    _int_attr(attrs, "msDS-LockoutObservationWindow")
                ),
                lockout_duration_minutes=_100ns_to_minutes(
                    _int_attr(attrs, "msDS-LockoutDuration")
                ),
                pwd_history_length=_int_attr(attrs, "msDS-PasswordHistoryLength"),
                complexity_enabled=_bool_attr(attrs, "msDS-PasswordComplexityEnabled"),
                reversible_encryption_enabled=_bool_attr(
                    attrs, "msDS-PasswordReversibleEncryptionEnabled"
                ),
                applies_to=applies_to,
                pwd_attrs_when_changed=pso_pwd_attrs,
                pwd_policy_last_changed=pso_pwd_attrs[0][1] if pso_pwd_attrs else None,
            )
            result.psos.append(pso)

    @staticmethod
    def _domain_sid_prefix(result: CollectionResult) -> str | None:
        """Return the domain SID string (e.g. ``S-1-5-21-X-Y-Z``) from the collected Domain node."""
        for node in result.nodes.values():
            if node.kind == "Domain":
                return node.object_id.upper()
        return None

    @staticmethod
    def _sid_in_domain(sid: str, domain_sid_prefix: str | None) -> bool:
        """Return True if *sid* belongs to the current domain.

        A SID belongs to the domain when it starts with the domain SID followed
        by ``-`` (i.e., it is a sub-RID of the domain SID).  Well-known built-in
        SIDs (S-1-5-32-* etc.) are considered local and therefore also in-domain
        so that they are not mis-classified as foreign principals.
        """
        if not domain_sid_prefix:
            return True  # cannot determine — assume local
        sid_upper = sid.upper()
        # Exact match (e.g. domain SID itself used as trustee — unusual but safe)
        if sid_upper == domain_sid_prefix:
            return True
        # Normal sub-RID: domain SID is a proper prefix followed by '-'
        if sid_upper.startswith(domain_sid_prefix + "-"):
            return True
        # Well-known non-domain SIDs (e.g. S-1-1-0, S-1-5-11, S-1-5-32-*)
        # that are not sub-RIDs of any domain are treated as local/built-in.
        return False

    def _collect_objects(
        self,
        conn: ADscanLDAPConnection,
        config: ADscanLDAPConfig,
        result: CollectionResult,
        acl_parser: ACLParser,
    ) -> None:
        scope = self._active_scope or LDAPCollectionScope.full_authenticated()
        # Skip the SD_FLAGS control entirely when ACL parsing is disabled —
        # this also avoids hitting hardened DCs with a control they would
        # reject from anonymous binds.
        ldap_filter = scope.object_class_filter()
        if not ldap_filter:
            return
        # Diagnostic (bracket-free marker; sizes/counts/mechanism only). This is
        # the paged search that reads nTSecurityDescriptor (ACL) blobs when
        # scope.acls is True — the large-binary read most likely to be cut by a
        # SASL sign/seal channel close. Logs which sub-collection is in flight,
        # the page size, whether the SD_FLAGS (ACL) control is attached, and the
        # confidentiality mechanism that sealed the channel.
        print_info_debug(
            "ldap-collector-seal: starting paged objects search "
            f"phase={self._active_phase} sub=objects acls={scope.acls} "
            f"paged_size={config.paged_size} "
            f"attrs={len(_COLLECT_ATTRS)} "
            f"sd_flags_control={bool(scope.acls)} "
            f"sealing_mechanism={getattr(conn, 'mechanism', None)}"
        )
        try:
            conn.search(
                search_base=config.domain_dn,
                search_filter=ldap_filter,
                attributes=_COLLECT_ATTRS,
                search_scope="SUBTREE",
                controls=SD_FLAGS_DACL_CONTROL if scope.acls else None,
            )
        except Exception as exc:
            telemetry.capture_exception(exc)
            # Diagnostic (bracket-free). When this fires with a 'Connection
            # closed!' exc on a sealed channel, cross-reference the badldap
            # 'ldap-conn-closed:' debug line (recv_buffer_pending / mid_response)
            # to tell a mid-response cut (large sealed nTSecurityDescriptor read)
            # apart from a clean post-message close. objects_received is how many
            # entries were already collected before the close.
            print_info_debug(
                "ldap-collector-seal: paged objects search ended with error "
                f"phase={self._active_phase} acls={scope.acls} "
                f"sealing_mechanism={getattr(conn, 'mechanism', None)} "
                f"objects_received={len(conn.entries)} "
                f"error_type={type(exc).__name__}"
            )
            print_warning_debug(
                f"[ldap-collector] _collect_objects search failed: {exc}"
            )
            return

        domain_sid_prefix = self._domain_sid_prefix(result)
        per_kind_caps: dict[str, int | None] = {
            "User": scope.max_users,
            "Group": scope.max_groups,
            "Computer": scope.max_computers,
        }
        per_kind_seen: dict[str, int] = {"User": 0, "Group": 0, "Computer": 0}

        for entry in conn.entries:
            try:
                node = _entry_to_node(entry, config.domain)
                if node:
                    cap = per_kind_caps.get(node.kind)
                    if cap is not None:
                        if per_kind_seen[node.kind] >= cap:
                            continue
                        per_kind_seen[node.kind] += 1
                    result.add_node(node)

                    # Parse ACL — skipped entirely when scope.acls is False so
                    # anonymous binds don't pay the cost of trying to parse
                    # absent / denied nTSecurityDescriptor reads.
                    sd_bytes = (
                        _raw_bytes(entry, "nTSecurityDescriptor")
                        if scope.acls
                        else None
                    )
                    if sd_bytes:
                        acl_edges = acl_parser.parse_sd(
                            sd_bytes, node.object_id, node.kind
                        )
                        for edge in acl_edges:
                            result.add_edge(edge)
                            # Register ACE trustees from foreign domains as FSP placeholders.
                            trustee_sid = edge.source_object_id.upper()
                            if not self._sid_in_domain(trustee_sid, domain_sid_prefix):
                                # Derive the foreign domain from the SID if we can; fall
                                # back to a generic sentinel so the orchestrator still
                                # creates a placeholder node.
                                result.add_fsp_placeholder(trustee_sid, "unknown")

                    # AllowedToDelegate edges
                    attrs = _attrs(entry)
                    for delegate_target in _str_values(
                        attrs, "msDS-AllowedToDelegateTo"
                    ):
                        result.add_edge(
                            CollectorEdge(
                                source_object_id=node.object_id,
                                target_object_id=delegate_target,
                                relation="AllowedToDelegate",
                                source="ldap",
                                method="msDS-AllowedToDelegateTo",
                            )
                        )

                    rbcd_sd_bytes = _raw_bytes(
                        entry, "msDS-AllowedToActOnBehalfOfOtherIdentity"
                    )
                    if rbcd_sd_bytes and node.kind == "Computer":
                        for edge in _parse_allowed_to_act_sd(
                            rbcd_sd_bytes,
                            target_object_id=node.object_id,
                        ):
                            result.add_edge(edge)
                            trustee_sid = edge.source_object_id.upper()
                            if not self._sid_in_domain(trustee_sid, domain_sid_prefix):
                                result.add_fsp_placeholder(trustee_sid, "unknown")

                    gmsa_membership_sd_bytes = _raw_bytes(
                        entry, "msDS-GroupMSAMembership"
                    )
                    if gmsa_membership_sd_bytes:
                        for edge in _parse_gmsa_membership_sd(
                            gmsa_membership_sd_bytes,
                            target_object_id=node.object_id,
                        ):
                            result.add_edge(edge)
                            trustee_sid = edge.source_object_id.upper()
                            if not self._sid_in_domain(trustee_sid, domain_sid_prefix):
                                result.add_fsp_placeholder(trustee_sid, "unknown")

                    # HasSIDHistory edges
                    for raw_sid in _values(attrs, "sIDHistory"):
                        hist_sid = _decode_sid(raw_sid).upper()
                        if hist_sid:
                            result.add_edge(
                                CollectorEdge(
                                    source_object_id=node.object_id,
                                    target_object_id=hist_sid,
                                    relation="HasSIDHistory",
                                    source="ldap",
                                    method="sIDHistory",
                                )
                            )
            except Exception as exc:
                telemetry.capture_exception(exc)
                print_info_debug(f"[ldap-collector] entry processing failed: {exc}")

    def _collect_deleted_objects(
        self,
        conn: ADscanLDAPConnection,
        config: ADscanLDAPConfig,
        result: CollectionResult,
        acl_parser: ACLParser,
    ) -> None:
        """Enumerate tombstoned accounts in CN=Deleted Objects (AD Recycle Bin).

        Searches with the Show Deleted Objects control so the DC returns deleted
        objects (a normal search never does), reusing the SAME ACL parsing as live
        objects: a writable ACE over a tombstone yields its real GenericWrite/
        GenericAll edge, with the target node flagged ``tombstoned`` so execution
        reanimates it first. Best-effort: never aborts the sweep.
        """
        from adscan_internal.services.ldap_transport_service import (
            build_show_deleted_controls,
        )

        try:
            conn.search(
                search_base=f"CN=Deleted Objects,{config.domain_dn}",
                search_filter="(&(isDeleted=TRUE)(objectClass=user))",
                attributes=[*_COLLECT_ATTRS, "msDS-LastKnownRDN", "lastKnownParent"],
                search_scope="SUBTREE",
                controls=build_show_deleted_controls(with_sd_flags=True),
            )
        except Exception as exc:  # noqa: BLE001 - never abort the sweep
            telemetry.capture_exception(exc)
            print_warning_debug(
                f"[ldap-collector] _collect_deleted_objects search failed: {exc}"
            )
            return

        domain_sid_prefix = self._domain_sid_prefix(result)
        for entry in conn.entries:
            try:
                node = _deleted_entry_to_node(entry, config.domain)
                if not node:
                    continue
                result.add_node(node)
                sd_bytes = _raw_bytes(entry, "nTSecurityDescriptor")
                if not sd_bytes:
                    continue
                for edge in acl_parser.parse_sd(sd_bytes, node.object_id, node.kind):
                    result.add_edge(edge)
                    trustee_sid = edge.source_object_id.upper()
                    if not self._sid_in_domain(trustee_sid, domain_sid_prefix):
                        result.add_fsp_placeholder(trustee_sid, "unknown")
            except Exception as exc:  # noqa: BLE001 - one bad tombstone is non-fatal
                telemetry.capture_exception(exc)
                print_info_debug(
                    f"[ldap-collector] deleted-entry processing failed: {exc}"
                )

    def _collect_group_memberships(
        self,
        conn: ADscanLDAPConnection,
        config: ADscanLDAPConfig,
        result: CollectionResult,
    ) -> None:
        try:
            conn.search(
                search_base=config.domain_dn,
                search_filter="(objectClass=group)",
                attributes=["objectSid", "distinguishedName", "member"],
                search_scope="SUBTREE",
            )
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_warning_debug(
                f"[ldap-collector] _collect_group_memberships search failed: {exc}"
            )
            return

        dn_to_id: dict[str, str] = {
            node.distinguished_name.upper(): object_id
            for object_id, node in result.nodes.items()
            if node.distinguished_name
        }

        for entry in conn.entries:
            try:
                attrs = _attrs(entry)
                raw_sid = _first(attrs, "objectSid")
                group_sid = _decode_sid(raw_sid).upper() if raw_sid else ""
                if not group_sid:
                    continue
                for member_dn in _str_values(attrs, "member"):
                    member_sid = dn_to_id.get(member_dn.upper())
                    if not member_sid:
                        continue
                    result.add_edge(
                        CollectorEdge(
                            source_object_id=member_sid,
                            target_object_id=group_sid,
                            relation="MemberOf",
                            source="ldap",
                            method="group.member",
                        )
                    )
            except Exception as exc:
                telemetry.capture_exception(exc)
                print_info_debug(
                    f"[ldap-collector] group membership entry failed: {exc}"
                )

    def _collect_gpo_links(
        self,
        conn: ADscanLDAPConnection,
        config: ADscanLDAPConfig,
        result: CollectionResult,
    ) -> None:
        try:
            conn.search(
                search_base=config.domain_dn,
                search_filter="(|(objectClass=organizationalUnit)(objectClass=domainDNS))",
                attributes=["objectGUID", "objectSid", "distinguishedName", "gPLink"],
                search_scope="SUBTREE",
            )
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_warning_debug(
                f"[ldap-collector] _collect_gpo_links search failed: {exc}"
            )
            return

        for entry in conn.entries:
            try:
                attrs = _attrs(entry)
                gp_link = _first_str(attrs, "gPLink")
                if not gp_link:
                    continue

                raw_guid = _first(attrs, "objectGUID")
                raw_sid = _first(attrs, "objectSid")
                container_id = (
                    _decode_sid(raw_sid).upper()
                    if raw_sid
                    else (_decode_guid(raw_guid).upper() if raw_guid else "")
                )
                if not container_id:
                    continue

                for gpo_guid in _GPO_LINK_RE.findall(gp_link):
                    gpo_node_id = gpo_guid.upper()
                    result.add_edge(
                        CollectorEdge(
                            source_object_id=gpo_node_id,
                            target_object_id=container_id,
                            relation="GPLink",
                            source="ldap",
                            method="gPLink",
                        )
                    )
            except Exception as exc:
                telemetry.capture_exception(exc)
                print_info_debug(f"[ldap-collector] gpo link entry failed: {exc}")

    def _collect_trusts(
        self,
        conn: ADscanLDAPConnection,
        config: ADscanLDAPConfig,
        result: CollectionResult,
    ) -> None:
        from adscan_internal.services.enumeration.trust_query import (
            query_trusted_domains,
        )

        try:
            entries = query_trusted_domains(conn, config.domain_dn)
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_warning_debug(f"[ldap-collector] _collect_trusts query failed: {exc}")
            return

        domain_sid = ""
        for node in result.nodes.values():
            if node.kind == "Domain" and node.domain.lower() == config.domain.lower():
                domain_sid = node.object_id
                break

        for entry in entries:
            try:
                if entry.direction not in ("Outbound", "Bidirectional"):
                    continue
                result.add_edge(
                    CollectorEdge(
                        source_object_id=domain_sid or config.domain.upper(),
                        target_object_id=entry.partner.upper(),
                        relation="TrustedBy",
                        source="ldap",
                        method="trustedDomain",
                        notes={
                            "trustDirection": entry.direction,
                            "trustType": entry.trust_type,
                            "trustAttributes": entry.trust_attributes,
                            "attributeFlags": list(entry.attribute_flags),
                            "partnerSid": entry.sid,
                        },
                    )
                )
            except Exception as exc:
                telemetry.capture_exception(exc)
                print_info_debug(f"[ldap-collector] trust entry failed: {exc}")

    def _collect_adcs(
        self,
        conn: ADscanLDAPConnection,
        domain: str,
        acl_parser: ACLParser,
        result: CollectionResult,
    ) -> None:
        """Run native ADCS collection and merge into ``result``.

        ADCS may be absent (lab without certificate services) or the caller
        may lack read on the configuration container. Any failure here must
        not break the broader LDAP collection.
        """
        try:
            from adscan_internal.services.collector.adcs_collector import (
                ADCSCollector,
            )

            adcs_result = ADCSCollector(
                connection=conn, domain=domain, acl_parser=acl_parser
            ).collect()
            for node in adcs_result.nodes.values():
                result.add_node(node)
            for edge in adcs_result.edges:
                result.add_edge(edge)
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_info_debug(f"[ldap-collector] ADCS collection skipped: {exc}")
