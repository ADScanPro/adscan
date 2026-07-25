"""BadSuccessor (Akamai 2025 dMSA) native check.

Pure LDAP. Two queries:

1. For each OU in the domain, parse ``nTSecurityDescriptor`` and check
   whether the authenticated principal (or any of its transitive
   groups) has ``Create-Child`` rights on the
   ``msDS-DelegatedManagedServiceAccount`` object class.
2. Enumerate existing dMSA objects (``objectClass=
   msDS-DelegatedManagedServiceAccount``) and check whether the
   authenticated principal has ``WriteDACL`` / ``WriteOwner`` / ``Owns``
   over them.

Either condition flags the domain as BadSuccessor-vulnerable.

The check is gated on the domain functional level: BadSuccessor only
applies to Server 2025+ DFLs (level 10). On older DFLs we return
:attr:`CVEStatus.NOT_APPLICABLE`.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from adscan_core import telemetry
from adscan_core.rich_output import print_error, print_info_verbose
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.cve_scanner.result import (
    CVEResult,
    CVEStatus,
    Evidence,
    Severity,
)
from adscan_core.rich_output import print_exception

if TYPE_CHECKING:  # pragma: no cover
    from adscan_internal.services.cve_scanner.runner import ScanContext, ScanTarget


CVE_ID = "ADSCAN-BADSUCCESSOR-2025"
AKA = "BadSuccessor"
CVSS_V3 = 9.0
CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"

# Server 2025 functional level — first level introducing dMSAs.
SERVER_2025_FUNCTIONAL_LEVEL = 10

# AD Rights bits used for the BadSuccessor classifier. Values from
# [MS-DTYP] 2.4.4.1 ACCESS_MASK and [MS-ADTS] 5.1.3.2.
_ADS_RIGHT_DS_CREATE_CHILD = 0x0001
_ADS_RIGHT_GENERIC_ALL = 0x10000000
_ADS_RIGHT_WRITE_DAC = 0x00040000
_ADS_RIGHT_WRITE_OWNER = 0x00080000

# objectClass schemaIDGUID for msDS-DelegatedManagedServiceAccount.
# Source: AD schema (Win Server 2025).
DMSA_SCHEMA_GUID = "0feb936f-47b3-49f2-9386-1dedc2c23765"


@dataclass(frozen=True)
class BadSuccessorOU:
    """OU on which the principal can create dMSAs."""

    dn: str
    granting_ace: str


@dataclass(frozen=True)
class BadSuccessorDmsa:
    """Existing dMSA the principal can take over."""

    dn: str
    granting_ace: str


@dataclass(frozen=True)
class BadSuccessorFindings:
    """Aggregate BadSuccessor classifier output."""

    functional_level: int | None
    applies: bool
    ous_with_create_child: tuple[BadSuccessorOU, ...]
    dmsas_with_takeover: tuple[BadSuccessorDmsa, ...]
    notes: tuple[str, ...] = ()

    @property
    def vulnerable(self) -> bool:
        return self.applies and (
            bool(self.ous_with_create_child) or bool(self.dmsas_with_takeover)
        )


def _ace_grants_create_child_for_dmsa(ace: Any) -> bool:
    """Return True if the ACE grants Create-Child of dMSA objects."""
    if ace["AceType"] != 0x05:  # ACCESS_ALLOWED_OBJECT_ACE_TYPE
        # Plain ACCESS_ALLOWED with GenericAll also covers it.
        if ace["AceType"] == 0x00:
            mask = ace["Ace"]["Mask"]["Mask"]
            return bool(mask & _ADS_RIGHT_GENERIC_ALL) or bool(
                mask & _ADS_RIGHT_DS_CREATE_CHILD
            )
        return False
    mask = ace["Ace"]["Mask"]["Mask"]
    if not (mask & _ADS_RIGHT_DS_CREATE_CHILD):
        return False
    try:
        obj_type = ace["Ace"]["ObjectType"]
    except (KeyError, TypeError):
        obj_type = b""
    if not obj_type:
        return True  # Create-Child for *any* class.
    try:
        guid_str = _bin_to_guid_str(bytes(obj_type))
    except Exception:  # noqa: BLE001
        return False
    return guid_str.lower() == DMSA_SCHEMA_GUID.lower()


def _ace_grants_takeover(ace: Any) -> str | None:
    """Return the granting-right name if the ACE allows dMSA takeover."""
    if ace["AceType"] not in (0x00, 0x05):
        return None
    mask = ace["Ace"]["Mask"]["Mask"]
    if mask & _ADS_RIGHT_GENERIC_ALL:
        return "GenericAll"
    if mask & _ADS_RIGHT_WRITE_DAC:
        return "WriteDACL"
    if mask & _ADS_RIGHT_WRITE_OWNER:
        return "WriteOwner"
    return None


def _bin_to_guid_str(data: bytes) -> str:
    """Render a Windows GUID from its little-endian binary form."""
    if len(data) != 16:
        raise ValueError(f"GUID must be 16 bytes, got {len(data)}")
    a = int.from_bytes(data[0:4], "little")
    b = int.from_bytes(data[4:6], "little")
    c = int.from_bytes(data[6:8], "little")
    d = data[8:10]
    e = data[10:16]
    return f"{a:08x}-{b:04x}-{c:04x}-{d.hex()}-{e.hex()}"


def evaluate_findings(
    *,
    functional_level: int | None,
    principal_sids: set[bytes],
    ou_security_descriptors: list[tuple[str, bytes]],
    dmsa_security_descriptors: list[tuple[str, bytes]],
) -> BadSuccessorFindings:
    """Pure-logic classifier — drives the L1 unit tests.

    Args:
        functional_level: Domain functional level. ``None`` = unknown.
        principal_sids: Authenticated principal + transitive group SIDs
            in their binary form (``LDAP_SID.getData()``).
        ou_security_descriptors: ``[(dn, raw_sd_bytes)]`` for every OU
            in the domain.
        dmsa_security_descriptors: ``[(dn, raw_sd_bytes)]`` for every
            existing dMSA.
    """
    if functional_level is not None and functional_level < SERVER_2025_FUNCTIONAL_LEVEL:
        return BadSuccessorFindings(
            functional_level=functional_level,
            applies=False,
            ous_with_create_child=(),
            dmsas_with_takeover=(),
            notes=(
                f"Domain functional level {functional_level} < "
                f"{SERVER_2025_FUNCTIONAL_LEVEL} (Server 2025) — dMSAs unsupported",
            ),
        )

    try:
        from impacket.ldap import ldaptypes  # noqa: WPS433
    except ImportError as exc:
        return BadSuccessorFindings(
            functional_level=functional_level,
            applies=False,
            ous_with_create_child=(),
            dmsas_with_takeover=(),
            notes=(f"impacket missing: {exc}",),
        )

    def _matches_principal(ace: Any) -> bool:
        ace_sid = ace["Ace"]["Sid"].getData()
        return ace_sid in principal_sids

    ou_hits: list[BadSuccessorOU] = []
    for ou_dn, sd_bytes in ou_security_descriptors:
        try:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
            sd.fromString(sd_bytes)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            continue
        for ace in sd["Dacl"]["Data"] if sd["Dacl"] else []:
            if not _matches_principal(ace):
                continue
            if _ace_grants_create_child_for_dmsa(ace):
                ou_hits.append(
                    BadSuccessorOU(
                        dn=ou_dn,
                        granting_ace=(
                            "Create-Child of msDS-DelegatedManagedServiceAccount"
                        ),
                    )
                )
                break

    dmsa_hits: list[BadSuccessorDmsa] = []
    for dmsa_dn, sd_bytes in dmsa_security_descriptors:
        try:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
            sd.fromString(sd_bytes)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            continue
        if sd["OwnerSid"] and sd["OwnerSid"].getData() in principal_sids:
            dmsa_hits.append(BadSuccessorDmsa(dn=dmsa_dn, granting_ace="Owns"))
            continue
        for ace in sd["Dacl"]["Data"] if sd["Dacl"] else []:
            if not _matches_principal(ace):
                continue
            granting = _ace_grants_takeover(ace)
            if granting is not None:
                dmsa_hits.append(BadSuccessorDmsa(dn=dmsa_dn, granting_ace=granting))
                break

    return BadSuccessorFindings(
        functional_level=functional_level,
        applies=True,
        ous_with_create_child=tuple(ou_hits),
        dmsas_with_takeover=tuple(dmsa_hits),
    )


class BadSuccessorCheck:
    """LDAP-only BadSuccessor (dMSA) detection."""

    cve_id: str = CVE_ID

    def __init__(self, *, ldap_connector: Any | None = None) -> None:
        self._ldap_connector = ldap_connector

    async def run(
        self,
        target: "ScanTarget",
        creds: Any | None,
        ctx: "ScanContext",
    ) -> list[CVEResult]:
        if not target.is_dc:
            return [
                _not_applicable(target.host, "BadSuccessor only applies via DC LDAP")
            ]
        if creds is None:
            return [_error(target.host, "BadSuccessor requires authenticated LDAP")]
        try:
            findings = await asyncio.to_thread(self._collect_sync, target, creds, ctx)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_error(f"[badsuccessor] LDAP collection failed: {exc}")
            return [_error(target.host, str(exc))]
        return [_result_from_findings(target.host, findings)]

    def _collect_sync(
        self, target: "ScanTarget", creds: Any, ctx: "ScanContext"
    ) -> BadSuccessorFindings:
        connector = self._ldap_connector or _default_ldap_connector
        domain = (
            getattr(creds, "target_domain", None)
            or ctx.domain
            or getattr(creds, "domain", None)
        )
        if not domain:
            raise RuntimeError(
                "BadSuccessor: target_domain not resolvable from creds/context"
            )
        print_info_verbose(
            f"[badsuccessor] reading dMSA posture via LDAP on "
            f"{mark_sensitive(target.host, 'host')}"
        )
        with connector(domain=domain, dc_ip=target.host, creds=creds) as conn:
            functional_level = _read_domain_functional_level(conn)
            principal_sids = _read_principal_sids(conn, creds)
            ou_sds = _read_ou_security_descriptors(conn)
            dmsa_sds = _read_dmsa_security_descriptors(conn)
        return evaluate_findings(
            functional_level=functional_level,
            principal_sids=principal_sids,
            ou_security_descriptors=ou_sds,
            dmsa_security_descriptors=dmsa_sds,
        )


def _read_domain_functional_level(conn: Any) -> int | None:
    """Return the domainFunctionality level if exposed."""
    try:
        # rootDSE attributes are only retrievable via a BASE-scope search;
        # the AD LDAP server rejects SUBTREE/ONELEVEL with
        # ERROR_DS_NON_BASE_SEARCH (the badldap default scope).
        conn.search(
            search_base="",
            search_filter="(objectClass=*)",
            attributes=["domainFunctionality"],
            search_scope="BASE",
        )
    except Exception:  # noqa: BLE001
        return None
    for entry in conn.entries or []:
        values = entry.entry_attributes_as_dict.get("domainFunctionality")
        if values:
            try:
                return int(values[0])
            except (TypeError, ValueError):
                return None
    return None


def _read_principal_sids(conn: Any, creds: Any) -> set[bytes]:
    """Return the principal's objectSid + tokenGroups (transitive groups).

    ``tokenGroups`` is a constructed AD attribute. The DC only computes it
    on a BASE-scope query against the user object itself; SUBTREE returns
    ERROR_DS_NON_BASE_SEARCH. We therefore split the read in two:

    1. SUBTREE search by ``sAMAccountName`` to discover the user DN and
       ``objectSid``.
    2. BASE search on that DN to retrieve ``tokenGroups`` (transitive
       group SIDs including domain-local membership).
    """
    username = getattr(creds, "username", None)
    if not username:
        return set()
    sam = username.split("@", 1)[0].split("\\")[-1]
    sids: set[bytes] = set()

    conn.search(
        search_base=conn.domain_dn,
        search_filter=f"(sAMAccountName={sam})",
        attributes=["objectSid", "distinguishedName"],
    )
    user_dn: str | None = None
    for entry in conn.entries or []:
        raw = entry.entry_raw_attributes
        for value in raw.get("objectSid") or []:
            if isinstance(value, bytes):
                sids.add(value)
        if user_dn is None:
            user_dn = str(getattr(entry, "dn", "")) or None

    if user_dn:
        try:
            conn.search(
                search_base=user_dn,
                search_filter="(objectClass=*)",
                attributes=["tokenGroups"],
                search_scope="BASE",
            )
        except Exception:  # noqa: BLE001
            return sids
        for entry in conn.entries or []:
            raw = entry.entry_raw_attributes
            for value in raw.get("tokenGroups") or []:
                if isinstance(value, bytes):
                    sids.add(value)
    return sids


def _read_ou_security_descriptors(conn: Any) -> list[tuple[str, bytes]]:
    conn.search(
        search_base=conn.domain_dn,
        search_filter="(objectClass=organizationalUnit)",
        attributes=["nTSecurityDescriptor", "distinguishedName"],
    )
    out: list[tuple[str, bytes]] = []
    for entry in conn.entries or []:
        raw = entry.entry_raw_attributes
        sd_values = raw.get("nTSecurityDescriptor") or []
        if not sd_values:
            continue
        sd_bytes = sd_values[0]
        if isinstance(sd_bytes, bytes):
            out.append((str(getattr(entry, "distinguishedName", "")) or "", sd_bytes))
    return out


def _read_dmsa_security_descriptors(conn: Any) -> list[tuple[str, bytes]]:
    conn.search(
        search_base=conn.domain_dn,
        search_filter="(objectClass=msDS-DelegatedManagedServiceAccount)",
        attributes=["nTSecurityDescriptor", "distinguishedName"],
    )
    out: list[tuple[str, bytes]] = []
    for entry in conn.entries or []:
        raw = entry.entry_raw_attributes
        sd_values = raw.get("nTSecurityDescriptor") or []
        if not sd_values:
            continue
        sd_bytes = sd_values[0]
        if isinstance(sd_bytes, bytes):
            out.append((str(getattr(entry, "distinguishedName", "")) or "", sd_bytes))
    return out


def _default_ldap_connector(*, domain: str, dc_ip: str, creds: Any) -> Any:
    from adscan_internal.services.ldap_transport_service import (
        ADscanLDAPConfig,
        ADscanLDAPConnection,
    )

    config = ADscanLDAPConfig(
        domain=domain,
        dc_ip=dc_ip,
        use_ldaps=True,
        use_kerberos=getattr(creds, "use_kerberos", True),
        username=getattr(creds, "username", None),
        # ADscanLDAPConfig has no nt_hash field — when only an NT hash is
        # available, pass it as password: _build_ldap_connection_url
        # detects 32-hex strings and selects the ntlm-nt / kerberos-rc4
        # auth scheme automatically (see ldap_transport_service._is_nt_hash).
        password=getattr(creds, "password", None) or getattr(creds, "nt_hash", None),
    )
    return ADscanLDAPConnection(config)


def _result_from_findings(host: str, findings: BadSuccessorFindings) -> CVEResult:
    base = dict(
        cve_id=CVE_ID,
        aka=AKA,
        host=host,
        cvss_v3=CVSS_V3,
        cvss_vector=CVSS_VECTOR,
        severity=Severity.from_cvss(CVSS_V3),
    )
    payload = {
        "functional_level": findings.functional_level,
        "applies": findings.applies,
        "ous_with_create_child": [
            {"dn": ou.dn, "granting_ace": ou.granting_ace}
            for ou in findings.ous_with_create_child
        ],
        "dmsas_with_takeover": [
            {"dn": d.dn, "granting_ace": d.granting_ace}
            for d in findings.dmsas_with_takeover
        ],
        "notes": list(findings.notes),
    }
    if not findings.applies:
        return CVEResult(
            **base,
            status=CVEStatus.NOT_APPLICABLE,
            evidence=Evidence(
                summary=(
                    "BadSuccessor not applicable — domain functional level below "
                    "Server 2025"
                ),
                payload=payload,
            ),
        )
    if findings.vulnerable:
        n_ou = len(findings.ous_with_create_child)
        n_dmsa = len(findings.dmsas_with_takeover)
        return CVEResult(
            **base,
            status=CVEStatus.VULNERABLE,
            evidence=Evidence(
                summary=(
                    f"BadSuccessor vulnerable: {n_ou} OU(s) with Create-Child + "
                    f"{n_dmsa} dMSA(s) with takeover ACL"
                ),
                payload=payload,
            ),
        )
    return CVEResult(
        **base,
        status=CVEStatus.NOT_VULNERABLE,
        evidence=Evidence(
            summary="No OU/dMSA grants BadSuccessor preconditions to the principal",
            payload=payload,
        ),
    )


def _not_applicable(host: str, reason: str) -> CVEResult:
    return CVEResult(
        cve_id=CVE_ID,
        aka=AKA,
        host=host,
        status=CVEStatus.NOT_APPLICABLE,
        severity=Severity.from_cvss(CVSS_V3),
        cvss_v3=CVSS_V3,
        cvss_vector=CVSS_VECTOR,
        evidence=Evidence(summary=reason, payload={"reason": reason}),
    )


def _error(host: str, message: str) -> CVEResult:
    return CVEResult(
        cve_id=CVE_ID,
        aka=AKA,
        host=host,
        status=CVEStatus.ERROR,
        severity=Severity.from_cvss(CVSS_V3),
        cvss_v3=CVSS_V3,
        cvss_vector=CVSS_VECTOR,
        error=message,
        evidence=Evidence(summary=f"BadSuccessor error: {message}", payload={}),
    )


__all__ = [
    "AKA",
    "BadSuccessorCheck",
    "BadSuccessorDmsa",
    "BadSuccessorFindings",
    "BadSuccessorOU",
    "CVE_ID",
    "CVSS_V3",
    "CVSS_VECTOR",
    "DMSA_SCHEMA_GUID",
    "SERVER_2025_FUNCTIONAL_LEVEL",
    "evaluate_findings",
]
