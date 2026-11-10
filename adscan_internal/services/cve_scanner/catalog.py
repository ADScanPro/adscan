"""Frozen registry of CVE definitions known to the native scanner.

Slice 1 only ships the five coercion-technique entries that are actually
wired up. Adding a new check is a two-step change: drop the
:class:`CVEDefinition` row here and add the check class.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from adscan_internal.services.cve_scanner.checks.base import CVECheck
from adscan_internal.services.cve_scanner.checks.coercion import CoercionCVECheck
from adscan_internal.services.cve_scanner.checks.badsuccessor import BadSuccessorCheck
from adscan_internal.services.cve_scanner.checks.drop_the_mic import DropTheMICCheck
from adscan_internal.services.cve_scanner.checks.drop_the_mic_2 import DropTheMIC2Check
from adscan_internal.services.cve_scanner.checks.ms17_010 import MS17_010Check
from adscan_internal.services.cve_scanner.checks.printerbug import (
    PrinterBugSurfaceCheck,
)
from adscan_internal.services.cve_scanner.checks.smbghost import SMBGhostCheck
from adscan_internal.services.cve_scanner.checks.webdav import WebDAVCheck
from adscan_internal.services.cve_scanner.checks.nopac import NoPacCheck
from adscan_internal.services.cve_scanner.checks.printnightmare import (
    PrintNightmareCheck,
)
from adscan_internal.services.cve_scanner.checks.zerologon import ZerologonCheck
from adscan_internal.services.cve_scanner.result import Severity
from adscan_internal.services.edge_kind import EdgeKind


class TargetScope(str, Enum):
    """Where a CVE check applies."""

    DCS_ONLY = "dcs_only"
    ALL_HOSTS = "all_hosts"
    DOMAIN_LDAP = "domain_ldap"


@dataclass(frozen=True)
class CVEDefinition:
    """Catalog entry for one CVE the native scanner knows how to check.

    ``required_ports`` declares the TCP port(s) the check's transport must
    reach on the target for the check to run at all. The runner preflights
    each ``(host, required_port)`` via the reachability SSOT before
    dispatching, so an unreachable host is recorded as a data gap rather
    than timing out on a full-check connect. A host is considered reachable
    for the check when ANY of the declared ports answers (e.g. a DC's LDAP
    check tries LDAPS 636 then LDAP 389 — either open satisfies the gate).

    The port is derived from the check's actual binding, NOT the ``aka``:

    - ``epm.hept_map`` → ``ncacn_ip_tcp`` (RPC endpoint mapper) → 135
    - ``kerberos_transport.get_tgt`` (AS-REQ) → 88
    - ``ncacn_np:...[\\PIPE\\...]`` / raw SMB / aiosmb / coercion pipes → 445
    - ``ADscanLDAPConfig`` (LDAPS→LDAP fallback) → 636, 389

    An empty tuple means "no reachability precondition" — the runner
    dispatches the check unconditionally (used by synthetic/test entries).

    ``detection_basis`` says how a VULNERABLE verdict was reached, and it is
    what ``severity`` follows (founder decision 2026-11-05, severity follows
    the source of certainty; ADscan never runs these exploits):

    - ``confirmed``: a non-disruptive probe got the definitive vulnerable
      answer and the flaw leads directly to a known compromise → CRITICAL.
    - ``confirmed_enabler``: a probe confirmed a flaw that only ENABLES a
      relay chain (the MIC CVEs) → HIGH; Critical belongs to a walked relay.
    - ``inferred``: the verdict reads patch level, a build number, a
      capability or a permission, not the flaw itself → HIGH.
    - ``None``: not a CVE check (coercion and surface checks are configuration
      conditions) and keeps its own band.

    Locked by ``tests/unit/services/cve_scanner/test_catalog_detection_basis.py``.
    """

    id: str
    aka: str
    cvss_v3: float
    cvss_vector: str
    severity: Severity
    target_scope: TargetScope
    requires_auth: bool
    affects_protocol: str
    references: tuple[str, ...]
    mitre_attack: tuple[str, ...]
    check_class: type[CVECheck]
    graph_edge_relation: str | None
    graph_edge_kind: EdgeKind | None
    promotes_to_domain_breaker: bool
    technique: str | None = None
    required_ports: tuple[int, ...] = ()
    detection_basis: str | None = None



#: The band each ``detection_basis`` implies (see :class:`CVEDefinition`).
SEVERITY_BY_DETECTION_BASIS: dict[str, Severity] = {
    "confirmed": Severity.CRITICAL,
    "confirmed_enabler": Severity.HIGH,
    "inferred": Severity.HIGH,
}

_PETITPOTAM_REFS = (
    "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942",
    "https://github.com/topotam/PetitPotam",
)
_PRINTERBUG_REFS = ("https://github.com/leechristensen/SpoolSample",)
_SHADOWCOERCE_REFS = ("https://github.com/ShutdownRepo/ShadowCoerce",)
_MSEVEN_REFS = ("https://github.com/Wh04m1001/MS-EVEN",)
_DFSCOERCE_REFS = ("https://github.com/Wh04m1001/DFSCoerce",)


CVE_CATALOG: tuple[CVEDefinition, ...] = (
    CVEDefinition(
        id="ADSCAN-COERCION-PETITPOTAM",
        aka="PetitPotam",
        # CVE-2021-36942. MSRC publishes 7.5 at PR:N in this C:H/I:N shape
        # (NIST scores the same 7.5 as C:N/I:H); the vector read PR:L, which
        # computes 6.5 and contradicted the number beside it.
        cvss_v3=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        severity=Severity.HIGH,
        target_scope=TargetScope.ALL_HOSTS,
        requires_auth=True,
        affects_protocol="MS-EFSR",
        references=_PETITPOTAM_REFS,
        mitre_attack=("T1187",),
        check_class=CoercionCVECheck,
        graph_edge_relation="CoercePetitPotam",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=False,
        technique="PetitPotam",
        # MS-EFSR over the SMB named pipe \PIPE\lsarpc / \PIPE\efsrpc.
        required_ports=(445,),
    ),
    CVEDefinition(
        id="ADSCAN-COERCION-PRINTERBUG",
        aka="PrinterBug",
        # ADscan's own grading, NOT a CVSS base score: no authority publishes
        # one (Microsoft treats this coercion primitive as by-design, so there
        # is no CVE). The vector describes the primitive itself and computes
        # 6.5; ADscan grades the exposure HIGH because its value to an attacker
        # is the NTLM relay chain it enables, which a Base score cannot express.
        # Allow-listed in tests/unit/services/cve_scanner/test_cvss_vector_agreement.py.
        cvss_v3=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        severity=Severity.HIGH,
        target_scope=TargetScope.ALL_HOSTS,
        requires_auth=True,
        affects_protocol="MS-RPRN",
        references=_PRINTERBUG_REFS,
        mitre_attack=("T1187",),
        check_class=CoercionCVECheck,
        graph_edge_relation="CoercePrinterBug",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=False,
        technique="PrinterBug",
        # MS-RPRN over the SMB named pipe \PIPE\spoolss.
        required_ports=(445,),
    ),
    CVEDefinition(
        id="ADSCAN-COERCION-DFSCOERCE",
        aka="DFSCoerce",
        # ADscan's own grading, NOT a CVSS base score: no authority publishes
        # one (Microsoft treats this coercion primitive as by-design, so there
        # is no CVE). The vector describes the primitive itself and computes
        # 6.5; ADscan grades the exposure HIGH because its value to an attacker
        # is the NTLM relay chain it enables, which a Base score cannot express.
        # Allow-listed in tests/unit/services/cve_scanner/test_cvss_vector_agreement.py.
        cvss_v3=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        severity=Severity.HIGH,
        target_scope=TargetScope.ALL_HOSTS,
        requires_auth=True,
        affects_protocol="MS-DFSNM",
        references=_DFSCOERCE_REFS,
        mitre_attack=("T1187",),
        check_class=CoercionCVECheck,
        graph_edge_relation="CoerceDFSCoerce",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=False,
        technique="DFSCoerce",
        # MS-DFSNM over the SMB named pipe \PIPE\netdfs.
        required_ports=(445,),
    ),
    CVEDefinition(
        id="ADSCAN-COERCION-SHADOWCOERCE",
        aka="ShadowCoerce",
        # Derived from the vector below; stays in the MEDIUM band.
        cvss_v3=5.4,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        severity=Severity.MEDIUM,
        target_scope=TargetScope.ALL_HOSTS,
        requires_auth=True,
        affects_protocol="MS-FSRVP",
        references=_SHADOWCOERCE_REFS,
        mitre_attack=("T1187",),
        check_class=CoercionCVECheck,
        graph_edge_relation="CoerceShadowCoerce",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=False,
        technique="ShadowCoerce",
        # MS-FSRVP over the SMB named pipe \PIPE\FssagentRpc.
        required_ports=(445,),
    ),
    CVEDefinition(
        id="ADSCAN-COERCION-MSEVENCOERCE",
        aka="MSEvenCoerce",
        # Derived from the vector below; stays in the MEDIUM band.
        cvss_v3=5.4,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        severity=Severity.MEDIUM,
        target_scope=TargetScope.ALL_HOSTS,
        requires_auth=True,
        affects_protocol="MS-EVEN",
        references=_MSEVEN_REFS,
        mitre_attack=("T1187",),
        check_class=CoercionCVECheck,
        graph_edge_relation="CoerceMSEvenCoerce",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=False,
        technique="MSEvenCoerce",
        # MS-EVEN over the SMB named pipe \PIPE\eventlog.
        required_ports=(445,),
    ),
    # ----- Slice 2: Pack DC ------------------------------------------------
    CVEDefinition(
        id="CVE-2020-1472",
        aka="Zerologon",
        cvss_v3=10.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        severity=Severity.CRITICAL,
        target_scope=TargetScope.DCS_ONLY,
        requires_auth=False,
        affects_protocol="MS-NRPC",
        references=(
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472",
            "https://www.secura.com/uploads/whitepapers/Zerologon.pdf",
        ),
        mitre_attack=("T1068", "T1210"),
        check_class=ZerologonCheck,
        graph_edge_relation="Zerologon",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=True,
        # MS-NRPC via epm.hept_map → ncacn_ip_tcp: the RPC endpoint mapper
        # (135) must be reachable; a closed 135 means the mapper — and the
        # dynamic NRPC endpoint it hands out — is unreachable.
        required_ports=(135,),
        detection_basis="confirmed",
    ),
    CVEDefinition(
        id="CVE-2021-42278",
        aka="NoPac",
        cvss_v3=8.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        severity=Severity.HIGH,
        target_scope=TargetScope.DCS_ONLY,
        requires_auth=True,
        affects_protocol="MS-NRPC/Kerberos",
        references=(
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287",
            "https://github.com/cube0x0/noPac",
        ),
        mitre_attack=("T1068",),
        check_class=NoPacCheck,
        graph_edge_relation="NoPac",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=True,
        # Primary probe is a Kerberos AS-REQ via kerberos_transport.get_tgt
        # (port 88); a closed 88 means the KDC is unreachable.
        required_ports=(88,),
        detection_basis="inferred",
    ),
    CVEDefinition(
        id="CVE-2021-34527",
        aka="PrintNightmare",
        # NVD (NIST) and MSRC both publish 8.8 at S:U; the vector read S:C,
        # which computes 9.9 and contradicted the number beside it.
        cvss_v3=8.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        severity=Severity.HIGH,
        target_scope=TargetScope.ALL_HOSTS,
        requires_auth=True,
        affects_protocol="MS-RPRN",
        references=(
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527",
            "https://github.com/calebstewart/CVE-2021-34527",
        ),
        mitre_attack=("T1068",),
        check_class=PrintNightmareCheck,
        graph_edge_relation="PrintNightmare",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=True,
        # MS-RPRN over ncacn_np:...[\PIPE\spoolss] with set_dport(445).
        required_ports=(445,),
        detection_basis="inferred",
    ),
    CVEDefinition(
        id="ADSCAN-BADSUCCESSOR-2025",
        aka="BadSuccessor",
        # Derived from the vector below; stays in the CRITICAL band. The
        # reported severity follows detection_basis, not this number.
        cvss_v3=9.9,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
        severity=Severity.HIGH,
        target_scope=TargetScope.DCS_ONLY,
        requires_auth=True,
        affects_protocol="LDAP",
        references=(
            "https://www.akamai.com/blog/security-research/abusing-dmsa-for-priv-esc-in-active-directory",
        ),
        mitre_attack=("T1078.002", "T1098.001"),
        check_class=BadSuccessorCheck,
        graph_edge_relation="BadSuccessor",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=True,
        # LDAP via ADscanLDAPConfig (LDAPS 636 tried first, LDAP 389
        # fallback) against the DC — either open satisfies the gate.
        required_ports=(636, 389),
        detection_basis="inferred",
    ),
    # ----- Slice 3: host-level CVEs and NTLM enablers --------------------
    CVEDefinition(
        id="CVE-2017-0144",
        aka="MS17-010",
        cvss_v3=8.1,
        cvss_vector="CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity=Severity.CRITICAL,
        target_scope=TargetScope.ALL_HOSTS,
        requires_auth=False,
        affects_protocol="SMBv1",
        references=(
            "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
            "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010",
        ),
        mitre_attack=("T1210",),
        check_class=MS17_010Check,
        graph_edge_relation="MS17-010",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=False,
        # Raw SMBv1 TCP connect to 445.
        required_ports=(445,),
        detection_basis="confirmed",
    ),
    CVEDefinition(
        id="CVE-2020-0796",
        aka="SMBGhost",
        # NVD (NIST, primary) publishes 10.0 at S:C; the vector read S:U,
        # which computes 9.8 and contradicted the number beside it.
        cvss_v3=10.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        severity=Severity.HIGH,
        target_scope=TargetScope.ALL_HOSTS,
        requires_auth=False,
        affects_protocol="SMB 3.1.1",
        references=(
            "https://nvd.nist.gov/vuln/detail/CVE-2020-0796",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0796",
        ),
        mitre_attack=("T1210",),
        check_class=SMBGhostCheck,
        graph_edge_relation="SMBGhost",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=False,
        # aiosmb SMB 3.1.1 NEGOTIATE to 445.
        required_ports=(445,),
        detection_basis="inferred",
    ),
    CVEDefinition(
        id="ADSCAN-PRINTERBUG-SURFACE",
        aka="PrinterBugSurface",
        # ADscan's own grading, NOT a CVSS base score: no authority publishes
        # one (Microsoft treats this coercion primitive as by-design, so there
        # is no CVE). The vector describes the primitive itself and computes
        # 6.5; ADscan grades the exposure HIGH because its value to an attacker
        # is the NTLM relay chain it enables, which a Base score cannot express.
        # Allow-listed in tests/unit/services/cve_scanner/test_cvss_vector_agreement.py.
        cvss_v3=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        severity=Severity.HIGH,
        target_scope=TargetScope.ALL_HOSTS,
        requires_auth=True,
        affects_protocol="MS-RPRN",
        references=(
            "https://github.com/leechristensen/SpoolSample",
            "https://posts.specterops.io/the-ghost-of-printer-past-87cd3a4f8ae3",
        ),
        mitre_attack=("T1187",),
        check_class=PrinterBugSurfaceCheck,
        graph_edge_relation="PrinterBugSurface",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=False,
        # MS-RPRN over ncacn_np:...[\PIPE\spoolss] with set_dport(445).
        required_ports=(445,),
    ),
    CVEDefinition(
        id="ADSCAN-WEBDAV-ENABLED",
        aka="WebDAVEnabled",
        # Derived from the vector below; stays in the MEDIUM band.
        cvss_v3=5.4,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        severity=Severity.MEDIUM,
        target_scope=TargetScope.ALL_HOSTS,
        requires_auth=True,
        affects_protocol="SMB / WebClient",
        references=(
            "https://www.thehacker.recipes/ad/movement/ntlm/relay#webdav",
            "https://github.com/Wh04m1001/WebDAVPocs",
        ),
        mitre_attack=("T1187",),
        check_class=WebDAVCheck,
        graph_edge_relation="WebDAVEnabled",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=False,
        # SMB via smb_machine_with_fallback (\PIPE\DAV RPC SERVICE probe).
        required_ports=(445,),
    ),
    CVEDefinition(
        # Drop the MIC 2: bypass of the CVE-2019-1040 fix through a duplicated
        # MsvAvFlags AV pair (Preempt, October 2019). No sign-in probe tells a
        # patched server from a vulnerable one (a patched 17763.1935 DC accepts
        # the duplicated layout), so the verdict reads the patch level: inferred.
        id="CVE-2019-1166",
        aka="DropTheMIC2",
        cvss_v3=5.9,
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
        severity=Severity.HIGH,
        target_scope=TargetScope.ALL_HOSTS,
        requires_auth=True,
        affects_protocol="NTLM",
        references=(
            "https://nvd.nist.gov/vuln/detail/CVE-2019-1166",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-1166",
            "https://www.crowdstrike.com/en-us/blog/active-directory-ntlm-attack-security-advisory/",
        ),
        mitre_attack=("T1557.001",),
        check_class=DropTheMIC2Check,
        graph_edge_relation="DropTheMIC2",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=False,
        # Build and UBR over Remote Registry (\PIPE\winreg) on 445.
        required_ports=(445,),
        detection_basis="inferred",
    ),
    CVEDefinition(
        # Drop the MIC: the server does not enforce the MIC that MsvAvFlags
        # announces (Preempt, June 2019).
        id="CVE-2019-1040",
        aka="DropTheMIC",
        # NVD (NIST) base score; the record publishes it as CVSS 3.0.
        cvss_v3=5.9,
        cvss_vector="CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
        severity=Severity.HIGH,
        target_scope=TargetScope.ALL_HOSTS,
        requires_auth=True,
        affects_protocol="NTLM",
        references=(
            "https://nvd.nist.gov/vuln/detail/CVE-2019-1040",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-1040",
            "https://www.crowdstrike.com/en-us/blog/from-the-archives-drop-the-mic-cve-2019-1040/",
        ),
        mitre_attack=("T1557.001",),
        check_class=DropTheMICCheck,
        graph_edge_relation="DropTheMIC",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=False,
        # NTLM SMB session setup without a MIC via impacket SMBConnection.
        required_ports=(445,),
        detection_basis="confirmed_enabler",
    ),
)


# ── Scan-policy declarations (docs/superpowers/specs/2026-11-04-scan-policy-
# checks-by-family-design.md § 4.4.3 and § 5) ───────────────────────────────
# Plain strings so the registry builder reads them without the check classes
# mattering. Every probe changes nothing (the phase contract is "read-only
# vulnerability detection, no exploitation"); what differs is how it touches the
# target. ``undeclared`` is kept where the code cannot settle the answer, which
# keeps the probe out of the ``safe_for_production`` built-in.
#
#   lockout_risk:
#     * ``not_applicable`` - an unauthenticated negotiate (MS17-010, SMBGhost) or
#       one authenticated call per host with the already-verified credential.
#     * ``bounded`` / ``failing_auth_budget`` - Drop the MIC (CVE-2019-1040)
#       sends an NTLM session setup without its MIC that a patched server
#       rejects. (Drop the MIC 2, CVE-2019-1166, sent one too until 13.2; it now
#       reads the patch level with the verified credential: ``not_applicable``.)
#       The earlier construction of these probes corrupted the user / workstation names and the DC counted each
#       rejection as a failed sign-in for the scan account (GOAD 2026-11-05:
#       event 4625, 0xC000006A, per probe). The current one sends the real
#       credential, so the rejection should come from the target's MIC check and
#       not from the DC; the guard stays until that is measured. Each
#       probe reserves one attempt from the account's real lockout headroom
#       (``failing_auth_budget``, spray-eligibility SSOT, keeping
#       ``FAILING_SIGN_IN_SAFETY_MARGIN`` spare) and is reported not assessed
#       when none is left. Founder decision 2026-11-05: bounded, so Audit runs
#       them and Production-sensitive (lockout-counting attempts excluded) does not.
#     * ``none`` - Zerologon sends authentication requests that cannot lock a
#       user account: it binds anonymously over MS-NRPC and authenticates as the
#       DC's OWN machine account with a zero credential (its ``note`` carries the
#       rationale and the measurement).
#   service_interference: ``transient`` for the probes that make the target
#   authenticate outward (coercion) or that exercise its print / WebDAV client.
#   event_ids: undeclared for every probe today (no audited source in the code);
#   tracked by the declaration baseline in tests/unit/scan_policy/.
#: The Windows events a probe itself leaves, per CVE-catalog id (the scan-policy
#: registry and the client coverage matrix read them). A coercion check calls an
#: RPC method over an SMB named pipe on each host and makes an exposed host open
#: a connection to the scanner: the scanner's network logon on that host (4624)
#: and the named-pipe access when detailed file-share auditing is on (5145).
CVE_EVENT_DECLARATIONS: dict[str, tuple[str, ...]] = {
    cve_id: ("4624", "5145")
    for cve_id in (
        "ADSCAN-COERCION-PETITPOTAM",
        "ADSCAN-COERCION-PRINTERBUG",
        "ADSCAN-COERCION-DFSCOERCE",
        "ADSCAN-COERCION-SHADOWCOERCE",
        "ADSCAN-COERCION-MSEVENCOERCE",
    )
}
CVE_EVENT_DECLARATIONS.update({
    # checks/nopac.py: two TGT requests for the scan account (with and without PAC).
    "CVE-2021-42278": ("4768",),
    # checks/printnightmare.py: one SMB session; lists the spoolss pipe on IPC$
    # and reads two registry keys over Remote Registry. Nothing is installed.
    "CVE-2021-34527": ("4624", "5145"),
    # checks/badsuccessor.py: LDAP reads of OU security descriptors and dMSA objects.
    "ADSCAN-BADSUCCESSOR-2025": ("4624", "4662"),
    # checks/printerbug.py: RPC bind to MS-RPRN on \\PIPE\\spoolss and RpcOpenPrinterEx.
    "ADSCAN-PRINTERBUG-SURFACE": ("4624", "5145"),
    # checks/webdav.py: named-pipe listing on IPC$ (DAV RPC SERVICE).
    "ADSCAN-WEBDAV-ENABLED": ("4624", "5145"),
    # checks/drop_the_mic_2.py: patch level read over Remote Registry, no sign-in probe.
    "CVE-2019-1166": ("4624", "5145"),
    # checks/drop_the_mic.py: one tampered sign-in per host; a patched host rejects
    # it and the domain controller can record the failed sign-in.
    "CVE-2019-1040": ("4625",),
})

CVE_POLICY_DECLARATIONS: dict[str, dict[str, str]] = {
    "ADSCAN-COERCION-PETITPOTAM": {"family": "coercion_relay", "lockout_risk": "not_applicable", "service_interference": "transient"},
    "ADSCAN-COERCION-PRINTERBUG": {"family": "coercion_relay", "lockout_risk": "not_applicable", "service_interference": "transient"},
    "ADSCAN-COERCION-DFSCOERCE": {"family": "coercion_relay", "lockout_risk": "not_applicable", "service_interference": "transient"},
    "ADSCAN-COERCION-SHADOWCOERCE": {"family": "coercion_relay", "lockout_risk": "not_applicable", "service_interference": "transient"},
    "ADSCAN-COERCION-MSEVENCOERCE": {"family": "coercion_relay", "lockout_risk": "not_applicable", "service_interference": "transient"},
    "ADSCAN-PRINTERBUG-SURFACE": {"family": "coercion_relay", "lockout_risk": "not_applicable", "service_interference": "none"},
    "ADSCAN-WEBDAV-ENABLED": {"family": "coercion_relay", "lockout_risk": "not_applicable", "service_interference": "none"},
    "CVE-2020-1472": {
        "family": "cve",
        "lockout_risk": "none",
        "service_interference": "none",
        # Founder decision 2026-11-04. Read by maintainers, not by the builder.
        "note": (
            "Unauthenticated: an anonymous MS-NRPC bind, then NetrServerAuthenticate3 "
            "for the DC's own machine account with an all-zero credential, so no user "
            "account is ever tried. GOAD 2026-11-04: after about 5,500 attempts, most "
            "answered ACCESS_DENIED, the DC account's badPwdCount and badPasswordTime "
            "stayed 0 under a domain lockout threshold of 5."
        ),
    },
    "CVE-2021-42278": {"family": "cve", "lockout_risk": "not_applicable", "service_interference": "none"},
    "CVE-2021-34527": {
        "family": "cve",
        "lockout_risk": "not_applicable",
        "service_interference": "none",
        # Founder decision 2026-11-06. Read by maintainers, not by the builder.
        "note": (
            "Read-only since 2026-11-06: lists the named pipes on IPC$ (spooler "
            "exposure) and reads two registry keys over Remote Registry (the Point "
            "and Print policy and the OS build and UBR). It no longer calls "
            "RpcAddPrinterDriverEx or any other print-spooler add or install function. "
            "When ADscan holds an administrator of the host (Domain Admin first, then "
            "the host's own local administrator material) the session uses it, and a "
            "host first left not assessed is re-read after the privileged collection "
            "(patch_level_rerun). Still reads only: no environment change; the sign-in "
            "is a verified credential behind the auth-attempt guard, so no lockout risk."
        ),
    },
    "ADSCAN-BADSUCCESSOR-2025": {"family": "cve", "lockout_risk": "not_applicable", "service_interference": "none"},
    "CVE-2017-0144": {"family": "cve", "lockout_risk": "not_applicable", "service_interference": "none"},
    "CVE-2020-0796": {"family": "cve", "lockout_risk": "not_applicable", "service_interference": "none"},
    "CVE-2019-1166": {
        "family": "cve",
        "lockout_risk": "not_applicable",
        "service_interference": "none",
        # Founder decision 2026-11-06. Read by maintainers, not by the builder.
        "note": (
            "Read-only: reads CurrentBuildNumber and UBR over Remote Registry with the "
            "verified credential and grades them against the October 2019 update. It "
            "sends no tampered sign-in: on a patched DC (17763.1935) the duplicated "
            "MsvAvFlags sign-in was accepted, so that probe could not discriminate. "
            "The read is shared with every patch-level check (one per host per run) "
            "and is made with an administrator of the host when ADscan holds one, "
            "including a re-read after the privileged collection (patch_level_rerun). "
            "Still reads only: no environment change, no lockout risk."
        ),
    },
    "CVE-2019-1040": {
        "family": "cve",
        "lockout_risk": "bounded",
        "lockout_guard": "failing_auth_budget",
        "service_interference": "none",
    },
}


def _validate_catalog_graph_relations() -> None:
    """Fail at import time if a catalog entry names a non-canonical edge.

    Every ``graph_edge_relation`` a catalog entry declares is inserted into the
    attack graph at scan time by ``insert_derived_edge``, which rejects any
    relation outside the canonical derived-edge allow-list. Validating the whole
    catalog against that same allow-list here turns a catalog misconfiguration
    into an import-time (build) error, so it is caught before a scan — never as a
    runtime ``ValueError`` in front of an operator, and never by dumping the
    internal allow-list to a client-facing terminal.
    """
    from adscan_internal.services.attack_graph_derived import (  # noqa: PLC0415
        ALLOWED_DERIVED_RELATIONS,
    )

    offenders = {
        cve.id: cve.graph_edge_relation
        for cve in CVE_CATALOG
        if cve.graph_edge_relation is not None
        and cve.graph_edge_relation not in ALLOWED_DERIVED_RELATIONS
    }
    if offenders:
        detail = ", ".join(
            f"{cid} -> {relation!r}" for cid, relation in sorted(offenders.items())
        )
        raise ValueError(
            "CVE catalog declares graph_edge_relation values that are not "
            f"canonical derived edges: {detail}. Add them to "
            "ALLOWED_DERIVED_RELATIONS in attack_graph_derived.py (and to "
            "edge_kind.py as EdgeKind.DERIVED) before shipping the catalog entry."
        )


def _validate_catalog_required_ports() -> None:
    """Fail at import time if a catalog entry declares no reachability port.

    Every shipped catalog entry authenticates against / connects to the
    target over a concrete transport, so it MUST declare the port(s) the
    runner preflights before dispatching (see ``CVEDefinition.required_ports``).
    A missing declaration would silently fall back to "no reachability
    precondition" and reintroduce the per-host timeout flood this gate
    exists to prevent. Turning the omission into a build error keeps the
    port map in lockstep with the catalog as new checks are added.
    """

    missing = [cve.id for cve in CVE_CATALOG if not cve.required_ports]
    if missing:
        raise ValueError(
            "CVE catalog entries declare no required_ports (the runner cannot "
            f"preflight their reachability): {', '.join(sorted(missing))}. Add "
            "required_ports=(<port>,) matching the check's transport binding "
            "(135 for epm/ncacn_ip_tcp, 88 for Kerberos, 445 for SMB/named "
            "pipes, 636/389 for LDAP)."
        )


_validate_catalog_graph_relations()
_validate_catalog_required_ports()


def _norm_domain(value: str | None) -> str:
    """Lowercase + strip a domain token for comparison."""

    return str(value or "").strip().rstrip(".").lower()


def credential_covers_domain(
    target_domain: str | None,
    cred_auth_domains: frozenset[str] | set[str] | tuple[str, ...] | None,
) -> bool:
    """Return whether the scan credential can authenticate to ``target_domain``.

    Conservative by design (Exposure-Validation doctrine): only returns
    ``False`` when we can POSITIVELY determine the target's domain is one the
    credential does not cover — i.e. both the target domain and the credential's
    covered-domain set are known AND the target is not among them. An unknown
    target domain, an unknown/empty credential set, or a match all return
    ``True`` so a legitimate target is never silently dropped.

    ADscan does not enumerate trust-based reachability here, so "covered" means
    the credential's own auth domain(s). A DC in a foreign forest the credential
    has no path to is the case this skips — the very ``SEC_E_LOGON_DENIED``
    class this gate exists to avoid.
    """

    tgt = _norm_domain(target_domain)
    if not tgt:
        return True
    covered = {_norm_domain(d) for d in (cred_auth_domains or ()) if _norm_domain(d)}
    if not covered:
        return True
    return tgt in covered


def scope_applies_to_target(
    scope: TargetScope,
    *,
    is_dc: bool,
    target_domain: str | None = None,
    cred_auth_domains: frozenset[str] | set[str] | tuple[str, ...] | None = None,
) -> bool:
    """Return whether a catalog ``scope`` runs against a target.

    This is the **single source of truth** for the scope→target gate.
    ``runner._applies`` delegates here so the live scheduler and any
    pre-scan display (e.g. the confirmation panel) can never disagree
    about which checks will actually execute.

    Semantics:

    - ``ALL_HOSTS`` runs against every target (DC or member host).
    - ``DCS_ONLY`` / ``DOMAIN_LDAP`` run only against domain controllers.
    - A domain controller whose domain the scan credential does not cover is
      skipped (cross-forest foreign DC) — see :func:`credential_covers_domain`.
      This is CONSERVATIVE: it only fires when the foreign domain is positively
      known; an indeterminate case still runs.

    Args:
        scope: The catalog entry's :class:`TargetScope`.
        is_dc: Whether the target is a domain controller.
        target_domain: The domain the target host belongs to (``None`` when
            undetermined). Used only for the cross-domain foreign-DC gate.
        cred_auth_domains: The domain(s) the scan credential can authenticate
            to (``None``/empty when unknown). Used only for the gate.

    Returns:
        ``True`` when a check with ``scope`` would run against the target.
    """

    if scope is TargetScope.ALL_HOSTS:
        return True
    if scope in (TargetScope.DCS_ONLY, TargetScope.DOMAIN_LDAP):
        if not is_dc:
            return False
        # DC-only checks bind to the target domain's DC. A DC in a domain the
        # credential cannot cover is a foreign forest — skip rather than attempt
        # a bind that returns SEC_E_LOGON_DENIED (cross-domain audit finding).
        return credential_covers_domain(target_domain, cred_auth_domains)
    return False


def cves_for_target(*, is_dc: bool) -> tuple[CVEDefinition, ...]:
    """Return the catalog entries that will run against a target type.

    Data-driven counterpart to the scheduler: pass ``is_dc=True`` for the
    "Domain Controllers only" scope (DC-scoped checks PLUS the all-hosts
    checks like coercion that also run against a DC), or ``is_dc=False``
    for a non-DC member host (all-hosts checks only). The result is the
    exact set the scan would execute, so any operator-facing list derived
    from it can never drift from reality.

    Args:
        is_dc: Whether the targeted host(s) are domain controllers.

    Returns:
        The applicable :class:`CVEDefinition` entries, in catalog order.
    """

    return tuple(
        cve
        for cve in CVE_CATALOG
        if scope_applies_to_target(cve.target_scope, is_dc=is_dc)
    )


def cve_akas_for_target(*, is_dc: bool) -> tuple[str, ...]:
    """Return the de-duplicated display labels (``aka``) for a target type.

    Convenience wrapper over :func:`cves_for_target` for building the
    operator-facing CVE list in the confirmation panel. Order follows the
    catalog; duplicates (none today, but cheap insurance) are dropped.

    Args:
        is_dc: Whether the targeted host(s) are domain controllers.

    Returns:
        The ordered, de-duplicated ``aka`` labels for the applicable checks.
    """

    seen: set[str] = set()
    out: list[str] = []
    for cve in cves_for_target(is_dc=is_dc):
        if cve.aka not in seen:
            seen.add(cve.aka)
            out.append(cve.aka)
    return tuple(out)


def _normalize_selector(value: str) -> str:
    """Lower-case and strip non-alphanumeric chars for fuzzy matching.

    Lets ``"printerbug-surface"``, ``"PrinterBugSurface"``, ``"printerbug surface"``
    all resolve to the same catalog entry.
    """

    return "".join(ch for ch in value.lower() if ch.isalnum())


_SHORT_ALIASES: dict[str, str] = {
    # Operator-friendly short selectors → canonical aka.
    "webdav": "WebDAVEnabled",
    "printerbug": "PrinterBugSurface",
    "printerbugsurface": "PrinterBugSurface",
    "dropthemic": "DropTheMIC",
    "dropthemic2": "DropTheMIC2",
    # Legacy selector: before 13.2 the CVE-2019-1040 check was mislabelled
    # "NTLMReflection". Kept so an operator's habit or script still resolves to
    # the same check id it always selected.
    "ntlmreflection": "DropTheMIC",
    "ms17010": "MS17-010",
}


def _index() -> dict[str, CVEDefinition]:
    """Build a case-insensitive, punctuation-insensitive id/aka index."""

    idx: dict[str, CVEDefinition] = {}
    for cve in CVE_CATALOG:
        idx[cve.id.lower()] = cve
        idx[cve.aka.lower()] = cve
        idx[_normalize_selector(cve.id)] = cve
        idx[_normalize_selector(cve.aka)] = cve
    by_aka = {cve.aka: cve for cve in CVE_CATALOG}
    for short, aka in _SHORT_ALIASES.items():
        if aka in by_aka:
            idx[short] = by_aka[aka]
    return idx


def resolve_cves(selectors: tuple[str, ...]) -> tuple[CVEDefinition, ...]:
    """Resolve CLI selectors (id or aka) to catalog entries.

    An empty ``selectors`` resolves to the full catalog. Unknown
    selectors raise ``KeyError`` listing the valid options.
    """

    if not selectors:
        return CVE_CATALOG
    idx = _index()
    out: list[CVEDefinition] = []
    seen: set[str] = set()
    for sel in selectors:
        key = sel.lower()
        if key not in idx:
            key = _normalize_selector(sel)
        if key not in idx:
            valid = sorted({cve.id for cve in CVE_CATALOG})
            raise KeyError(f"Unknown CVE selector {sel!r}. Known: {valid}")
        cve = idx[key]
        if cve.id not in seen:
            out.append(cve)
            seen.add(cve.id)
    return tuple(out)


__all__ = [
    "CVE_CATALOG",
    "CVEDefinition",
    "SEVERITY_BY_DETECTION_BASIS",
    "TargetScope",
    "cve_akas_for_target",
    "cves_for_target",
    "resolve_cves",
    "scope_applies_to_target",
]
