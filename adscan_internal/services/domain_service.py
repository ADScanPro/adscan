"""Domain service for domain-related operations.

This module provides services for domain enumeration, trust relationships,
and domain authentication operations.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
import logging
import subprocess
import time
from typing import Any, Dict, List, Optional

from adscan_core import telemetry
from adscan_core.rich_output import print_warning

from adscan_internal.services.base_service import BaseService
from adscan_internal.services.ldap_transport_service import (
    ADscanLDAPConfig,
    ADscanLDAPConnection,
)
from adscan_internal.services.domain_posture import DomainPosture
from adscan_internal.services.posture_sink import PostureSink
from adscan_internal.services.enumeration.trust_query import (
    TrustedDomainEntry,
    query_trusted_domains,
)
from adscan_internal.subprocess_env import get_clean_env_for_compilation


logger = logging.getLogger(__name__)


# Per-foreign-domain LDAP connect budget for trust BFS. A partner DC that is
# unreachable from our vantage, or a foreign/trust realm whose AES-only KDC the
# current credential cannot authenticate to, must NOT hang the trust phase for
# the kerbad/transport defaults (observed ~77-90s per dead domain in the field).
# 8s covers a legitimate LDAPS+bind round-trip even over VPN (≈2-3 RTT TLS + a
# bind at 300-500ms RTT; see adscan-ad-constraints § 7bis) while failing a dead
# realm fast. Bounds BOTH the Kerberos AS-REQ pre-mint and the LDAPS/LDAP
# connect inside ``ADscanLDAPConnection``.
_TRUST_FOREIGN_CONNECT_TIMEOUT_S: float = 8.0


@dataclass
class TrustRelationship:
    """Represents a domain trust relationship.

    Attributes:
        source_domain: Source domain name.
        target_domain: Target domain name.
        trust_type: Human label (Forest, External, Parent-Child, …).
        trust_direction: Direction (Inbound, Outbound, Bidirectional, Disabled).
        target_pdc: Target domain's PDC IP (if known).
        trust_attributes: Raw ``trustAttributes`` bitmask.
        attribute_flags: Decoded ``trustAttributes`` bit names.
        partner_sid: Partner domain SID when available.
    """

    source_domain: str
    target_domain: str
    trust_type: str = "Unknown"
    trust_direction: str = "Unknown"
    target_pdc: Optional[str] = None
    trust_attributes: int = 0
    attribute_flags: List[str] = field(default_factory=list)
    partner_sid: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_domain": self.source_domain,
            "target_domain": self.target_domain,
            "trust_type": self.trust_type,
            "trust_direction": self.trust_direction,
            "target_pdc": self.target_pdc,
            "trust_attributes": self.trust_attributes,
            "attribute_flags": list(self.attribute_flags),
            "partner_sid": self.partner_sid,
        }


@dataclass
class TrustEnumerationResult:
    """Structured output for recursive trust enumeration."""

    trusts: List[TrustRelationship]
    discovered_domains: List[str]
    domain_controllers: Dict[str, str]
    domain_connectivity: Dict[str, Dict[str, Any]]
    failed_domains: Dict[str, str] = field(default_factory=dict)
    per_domain_durations: Dict[str, float] = field(default_factory=dict)


class DomainService(BaseService):
    """Service for domain operations."""

    def enumerate_trusts(
        self,
        domain: str,
        pdc: str,
        username: str,
        password: str,
        *,
        auth_domain: Optional[str] = None,
        auth_kdc: Optional[str] = None,
        use_kerberos: bool = True,
        nt_hash: Optional[str] = None,
        aes_key: Optional[str] = None,
        dc_hostname: Optional[str] = None,
        resolve_dc_hostname: Optional[Callable[[str, str], Optional[str]]] = None,
        resolve_pdc_ip: Optional[Callable[[str, str], Optional[str]]] = None,
        check_domain_reachability: Optional[
            Callable[[str, str, str], Dict[str, Any]]
        ] = None,
        scan_id: Optional[str] = None,
        timeout: int = 60,
        progress_cb: Optional[Callable[[Any], None]] = None,
        posture_sink: Optional[PostureSink] = None,
        posture_snapshot: Optional[DomainPosture] = None,
        allowed_partner_domains: Optional[set] = None,
    ) -> TrustEnumerationResult:
        """Enumerate trusts recursively over native badldap.

        BFS expands across all reachable partner domains, opening a fresh
        LDAP connection per domain (with built-in LDAPS→LDAP fallback).

        When ``allowed_partner_domains`` is provided (lower-cased domain names),
        the BFS only expands INTO those partner domains — the source domain is
        always enumerated, and discovered trusts to non-listed partners are
        still recorded, but ADscan does not recurse into them. ``None`` (the
        default) enumerates every reachable partner, exactly as before.

        Args:
            domain: Source domain to enumerate.
            pdc: Source domain's PDC address.
            username: Authenticating user (lives in ``auth_domain``).
            password: Plaintext password (or NT hash if ``nt_hash`` is empty).
            auth_domain: Domain the credential belongs to. Defaults to ``domain``.
            auth_kdc: KDC for ``auth_domain``. Defaults to ``pdc``.
            use_kerberos: Bind with Kerberos when True.
            nt_hash: 32-hex NT hash (passed in lieu of password when set).
            aes_key: AES Kerberos key (32 or 64 hex chars).
            resolve_pdc_ip: Optional callback ``(partner, resolver_ip) -> ip``.
            check_domain_reachability: Optional reachability probe callback.
            scan_id: Optional scan id for progress events.
            timeout: Per-domain LDAP timeout (seconds). Reserved.
            progress_cb: Optional ``TrustEnumProgressEvent`` consumer.

        Returns:
            ``TrustEnumerationResult``.
        """
        from adscan_internal.cli.widgets.trust_enum_live import (
            TrustEnumProgressEvent,
        )

        normalized_domain = domain.strip().lower()
        effective_auth_domain = (auth_domain or normalized_domain).strip().lower()
        effective_auth_kdc = (auth_kdc or pdc).strip()

        pending_domains: list[str] = [normalized_domain]
        seen_domains: set[str] = set()
        discovered_domains: list[str] = [normalized_domain]
        domain_controllers: Dict[str, str] = {normalized_domain: pdc}
        domain_hostnames: Dict[str, str] = {}
        if dc_hostname:
            domain_hostnames[normalized_domain] = dc_hostname.strip()
        domain_connectivity: Dict[str, Dict[str, Any]] = {}
        trusts: List[TrustRelationship] = []
        failed_domains: Dict[str, str] = {}
        per_domain_durations: Dict[str, float] = {}

        def _emit(event: TrustEnumProgressEvent) -> None:
            if progress_cb is not None:
                try:
                    progress_cb(event)
                except Exception as cb_exc:  # noqa: BLE001
                    telemetry.capture_exception(cb_exc)

        # Pick the credential value badldap will receive.
        secret = nt_hash or password

        self._emit_progress(
            scan_id=scan_id,
            phase="trust_enumeration",
            progress=0.0,
            message=f"Starting trust enumeration for {normalized_domain}",
        )

        while pending_domains:
            current_domain = pending_domains.pop(0)
            if current_domain in seen_domains:
                continue
            current_pdc = domain_controllers.get(current_domain)
            if not current_pdc:
                seen_domains.add(current_domain)
                continue

            _emit(
                TrustEnumProgressEvent(
                    phase="connect",
                    current_domain=current_domain,
                    pdc=current_pdc,
                )
            )

            self._emit_progress(
                scan_id=scan_id,
                phase="trust_enumeration",
                progress=0.3,
                message=f"Enumerating trusts for {current_domain}",
            )

            entries: list[TrustedDomainEntry] = []
            t_start = time.monotonic()
            try:
                target_hostname = domain_hostnames.get(current_domain)
                ldap_cfg = ADscanLDAPConfig(
                    domain=current_domain,
                    dc_ip=current_pdc,
                    use_ldaps=True,
                    use_kerberos=use_kerberos,
                    username=username,
                    password=secret,
                    auth_domain=effective_auth_domain,
                    auth_kdc=effective_auth_kdc,
                    aes_key=aes_key,
                    kerberos_target_hostname=target_hostname,
                    posture_sink=posture_sink,
                    posture_snapshot=posture_snapshot,
                )
                _emit(
                    TrustEnumProgressEvent(
                        phase="querying",
                        current_domain=current_domain,
                        pdc=current_pdc,
                    )
                )
                with ADscanLDAPConnection(
                    ldap_cfg, connect_timeout=_TRUST_FOREIGN_CONNECT_TIMEOUT_S
                ) as conn:
                    entries = query_trusted_domains(conn, ldap_cfg.domain_dn)
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                err_text = self._summarize_ldap_error(exc)
                failed_domains[current_domain] = err_text
                duration_ms = (time.monotonic() - t_start) * 1000.0
                per_domain_durations[current_domain] = duration_ms
                seen_domains.add(current_domain)
                _emit(
                    TrustEnumProgressEvent(
                        phase="failed",
                        current_domain=current_domain,
                        pdc=current_pdc,
                        error=err_text,
                        duration_ms=duration_ms,
                    )
                )
                continue

            duration_ms = (time.monotonic() - t_start) * 1000.0
            per_domain_durations[current_domain] = duration_ms
            seen_domains.add(current_domain)

            for entry in entries:
                partner = entry.partner
                if not partner:
                    continue

                partner_pdc = domain_controllers.get(partner)
                if not partner_pdc and resolve_pdc_ip is not None:
                    try:
                        partner_pdc = resolve_pdc_ip(partner, current_pdc)
                    except Exception as rexc:  # noqa: BLE001
                        telemetry.capture_exception(rexc)
                        partner_pdc = None
                    if partner_pdc:
                        domain_controllers[partner] = partner_pdc

                if partner not in domain_hostnames and resolve_dc_hostname is not None:
                    try:
                        partner_host = resolve_dc_hostname(partner, current_pdc)
                    except Exception as hexc:  # noqa: BLE001
                        telemetry.capture_exception(hexc)
                        partner_host = None
                    if partner_host:
                        domain_hostnames[partner] = partner_host.strip()

                trusts.append(
                    TrustRelationship(
                        source_domain=current_domain,
                        target_domain=partner,
                        trust_type=entry.trust_type,
                        trust_direction=entry.direction,
                        target_pdc=partner_pdc,
                        trust_attributes=entry.trust_attributes,
                        attribute_flags=list(entry.attribute_flags),
                        partner_sid=entry.sid,
                    )
                )

                if partner not in discovered_domains:
                    discovered_domains.append(partner)

                _emit(
                    TrustEnumProgressEvent(
                        phase="partner_resolved",
                        current_domain=current_domain,
                        pdc=current_pdc,
                        partner=partner,
                    )
                )

                should_enqueue = True
                # Scope the BFS expansion to the configured partner allowlist
                # (trust_enumeration.policy == "selected"). The trust to this
                # partner is still recorded above; we just do not recurse into a
                # partner the operator did not select.
                if (
                    allowed_partner_domains is not None
                    and partner.strip().lower() not in allowed_partner_domains
                ):
                    should_enqueue = False
                if should_enqueue and partner_pdc and check_domain_reachability is not None:
                    try:
                        connectivity = check_domain_reachability(
                            partner, partner_pdc, current_domain
                        )
                    except Exception as cexc:  # noqa: BLE001
                        telemetry.capture_exception(cexc)
                        connectivity = {}
                    if connectivity:
                        domain_connectivity[partner] = connectivity
                        should_enqueue = bool(connectivity.get("reachable"))

                if (
                    should_enqueue
                    and partner not in seen_domains
                    and partner not in pending_domains
                ):
                    pending_domains.append(partner)

            _emit(
                TrustEnumProgressEvent(
                    phase="done",
                    current_domain=current_domain,
                    pdc=current_pdc,
                    duration_ms=duration_ms,
                    trust_count=len(entries),
                )
            )

        self._emit_progress(
            scan_id=scan_id,
            phase="trust_enumeration",
            progress=1.0,
            message=f"Trust enumeration completed: {len(trusts)} trust(s) found",
        )
        return TrustEnumerationResult(
            trusts=trusts,
            discovered_domains=discovered_domains,
            domain_controllers=domain_controllers,
            domain_connectivity=domain_connectivity,
            failed_domains=failed_domains,
            per_domain_durations=per_domain_durations,
        )

    @staticmethod
    def _summarize_ldap_error(exc: BaseException) -> str:
        """Compress an LDAP/Kerberos exception chain into one user line."""
        from adscan_internal.services.auth_error_classification import (
            is_unreachable_foreign_realm_error,
        )

        # A foreign/trust realm whose KDC the current credential cannot
        # authenticate against (cross-forest AES-only KDC, no shared trust key)
        # surfaces TWO cryptic ways from ONE root cause — a ``None`` Kerberos
        # ticket: the ``encoded_data must be a byte string, not NoneType`` asn1
        # ``TypeError`` and the ``KDC_ERR_ETYPE_NOTSUPP`` / preauth-failed
        # ``KerberosError``. Collapse both into one clean line (routed to the
        # summary's ``preauth`` remediation branch) instead of leaking the raw
        # asn1 message or a Kerberos traceback. There is no recovery here — the
        # realm is genuinely out of reach with this credential.
        if is_unreachable_foreign_realm_error(exc):
            return (
                "not reachable with the current credential "
                "(cross-realm Kerberos auth unavailable)"
            )
        # Fast-fail connect budget hit (dead partner DC / firewalled port). The
        # bounded ``ADscanLDAPConnection`` surfaces a bare ``TimeoutError`` whose
        # ``str()`` is empty, so key on the type before the text checks below.
        # (Py3.11+: asyncio.TimeoutError is an alias of the builtin TimeoutError.)
        if isinstance(exc, TimeoutError):
            return "timeout (partner DC unreachable from current vantage)"
        text = str(exc or "")
        lower = text.lower()
        if "signing" in lower or "strongerauth" in lower:
            return "LDAP signing required"
        if "channel binding" in lower:
            return "LDAP channel binding required"
        if (
            "preauth" in lower
            or "client not found" in lower
            or "decrypt integrity" in lower
        ):
            return "bind failed (credential rejected)"
        if "timeout" in lower or "timed out" in lower:
            return "timeout"
        if (
            "no route" in lower
            or "unreachable" in lower
            or "connection refused" in lower
        ):
            return "DC unreachable"
        if "kerberos" in lower or "krb_ap_err" in lower or "gssapi" in lower:
            # Surface the actual KDC error code so the operator can judge
            # recoverability (clock-skew vs unknown-SPN vs unsupported-etype vs
            # unreachable). ``KerberosError`` carries ``.errorcode`` whose
            # ``.name`` is the wire code (e.g. KDC_ERR_S_PRINCIPAL_UNKNOWN).
            errorcode = getattr(exc, "errorcode", None)
            code_name = getattr(errorcode, "name", None)
            if code_name:
                return f"Kerberos error: {code_name}"
            return f"Kerberos error: {type(exc).__name__}"
        # Compact fallback
        compact = text.strip().splitlines()[0] if text.strip() else type(exc).__name__
        return compact[:160]

    def verify_domain_connectivity(
        self,
        domain: str,
        pdc: str,
        scan_id: Optional[str] = None,
    ) -> bool:
        """Verify basic connectivity to domain via ICMP."""
        self._emit_progress(
            scan_id=scan_id,
            phase="domain_connectivity",
            progress=0.0,
            message=f"Checking connectivity to {domain}",
        )
        try:
            clean_env = get_clean_env_for_compilation()
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "2", pdc],
                capture_output=True,
                timeout=5,
                check=False,
                env=clean_env,
            )
            is_reachable = result.returncode == 0
            self._emit_progress(
                scan_id=scan_id,
                phase="domain_connectivity",
                progress=1.0,
                message=f"Domain {'reachable' if is_reachable else 'unreachable'}",
            )
            return is_reachable
        except (subprocess.TimeoutExpired, Exception) as e:  # noqa: BLE001
            telemetry.capture_exception(e)
            self._emit_progress(
                scan_id=scan_id,
                phase="domain_connectivity",
                progress=1.0,
                message="Connectivity check failed",
            )
            print_warning(f"Connectivity check failed: {e}")
            return False
