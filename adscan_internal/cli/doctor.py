"""``adscan doctor`` — fast one-shot PoV health check.

A pre-engagement smoke test: confirm the operator's environment can actually
reach and talk to the target before the real scan. It runs the key validations
and prints one scannable GREEN/RED matrix so the answer to "is everything
working?" is a single glance, not a scan log read in anger.

Checks (each reuses an existing service — nothing is reimplemented here):

* **Preflight** — the shared ``adscan check`` runtime preflight (tools, system
  packages, DNS configuration). Same gate ``start`` / ``ci`` run.
* **DNS resolution / Domain controller** — resolve the domain and locate its
  PDC via the shared ``DNSDiscoveryService`` discovery SSOT (the same path
  ``start_auth`` uses). When ``--dc-ip`` is given but is reachable yet NOT the
  PDC, the actual PDC is discovered and reported; the effective (corrected) DC
  IP flows into every downstream check. Never prompts, never loops.
* **DC connectivity** — TCP reachability of the DC's AD ports via
  ``assess_target_reachability`` (route + 53/88/389/445 probe).
* **Authentication** — when credentials are supplied, an ISOLATED lightweight
  LDAP bind against the DC (posture-aware, LDAPS->LDAP fallback). It does NOT
  route through ``add_credential`` — that triggers the full authenticated scan
  (native collector + ADCS + reachability sweep + attack-path build).
* **Enabled counts** — when authenticated, a lightweight PAGED LDAP query counts
  enabled users and enabled computers (NOT a graph build). PoV sizing inputs;
  emitted as informational ``"info"`` rows.
* **Trust relationships** — when authenticated, ONE direct
  ``(objectClass=trustedDomain)`` LDAP query lists the source domain's trust
  partners (no collector, no recursion). Informational ``"info"``.
* **Posture probe** — the centralized ``ensure_posture_fresh`` guard runs the
  lightweight posture PROBE (LDAP signing / CBT / LDAPS reachability) against the
  DC; it is a probe, never a collection.

Non-interactive-safe: defaults to an ephemeral temp workspace and never blocks
on a prompt. The exit code is ``0`` only when every applicable check passed
(``"skip"`` and ``"info"`` rows never fail the run). Pass ``--json`` to emit one
structured JSON object to stdout for the web backend instead of the human matrix.
"""

from __future__ import annotations

import os
import shutil
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from adscan_internal import (
    print_error,
    print_info,
    telemetry,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.graph_queries.inventories import (
    ENABLED_REAL_COMPUTERS_LDAP_FILTER,
    ENABLED_REAL_USERS_LDAP_FILTER,
)


# --------------------------------------------------------------------------- #
# Result model
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class DoctorCheck:
    """One health-check row.

    Attributes:
        name: Short check label shown in the matrix.
        status: ``"pass"``, ``"fail"``, ``"skip"``, or ``"info"``. ``"info"`` is
            an informational row (sizing/inventory data) that never fails the run.
        detail: One-line human-facing explanation.
        value: Optional numeric payload (e.g. an enabled-object count) for the
            structured ``--json`` machine contract. ``None`` for non-numeric rows.
        items: Optional string list payload (e.g. trusted-domain names) for the
            structured ``--json`` machine contract. ``None`` when not applicable.
    """

    name: str
    status: str
    detail: str = ""
    value: int | None = None
    items: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize one row to the structured machine contract."""
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "value": self.value,
            "items": list(self.items) if self.items is not None else None,
        }


@dataclass
class DoctorReport:
    """The aggregate result of a ``doctor`` run.

    ``on_check`` is an optional callback fired with each :class:`DoctorCheck` the
    instant it is appended. The streaming web preflight wires it to emit one
    ``doctor_check`` structured event per row so the platform matrix fills in
    live (DNS, then DC connectivity, then Authentication, …) instead of one batch
    at the end. It is a no-op for the plain CLI matrix path, so the human
    ``adscan doctor`` run is unaffected.
    """

    checks: list[DoctorCheck] = field(default_factory=list)
    on_check: Callable[[DoctorCheck], None] | None = None

    def add(
        self,
        name: str,
        status: str,
        detail: str = "",
        *,
        value: int | None = None,
        items: list[str] | None = None,
    ) -> None:
        """Append a check result and notify the streaming callback.

        Args:
            name: Short check label.
            status: ``"pass"`` / ``"fail"`` / ``"skip"`` / ``"info"``.
            detail: One-line human-facing explanation.
            value: Optional numeric payload (counts) for the JSON contract.
            items: Optional string-list payload (trust domains) for the JSON contract.
        """
        check = DoctorCheck(
            name=name, status=status, detail=detail, value=value, items=items
        )
        self.checks.append(check)
        # Stream this row live (web preflight); best-effort so a broken sink can
        # never break the check itself or the final report.
        if self.on_check is not None:
            try:
                self.on_check(check)
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)

    @property
    def passed(self) -> bool:
        """True when no applicable check failed.

        Only ``"fail"`` flips the run to unhealthy. ``"skip"`` (not applicable)
        and ``"info"`` (informational sizing/inventory data) never fail.
        """
        return all(c.status != "fail" for c in self.checks)

    @property
    def exit_code(self) -> int:
        """Process exit code: 0 when healthy, 1 when any check failed."""
        return 0 if self.passed else 1

    def to_dict(self, *, domain: str = "", dc_ip: str = "") -> dict[str, Any]:
        """Serialize the whole report to the structured machine contract.

        Single source of truth for the ``--json`` output the local web backend
        ingests. Counts and domain names stay as plain data (no telemetry path).
        """
        return {
            "domain": domain,
            "dc_ip": dc_ip,
            "passed": self.passed,
            "checks": [c.to_dict() for c in self.checks],
        }

    def to_json(self, *, domain: str = "", dc_ip: str = "") -> str:
        """Serialize the report to a single-line JSON string (the web contract)."""
        import json  # noqa: PLC0415

        return json.dumps(self.to_dict(domain=domain, dc_ip=dc_ip), ensure_ascii=False)


# --------------------------------------------------------------------------- #
# Config + dependency injection
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class DoctorConfig:
    """Parsed inputs for one ``adscan doctor`` invocation."""

    domain: Optional[str] = None
    dc_ip: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    workspace: Optional[str] = None
    interface: Optional[str] = None
    keep_workspace: bool = False
    requested_pro: bool = False
    json_output: bool = False


@dataclass(frozen=True)
class DoctorDeps:
    """Injected dependencies — keeps this module decoupled from ``adscan.py``."""

    build_preflight_args: Callable[[], object]
    handle_check: Callable[[object], bool]
    resolve_license_mode: Callable[[bool], object]
    create_shell: Callable[[object, object], object]
    console: object


# --------------------------------------------------------------------------- #
# Individual checks (each delegates to an existing service)
# --------------------------------------------------------------------------- #


def _check_preflight(report: DoctorReport, deps: DoctorDeps) -> None:
    """Runtime preflight — the shared ``adscan check`` gate."""
    try:
        ok = bool(deps.handle_check(deps.build_preflight_args()))
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        report.add("Runtime preflight", "fail", "Preflight raised an error.")
        return
    report.add(
        "Runtime preflight",
        "pass" if ok else "fail",
        "Tools, packages, and DNS configuration verified."
        if ok
        else "One or more prerequisites are missing — run `adscan check --fix`.",
    )


def _check_dns(report: DoctorReport, shell: Any, config: DoctorConfig) -> str:
    """Resolve the effective DC/PDC IP via the shared discovery SSOT.

    Mirrors ``start_auth``: this reuses :class:`DNSDiscoveryService` (through the
    non-interactive PDC preflight) instead of doctor's own fragile path. The
    rules, matching ``start_auth`` exactly:

    * ``--dc-ip`` given → run the **non-interactive** PDC preflight on it. If the
      entered IP is reachable but is NOT the PDC (or DNS can't resolve the
      domain), the service DISCOVERS the actual PDC and we use the discovered IP,
      recording a "Domain controller" correction row so the operator sees it.
    * ``--dc-ip`` omitted → drive ``find_pdc_with_selection`` against the system
      resolver to locate a PDC for the domain.
    * No DC can be located at all → a ``fail`` row; downstream checks then skip
      with a clear reason (no DC IP resolved).

    Never prompts and never loops: in doctor (always non-interactive) the
    preflight resolves to its best-effort answer and reports it. Returns the
    EFFECTIVE (possibly corrected) DC IP, or ``""`` when none could be located.
    """
    domain = (config.domain or "").strip()
    if not domain:
        report.add("DNS resolution", "skip", "No --domain provided.")
        return ""

    entered_ip = (config.dc_ip or "").strip()
    try:
        if entered_ip:
            effective_ip = _discover_pdc_from_entered_ip(
                report, shell, domain=domain, entered_ip=entered_ip
            )
        else:
            effective_ip = _discover_pdc_without_ip(report, shell, domain=domain)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        report.add("DNS resolution", "fail", f"DC discovery raised: {exc}")
        return ""
    return effective_ip


def _discover_pdc_from_entered_ip(
    report: DoctorReport, shell: Any, *, domain: str, entered_ip: str
) -> str:
    """Validate the entered DC IP and correct it to the real PDC if needed.

    Drives the SAME non-interactive PDC preflight ``start_auth`` uses. The
    preflight resolves the domain through the entered IP, probes its DC/KDC
    ports, and — when the entered IP is reachable but not the PDC — discovers
    the PDC and returns it. It never prompts.
    """
    from adscan_internal.cli.dns import (  # noqa: PLC0415
        preflight_domain_pdc_noninteractive,
        persist_pdc_preflight_result,
    )

    marked_domain = mark_sensitive(domain, "domain")
    decision = preflight_domain_pdc_noninteractive(
        shell, domain=domain, candidate_ip=entered_ip, mode_label="doctor"
    )
    pdc_ip = (getattr(decision, "pdc_ip", None) or "").strip()
    if decision.action != "use" or not pdc_ip:
        report.add(
            "DNS resolution",
            "fail",
            f"Could not resolve {marked_domain} or locate a domain controller "
            f"from {mark_sensitive(entered_ip, 'ip')}.",
        )
        return ""

    # Persist the (possibly corrected) PDC so the inventory/posture checks reuse
    # it via the canonical config builder, exactly as start_auth does.
    persist_pdc_preflight_result(shell, decision)
    # Ensure a recoverable DC FQDN is on record so the Kerberos SPN the authed
    # checks build is a real FQDN (not the IP). The preflight only persists a
    # hostname when it did the PDC SRV lookup; when the operator passes the
    # actual PDC IP it validates without that lookup, leaving no FQDN.
    _ensure_dc_fqdn(shell, domain, pdc_ip)

    report.add(
        "DNS resolution",
        "pass",
        f"Resolved {marked_domain} and located its domain controller(s).",
    )
    if pdc_ip != entered_ip:
        report.add(
            "Domain controller",
            "info",
            detail=(
                f"Located PDC at {mark_sensitive(pdc_ip, 'ip')} "
                f"(entered IP {mark_sensitive(entered_ip, 'ip')} was not the PDC)."
            ),
        )
    return pdc_ip


def _discover_pdc_without_ip(report: DoctorReport, shell: Any, *, domain: str) -> str:
    """Locate the PDC for ``domain`` via the system resolver (no --dc-ip given).

    Reuses ``DNSDiscoveryService.find_pdc_with_selection`` against the first
    configured nameserver — the same service start_auth threads through. When no
    PDC SRV answer is obtained (DNS not configured for the realm) a ``fail`` row
    is recorded and downstream checks skip with a clear reason.
    """
    marked_domain = mark_sensitive(domain, "domain")
    service = shell._get_dns_discovery_service()  # noqa: SLF001

    resolver_ip = ""
    try:
        nameservers = service._get_resolv_conf_nameservers(  # noqa: SLF001
            include_loopback=True
        )
        resolver_ip = next((ns for ns in (nameservers or []) if ns), "")
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)

    selected_ip = ""
    if resolver_ip:
        try:
            selected_ip, _hostname = service.find_pdc_with_selection(
                domain=domain, resolver_ip=resolver_ip
            )
            selected_ip = (selected_ip or "").strip()
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            selected_ip = ""

    if not selected_ip:
        report.add(
            "DNS resolution",
            "fail",
            f"Could not resolve {marked_domain} or locate a domain controller "
            "(no --dc-ip given and DNS did not return a PDC). "
            "Provide --dc-ip <reachable DC>.",
        )
        return ""

    # Seed the resolved PDC so the inventory/posture checks reuse it. Note:
    # ``shell.domains_data`` may be an empty (falsy) dict, so mutate it directly
    # — ``(shell.domains_data or {})`` would create and mutate a throwaway dict.
    try:
        if getattr(shell, "domains_data", None) is None:
            shell.domains_data = {}
        domain_data = shell.domains_data.setdefault(domain, {})
        domain_data.setdefault("pdc", selected_ip)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)

    # The SRV lookup above already returned a hostname (``_hostname``); still
    # route through the same helper so ``domains_data`` carries a recoverable
    # DC FQDN for the Kerberos SPN the authed checks build.
    _ensure_dc_fqdn(shell, domain, selected_ip)

    report.add(
        "DNS resolution",
        "pass",
        f"Resolved {marked_domain} and located PDC at {mark_sensitive(selected_ip, 'ip')}.",
    )
    return selected_ip


def _ensure_dc_fqdn(shell: Any, domain: str, pdc_ip: str) -> None:
    """Make sure ``domains_data[domain]`` carries a recoverable DC FQDN.

    ``419e78d4`` dropped the heavy ``add_credential`` -> ``do_enum_authenticated``
    collection from the auth check; that collection had a side effect the
    lightweight path lost — it resolved and persisted the DC hostname. Without it,
    when the operator passes the actual PDC IP, the preflight validates the IP
    WITHOUT the PDC SRV lookup, so no hostname is persisted and
    :func:`resolve_dc_fqdn` returns ``None`` — the LDAP Kerberos bind then has no
    FQDN for the service SPN and fails (and NTLM may be blocked).

    This restores ONLY the FQDN resolution side effect — one SRV/reverse-DNS
    lookup, never a collection. Steps:

    1. No-op when :func:`resolve_dc_fqdn` already yields an FQDN (never clobber a
       good one).
    2. Otherwise resolve a short hostname for ``pdc_ip`` via the sanctioned
       ``resolve_pdc_hostname_best_effort`` (PDC SRV target -> DC fingerprint ->
       PTR reverse lookup).
    3. Persist it as ``pdc_hostname`` (short is fine — ``resolve_dc_fqdn`` promotes
       ``<host>`` to ``<host>.<domain>``) or ``pdc_hostname_fqdn`` when already a
       full FQDN.

    Best-effort: if nothing resolves it leaves state clean and never raises — a DC
    with no resolvable FQDN and NTLM blocked genuinely cannot be Kerberos-bound,
    which the auth check then reports with its existing clear message.
    """
    domain = (domain or "").strip()
    pdc_ip = (pdc_ip or "").strip()
    if not (domain and pdc_ip):
        return
    try:
        from adscan_internal.models.domain import resolve_dc_fqdn  # noqa: PLC0415

        if getattr(shell, "domains_data", None) is None:
            shell.domains_data = {}
        domain_data = shell.domains_data.setdefault(domain, {})

        # 1. Already recoverable → don't clobber a good FQDN.
        if resolve_dc_fqdn(domain_data, target_domain=domain):
            return

        # 2. Resolve a hostname for the PDC IP via the sanctioned SSOT helper.
        from adscan_internal.cli.dns import (  # noqa: PLC0415
            resolve_pdc_hostname_best_effort,
        )
        from adscan_internal.services._kerberos_spn import is_ip_address  # noqa: PLC0415

        hostname = resolve_pdc_hostname_best_effort(
            shell, domain=domain, pdc_ip=pdc_ip
        )
        hostname = (hostname or "").strip().rstrip(".")
        # Never persist an IP as a hostname — that yields no real SPN FQDN.
        if not hostname or is_ip_address(hostname):
            return

        # 3. Persist so resolve_dc_fqdn recovers it on the next call. A full FQDN
        #    goes to ``pdc_hostname_fqdn``; a short label to ``pdc_hostname``
        #    (resolve_dc_fqdn promotes it to ``<host>.<domain>``).
        if "." in hostname:
            domain_data["pdc_hostname_fqdn"] = hostname
        else:
            domain_data["pdc_hostname"] = hostname
    except Exception as exc:  # noqa: BLE001 — best-effort; never crash doctor
        telemetry.capture_exception(exc)


def _check_connectivity(report: DoctorReport, shell: Any, dc_ip: str) -> None:
    """TCP reachability of the DC's AD ports (route + port probe)."""
    if not dc_ip:
        report.add("DC connectivity", "skip", "No DC IP resolved.")
        return
    try:
        from adscan_internal.services.network_preflight_service import (  # noqa: PLC0415
            assess_target_reachability,
        )

        # The shell satisfies the NetworkPreflightHost protocol (same call the
        # DNS preflight makes); pass it directly rather than reimplementing.
        assessment = assess_target_reachability(
            shell,
            target_ip=dc_ip,
            expected_interface=getattr(shell, "interface", None),
            tcp_ports=(53, 88, 389, 445),
            timeout_seconds=3.0,
        )
        open_ports = tuple(assessment.open_ports)
        if open_ports:
            report.add(
                "DC connectivity",
                "pass",
                f"{mark_sensitive(dc_ip, 'ip')} reachable on "
                f"{', '.join(str(p) for p in open_ports)}.",
            )
        else:
            report.add(
                "DC connectivity",
                "fail",
                f"No AD ports open on {mark_sensitive(dc_ip, 'ip')} "
                "(53/88/389/445 all closed or filtered).",
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        report.add("DC connectivity", "fail", f"Reachability probe raised: {exc}")


def _build_doctor_ldap_config(shell: Any, config: DoctorConfig, dc_ip: str) -> Any:
    """Build a posture-aware authed LDAP config for the doctor checks.

    Single source of truth for the authenticated LDAP transport doctor uses
    (the auth bind, the enabled counts, and the trust query). Reuses the
    sanctioned ``build_ldap_config_for_domain`` (LDAPS->LDAP fallback, posture
    aware, hardened-DC safe). Crucially this is an ISOLATED bind — it never
    routes through ``add_credential`` / ``do_enum_authenticated`` and so never
    triggers the native collector, ADCS discovery, the reachability sweep, or
    an attack-path build.
    """
    from adscan_internal.services.ldap_transport_service import (  # noqa: PLC0415
        build_ldap_config_for_domain,
    )
    from adscan_internal.services.domain_posture import (  # noqa: PLC0415  (best-effort)
        get_posture,
    )

    domain = (config.domain or "").strip()
    user = (config.username or "").strip()
    password = config.password or ""

    # Ensure the domain entry carries the resolved DC IP so the canonical config
    # builder finds it (DNS discovery seeds this; the explicit --dc-ip may not).
    domain_data = (shell.domains_data or {}).setdefault(domain, {})
    if dc_ip and not (domain_data.get("pdc") or domain_data.get("dc_ip")):
        domain_data["dc_ip"] = dc_ip

    try:
        posture_snapshot = get_posture(shell.domains_data, domain=domain)
    except Exception:  # noqa: BLE001 — posture is an optimization, never required
        posture_snapshot = None

    return build_ldap_config_for_domain(
        shell.domains_data,
        domain,
        username=user,
        password=password,
        use_ldaps=True,
        use_kerberos=True,
        posture_snapshot=posture_snapshot,
    )


def _check_auth(report: DoctorReport, shell: Any, config: DoctorConfig) -> bool:
    """Authentication — an ISOLATED, lightweight LDAP bind against the DC.

    A successful ``ADscanLDAPConnection`` ``__enter__`` IS the verification: it
    completes the auth (Kerberos TGT request or NTLM bind, posture-pruned via
    the auth-plan) without storing the credential and — deliberately — WITHOUT
    going through ``add_credential``, whose post-verify hook runs
    ``do_enum_authenticated`` (the full native collector + ADCS + reachability
    sweep + attack-path build). Doctor must stay a few-seconds preflight, so it
    binds directly here instead.

    Returns ``True`` only when the bind succeeded, so the downstream
    authenticated checks (enabled counts, trusts) know a bind is possible.
    """
    domain = (config.domain or "").strip()
    user = (config.username or "").strip()
    password = config.password or ""
    if not (domain and user and password):
        report.add(
            "Authentication",
            "skip",
            "No credentials supplied (-u/-p) — unauthenticated health check.",
        )
        return False
    dc_ip = ((shell.domains_data or {}).get(domain, {}) or {}).get("pdc") or (
        config.dc_ip or ""
    )
    if not dc_ip:
        report.add("Authentication", "skip", "No DC IP resolved.")
        return False
    try:
        from adscan_internal.services.ldap_transport_service import (  # noqa: PLC0415
            ADscanLDAPConnection,
        )

        ldap_cfg = _build_doctor_ldap_config(shell, config, str(dc_ip))
        # Opening the connection performs the bind; success == authenticated.
        with ADscanLDAPConnection(ldap_cfg):
            pass
        report.add(
            "Authentication",
            "pass",
            f"Bound as {mark_sensitive(user, 'user')}.",
        )
        return True
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        report.add(
            "Authentication",
            "fail",
            "Credential did not authenticate against the DC "
            f"({type(exc).__name__}).",
        )
        return False


# Enabled-account LDAP filters are the single source of truth in
# graph_queries/inventories.py (ENABLED_REAL_USERS_LDAP_FILTER /
# ENABLED_REAL_COMPUTERS_LDAP_FILTER) — the LDAP mirror of the scan's
# get_enabled_users()/get_enabled_computers() predicates. Doctor's raw paged
# COUNT issued here BEFORE any collection must read the SAME definition as the
# scan's Users/Computers inventory (gMSAs counted as users, trusts/machines
# excluded), so it imports the SSOT rather than re-declaring the filters.


def _count_enabled_objects(
    shell: Any, config: DoctorConfig, dc_ip: str, search_filter: str
) -> int:
    """Paged LDAP count of enabled objects matching ``search_filter``.

    Lightweight by design: requests a single minimal attribute and pages at 1000
    so a 2k+ object domain is counted without loading the graph. Reuses the
    sanctioned ``ADscanLDAPConnection`` transport (LDAPS->LDAP fallback, posture
    aware, hardened-DC safe) — never a graph build.
    """
    from adscan_internal.services.ldap_transport_service import (  # noqa: PLC0415
        ADscanLDAPConnection,
    )

    ldap_cfg = _build_doctor_ldap_config(shell, config, dc_ip)
    # Minimal attribute set + paging keep this a counting query, not a load.
    with ADscanLDAPConnection(ldap_cfg) as conn:
        conn.search(
            ldap_cfg.domain_dn,
            search_filter,
            attributes=["objectSid"],
            search_scope="SUBTREE",
            paged_size=1000,
        )
        return len(conn.entries)


def _check_enabled_counts(
    report: DoctorReport, shell: Any, config: DoctorConfig, dc_ip: str, *, authed: bool
) -> None:
    """Count ENABLED users + ENABLED computers via a lightweight paged LDAP query.

    These are PoV pricing/sizing inputs, so accuracy matters; emitted as
    ``"info"`` rows that never fail the run. Skipped (not failed) when there is
    no authenticated bind to issue the query from.
    """
    if not authed:
        report.add("Enabled users", "skip", "No authenticated LDAP bind available.")
        report.add("Enabled computers", "skip", "No authenticated LDAP bind available.")
        return
    if not dc_ip:
        report.add("Enabled users", "skip", "No DC IP resolved.")
        report.add("Enabled computers", "skip", "No DC IP resolved.")
        return

    for label, ldap_filter in (
        ("Enabled users", ENABLED_REAL_USERS_LDAP_FILTER),
        ("Enabled computers", ENABLED_REAL_COMPUTERS_LDAP_FILTER),
    ):
        try:
            count = _count_enabled_objects(shell, config, dc_ip, ldap_filter)
            report.add(label, "info", detail=str(count), value=count)
        except Exception as exc:  # noqa: BLE001 — best-effort; never crash doctor
            telemetry.capture_exception(exc)
            report.add(label, "skip", f"Count query failed: {exc}")


def _check_trusts(
    report: DoctorReport, shell: Any, config: DoctorConfig, dc_ip: str, *, authed: bool
) -> None:
    """List the source domain's trust partners via a single direct LDAP query.

    Doctor must stay a few-seconds preflight, so this issues ONE isolated
    ``(objectClass=trustedDomain)`` search under ``CN=System,<domain_dn>`` over
    the same sanctioned ``ADscanLDAPConnection`` the enabled-count check uses
    (``query_trusted_domains``, the trust-decoding SSOT). It deliberately does
    NOT call ``DomainService.enumerate_trusts`` — that runs the full recursive
    topology enumeration (native collector, ADCS, reachability sweep, SMB
    enrichment, the trust-enum live widget). Emitted as an ``"info"`` row.
    """
    if not authed:
        report.add("Trust relationships", "skip", "No authenticated LDAP bind available.")
        return
    if not dc_ip:
        report.add("Trust relationships", "skip", "No DC IP resolved.")
        return

    try:
        from adscan_internal.services.ldap_transport_service import (  # noqa: PLC0415
            ADscanLDAPConnection,
        )
        from adscan_internal.services.enumeration.trust_query import (  # noqa: PLC0415
            query_trusted_domains,
        )

        ldap_cfg = _build_doctor_ldap_config(shell, config, dc_ip)
        with ADscanLDAPConnection(ldap_cfg) as conn:
            entries = query_trusted_domains(conn, ldap_cfg.domain_dn)
        partners = sorted(
            {
                str(entry.partner).strip().lower()
                for entry in (entries or [])
                if str(getattr(entry, "partner", "") or "").strip()
            }
        )
        count = len(partners)
        if count:
            detail = f"{count} ({', '.join(partners)})"
        else:
            detail = "No trusts"
        report.add(
            "Trust relationships",
            "info",
            detail=detail,
            value=count,
            items=partners,
        )
    except Exception as exc:  # noqa: BLE001 — best-effort; never crash doctor
        telemetry.capture_exception(exc)
        report.add("Trust relationships", "skip", f"Trust enumeration failed: {exc}")


def _check_posture(
    report: DoctorReport, shell: Any, config: DoctorConfig, dc_ip: str
) -> None:
    """Posture probe — the centralized ``ensure_posture_fresh`` guard."""
    domain = (config.domain or "").strip()
    if not (domain and dc_ip):
        report.add("Posture probe", "skip", "No domain / DC IP to probe.")
        return
    try:
        import asyncio  # noqa: PLC0415

        from adscan_internal.services.posture_orchestration import (  # noqa: PLC0415
            ensure_posture_fresh,
        )
        from adscan_internal.services.posture_probe import (  # noqa: PLC0415
            ProbeCredentials,
            ProbePhase,
        )

        creds = None
        phase = ProbePhase.UNAUTH
        if config.username and config.password:
            creds = ProbeCredentials(
                username=str(config.username), password=str(config.password)
            )
            phase = ProbePhase.AUTH
        freshness = asyncio.run(
            ensure_posture_fresh(
                shell, domain=domain, dc_ip=dc_ip, creds=creds, phase=phase
            )
        )
        # ensure_posture_fresh never raises; a None/failed outcome is best-effort
        # and still a "reachable" answer unless it explicitly errored.
        error = getattr(freshness, "error", None)
        report.add(
            "Posture probe",
            "fail" if error else "pass",
            f"Probe error: {error}"
            if error
            else "DC reached; hardening posture recorded.",
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        report.add("Posture probe", "fail", f"Posture probe raised: {exc}")


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def render_doctor_report(report: DoctorReport, *, domain: str = "") -> None:
    """Render the scannable per-check pass/fail matrix panel."""
    from rich.table import Table  # noqa: PLC0415
    from rich import box as _box  # noqa: PLC0415
    from adscan_core.rich_output import print_panel  # noqa: PLC0415

    icons = {
        "pass": "[bold green]PASS[/]",
        "fail": "[bold red]FAIL[/]",
        "skip": "[dim]SKIP[/]",
        "info": "[bold cyan]INFO[/]",
    }

    table = Table(box=_box.SIMPLE_HEAD, expand=True, show_edge=False)
    table.add_column("", no_wrap=True, width=6)
    table.add_column("Check", style="bold", no_wrap=True)
    table.add_column("Detail")
    for check in report.checks:
        table.add_row(icons.get(check.status, "[dim]?[/]"), check.name, check.detail)

    healthy = report.passed
    border = "green" if healthy else "red"
    headline = (
        "All checks passed — the environment is ready."
        if healthy
        else "One or more checks failed — resolve the red rows before scanning."
    )
    subtitle = f"target: {mark_sensitive(domain, 'domain')}" if domain else None
    print_panel(
        table,
        title=f"ADscan Doctor · {'HEALTHY' if healthy else 'ISSUES FOUND'}",
        subtitle=subtitle,
        border_style=border,
    )
    (print_info if healthy else print_error)(headline)


def _make_check_emitter() -> Callable[[DoctorCheck], None]:
    """Build the per-check streaming callback for the ``--json`` web preflight.

    Returns a function that emits one structured ``doctor_check`` event the
    instant each row is appended, so the platform matrix fills in row-by-row
    (DNS, DC connectivity, Authentication, enabled counts, trusts, posture)
    instead of one batch at the end. The event payload is exactly
    :meth:`DoctorCheck.to_dict` — the single source of truth for the row shape
    shared with the final ``--json`` report. Emission is lightweight (no
    collection) and best-effort: a broken sink can never break the check.

    ``emit_event`` is itself a no-op unless ``ci_events._should_emit_events()``
    is true (the worker enables it via ``ADSCAN_EVENT_SINK=stderr-json`` +
    ``ADSCAN_SESSION_ENV=ci`` in the doctor subprocess env), so this stays inert
    on a hand-run ``adscan doctor --json`` and only the final JSON line prints.
    """
    from adscan_internal.cli.ci_events import emit_event  # noqa: PLC0415

    def _emit(check: DoctorCheck) -> None:
        emit_event("doctor_check", **check.to_dict())

    return _emit


def _emit_json(report: DoctorReport, *, domain: str = "", dc_ip: str = "") -> None:
    """Print exactly one JSON object to stdout — the web-backend machine contract.

    The human matrix is suppressed in this mode so stdout carries a single
    parseable line. This output is consumed by the local web backend on the same
    host (no telemetry path), so counts and domain names stay as plain data.
    """
    import sys  # noqa: PLC0415

    sys.stdout.write(report.to_json(domain=domain, dc_ip=dc_ip) + "\n")
    sys.stdout.flush()


def _maybe_emit_widget(report: DoctorReport, domain: str) -> None:
    """Best-effort: emit the shared matrix-panel widget for the web/recording.

    Reuses the existing widget contract (matrix-panel) so the web product can
    render the doctor matrix with zero new render code. Entirely optional —
    any failure is swallowed so it never affects the CLI result.
    """
    try:
        from adscan_internal.cli.widgets.widget_contract import (  # noqa: PLC0415
            MatrixPanelData,
            MatrixRow,
            MatrixSection,
            build_widget,
        )
        from adscan_internal.cli.widgets.widget_render import render_widget  # noqa: PLC0415

        tone = {"pass": "secure", "fail": "permissive", "skip": "unknown", "info": "neutral"}
        rows = [
            MatrixRow(
                label=c.name,
                state=c.status.upper(),
                state_tone=tone.get(c.status, "neutral"),
                detail=c.detail,
            )
            for c in report.checks
        ]
        widget = build_widget(
            "matrix-panel",
            key="doctor_health",
            title="ADscan Doctor",
            data=MatrixPanelData(sections=[MatrixSection(label="Health checks", rows=rows)]),
            domain=domain or None,
        )
        render_widget(widget.to_payload())
    except Exception:  # noqa: BLE001 — the widget is a bonus, never load-bearing
        pass


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def add_doctor_subparser(subparsers: Any) -> Any:
    """Register the ``doctor`` subparser. Shared by container + launcher."""
    import argparse  # noqa: PLC0415

    parser = subparsers.add_parser(
        "doctor",
        help="Fast one-shot health check (DNS, connectivity, auth, posture).",
        description=(
            "Run the key pre-engagement validations and print a GREEN/RED matrix "
            "so you can confirm the environment works before a scan.\n\n"
            "Examples:\n"
            "  adscan doctor -d corp.local --dc-ip 10.0.0.1\n"
            "  adscan doctor -d corp.local --dc-ip 10.0.0.1 -u alice -p Pass"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-d", "--domain", help="Target domain to validate.")
    parser.add_argument("--dc-ip", dest="dc_ip", help="PDC/DC IP for the target domain.")
    parser.add_argument("-u", "--username", help="Auth username (enables the auth check).")
    parser.add_argument("-p", "--password", help="Auth password or hash.")
    parser.add_argument(
        "-w", "--workspace",
        help="Named workspace to use (default: ephemeral temp, auto-cleaned).",
    )
    parser.add_argument("-i", "--interface", help="Network interface (myip auto-config).")
    parser.add_argument(
        "--keep-workspace",
        action="store_true",
        help="Keep an auto-created ephemeral workspace on exit.",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Emit one structured JSON object to stdout (machine-readable) "
        "instead of the human matrix.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output.")
    parser.add_argument("--debug", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--dev", action="store_true", help=argparse.SUPPRESS)
    return parser


def config_from_args(args: Any) -> DoctorConfig:
    """Build a :class:`DoctorConfig` from a parsed argparse namespace."""
    return DoctorConfig(
        domain=getattr(args, "domain", None),
        dc_ip=getattr(args, "dc_ip", None),
        username=getattr(args, "username", None),
        password=getattr(args, "password", None),
        workspace=getattr(args, "workspace", None),
        interface=getattr(args, "interface", None),
        keep_workspace=bool(getattr(args, "keep_workspace", False)),
        json_output=bool(getattr(args, "json_output", False)),
    )


def run_doctor(*, config: DoctorConfig, deps: DoctorDeps) -> int:
    """Run the doctor health check. Returns a process exit code."""
    # Non-interactive by construction.
    os.environ.setdefault("ADSCAN_SESSION_ENV", "ci")
    os.environ["ADSCAN_NONINTERACTIVE"] = "1"

    license_mode = deps.resolve_license_mode(config.requested_pro)
    shell = deps.create_shell(deps.console, license_mode)
    shell.session_command_type = "doctor"
    shell.auto = True
    shell.type = getattr(shell, "type", None) or "audit"
    if config.interface:
        shell.interface = config.interface

    shell.ensure_workspaces_dir()
    created = False
    if config.workspace:
        ws_dir = os.path.join(shell.workspaces_dir, config.workspace)
        os.makedirs(ws_dir, exist_ok=True)
        shell.current_workspace = config.workspace
        shell.current_workspace_dir = ws_dir
        shell.load_workspace_data(ws_dir)
    else:
        ws = f"doctor-{uuid.uuid4().hex[:6]}"
        ws_dir = os.path.join(shell.workspaces_dir, ws)
        os.makedirs(ws_dir, exist_ok=True)
        shell.current_workspace = ws
        shell.current_workspace_dir = ws_dir
        shell.load_workspace_data(ws_dir)
        created = True

    telemetry.capture("doctor_start", properties={"has_domain": bool(config.domain)})

    report = DoctorReport()
    # Stream each check live to the web preflight ONLY on the --json path. The
    # plain CLI human-matrix run leaves on_check None so it is unaffected. The
    # emitter is gated by ci_events._should_emit_events() (sink + ci session set
    # by the worker env), so a hand-run `adscan doctor --json` without that env
    # stays quiet and only prints the final JSON report.
    if config.json_output:
        report.on_check = _make_check_emitter()
    dc_ip = ""
    try:
        _check_preflight(report, deps)
        # _check_dns reuses the shared DNS/PDC discovery SSOT (the start_auth
        # path) and returns the EFFECTIVE (possibly PDC-corrected) DC IP. That
        # corrected IP flows into every downstream check so they probe the RIGHT
        # host — never the entered IP when it was not actually the PDC.
        dc_ip = _check_dns(report, shell, config)
        _check_connectivity(report, shell, dc_ip)
        authed = _check_auth(report, shell, config)
        # Probe the domain security posture BEFORE the LDAP inventory so the
        # enabled-count and trust queries below build their transport config
        # posture-aware (Kerberos vs NTLM, AES etypes, LDAP signing, channel
        # binding) instead of on an empty snapshot. ``ensure_posture_fresh`` is
        # idempotent, so running it here (rather than last) only changes WHEN the
        # snapshot is populated, making the doctor's own enumeration as robust on
        # a hardened DC as a full scan. The auth-plan still falls back on its own;
        # this just prunes impossible combos up front (fewer attempts, cleaner OPSEC).
        _check_posture(report, shell, config, dc_ip)
        # Authenticated, fast, no-graph inventory checks (PoV sizing + trusts) —
        # now consume the posture snapshot the probe above persisted.
        _check_enabled_counts(report, shell, config, dc_ip, authed=authed)
        _check_trusts(report, shell, config, dc_ip, authed=authed)
    finally:
        domain = (config.domain or "").strip()
        if config.json_output:
            _emit_json(report, domain=domain, dc_ip=dc_ip)
        else:
            render_doctor_report(report, domain=domain)
            _maybe_emit_widget(report, domain)
        if created and not config.keep_workspace:
            try:
                if shell.current_workspace_dir:
                    shutil.rmtree(shell.current_workspace_dir)
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
        try:
            shell.do_exit(exit=False)
        except Exception:  # noqa: BLE001
            pass

    return report.exit_code
