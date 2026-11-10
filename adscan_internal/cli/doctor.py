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
  ``assess_target_reachability`` (route + 53/88/389/445/636 probe).
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

* **Trusted domains (opt-in)** — ``--trusts all|selected`` repeats a lightweight
  subset of the above for each in-scope trust partner: locate its DC (the same
  cross-domain discovery the scan uses), probe the AD ports, authenticate with
  the SAME credential across the trust (auth domain = origin, target = trusted,
  Kerberos cross-realm) and count its enabled users/computers. Never recurses
  into the trusted domain's own trusts and never builds a graph. Default
  (``origin_only``) touches no other domain and is byte-identical to before.
  ``--trusts interactive`` asks which listed partners to validate (the scan's
  trust-scope prompt, over the remote-interaction bridge); with no operator to
  ask, or no answer in ``DOCTOR_DECISION_TIMEOUT_SECONDS``, it validates the
  origin only. Partners the operator declined are reported as such.

Non-interactive-safe: defaults to an ephemeral temp workspace and never blocks
on a prompt. Pass ``--json`` to emit one structured JSON object to stdout for the
web backend instead of the human matrix.

Exit-code contract (``DoctorReport.exit_code``):

* ``0`` — ready: every applicable check passed (``"skip"`` / ``"info"`` rows never
  fail the run) and every in-scope trusted domain validated.
* ``1`` — origin not ready: a runtime / origin-domain check failed.
* ``2`` — partial: the origin is ready but at least one in-scope trusted domain
  could not be reached or authenticated. The origin verdict is never turned red
  by a trusted domain; scripts that only care about the origin treat ``2`` as ok.
"""

from __future__ import annotations

import os
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
from adscan_core.rich_output import print_exception
from adscan_internal.services.scan_config import (
    TRUST_POLICY_ALL,
    TRUST_POLICY_INTERACTIVE,
    TRUST_POLICY_ORIGIN_ONLY,
    TRUST_POLICY_SELECTED,
)


# Trust-validation scopes doctor accepts: the scan's ``trust_enumeration.policy``
# vocabulary (scan_config.py) minus the ``skip`` alias. ``interactive`` is
# "decide during validation": after the origin's trust partners are listed the
# operator is asked which to validate, through the SAME remote-interaction bridge
# the scan's trust-scope prompt uses. Mirrored by the web schema and locked by
# tests/unit/test_cli_web_scan_config_contract.py.
DOCTOR_TRUST_SCOPES: tuple[str, ...] = (
    TRUST_POLICY_ORIGIN_ONLY,
    TRUST_POLICY_ALL,
    TRUST_POLICY_SELECTED,
    TRUST_POLICY_INTERACTIVE,
)

# How long the decision prompt waits for an answer before resolving to the
# origin only. A preflight must not hang for the scan prompt's one hour. The web
# worker exports it as ``ADSCAN_INTERACTIVE_TIMEOUT_SECONDS`` for the doctor
# process (the bridge reads its timeout from that variable) and sizes its own
# subprocess budget as the trust budget plus this window.
DOCTOR_DECISION_TIMEOUT_SECONDS = 180

# Resolutions of the decision prompt (``DoctorReport.decision``).
DECISION_ANSWERED = "answered"  # the operator chose (possibly the origin alone)
DECISION_TIMEOUT = "timeout"  # nobody answered in time: origin only
DECISION_AUTO = "auto"  # no operator channel (plain CLI / CI): origin only

# Hard ceiling on how many trusted domains ``--trusts all`` validates in one run.
# Each domain costs a DNS lookup, a port probe, a cross-realm bind and two paged
# counts, sequentially, so an unbounded forest would blow the preflight budget.
# Domains past the cap are reported "not validated" with the reason, never
# silently dropped.
MAX_TRUSTED_DOMAINS_VALIDATED = 16

ROLE_ORIGIN = "origin"
ROLE_TRUSTED = "trusted"

# Per-domain validation states in the report's ``domains`` block.
DOMAIN_STATE_READY = "ready"
DOMAIN_STATE_NOT_READY = "not_ready"
DOMAIN_STATE_NOT_VALIDATED = "not_validated"

VERDICT_READY = "ready"
VERDICT_PARTIAL = "partial"
VERDICT_NOT_READY = "not_ready"


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
        domain: The domain this row validates, or ``None`` for a runtime-level
            row (the preflight) that belongs to no domain.
        role: ``"origin"`` / ``"trusted"`` for a domain row, ``None`` otherwise.
            A row with ``role != "trusted"`` decides the origin verdict.
    """

    name: str
    status: str
    detail: str = ""
    value: int | None = None
    items: list[str] | None = None
    domain: str | None = None
    role: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize one row to the structured machine contract."""
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "value": self.value,
            "items": list(self.items) if self.items is not None else None,
            "domain": self.domain,
            "role": self.role,
        }


@dataclass(frozen=True)
class DomainValidation:
    """Validation outcome of one domain, for the report's ``domains`` block.

    Attributes:
        domain: Domain name.
        role: ``"origin"`` or ``"trusted"``.
        state: ``ready`` / ``not_ready`` / ``not_validated``. ``not_validated``
            means doctor deliberately did not look (outside the requested scope,
            over the cap, or the origin bind needed to reach it failed): its
            counts are unknown, not zero.
        dc_ip: The DC doctor located for the domain, when it did.
        enabled_users: Enabled user count, ``None`` when not measured.
        enabled_computers: Enabled computer count, ``None`` when not measured.
        reason: One-line human reason for any state other than ``ready``.
        trust_listed: For trusted domains, whether the origin lists it as a
            direct trust partner.
        declined: ``True`` only for a domain the operator was asked about and
            chose not to validate. Distinct from "outside the scope", which
            nobody decided.
    """

    domain: str
    role: str
    state: str
    dc_ip: str = ""
    enabled_users: int | None = None
    enabled_computers: int | None = None
    reason: str = ""
    trust_listed: bool | None = None
    declined: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize to the structured machine contract."""
        return {
            "domain": self.domain,
            "role": self.role,
            "state": self.state,
            "dc_ip": self.dc_ip,
            "enabled_users": self.enabled_users,
            "enabled_computers": self.enabled_computers,
            "reason": self.reason,
            "trust_listed": self.trust_listed,
            "declined": self.declined,
        }


@dataclass
class DoctorReport:
    """The aggregate result of a ``doctor`` run.

    ``on_check`` is an optional callback fired with each :class:`DoctorCheck` the
    instant it is appended. The streaming web preflight wires it to emit one
    ``doctor_check`` structured event per row so the platform matrix fills in
    live (DNS, then DC connectivity, then Authentication, ...) instead of one batch
    at the end. It is a no-op for the plain CLI matrix path, so the human
    ``adscan doctor`` run is unaffected.

    The multi-domain bookkeeping (``origin_domain``, ``scope_policy``, ...) is
    filled by :func:`run_doctor`; a bare report (unit tests, origin-only callers)
    leaves it empty and behaves exactly like the original single-domain report.
    """

    checks: list[DoctorCheck] = field(default_factory=list)
    on_check: Callable[[DoctorCheck], None] | None = None
    origin_domain: str = ""
    origin_dc_ip: str = ""
    scope_policy: str = TRUST_POLICY_ORIGIN_ONLY
    # Trust partners the origin lists (lower-cased), and the subset the operator
    # asked to validate. ``scope_domains`` is the REQUESTED scope after
    # resolution, before any cap or origin-auth gating.
    partners: list[str] = field(default_factory=list)
    scope_domains: list[str] = field(default_factory=list)
    # Per trusted domain: located DC ip and, for domains doctor decided not to
    # look at, the reason. Keys are lower-cased domain names.
    trusted_dc_ip: dict[str, str] = field(default_factory=dict)
    not_validated_reason: dict[str, str] = field(default_factory=dict)
    # Interactive scope: how the decision prompt resolved (DECISION_*), and the
    # partners the operator explicitly declined.
    decision: str | None = None
    declined_domains: list[str] = field(default_factory=list)
    # Per partner: {"direction", "type"} from the origin's trust listing, so the
    # decision prompt can draw the trust topology.
    partner_meta: dict[str, dict[str, str]] = field(default_factory=dict)

    def add(
        self,
        name: str,
        status: str,
        detail: str = "",
        *,
        value: int | None = None,
        items: list[str] | None = None,
        domain: str | None = None,
        role: str | None = None,
    ) -> None:
        """Append a check result and notify the streaming callback.

        Args:
            name: Short check label.
            status: ``"pass"`` / ``"fail"`` / ``"skip"`` / ``"info"``.
            detail: One-line human-facing explanation.
            value: Optional numeric payload (counts) for the JSON contract.
            items: Optional string-list payload (trust domains) for the JSON contract.
            domain: Domain the row belongs to (``None`` for runtime-level rows).
            role: ``"origin"`` / ``"trusted"`` for a domain row.
        """
        check = DoctorCheck(
            name=name,
            status=status,
            detail=detail,
            value=value,
            items=items,
            domain=domain,
            role=role,
        )
        self.checks.append(check)
        # Stream this row live (web preflight); best-effort so a broken sink can
        # never break the check itself or the final report.
        if self.on_check is not None:
            try:
                self.on_check(check)
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)

    def scoped(self, domain: str | None, role: str | None) -> "ScopedReport":
        """Return a view whose ``add`` stamps ``domain`` / ``role`` on every row.

        Lets the per-domain checks stay domain-agnostic: they call ``add`` as
        always and the view tags the row with the domain it validates.
        """
        return ScopedReport(self, domain, role)

    @property
    def origin_passed(self) -> bool:
        """True when no runtime / origin-domain check failed.

        Only ``"fail"`` flips a row red. ``"skip"`` (not applicable) and
        ``"info"`` (informational sizing/inventory data) never fail. Rows of a
        trusted domain are excluded: a trust partner that cannot be reached must
        never turn the origin verdict red.
        """
        return all(c.status != "fail" for c in self.checks if c.role != ROLE_TRUSTED)

    @property
    def passed(self) -> bool:
        """The origin verdict (kept as the gate the web scan form already uses)."""
        return self.origin_passed

    def domain_results(self) -> list[DomainValidation]:
        """Per-domain outcome: origin first, then every trust partner.

        Trusted domains doctor validated are ``ready`` / ``not_ready`` from their
        own rows; every listed partner it did not validate is ``not_validated``
        (counts unknown, not zero) so origin-only numbers are never read as
        forest-wide.
        """
        results: list[DomainValidation] = []
        origin = self.origin_domain
        if origin:
            rows = [c for c in self.checks if c.role == ROLE_ORIGIN]
            fail = next((c for c in rows if c.status == "fail"), None)
            ok = self.origin_passed
            results.append(
                DomainValidation(
                    domain=origin,
                    role=ROLE_ORIGIN,
                    state=DOMAIN_STATE_READY if ok else DOMAIN_STATE_NOT_READY,
                    dc_ip=self.origin_dc_ip,
                    enabled_users=_row_value(rows, "Enabled users"),
                    enabled_computers=_row_value(rows, "Enabled computers"),
                    reason="" if ok else (fail.detail if fail else ""),
                )
            )
        listed = {p.lower() for p in self.partners}
        seen: set[str] = set()
        for name in [*self.scope_domains, *self.partners]:
            key = name.strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            rows = [
                c
                for c in self.checks
                if c.role == ROLE_TRUSTED and (c.domain or "").lower() == key
            ]
            if not rows:
                results.append(
                    DomainValidation(
                        domain=key,
                        role=ROLE_TRUSTED,
                        state=DOMAIN_STATE_NOT_VALIDATED,
                        reason=self.not_validated_reason.get(
                            key, "Outside the validation scope."
                        ),
                        trust_listed=key in listed,
                        declined=key in self.declined_domains,
                    )
                )
                continue
            auth = next((c for c in rows if c.name == "Authentication"), None)
            fail = next((c for c in rows if c.status == "fail"), None)
            blocked = fail or next((c for c in rows if c.status == "skip"), None)
            ready = fail is None and auth is not None and auth.status == "pass"
            results.append(
                DomainValidation(
                    domain=key,
                    role=ROLE_TRUSTED,
                    state=DOMAIN_STATE_READY if ready else DOMAIN_STATE_NOT_READY,
                    dc_ip=self.trusted_dc_ip.get(key, ""),
                    enabled_users=_row_value(rows, "Enabled users"),
                    enabled_computers=_row_value(rows, "Enabled computers"),
                    reason="" if ready else (blocked.detail if blocked else ""),
                    trust_listed=key in listed,
                )
            )
        return results

    @property
    def verdict(self) -> str:
        """``ready`` / ``partial`` / ``not_ready``.

        ``not_ready``: the origin (or runtime) failed. ``partial``: the origin is
        ready but an in-scope trusted domain was reached for validation and did
        not pass. ``ready`` otherwise. Domains deliberately not validated do not
        degrade the verdict: they are unknown by the operator's own choice.
        """
        if not self.origin_passed:
            return VERDICT_NOT_READY
        trusted = [d for d in self.domain_results() if d.role == ROLE_TRUSTED]
        if any(d.state == DOMAIN_STATE_NOT_READY for d in trusted):
            return VERDICT_PARTIAL
        if self.scope_policy != TRUST_POLICY_ORIGIN_ONLY and any(
            d.state == DOMAIN_STATE_NOT_VALIDATED
            and d.domain in {s.lower() for s in self.scope_domains}
            for d in trusted
        ):
            # Asked for, but doctor could not even attempt it (origin bind failed
            # earlier, or over the cap): an honest partial, not a clean ready.
            return VERDICT_PARTIAL
        return VERDICT_READY

    @property
    def exit_code(self) -> int:
        """Process exit code: 0 ready, 1 origin not ready, 2 partial (see module doc)."""
        return {VERDICT_READY: 0, VERDICT_NOT_READY: 1}.get(self.verdict, 2)

    def to_dict(self, *, domain: str = "", dc_ip: str = "") -> dict[str, Any]:
        """Serialize the whole report to the structured machine contract.

        Single source of truth for the ``--json`` output the local web backend
        ingests. Counts and domain names stay as plain data (no telemetry path).
        The pre-existing keys are unchanged; ``verdict`` / ``scope`` / ``domains``
        are additive.
        """
        return {
            "domain": domain,
            "dc_ip": dc_ip,
            "passed": self.passed,
            "verdict": self.verdict,
            "scope": {
                "policy": self.scope_policy,
                "domains": list(self.scope_domains),
                "decision": self.decision,
            },
            "domains": [d.to_dict() for d in self.domain_results()],
            "checks": [c.to_dict() for c in self.checks],
        }

    def to_json(self, *, domain: str = "", dc_ip: str = "") -> str:
        """Serialize the report to a single-line JSON string (the web contract)."""
        import json  # noqa: PLC0415

        return json.dumps(self.to_dict(domain=domain, dc_ip=dc_ip), ensure_ascii=False)


class ScopedReport:
    """A :class:`DoctorReport` view that tags every added row with a domain."""

    def __init__(self, report: DoctorReport, domain: str | None, role: str | None):
        self._report = report
        self._domain = domain
        self._role = role

    @property
    def report(self) -> DoctorReport:
        """The underlying report."""
        return self._report

    def add(
        self,
        name: str,
        status: str,
        detail: str = "",
        *,
        value: int | None = None,
        items: list[str] | None = None,
    ) -> None:
        """Append a row stamped with this view's domain and role."""
        self._report.add(
            name,
            status,
            detail,
            value=value,
            items=items,
            domain=self._domain,
            role=self._role,
        )


def _row_value(rows: list[DoctorCheck], name: str) -> int | None:
    """Return the numeric payload of the named row, ``None`` when absent."""
    for row in rows:
        if row.name == name:
            return row.value
    return None


# --------------------------------------------------------------------------- #
# Config + dependency injection
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class DoctorConfig:
    """Parsed inputs for one ``adscan doctor`` invocation."""

    domain: Optional[str] = None
    dc_ip: Optional[str] = None
    dns_server: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    workspace: Optional[str] = None
    interface: Optional[str] = None
    requested_pro: bool = False
    json_output: bool = False
    # Trust-validation scope: ``origin_only`` (default, touches no other domain),
    # ``all`` (every trust partner the origin lists) or ``selected`` (only
    # ``trust_domains``). Same vocabulary as the scan's trust policy.
    trust_scope: str = TRUST_POLICY_ORIGIN_ONLY
    trust_domains: tuple[str, ...] = ()


@dataclass(frozen=True)
class _TrustedTarget:
    """A trusted domain doctor authenticates into with the ORIGIN credential.

    ``domains_data`` is a private, transient map holding only this domain's
    located DC, so the validation never writes a half-discovered domain into
    the operator's (possibly named, persisted) workspace.
    """

    domain: str
    auth_domain: str
    auth_kdc: str
    domains_data: dict


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
        print_exception(exception=exc)
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
    dns_server = (config.dns_server or "").strip() or None
    try:
        if entered_ip:
            effective_ip = _discover_pdc_from_entered_ip(
                report, shell, domain=domain, entered_ip=entered_ip, dns_server=dns_server
            )
        else:
            effective_ip = _discover_pdc_without_ip(
                report, shell, domain=domain, dns_server=dns_server
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        report.add("DNS resolution", "fail", f"DC discovery raised: {exc}")
        return ""
    return effective_ip


def _discover_pdc_from_entered_ip(
    report: DoctorReport,
    shell: Any,
    *,
    domain: str,
    entered_ip: str,
    dns_server: str | None = None,
) -> str:
    """Validate the entered DC IP and correct it to the real PDC if needed.

    Drives the SAME non-interactive PDC preflight ``start_auth`` uses. The
    preflight resolves the domain through the entered IP, probes its DC/KDC
    ports, and — when the entered IP is reachable but not the PDC — discovers
    the PDC and returns it. It never prompts.

    Split-DC/DNS (issue #15): when ``dns_server`` is set the DNS SRV/A validation
    targets that separate AD-zone DNS host instead of ``entered_ip`` (which stays
    the DC/KDC connectivity target). ``None`` keeps the DC as the resolver,
    byte-identical.
    """
    from adscan_internal.cli.dns import (  # noqa: PLC0415
        preflight_domain_pdc_noninteractive,
        persist_pdc_preflight_result,
    )

    marked_domain = mark_sensitive(domain, "domain")
    decision = preflight_domain_pdc_noninteractive(
        shell,
        domain=domain,
        candidate_ip=entered_ip,
        mode_label="doctor",
        dns_server=dns_server,
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


def _discover_pdc_without_ip(
    report: DoctorReport, shell: Any, *, domain: str, dns_server: str | None = None
) -> str:
    """Locate the PDC for ``domain`` via the system resolver (no --dc-ip given).

    Reuses ``DNSDiscoveryService.find_pdc_with_selection`` against the first
    configured nameserver — the same service start_auth threads through. When no
    PDC SRV answer is obtained (DNS not configured for the realm) a ``fail`` row
    is recorded and downstream checks skip with a clear reason.

    Split-DC/DNS (issue #15): when ``dns_server`` is set the PDC SRV lookup uses
    that separate AD-zone DNS host as the resolver instead of the system
    nameserver. ``None`` keeps the system resolver, byte-identical.
    """
    marked_domain = mark_sensitive(domain, "domain")
    service = shell._get_dns_discovery_service()  # noqa: SLF001

    resolver_ip = (dns_server or "").strip()
    if not resolver_ip:
        try:
            nameservers = service._get_resolv_conf_nameservers(  # noqa: SLF001
                include_loopback=True
            )
            resolver_ip = next((ns for ns in (nameservers or []) if ns), "")
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    selected_ip = ""
    if resolver_ip:
        try:
            selected_ip, _hostname = service.find_pdc_with_selection(
                domain=domain, resolver_ip=resolver_ip
            )
            selected_ip = (selected_ip or "").strip()
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
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
        print_exception(exception=exc)

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
        from adscan_internal.models.domain import resolve_dns_server  # noqa: PLC0415
        from adscan_internal.services._kerberos_spn import is_ip_address  # noqa: PLC0415

        hostname = resolve_pdc_hostname_best_effort(
            shell,
            domain=domain,
            pdc_ip=pdc_ip,
            dns_server=resolve_dns_server(domain_data),
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
        print_exception(exception=exc)


def _check_connectivity(report: Any, shell: Any, dc_ip: str) -> bool:
    """TCP reachability of the DC's AD ports (route + port probe).

    Returns ``True`` only when at least one AD port answered.
    """
    if not dc_ip:
        report.add("DC connectivity", "skip", "No DC IP resolved.")
        return False
    try:
        from adscan_internal.services.network_preflight_service import (  # noqa: PLC0415
            DC_REACHABILITY_TCP_PORTS,
            assess_target_reachability,
        )

        # The shell satisfies the NetworkPreflightHost protocol (same call the
        # DNS preflight makes); pass it directly rather than reimplementing.
        # Consume the SSOT port set so this check never drifts from the `start`
        # preflight — both must recognise a hardened DC exposing only 88/636.
        assessment = assess_target_reachability(
            shell,
            target_ip=dc_ip,
            expected_interface=getattr(shell, "interface", None),
            tcp_ports=DC_REACHABILITY_TCP_PORTS,
            timeout_seconds=3.0,
        )
        probed_ports_label = "/".join(str(p) for p in DC_REACHABILITY_TCP_PORTS)
        open_ports = tuple(assessment.open_ports)
        if open_ports:
            report.add(
                "DC connectivity",
                "pass",
                f"{mark_sensitive(dc_ip, 'ip')} reachable on "
                f"{', '.join(str(p) for p in open_ports)}.",
            )
            return True
        else:
            report.add(
                "DC connectivity",
                "fail",
                f"No AD ports open on {mark_sensitive(dc_ip, 'ip')} "
                f"({probed_ports_label} all closed or filtered).",
            )
            return False
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        report.add("DC connectivity", "fail", f"Reachability probe raised: {exc}")
        return False


def _build_doctor_ldap_config(
    shell: Any,
    config: DoctorConfig,
    dc_ip: str,
    target: _TrustedTarget | None = None,
) -> Any:
    """Build a posture-aware authed LDAP config for the doctor checks.

    Single source of truth for the authenticated LDAP transport doctor uses
    (the auth bind, the enabled counts, and the trust query). Reuses the
    sanctioned ``build_ldap_config_for_domain`` (LDAPS->LDAP fallback, posture
    aware, hardened-DC safe). Crucially this is an ISOLATED bind — it never
    routes through ``add_credential`` / ``do_enum_authenticated`` and so never
    triggers the native collector, ADCS discovery, the reachability sweep, or
    an attack-path build.

    With ``target`` the config points at a TRUSTED domain's DC while the
    credential stays the origin's (``auth_domain`` / ``auth_kdc``), i.e. the
    cross-realm Kerberos path the scan itself uses. No posture snapshot is
    applied there: the origin's hardening says nothing about the trusted
    forest, so the planner keeps its conservative chain.
    """
    from adscan_internal.services.ldap_transport_service import (  # noqa: PLC0415
        build_ldap_config_for_domain,
    )
    from adscan_internal.services.domain_posture import (  # noqa: PLC0415  (best-effort)
        get_posture,
    )

    user = (config.username or "").strip()
    password = config.password or ""

    if target is not None:
        return build_ldap_config_for_domain(
            target.domains_data,
            target.domain,
            username=user,
            password=password,
            auth_domain=target.auth_domain,
            auth_kdc=target.auth_kdc,
            use_ldaps=True,
            use_kerberos=True,
            posture_snapshot=None,
        )

    domain = (config.domain or "").strip()

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


def _describe_auth_failure(exc: BaseException) -> str:
    """Short, honest reason for a failed cross-trust bind (no secrets).

    Maps the Kerberos / LDAP markers an operator can act on; falls back to the
    exception type. Only used for trusted domains, where "the credential is
    wrong" and "the trust does not carry this credential" need telling apart.
    """
    text = f"{type(exc).__name__}: {exc}".lower()
    markers = (
        ("wrong_realm", "the KDC rejected the realm (wrong KDC for that domain)"),
        ("s_principal_unknown", "the DC's service principal was not found (SPN/FQDN mismatch)"),
        ("skew", "clock skew between this host and the domain"),
        ("client_not_trusted", "the KDC did not trust the client (certificate/clock)"),
        ("c_principal_unknown", "the account is unknown to its home KDC"),
        ("preauth_failed", "wrong password for the account"),
        ("invalidcredentials", "the DC refused the credential across the trust"),
        ("timeout", "the DC did not answer in time"),
    )
    for token, message in markers:
        if token in text:
            return message
    return type(exc).__name__


def _check_auth(
    report: Any,
    shell: Any,
    config: DoctorConfig,
    target: _TrustedTarget | None = None,
    dc_ip: str = "",
) -> bool:
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
    if target is None:
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

        ldap_cfg = (
            _build_doctor_ldap_config(shell, config, str(dc_ip))
            if target is None
            else _build_doctor_ldap_config(shell, config, str(dc_ip), target)
        )
        # Opening the connection performs the bind; success == authenticated.
        with ADscanLDAPConnection(ldap_cfg):
            pass
        if target is not None:
            report.add(
                "Authentication",
                "pass",
                f"Bound as {mark_sensitive(user, 'user')}@"
                f"{mark_sensitive(target.auth_domain, 'domain')} across the trust.",
            )
        else:
            report.add(
                "Authentication",
                "pass",
                f"Bound as {mark_sensitive(user, 'user')}.",
            )
        return True
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        if target is not None:
            report.add(
                "Authentication",
                "fail",
                "Credential did not authenticate across the trust "
                f"({_describe_auth_failure(exc)}).",
            )
            return False
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
    shell: Any,
    config: DoctorConfig,
    dc_ip: str,
    search_filter: str,
    target: _TrustedTarget | None = None,
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

    ldap_cfg = (
        _build_doctor_ldap_config(shell, config, dc_ip)
        if target is None
        else _build_doctor_ldap_config(shell, config, dc_ip, target)
    )
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
    report: Any,
    shell: Any,
    config: DoctorConfig,
    dc_ip: str,
    *,
    authed: bool,
    target: _TrustedTarget | None = None,
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
            count = _count_enabled_objects(
                shell, config, dc_ip, ldap_filter, target
            )
            report.add(label, "info", detail=str(count), value=count)
        except Exception as exc:  # noqa: BLE001 — best-effort; never crash doctor
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            report.add(label, "skip", f"Count query failed: {exc}")


def _check_trusts(
    report: Any, shell: Any, config: DoctorConfig, dc_ip: str, *, authed: bool
) -> list[str] | None:
    """List the source domain's trust partners via a single direct LDAP query.

    Doctor must stay a few-seconds preflight, so this issues ONE isolated
    ``(objectClass=trustedDomain)`` search under ``CN=System,<domain_dn>`` over
    the same sanctioned ``ADscanLDAPConnection`` the enabled-count check uses
    (``query_trusted_domains``, the trust-decoding SSOT). It deliberately does
    NOT call ``DomainService.enumerate_trusts`` — that runs the full recursive
    topology enumeration (native collector, ADCS, reachability sweep, SMB
    enrichment, the trust-enum live widget). Emitted as an ``"info"`` row.

    Returns the sorted partner list (also the ``--trusts all`` scope), or
    ``None`` when the partners could not be listed.
    """
    if not authed:
        report.add("Trust relationships", "skip", "No authenticated LDAP bind available.")
        return None
    if not dc_ip:
        report.add("Trust relationships", "skip", "No DC IP resolved.")
        return None

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
        # Keep direction / type per partner for the decision prompt's topology.
        meta = getattr(getattr(report, "report", report), "partner_meta", None)
        if isinstance(meta, dict):
            for entry in entries or []:
                name = str(getattr(entry, "partner", "") or "").strip().lower()
                if name:
                    meta[name] = {
                        "direction": str(getattr(entry, "direction", "") or ""),
                        "type": str(getattr(entry, "trust_type", "") or ""),
                    }
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
        return partners
    except Exception as exc:  # noqa: BLE001 — best-effort; never crash doctor
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        report.add("Trust relationships", "skip", f"Trust enumeration failed: {exc}")
        return None


def _check_posture(
    report: Any, shell: Any, config: DoctorConfig, dc_ip: str
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
        print_exception(exception=exc)
        report.add("Posture probe", "fail", f"Posture probe raised: {exc}")


# --------------------------------------------------------------------------- #
# Trusted-domain validation (opt-in via --trusts)
# --------------------------------------------------------------------------- #


def _normalize_domain_token(value: str) -> str:
    """Lower-case a domain name and strip whitespace / the FQDN root dot."""
    return str(value or "").strip().rstrip(".").lower()


def resolve_trust_scope(
    policy: str,
    selected: tuple[str, ...] | list[str],
    partners: list[str] | None,
    *,
    cap: int = MAX_TRUSTED_DOMAINS_VALIDATED,
) -> tuple[list[str], list[str]]:
    """Resolve the requested scope into the domains doctor will validate.

    Pure function (the unit-tested scope SSOT).

    Args:
        policy: One of :data:`DOCTOR_TRUST_SCOPES`.
        selected: Operator-picked domains (used by ``selected`` only).
        partners: Trust partners the origin lists, ``None`` when unknown.
        cap: Maximum domains validated in one run.

    Returns:
        ``(to_validate, over_cap)``. ``to_validate`` is the ordered, de-duplicated,
        lower-cased list doctor will visit; ``over_cap`` holds the requested
        domains dropped by the cap (reported "not validated", never silent).
        ``origin_only`` always yields two empty lists.
    """
    if policy == TRUST_POLICY_ALL:
        requested = list(partners or [])
    elif policy == TRUST_POLICY_SELECTED:
        requested = list(selected or [])
    else:
        return [], []
    ordered: list[str] = []
    for item in requested:
        token = _normalize_domain_token(item)
        if token and token not in ordered:
            ordered.append(token)
    return ordered[:cap], ordered[cap:]


def _locate_trusted_dc(
    report: Any,
    shell: Any,
    config: DoctorConfig,
    domain: str,
    *,
    resolver_ip: str,
) -> tuple[str, str]:
    """Locate a trusted domain's DC the way the scan's trust walk does.

    Uses ``find_pdc_with_selection(cross_domain=True)`` (which composes
    ``select_reachable_dc_ip``): the origin DC / AD-zone DNS server is ONLY the
    resolver for the trusted realm's SRV/A records and is never a DC candidate,
    so the source realm's DC can not be substituted for a foreign realm's PDC
    (that yields ``KDC_ERR_WRONG_REALM``). Records the DNS row on ``report``.

    Returns:
        ``(dc_ip, dc_fqdn)``; both ``""`` when no reachable DC was located.
    """
    marked = mark_sensitive(domain, "domain")
    try:
        service = shell._get_dns_discovery_service()  # noqa: SLF001
        result = service.find_pdc_with_selection(
            domain=domain,
            resolver_ip=resolver_ip,
            preferred_ips=[resolver_ip],
            reference_ip=resolver_ip,
            cross_domain=True,
            return_selection=True,
        )
        if len(result) == 3:
            selected_ip, hostname, selection = result
        else:  # defensive: a stubbed service may ignore return_selection
            selected_ip, hostname = result
            selection = None
    except Exception as exc:  # noqa: BLE001 — never crash doctor
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        report.add("DNS resolution", "fail", f"DC discovery for {marked} raised: {exc}")
        return "", ""

    hostname = str(hostname or "").strip().rstrip(".")
    fqdn = ""
    if hostname:
        fqdn = hostname if "." in hostname else f"{hostname}.{domain}"
    selected_ip = str(selected_ip or "").strip()
    resolver_label = mark_sensitive(resolver_ip, "ip")
    if selected_ip:
        report.add(
            "DNS resolution",
            "pass",
            f"Located a domain controller at {mark_sensitive(selected_ip, 'ip')} "
            f"(resolved through {resolver_label}).",
        )
        return selected_ip, fqdn
    if hostname:
        seen_at = str(getattr(selection, "unreachable_dns_ip", "") or "").strip()
        where = f" (advertised at {mark_sensitive(seen_at, 'ip')})" if seen_at else ""
        report.add(
            "DNS resolution",
            "fail",
            f"{marked} resolved, but none of its domain controllers is reachable "
            f"from this network{where}.",
        )
    else:
        report.add(
            "DNS resolution",
            "fail",
            f"Could not resolve {marked} through {resolver_label}. The origin DC "
            "may have no DNS forwarder for that domain.",
        )
    return "", ""


def _validate_trusted_domain(
    report: DoctorReport,
    shell: Any,
    config: DoctorConfig,
    domain: str,
    *,
    origin_dc_ip: str,
) -> None:
    """Run the lightweight per-domain checks for ONE trusted domain.

    DNS/DC location, AD-port connectivity, authentication with the origin
    credential across the trust, and the enabled user/computer counts. No
    collector, no posture probe, no recursion into the domain's own trusts. Every
    failure becomes an honest per-domain row; nothing raises.
    """
    scoped = report.scoped(domain, ROLE_TRUSTED)
    origin = (config.domain or "").strip()
    resolver_ip = (config.dns_server or "").strip() or origin_dc_ip
    try:
        dc_ip, fqdn = _locate_trusted_dc(
            scoped, shell, config, domain, resolver_ip=resolver_ip
        )
        if not dc_ip:
            scoped.add("DC connectivity", "skip", "No DC located for this domain.")
            scoped.add("Authentication", "skip", "No DC located for this domain.")
            scoped.add("Enabled users", "skip", "No DC located for this domain.")
            scoped.add("Enabled computers", "skip", "No DC located for this domain.")
            return
        report.trusted_dc_ip[domain] = dc_ip

        if not fqdn:
            # Kerberos needs a real FQDN for the DC's SPN (never the IP).
            from adscan_internal.cli.dns import (  # noqa: PLC0415
                resolve_pdc_hostname_best_effort,
            )

            short = resolve_pdc_hostname_best_effort(
                shell, domain=domain, pdc_ip=dc_ip, dns_server=resolver_ip
            )
            short = str(short or "").strip().rstrip(".")
            if short:
                fqdn = short if "." in short else f"{short}.{domain}"

        domain_data: dict[str, Any] = {"pdc": dc_ip}
        if fqdn:
            domain_data["pdc_hostname_fqdn"] = fqdn
        target = _TrustedTarget(
            domain=domain,
            auth_domain=origin,
            auth_kdc=origin_dc_ip,
            domains_data={domain: domain_data},
        )

        if not _check_connectivity(scoped, shell, dc_ip):
            scoped.add("Authentication", "skip", "Domain controller not reachable.")
            scoped.add("Enabled users", "skip", "Domain controller not reachable.")
            scoped.add("Enabled computers", "skip", "Domain controller not reachable.")
            return
        authed = _check_auth(scoped, shell, config, target=target, dc_ip=dc_ip)
        _check_enabled_counts(
            scoped, shell, config, dc_ip, authed=authed, target=target
        )
    except Exception as exc:  # noqa: BLE001 — a trusted domain never crashes doctor
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        scoped.add("Authentication", "fail", f"Validation raised: {exc}")


def _decide_trusted_domains(
    report: DoctorReport,
    shell: Any,
    config: DoctorConfig,
    *,
    origin_scoped: ScopedReport,
    partners: list[str] | None,
    origin_authed: bool,
) -> list[str] | None:
    """Resolve the ``interactive`` scope: ask which listed partners to validate.

    The prompt is the scan's own trust-scope multiselect, sent through
    ``shell._questionary_multiselect`` (the centralized prompt helper): over the
    remote-interaction bridge when a web worker enabled it, otherwise the helper's
    non-interactive path, which returns the default. So it can never hang:

    * answered      -> the chosen partners (the origin is always kept);
    * no answer in ``DOCTOR_DECISION_TIMEOUT_SECONDS`` (web) -> origin only;
    * no operator channel (plain CLI / CI; doctor is non-interactive by
      construction) -> origin only, and a row says so.

    Returns:
        The partners to validate (possibly empty), or ``None`` when no decision
        was possible (the row explaining why is already recorded).
    """
    if not origin_authed:
        for name in partners or []:
            report.not_validated_reason[name] = (
                "Needs an authenticated origin bind: the same credential is used "
                "across the trust."
            )
        origin_scoped.add(
            "Trust validation",
            "skip",
            "Needs an authenticated origin bind to validate trusted domains.",
        )
        return None
    if partners is None:
        origin_scoped.add(
            "Trust validation", "skip", "The origin's trust partners could not be listed."
        )
        return None
    if not partners:
        origin_scoped.add("Trust validation", "info", "No trusted domains to choose from.")
        return None

    origin = _normalize_domain_token(config.domain or "")
    options = [origin, *[p for p in partners if p != origin]]
    context = {
        "category": "trust_scope",
        "purpose": "validate",
        "origin_domain": origin,
        "candidate_count": len(options),
        "trust_matrix": [
            {
                "source": origin,
                "partner": p,
                "direction": (report.partner_meta.get(p) or {}).get("direction", ""),
                "type": (report.partner_meta.get(p) or {}).get("type", ""),
            }
            for p in options[1:]
        ],
        "discovered_domains": [
            {
                "domain": d,
                "is_origin": d == origin,
                "trust_count": 1 if d != origin else len(options) - 1,
            }
            for d in options
        ],
        "remote_interaction": True,
    }
    chosen: list[str] = []
    decision = DECISION_AUTO
    try:
        from adscan_internal.interactive_requests import (  # noqa: PLC0415
            is_remote_interaction_enabled,
            last_resolution,
        )

        selector = getattr(shell, "_questionary_multiselect", None)
        remote = is_remote_interaction_enabled()
        selected: list[str] | None = []
        if callable(selector):
            selected = selector(
                "Select trusted domains to validate:",
                options,
                default_values=[origin],
                timeout_values=[origin],
                context=context,
            )
        if remote and callable(selector):
            decision = (
                DECISION_ANSWERED if last_resolution() == "answered" else DECISION_TIMEOUT
            )
        picked = {_normalize_domain_token(v) for v in (selected or [])}
        chosen = [p for p in partners if p in picked]
    except Exception as exc:  # noqa: BLE001 — a failed prompt means origin only
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        chosen, decision = [], DECISION_AUTO

    report.decision = decision
    declined = [p for p in partners if p not in chosen]
    if decision == DECISION_ANSWERED:
        report.declined_domains = declined
        for name in declined:
            report.not_validated_reason[name] = "Declined by the operator."
        detail = (
            f"Operator chose {len(chosen)} trusted domain"
            f"{'s' if len(chosen) != 1 else ''}: {', '.join(chosen)}"
            if chosen
            else "Operator chose the origin domain only."
        )
    elif decision == DECISION_TIMEOUT:
        for name in declined:
            report.not_validated_reason[name] = (
                "No decision in time: only the origin was validated."
            )
        detail = "No answer in time: validated the origin domain only."
    else:
        for name in declined:
            report.not_validated_reason[name] = (
                "No operator to ask in this run. Use --trusts selected to name domains."
            )
        detail = (
            "No operator to ask in this run: validated the origin domain only. "
            "Use --trusts selected to name domains."
        )
    if not chosen:
        origin_scoped.add("Trust validation", "info", detail)
        return None
    report.scope_domains = list(chosen)
    return chosen


def _check_trusted_domains(
    report: DoctorReport,
    shell: Any,
    config: DoctorConfig,
    *,
    origin_dc_ip: str,
    partners: list[str] | None,
    origin_authed: bool,
) -> None:
    """Validate the in-scope trusted domains (no-op for ``origin_only``).

    The origin credential is the only credential in play, so an origin that did
    not authenticate can not validate anything across the trust: those domains
    are reported ``not_validated`` with that reason instead of burning a bind per
    domain that is certain to fail (and risking lockout on a bad credential).
    """
    policy = config.trust_scope
    if policy == TRUST_POLICY_ORIGIN_ONLY:
        return
    report.scope_policy = policy
    origin_scoped = report.scoped((config.domain or "").strip(), ROLE_ORIGIN)
    if policy == TRUST_POLICY_INTERACTIVE:
        decided = _decide_trusted_domains(
            report,
            shell,
            config,
            origin_scoped=origin_scoped,
            partners=partners,
            origin_authed=origin_authed,
        )
        if decided is None:
            return
        to_validate, over_cap = resolve_trust_scope(
            TRUST_POLICY_SELECTED, decided, partners
        )
    else:
        to_validate, over_cap = resolve_trust_scope(
            policy, config.trust_domains, partners
        )
    report.scope_domains = [*to_validate, *over_cap]
    for name in over_cap:
        report.not_validated_reason[name] = (
            f"Over the limit of {MAX_TRUSTED_DOMAINS_VALIDATED} trusted domains "
            "validated per run."
        )
    if not origin_authed:
        for name in to_validate:
            report.not_validated_reason[name] = (
                "Needs an authenticated origin bind: the same credential is used "
                "across the trust."
            )
        origin_scoped.add(
            "Trust validation",
            "skip",
            "Needs an authenticated origin bind to validate trusted domains.",
        )
        return
    if policy == TRUST_POLICY_ALL and partners is None:
        origin_scoped.add(
            "Trust validation",
            "skip",
            "The origin's trust partners could not be listed.",
        )
        return
    if not to_validate:
        origin_scoped.add("Trust validation", "info", "No trusted domains in scope.")
        return
    origin_scoped.add(
        "Trust validation",
        "info",
        f"Validating {len(to_validate)} trusted domain"
        f"{'s' if len(to_validate) != 1 else ''}: {', '.join(to_validate)}",
        value=len(to_validate),
        items=to_validate,
    )
    for name in to_validate:
        _validate_trusted_domain(
            report, shell, config, name, origin_dc_ip=origin_dc_ip
        )


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def _check_label(check: DoctorCheck) -> str:
    """Matrix label: trusted-domain rows carry their domain, origin rows do not."""
    if check.role == ROLE_TRUSTED and check.domain:
        return f"{check.name} ({check.domain})"
    return check.name


def render_doctor_report(report: DoctorReport, *, domain: str = "") -> None:
    """Render the scannable per-check pass/fail matrix panel."""
    from rich.table import Table  # noqa: PLC0415
    from rich import box as _box  # noqa: PLC0415
    from rich.markup import escape  # noqa: PLC0415
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
        table.add_row(
            icons.get(check.status, "[dim]?[/]"), escape(_check_label(check)), check.detail
        )

    verdict = report.verdict
    border = {VERDICT_READY: "green", VERDICT_PARTIAL: "yellow"}.get(verdict, "red")
    headline = {
        VERDICT_READY: "All checks passed — the environment is ready.",
        VERDICT_PARTIAL: (
            "The origin domain is ready, but one or more trusted domains could "
            "not be validated — review the rows tagged with a domain."
        ),
    }.get(
        verdict,
        "One or more checks failed — resolve the red rows before scanning.",
    )
    status_word = {
        VERDICT_READY: "HEALTHY",
        VERDICT_PARTIAL: "ORIGIN READY, TRUSTS PARTIAL",
    }.get(verdict, "ISSUES FOUND")
    subtitle = f"target: {mark_sensitive(domain, 'domain')}" if domain else None
    print_panel(
        table,
        title=f"ADscan Doctor · {status_word}",
        subtitle=subtitle,
        border_style=border,
    )
    if report.scope_policy != TRUST_POLICY_ORIGIN_ONLY:
        _render_domain_summary(report)
    (print_info if verdict != VERDICT_NOT_READY else print_error)(headline)


def _render_domain_summary(report: DoctorReport) -> None:
    """Per-domain sizing table — shown only when trusted domains were in scope."""
    from rich.table import Table  # noqa: PLC0415
    from rich import box as _box  # noqa: PLC0415
    from rich.markup import escape  # noqa: PLC0415
    from adscan_core.rich_output import print_panel  # noqa: PLC0415

    styles = {
        DOMAIN_STATE_READY: "[bold green]ready[/]",
        DOMAIN_STATE_NOT_READY: "[bold red]not ready[/]",
        DOMAIN_STATE_NOT_VALIDATED: "[dim]not validated[/]",
    }
    declined = {d.domain for d in report.domain_results() if d.declined}
    table = Table(box=_box.SIMPLE_HEAD, expand=True, show_edge=False)
    table.add_column("Domain", style="bold", no_wrap=True)
    table.add_column("State", no_wrap=True)
    table.add_column("Users", justify="right")
    table.add_column("Computers", justify="right")
    table.add_column("Note")

    def _num(value: int | None) -> str:
        return "-" if value is None else f"{value:,}"

    for item in report.domain_results():
        name = escape(item.domain) + (" (origin)" if item.role == ROLE_ORIGIN else "")
        table.add_row(
            name,
            "[dim]not validated (declined)[/]"
            if item.domain in declined
            else styles.get(item.state, item.state),
            _num(item.enabled_users),
            _num(item.enabled_computers),
            escape(item.reason),
        )
    print_panel(table, title="Directory sizing by domain", border_style="cyan")


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
                label=_check_label(c),
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
            "  adscan doctor -d corp.local --dc-ip 10.0.0.1 -u alice -p Pass\n"
            "  adscan doctor -d corp.local --dc-ip 10.0.0.1 -u alice -p Pass --trusts all\n"
            "  adscan doctor -d corp.local --dc-ip 10.0.0.1 -u alice -p Pass "
            "--trusts selected --trust-domains partner.local\n\n"
            "Exit code: 0 ready, 1 origin not ready, 2 origin ready but a trusted "
            "domain could not be validated."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-d", "--domain", help="Target domain to validate.")
    parser.add_argument("--dc-ip", dest="dc_ip", help="PDC/DC IP for the target domain.")
    parser.add_argument(
        "--dns-server",
        dest="dns_server",
        metavar="IP",
        help=(
            "Optional AD-zone DNS server IP for segmented networks where DNS is "
            "a separate host from the DC. The DNS validation queries this server; "
            "--dc-ip stays the connectivity/auth target. Defaults to --dc-ip when "
            "omitted."
        ),
    )
    parser.add_argument(
        "--trusts",
        dest="trust_scope",
        choices=DOCTOR_TRUST_SCOPES,
        default=TRUST_POLICY_ORIGIN_ONLY,
        help=(
            "Which trusted domains to validate besides the origin (needs -u/-p): "
            "origin_only (default, touches no other domain), all (every trust "
            "partner the origin lists), selected (only --trust-domains) or "
            "interactive (ask which partners to validate; a run with no operator "
            "to ask validates the origin only). Each "
            "gets DC discovery, connectivity, a cross-trust authentication with "
            "the same credential and enabled user/computer counts."
        ),
    )
    parser.add_argument(
        "--trust-domains",
        dest="trust_domains",
        metavar="DOMAINS",
        help="Comma-separated trusted domains to validate (with --trusts selected).",
    )
    parser.add_argument("-u", "--username", help="Auth username (enables the auth check).")
    parser.add_argument("-p", "--password", help="Auth password or hash.")
    parser.add_argument(
        "-w", "--workspace",
        help=(
            "Named workspace to check from (kept). Omitted: a throwaway workspace "
            "deleted when the check ends."
        ),
    )
    parser.add_argument("-i", "--interface", help="Network interface (myip auto-config).")
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
        dns_server=getattr(args, "dns_server", None),
        username=getattr(args, "username", None),
        password=getattr(args, "password", None),
        workspace=getattr(args, "workspace", None),
        interface=getattr(args, "interface", None),
        json_output=bool(getattr(args, "json_output", False)),
        trust_scope=_normalize_trust_scope(getattr(args, "trust_scope", None)),
        trust_domains=_parse_trust_domains(getattr(args, "trust_domains", None)),
    )


def _normalize_trust_scope(value: Any) -> str:
    """Return a canonical scope; the ``skip`` alias and unknowns mean origin only."""
    scope = str(value or TRUST_POLICY_ORIGIN_ONLY).strip().lower()
    return scope if scope in DOCTOR_TRUST_SCOPES else TRUST_POLICY_ORIGIN_ONLY


def _parse_trust_domains(value: Any) -> tuple[str, ...]:
    """Split a comma-separated ``--trust-domains`` value into normalized names."""
    if not value:
        return ()
    out: list[str] = []
    for item in str(value).split(","):
        token = _normalize_domain_token(item)
        if token and token not in out:
            out.append(token)
    return tuple(out)


def run_doctor(*, config: DoctorConfig, deps: DoctorDeps) -> int:
    """Run the doctor health check. Returns a process exit code."""
    # Non-interactive by construction.
    os.environ.setdefault("ADSCAN_SESSION_ENV", "ci")
    os.environ["ADSCAN_NONINTERACTIVE"] = "1"

    license_mode = deps.resolve_license_mode(config.requested_pro)
    shell = deps.create_shell(deps.console, license_mode)
    shell.session_command_type = "doctor"
    shell.auto = True
    if config.interface:
        shell.interface = config.interface

    from adscan_internal.workspaces.session import activate_workspace  # noqa: PLC0415

    shell.ensure_workspaces_dir()
    created = False
    if config.workspace:
        ws_dir = os.path.join(shell.workspaces_dir, config.workspace)
        os.makedirs(ws_dir, exist_ok=True)
        activate_workspace(
            shell, workspaces_dir=shell.workspaces_dir, workspace_name=config.workspace
        )
        shell.load_workspace_data(ws_dir)
    else:
        ws = f"doctor-{uuid.uuid4().hex[:6]}"
        ws_dir = os.path.join(shell.workspaces_dir, ws)
        os.makedirs(ws_dir, exist_ok=True)
        activate_workspace(shell, workspaces_dir=shell.workspaces_dir, workspace_name=ws)
        shell.load_workspace_data(ws_dir)
        created = True

    telemetry.capture("doctor_start", properties={"has_domain": bool(config.domain)})

    # Split-DC/DNS (issue #15): a separate AD-zone DNS server for segmented
    # networks. Persist it session-wide and under the target domain (mirroring
    # `ci`) so every resolver-update path — and the DNS validation below — points
    # at the DNS host while --dc-ip stays the connectivity/auth target. When it is
    # absent the DC resolves exactly as before (byte-identical).
    _doctor_dns_server = (config.dns_server or "").strip()
    if _doctor_dns_server:
        shell._pending_dns_server = _doctor_dns_server  # noqa: SLF001
        _doctor_dns_domain = (config.domain or "").strip()
        if _doctor_dns_domain:
            shell.domains_data.setdefault(_doctor_dns_domain, {})[
                "dns_server"
            ] = _doctor_dns_server

    origin_domain = (config.domain or "").strip()
    report = DoctorReport(
        origin_domain=origin_domain,
        scope_policy=config.trust_scope,
        scope_domains=list(config.trust_domains)
        if config.trust_scope == TRUST_POLICY_SELECTED
        else [],
    )
    # Every origin-domain row is tagged with the origin; the runtime preflight
    # belongs to no domain. Trusted-domain rows are tagged by their own view.
    origin = report.scoped(origin_domain or None, ROLE_ORIGIN)
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
        dc_ip = _check_dns(origin, shell, config)
        _check_connectivity(origin, shell, dc_ip)
        authed = _check_auth(origin, shell, config)
        # Probe the domain security posture BEFORE the LDAP inventory so the
        # enabled-count and trust queries below build their transport config
        # posture-aware (Kerberos vs NTLM, AES etypes, LDAP signing, channel
        # binding) instead of on an empty snapshot. ``ensure_posture_fresh`` is
        # idempotent, so running it here (rather than last) only changes WHEN the
        # snapshot is populated, making the doctor's own enumeration as robust on
        # a hardened DC as a full scan. The auth-plan still falls back on its own;
        # this just prunes impossible combos up front (fewer attempts, cleaner OPSEC).
        _check_posture(origin, shell, config, dc_ip)
        # Authenticated, fast, no-graph inventory checks (PoV sizing + trusts) —
        # now consume the posture snapshot the probe above persisted.
        _check_enabled_counts(origin, shell, config, dc_ip, authed=authed)
        partners = _check_trusts(origin, shell, config, dc_ip, authed=authed)
        report.origin_dc_ip = dc_ip
        report.partners = list(partners or [])
        # Opt-in: validate the in-scope trusted domains with the same credential.
        # A no-op for the default ``origin_only`` scope (nothing else is touched).
        _check_trusted_domains(
            report,
            shell,
            config,
            origin_dc_ip=dc_ip,
            partners=partners,
            origin_authed=authed,
        )
    finally:
        domain = (config.domain or "").strip()
        if config.json_output:
            _emit_json(report, domain=domain, dc_ip=dc_ip)
        else:
            render_doctor_report(report, domain=domain)
            _maybe_emit_widget(report, domain)
        # doctor is a health check: its throwaway workspace always goes (a
        # failed check keeps only logs/), a named -w workspace always stays.
        # Same disposal SSOT as ci/execute, silent so the matrix/JSON is the
        # whole output.
        from adscan_internal.workspaces.retention import (  # noqa: PLC0415
            close_run_workspace,
        )

        close_run_workspace(
            name=shell.current_workspace,
            workspace_dir=shell.current_workspace_dir,
            created=created,
            ephemeral=created,
            failed=int(getattr(report, "exit_code", 1) or 0) != 0,
            announce=False,
        )
        try:
            shell.do_exit(exit=False)
        except Exception:  # noqa: BLE001
            pass

    return report.exit_code
