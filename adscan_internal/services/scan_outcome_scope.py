"""Which domain is a scan's outcome ABOUT — the subject of the end-of-scan claim.

``shell.domains`` is not an answer to that question and was never meant to be.
It is the list of every domain name the session knows: the domain the operator
supplied credentials for, plus every domain learned by reading a trust off it,
appended unconditionally so the per-domain scan phases (attack-path discovery,
timeroast, LDAP description parsing) gate correctly. The trust-enumeration path
even rewrites it as ``list(set(shell.domains))``, so its ORDER is a hash
artifact, not recency.

Reading "the last entry" off that list and pairing it with the session-global
compromise verdict is how the recap panel came to print

    ★ DOMAIN COMPROMISED   north.sevenkingdoms.local

for a run that compromised ``essos.local`` and never authenticated against
``north.sevenkingdoms.local`` at all — a false claim on the strongest statement
the product makes, printed for a pentester to repeat to their client. The same
wrong domain then resolved the findings and the attack-path counts, so the panel
also went silent on both (that domain has zero of each).

Two facts ADscan already records answer it properly, and this module composes
them rather than adding a third notion of either:

* **Assessed vs discovered** — :mod:`adscan_core.reporting.domain_scope` and
  :func:`~adscan_internal.services.report_attack_paths.resolve_domain_assessment`,
  the SSOT both report tiers use for "did this engagement actually enumerate the
  domain". A recorded ``assessment.enumerated`` marker wins when the report run
  has already stamped one; otherwise the collector's own output decides (did it
  produce an attack graph for the domain?). At end-of-scan the marker usually
  does not exist yet — it is written when the report is generated, moments later
  — which is precisely why the workspace-backed resolver is the one that has to
  work here.
* **Proven full compromise, per domain** — ``domains_data[<domain>]["auth"] ==
  "pwned"``, written only by
  :func:`~adscan_internal.services.domain_compromise_promotion.promote_to_pwned`
  and already documented as meaning "this domain has been fully owned,
  regardless of whether it is the primary/active domain".

The subject is then the domain the outcome concerns: a domain we PROVED we
compromised, preferring the engagement's primary target when it is one of them;
otherwise the primary assessed domain. A domain reached only through a trust can
never become the subject unless we compromised it, in which case naming it is
the honest thing to do.

Following :mod:`adscan_core.reporting.domain_scope`, inference here never
reports zero coverage: when nothing looks assessed the whole known set is
treated as assessed, so a workspace whose graph cannot be located degrades to
the primary domain rather than to no subject at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from adscan_core.reporting.domain_scope import (
    ASSESSMENT_KEY,
    DomainScope,
    domain_was_assessed,
    format_domain_scope_label,
)
from adscan_internal.services.session_compromise_state_service import (
    DOMAIN_AUTH_STATE_PWNED,
    SESSION_COMPROMISE_STATUS_DOMAIN,
    normalize_session_compromise_status,
)


@dataclass(frozen=True)
class ScanOutcomeScope:
    """The domains a finished scan may speak about, and which one it is about.

    ``subject`` is the only domain a headline may name. ``compromised`` exists so
    a multi-domain compromise can be stated in full instead of one domain being
    picked silently, and ``scope`` carries the assessed/discovered split in the
    same shape (and with the same label wording) the client reports use.
    """

    subject: str | None = None
    scope: DomainScope = DomainScope()
    compromised: tuple[str, ...] = ()
    domain_compromised: bool = False

    @property
    def also_compromised(self) -> tuple[str, ...]:
        """Compromised domains other than the subject, in session order."""
        return tuple(name for name in self.compromised if name != self.subject)

    @property
    def scope_label(self) -> str:
        """The cover-line label, e.g. ``"1 assessed · 2 discovered"``."""
        return format_domain_scope_label(self.scope)


def _known_domains(shell: Any) -> tuple[str, ...]:
    """Return every domain the session knows, in session order, de-duplicated.

    ``shell.domains`` leads because it is the order the scan met the domains in;
    ``domains_data`` is unioned in so a workspace reloaded before the list was
    repopulated still resolves (the two stores drift, which is exactly why the
    scan phases guard on one and the active context on the other).
    """
    names: list[str] = []
    listed = getattr(shell, "domains", None)
    if isinstance(listed, (list, tuple)):
        names.extend(str(name or "").strip() for name in listed)
    loaded = getattr(shell, "domains_data", None)
    if isinstance(loaded, Mapping):
        names.extend(str(name or "").strip() for name in loaded)
    return tuple(dict.fromkeys(name for name in names if name))


def _primary_domain(shell: Any) -> str:
    """Return the engagement's primary target, or ``""``.

    ``shell.domain`` is written by exactly one function
    (:func:`~adscan_internal.cli.common.set_active_domain`) and the per-domain
    trust-enumeration loop deliberately does not flip it, so it stays the domain
    the operator actually engaged. The shared resolver is reused rather than
    re-implemented so the recap and the bare REPL commands agree on what "this
    domain" means.
    """
    try:
        from adscan_internal.cli.common import resolve_repl_domain_or_default

        return str(resolve_repl_domain_or_default(shell, None) or "").strip()
    except Exception:  # noqa: BLE001 - fall back to the raw attribute
        return str(getattr(shell, "domain", "") or "").strip()


def _report_domains(shell: Any) -> Mapping[str, Any]:
    """Return the technical report's ``domains`` block, or an empty mapping."""
    try:
        from adscan_core.reporting.technical_report import _load_technical_report

        report = _load_technical_report(shell)
        domains = report.get("domains") if isinstance(report, Mapping) else None
        return domains if isinstance(domains, Mapping) else {}
    except Exception:  # noqa: BLE001 - no report yet just means "ask the workspace"
        return {}


def _workspace_dir(shell: Any) -> str:
    """Return the workspace root whose artifacts belong to THIS scan."""
    from adscan_internal.services.attack_path_counts import resolve_scan_workspace_dir

    return resolve_scan_workspace_dir(shell)


def _was_assessed(workspace_dir: str, domain: str, report_entry: Any) -> bool:
    """Return whether *domain* was enumerated by this engagement.

    Recorded fact first (:func:`domain_was_assessed` reads the stamped
    ``assessment`` marker), then the workspace-backed resolver both report tiers
    use. No third definition of "assessed" is introduced here.
    """
    if isinstance(report_entry, Mapping):
        marker = report_entry.get(ASSESSMENT_KEY)
        if isinstance(marker, Mapping) and isinstance(marker.get("enumerated"), bool):
            return domain_was_assessed(report_entry)
    if not workspace_dir:
        return False
    try:
        from adscan_internal.services.report_attack_paths import (
            resolve_domain_assessment,
        )

        enumerated, _basis = resolve_domain_assessment(
            workspace_dir, domain, report_entry
        )
        return bool(enumerated)
    except Exception:  # noqa: BLE001 - a resolution error just means "no evidence"
        return False


def _is_compromised(shell: Any, domain: str) -> bool:
    """Return whether *domain* carries the proven full-compromise marker."""
    loaded = getattr(shell, "domains_data", None)
    if not isinstance(loaded, Mapping):
        return False
    entry = loaded.get(domain)
    return isinstance(entry, Mapping) and entry.get("auth") == DOMAIN_AUTH_STATE_PWNED


def resolve_scan_outcome_scope(shell: Any) -> ScanOutcomeScope:
    """Return the domain scope of a finished scan, and the domain to name.

    Best-effort by construction: every lookup degrades to "no evidence" rather
    than raising, because the only consumer is an end-of-scan panel that must
    never break a successful run.

    Args:
        shell: The active pentest shell (session domains + workspace context).

    Returns:
        A populated :class:`ScanOutcomeScope`. ``subject`` is ``None`` only when
        the session knows no domain at all.
    """
    known = _known_domains(shell)
    if not known:
        return ScanOutcomeScope()

    workspace_dir = _workspace_dir(shell)
    report_domains = _report_domains(shell)
    assessed = tuple(
        name
        for name in known
        if _was_assessed(workspace_dir, name, report_domains.get(name))
    )
    # Never report zero coverage from inference alone — same rule, same reason,
    # as the report-side classifier: an assessment that recorded nothing is still
    # an assessment, and there is nothing to separate an assessed domain FROM.
    if not assessed:
        assessed = known
    discovered = tuple(name for name in known if name not in assessed)

    # Proof of compromise is stronger evidence than a collected graph: a domain
    # taken over across a trust without ever being enumerated is still a domain
    # we compromised, and naming it is the honest outcome.
    compromised = tuple(name for name in known if _is_compromised(shell, name))

    # The session-global status is kept as a second net: it is in-memory only, so
    # a workspace reloaded from disk carries the per-domain marker without it,
    # and a session that reached compromise carries it before anything else could
    # have been persisted.
    session_status = normalize_session_compromise_status(
        getattr(shell, "_session_compromise_status", None)
    )
    session_says_compromised = session_status == SESSION_COMPROMISE_STATUS_DOMAIN
    domain_compromised = bool(compromised) or session_says_compromised

    pool = compromised or assessed
    primary = _primary_domain(shell)
    subject = primary if primary in pool else pool[0]

    return ScanOutcomeScope(
        subject=subject,
        scope=DomainScope(assessed=assessed, discovered=discovered),
        compromised=compromised,
        domain_compromised=domain_compromised,
    )


__all__ = ["ScanOutcomeScope", "resolve_scan_outcome_scope"]
