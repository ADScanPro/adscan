"""Promote an attribute leak the spray later PROVED on a different principal.

The case. A cleartext password is written into a readable directory attribute.
The sweep extracts it, verifies it against the account whose attribute held it,
and the domain controller refuses it, so the run reports the honest unproven
observation ("a readable attribute holds secret-shaped text, still worth
clearing, never stated as a proven credential") and no attack step. A password
spray then finds that same string valid for a DIFFERENT account.

At that moment the leak IS exploitable, against a principal the leaking object
never named. Before this module nothing noticed: the deliverable kept a medium
"this may be stale" next to a proven credential carrying the same string, and
the spray hit carried an origin that could not name the attribute to clear. Two
true facts, each separately reported, and the client could not join them.

Why the promotion lives at the finding-reconciliation seam
---------------------------------------------------------
The sweep's verification pass finishes before any spray starts, so the
promotion is necessarily a LATER re-evaluation and cannot live in the producer.
:func:`~adscan_internal.services.attack_graph_findings.reconcile_workspace_attack_graph_findings`
is the one seam that runs after every phase boundary AND is called by both
report tiers before they read ``technical_report.json``, so one implementation
serves the free report, the paid kit and (because the web ingests the mutated
artifact) the CTEM, with no second renderer to keep in step.

Two rules this module exists to keep
------------------------------------
* **The spray decides nothing.** It records a fact in the credential store's
  rejected-secret pool (``record_cross_attributed_hit``) and stops. A spray has
  no business grading a finding, and a second producer of a high-severity "we
  logged in with it" claim is how that claim stops resting on an
  authentication.
* **Nothing is promoted without a RECORDED proof.** The promotion fires only
  for a pool record that carries a cross-attributed hit, and only onto a
  finding the run already recorded. It never materialises a high-severity
  credential finding out of a pattern match, and it never invents an
  observation the sweep did not make.

Severity. The promoted finding IS ``credential_in_ldap_attribute`` as the
catalog already defines it (a secret in a directory attribute that
authenticates) at its existing ``high``. The honest difference is not the
grade, it is the affected assets: the promoted record names the leaking object
WITH its attribute (what an administrator clears) and the principal that fell
(what the exposure costs). A ``critical`` variant is deliberately not minted:
the "it also evidences password reuse" aspect is a separate existing finding
family, and stacking two true findings is the honest representation. The
escalation that does belong is the contextual overlay's, which grades by the
target's privilege tier and fires on its own once the compromised principal's
entity is stamped Tier 0 (``adscan_core.cvss.contextual_rules``). An asset the
assessment could not grade elevates nothing.

Spec: ``docs/superpowers/specs/2026-10-09-leaked-attribute-secret-cross-attribution.md``.
"""

from __future__ import annotations

import os
from typing import Any, Iterable, Mapping

from adscan_core import telemetry
from adscan_core.reporting.cross_attribution_copy import (
    CrossAttributedLeak,
    cross_attributed_secret_statement,
)
from adscan_core.reporting.principal_display import humanize_principal_for_prose
from adscan_core.reporting.technical_report import (
    ReportShell,
    _load_technical_report,
    _save_technical_report,
    _utc_now_iso,
    finding_catalog,
)
from adscan_core.rich_output import print_exception, print_info_debug

from adscan_internal.services.credentials.rejected_secret_pool import (
    RejectedSecretCandidate,
    iter_rejected_secret_candidates,
)

#: The CONFIRMED member of the description-secret alias family: a secret in a
#: directory attribute that authenticates. The promotion's destination, and the
#: key whose compliance mapping and ``high`` severity a promoted finding moves
#: onto.
CANONICAL_FINDING_KEY = "credential_in_ldap_attribute"

#: The UNPROVEN members, each with its own live producer. A promotion only ever
#: moves a finding recorded under one of these; it never creates one.
UNPROVEN_FINDING_KEYS: tuple[str, ...] = (
    "ldap_user_description_password_leak",
    "user_description_credential_leak",
)

#: Record containers the family's two producers write, in the order the
#: canonical affected-asset rule reads them.
_RECORD_CONTAINERS: tuple[str, ...] = ("findings", "samples")

#: Where the promoted proof rides: one record per compromised principal, in the
#: container the CONFIRMED producer already uses, so the canonical
#: affected-asset rule surfaces it with no new rule.
_PROOF_CONTAINER = "findings"

#: The machine-readable join the web and any later renderer read: which leak,
#: which attribute, which accounts the value opened.
CROSS_ATTRIBUTION_DETAIL_KEY = "cross_attributed_secrets"

#: Audit trail on a promoted finding: the key it was recorded under before the
#: proof arrived, so a reviewer can see the move without re-running a scan.
PROMOTED_FROM_DETAIL_KEY = "promoted_from_finding_key"

_VARIABLES_FILENAME = "variables.json"


def _pool_domains_data(workspace_dir: str) -> Mapping[str, Any]:
    """Return the workspace's persisted ``domains_data``, or an empty mapping.

    The pool lives in the credential store (the workspace-root
    ``variables.json``), because "this string was proven wrong for this
    principal" is credential-store knowledge. The reconciliation runs off a
    bare shell with no in-memory session state, so the file is the only source
    it has, and the spray flow persists the workspace immediately after
    recording a hit.
    """
    from adscan_internal.workspaces import read_json_file  # noqa: PLC0415

    path = os.path.join(str(workspace_dir), _VARIABLES_FILENAME)
    if not os.path.isfile(path):
        return {}
    variables = read_json_file(path)
    if not isinstance(variables, dict):
        return {}
    domains_data = variables.get("domains_data")
    return domains_data if isinstance(domains_data, Mapping) else {}


def _promotable_leaks(
    domains_data: Mapping[str, Any], domain: str
) -> list[RejectedSecretCandidate]:
    """Return the domain's leak records that carry a proven other principal.

    A record with no cross-attributed hit is the normal case and stays exactly
    as it is: the string was refused for its owner and proved nowhere else, so
    the unproven observation is the whole truth about it.
    """
    return [
        candidate
        for candidate in iter_rejected_secret_candidates(domains_data, domain=domain)
        if candidate.cross_attributed_hits
    ]


def _domain_entry(report: Any, domain: str) -> dict[str, Any] | None:
    """Return the report's entry for *domain*, matching case-insensitively.

    Never creates one. A domain with no findings recorded has no observation to
    promote, and manufacturing an entry here would be the first step toward
    manufacturing a finding.
    """
    domains = report.get("domains") if isinstance(report, dict) else None
    if not isinstance(domains, dict):
        return None
    entry = domains.get(domain)
    if isinstance(entry, dict):
        return entry
    wanted = str(domain or "").strip().lower()
    for name, candidate in domains.items():
        if str(name).strip().lower() == wanted and isinstance(candidate, dict):
            return candidate
    return None


def _records(details: Mapping[str, Any], container: str) -> list[dict[str, Any]]:
    """Return one record container's dict entries."""
    raw = details.get(container)
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict)]


def _record_name(record: Mapping[str, Any]) -> str:
    """Return a record's principal name, lower-cased for comparison."""
    for key in ("samaccountname", "username", "name"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return ""


def _select_target_finding(
    findings: list[Any], leak: RejectedSecretCandidate
) -> dict[str, Any] | None:
    """Return the finding this leak's proof belongs on, or ``None``.

    Preference order, and each step is a recorded fact rather than a guess:

    1. the finding the leak itself says it was recorded under
       (``source.finding_key``), which is why that field is stored;
    2. the CONFIRMED finding, when the same sweep already proved another
       account's attribute, so the proof joins the finding that already makes
       the claim;
    3. any unproven member present, for a leak recorded before the source
       fields existed.

    ``None`` means the run never reported this leak, and a promotion then has
    nothing to promote.
    """
    by_key: dict[str, dict[str, Any]] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        key = str(finding.get("key") or "").strip()
        if key and key not in by_key:
            by_key[key] = finding

    recorded_key = str(leak.source.finding_key or "").strip()
    if recorded_key and recorded_key in by_key:
        return by_key[recorded_key]
    if CANONICAL_FINDING_KEY in by_key:
        return by_key[CANONICAL_FINDING_KEY]
    for key in UNPROVEN_FINDING_KEYS:
        if key in by_key:
            return by_key[key]
    return None


def _apply_catalog_identity(finding: dict[str, Any]) -> bool:
    """Rekey *finding* to the canonical key and refresh its catalog fields.

    The finding MOVES: its key, title, severity band, category, knowledge block
    and CVSS base all come from the canonical catalog entry, which is also what
    moves it between the mapped compliance requirement sets (the unproven keys
    and the canonical are mapped to different controls).

    Returns:
        ``True`` when anything changed.
    """
    previous_key = str(finding.get("key") or "").strip()
    if previous_key == CANONICAL_FINDING_KEY:
        return False
    catalog = finding_catalog().get(CANONICAL_FINDING_KEY) or {}
    finding["key"] = CANONICAL_FINDING_KEY
    details = finding.setdefault("details", {})
    if isinstance(details, dict) and previous_key:
        if details.get(PROMOTED_FROM_DETAIL_KEY) != previous_key:
            details[PROMOTED_FROM_DETAIL_KEY] = previous_key
    for field, catalog_field in (
        ("title", "title"),
        ("severity", "severity"),
        ("category", "category"),
    ):
        value = catalog.get(catalog_field)
        if isinstance(value, str) and value.strip():
            finding[field] = value.strip()
    base = catalog.get("cvss_base")
    vector = catalog.get("cvss_base_vector")
    # The score and its vector travel together or not at all: a base nobody can
    # reproduce is the one number no client surface may print.
    if isinstance(base, (int, float)) and base and isinstance(vector, str) and vector:
        finding["cvss_base"] = base
        finding["cvss_base_vector"] = vector
    return True


def _weave_statement(finding: dict[str, Any], statement: str) -> bool:
    """Put the client statement on the finding's knowledge ``impact``.

    Re-woven from the catalog baseline on every pass, so a re-reconciliation is
    idempotent and never appends the sentence twice. Both the paid report and
    the web CTEM render the per-finding ``knowledge`` strings verbatim, so
    authoring it here reaches both surfaces with no per-finding render code. In
    LITE there is no knowledge block at all (the meta-only catalog yields none)
    and the per-asset rows carry the distinction instead.

    Returns:
        ``True`` when the knowledge block changed.
    """
    if not statement:
        return False
    catalog = finding_catalog().get(CANONICAL_FINDING_KEY) or {}
    baseline = catalog.get("knowledge")
    if not isinstance(baseline, dict) or not baseline:
        return False
    woven = dict(baseline)
    impact = str(woven.get("impact") or "").strip()
    woven["impact"] = f"{impact} {statement}".strip() if impact else statement
    if finding.get("knowledge") == woven:
        return False
    finding["knowledge"] = woven
    return True


def _display(name: str, domain: str) -> str:
    """Return a principal's client-prose display form."""
    text = str(name or "").strip()
    if not text:
        return ""
    try:
        return (
            humanize_principal_for_prose(
                label=text, samaccountname=text, kind="user", report_domain=domain
            )
            or text
        )
    except Exception:  # noqa: BLE001 - a label is never worth a failure
        return text


def _promote_domain(
    domain: str,
    leaks: list[RejectedSecretCandidate],
    report: Any,
) -> bool:
    """Promote one domain's cross-attributed leaks in a loaded report.

    Returns:
        ``True`` when the report was mutated.
    """
    entry = _domain_entry(report, domain)
    if entry is None:
        return False
    findings = entry.get("findings")
    if not isinstance(findings, list) or not findings:
        return False

    changed = False
    # Group by target finding so one finding carrying several leaks is woven
    # once, with one statement naming all of them.
    grouped: dict[int, list[RejectedSecretCandidate]] = {}
    for leak in leaks:
        target = _select_target_finding(findings, leak)
        if target is None:
            print_info_debug(
                "[report] cross-attributed attribute secret has no recorded "
                "finding to promote; leaving the artifact untouched"
            )
            continue
        grouped.setdefault(id(target), []).append(leak)
    targets = {id(f): f for f in findings if isinstance(f, dict)}

    for target_id, target_leaks in grouped.items():
        finding = targets.get(target_id)
        if finding is None:
            continue
        finding_changed = False
        details = finding.get("details")
        if not isinstance(details, dict):
            details = {}
            finding["details"] = details

        join: list[dict[str, Any]] = []
        copy_leaks: list[CrossAttributedLeak] = []
        for leak in target_leaks:
            principals = [
                hit.compromised_principal
                for hit in leak.cross_attributed_hits
                if hit.compromised_principal
            ]
            if not principals:
                continue
            leaking = str(leak.source.principal or leak.rejected_for or "").strip()
            attribute = str(leak.source.attribute or "").strip()
            join.append(
                {
                    "leaking_principal": leaking,
                    "attribute": attribute,
                    "compromised_principals": principals,
                    "at": next(
                        (hit.at for hit in leak.cross_attributed_hits if hit.at), ""
                    ),
                }
            )
            copy_leaks.append(
                CrossAttributedLeak(
                    leaking_display=_display(leaking, domain),
                    attribute=attribute,
                    compromised_displays=tuple(
                        _display(name, domain) for name in principals
                    ),
                )
            )
            finding_changed |= _record_proof(details, leak, principals)
            finding_changed |= _annotate_leaking_record(
                details, leaking, attribute, principals
            )

        if not join:
            continue
        if details.get(CROSS_ATTRIBUTION_DETAIL_KEY) != join:
            details[CROSS_ATTRIBUTION_DETAIL_KEY] = join
            finding_changed = True
        if _apply_catalog_identity(finding):
            finding_changed = True
        if _weave_statement(finding, cross_attributed_secret_statement(copy_leaks)):
            finding_changed = True
        if finding.get("status") != "confirmed":
            finding["status"] = "confirmed"
            finding_changed = True
        if finding_changed:
            finding["last_seen"] = _utc_now_iso()
            changed = True
    return changed


def _record_proof(
    details: dict[str, Any],
    leak: RejectedSecretCandidate,
    principals: list[str],
) -> bool:
    """Add one record per compromised principal, idempotently.

    The record names the account the value OPENS and says so with
    ``verified: True``, which is the flag the per-row rendering reads. It
    carries the leak it came from under its own field names, never under
    ``field``: that key is the affected-asset qualifier and would read as "this
    account's own attribute", which is the one thing this finding must not say.
    """
    container = details.get(_PROOF_CONTAINER)
    if not isinstance(container, list):
        container = []
        details[_PROOF_CONTAINER] = container
    leaking = str(leak.source.principal or leak.rejected_for or "").strip()
    attribute = str(leak.source.attribute or "").strip()
    changed = False
    for principal in principals:
        wanted = principal.strip().lower()
        existing = next(
            (
                item
                for item in container
                if isinstance(item, dict)
                and _record_name(item) == wanted
                and str(item.get("cross_attributed_from") or "").strip().lower()
                == leaking.lower()
            ),
            None,
        )
        record = {
            "samaccountname": principal,
            "verified": True,
            "cross_attributed_from": leaking,
            "cross_attributed_from_attribute": attribute,
            "rule_name": str(leak.source.rule or ""),
        }
        if existing is None:
            container.append(record)
            changed = True
        elif any(existing.get(k) != v for k, v in record.items()):
            existing.update(record)
            changed = True
    return changed


def _annotate_leaking_record(
    details: dict[str, Any],
    leaking: str,
    attribute: str,
    principals: list[str],
) -> bool:
    """Name the proven accounts on the LEAKING object's own record.

    The record keeps ``verified: False``: the value genuinely did not
    authenticate as this account, and flipping that flag would turn an honest
    observation into a claim the run cannot support. What it gains is the other
    half of the join, so a reader of the raw artifact can follow the attribute
    to the account it opens.
    """
    wanted = str(leaking or "").strip().lower()
    if not wanted:
        return False
    changed = False
    for container in _RECORD_CONTAINERS:
        for record in _records(details, container):
            if _record_name(record) != wanted:
                continue
            if attribute and str(record.get("field") or "").strip().lower() not in (
                "",
                attribute.lower(),
            ):
                continue
            if record.get("verified") is True:
                # The CONFIRMED producer's own record for this account. Its
                # value authenticated, so it is not the leak being promoted.
                continue
            current = record.get("cross_attributed_to")
            if current != principals:
                record["cross_attributed_to"] = list(principals)
                changed = True
    return changed


def promote_cross_attributed_attribute_secrets(
    shell: ReportShell,
    workspace_dir: str,
    *,
    domains: Iterable[str] | None = None,
) -> bool:
    """Promote every domain's cross-attributed attribute leaks in the report.

    Best-effort and total: a workspace with no leak records, or none carrying a
    proven other principal, is left byte-identical, and any failure is logged
    rather than raised, because a deliverable must never fail to render over an
    enrichment.

    Args:
        shell: The report shell the reconciliation already built (it resolves
            the exact ``technical_report.json`` being rendered).
        workspace_dir: Workspace root holding the credential store.
        domains: Domains to consider. ``None`` reads every domain the
            credential store knows.

    Returns:
        ``True`` when the technical report was rewritten.
    """
    try:
        domains_data = _pool_domains_data(workspace_dir)
        if not domains_data:
            return False
        names = (
            [str(name) for name in domains if str(name).strip()]
            if domains is not None
            else [str(name) for name in domains_data.keys()]
        )
        pending = {
            name: leaks
            for name in names
            if (leaks := _promotable_leaks(domains_data, name))
        }
        if not pending:
            return False

        report = _load_technical_report(shell)
        changed = False
        for name, leaks in pending.items():
            changed |= _promote_domain(name, leaks, report)
        if changed:
            _save_technical_report(shell, report)
        return changed
    except Exception as exc:  # noqa: BLE001 - a report never fails on this
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False


__all__ = [
    "CANONICAL_FINDING_KEY",
    "CROSS_ATTRIBUTION_DETAIL_KEY",
    "PROMOTED_FROM_DETAIL_KEY",
    "UNPROVEN_FINDING_KEYS",
    "promote_cross_attributed_attribute_secrets",
]
