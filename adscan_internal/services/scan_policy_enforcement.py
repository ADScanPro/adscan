"""Engine-side scan-policy enforcement: the one refusal path every seam uses.

The fail-closed predicates live in :mod:`adscan_core.scan_policy.gate` (pure,
shell-attribute based, importable from ``adscan_core``). This module adds the
engine-side pieces the seams need on top of them:

* **Relation canonicalisation.** Attack-graph steps carry relation names in
  several spellings (``GenericAll``, ``AllowedToActOnBehalfOfOtherIdentity``,
  ``MssqlImpersonateLogin``). The registry is keyed by the catalog's canonical
  key, so a seam must resolve the catalog entry first; otherwise a legitimate
  step would fail closed as "unknown".
* **Safety ownership.** The four hard-blocked techniques (``never_executed``)
  are refused by the destructive-action policy and rendered as a safety
  abstention. The scan policy never claims them, so they keep their
  ``safety_blocked`` label instead of reading "excluded by scan policy".
* **:func:`refuse`.** The operator explanation (through the skip-notice SSOT,
  :mod:`adscan_internal.services.scan_policy_notice`), the run record, the edge note
  ``not_executed_reason = "excluded_by_scan_policy"`` (the step keeps its
  status: it is never written ``blocked`` or ``attempted``) and the execution
  event. Callers never print their own line.

Every refusal is also appended to ``shell._scan_policy_refusals`` so the
disclosure layer can state what was not executed and where.

Design: docs/superpowers/specs/2026-11-04-scan-policy-checks-by-family-design.md § 7.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Iterable

from rich.markup import escape as rich_markup_escape

from adscan_core.rich_output import print_exception, print_info, print_info_debug
from adscan_core.scan_policy import gate
from adscan_core.scan_policy.model import (
    LOCKED_NEVER_EXECUTED,
    UNDECLARED,
    WRITING_ENVIRONMENT_CHANGES,
    CheckDefinition,
)
from adscan_core.scan_policy.registry import CheckRegistry, load_registry
from adscan_internal import telemetry
from adscan_internal.rich_output import mark_sensitive

#: Value of the edge note ``not_executed_reason`` for a policy exclusion.
NOT_EXECUTED_REASON = "excluded_by_scan_policy"
#: Edge / step note keys written on a refused step.
NOTE_REASON_KEY = "not_executed_reason"
NOTE_CHECK_KEY = "scan_policy_check_id"
#: ``meta.execution_support_status`` of a path the policy keeps from starting.
EXECUTION_STATUS_EXCLUDED = NOT_EXECUTED_REASON
#: Operator-facing suffix shared by every refusal line.
REFUSAL_SUFFIX = "not executed: excluded by scan policy."
#: Suffix of a refusal made only because the policy leaves attack steps to an
#: operator and this run has none (execution spec § 4, ``map_only``).
OPERATOR_REQUIRED_SUFFIX = "not executed: the scan policy leaves this step to an operator."
#: Record ``reason`` of a map-only refusal.
REASON_OPERATOR_REQUIRED = "operator_required"
#: Refusal surfaces that answer a step the operator asked for directly. A
#: repeated refusal there still prints a short line (never a silent stop).
OPERATOR_REQUEST_SURFACES = frozenset({"attack_path"})

#: Statuses that mean a step already ran in an earlier scan.
_ALREADY_PROCESSED_STATUSES = frozenset({"success", "succeeded", "attempted"})

_SHELL_REFUSALS_ATTR = "_scan_policy_refusals"
_SHELL_REFUSAL_KEYS_ATTR = "_scan_policy_refusal_keys"


# ── lookups ──────────────────────────────────────────────────────────────────
def policy_active(shell: Any) -> bool:
    """True when a resolved scan policy is in force on ``shell``."""
    return gate.active_policy(shell) is not None


def _registry(shell: Any) -> CheckRegistry:
    reg = getattr(shell, "scan_policy_registry", None)
    return reg if isinstance(reg, CheckRegistry) else load_registry()


def canonical_relation(shell: Any, relation: str) -> str:
    """Return the registry key for an attack-graph relation spelling.

    The registry is consulted first (so an execution alias the registry folds,
    such as ``sqlaccess``, keeps its own key); then the catalog entry; then the
    execution-family normaliser.
    """
    raw = str(relation or "").strip().lower()
    if not raw:
        return ""
    reg = _registry(shell)
    if reg.is_known_relation(raw):
        return raw
    try:
        from adscan_internal.services.attack_step_catalog import (  # noqa: PLC0415
            get_attack_step_entry,
            normalize_execution_relation,
        )

        entry = get_attack_step_entry(raw)
        if entry is not None and reg.is_known_relation(entry.relation):
            return entry.relation
        normalized = normalize_execution_relation(raw)
        if normalized and reg.is_known_relation(normalized):
            return normalized
    except Exception as exc:  # noqa: BLE001 - canonicalisation is best-effort
        telemetry.capture_exception(exc)
    return raw


def check_for_relation(shell: Any, relation: str) -> CheckDefinition | None:
    """The technique check that gates ``relation`` (aliases folded), or ``None``."""
    return _registry(shell).check_for_relation(canonical_relation(shell, relation))


def relation_excluded(shell: Any, relation: str) -> bool:
    """True when the active policy refuses to execute ``relation``.

    ``False`` without a policy (today's behaviour) and for a hard-blocked
    technique, which the safety policy refuses and labels on its own. With a
    policy, a relation the registry does not know is refused (fail closed).
    """
    if not policy_active(shell):
        return False
    try:
        canonical = canonical_relation(shell, relation)
        check = _registry(shell).check_for_relation(canonical)
        if check is not None and check.locked_state == LOCKED_NEVER_EXECUTED:
            return False
        return not gate.relation_allowed(shell, canonical)
    except Exception as exc:  # noqa: BLE001 - a broken policy fails closed
        telemetry.capture_exception(exc)
        return True


def check_excluded(shell: Any, check_id: str) -> bool:
    """True when the active policy switches ``check_id`` off (fail closed)."""
    if not policy_active(shell):
        return False
    return not gate.check_allowed(shell, check_id)


def cve_excluded(shell: Any, cve_id: str) -> bool:
    """True when the active policy refuses the CVE probe ``cve_id``."""
    if not policy_active(shell):
        return False
    return not gate.cve_allowed(shell, cve_id)


def job_excluded(shell: Any, kind: str) -> bool:
    """True when the active policy refuses the background job ``kind``."""
    if not policy_active(shell):
        return False
    return not gate.job_allowed(shell, kind)


def step_excluded(shell: Any, step: dict[str, Any]) -> bool:
    """True when the path step's relation is excluded by the active policy."""
    if not isinstance(step, dict):
        return False
    return relation_excluded(shell, str(step.get("action") or ""))


def step_already_processed(step: dict[str, Any]) -> bool:
    """True when a step already ran in an earlier scan (nothing to execute now)."""
    if not isinstance(step, dict):
        return False
    return str(step.get("status") or "").strip().lower() in _ALREADY_PROCESSED_STATUSES


def pending_excluded_steps(
    shell: Any, steps: Iterable[Any], *, counts: Callable[[str], bool]
) -> list[tuple[int, dict[str, Any]]]:
    """Every pending executable step of a path the active policy excludes.

    Same reading as :func:`first_pending_excluded_step` (``counts`` decides which
    relations are executable steps; a step already processed in an earlier scan
    is passed over because it will not run again), but over the WHOLE path. A
    path with at least one is one the policy cuts short: it cannot be walked end
    to end in this run. Index is 1-based. Empty without a policy.
    """
    found: list[tuple[int, dict[str, Any]]] = []
    if not policy_active(shell):
        return found
    for idx, step in enumerate(steps or (), start=1):
        if not isinstance(step, dict):
            continue
        action = str(step.get("action") or "").strip().lower()
        if not action or not counts(action):
            continue
        if step_already_processed(step):
            continue
        if relation_excluded(shell, action):
            found.append((idx, step))
    return found


def relation_writes_directory(shell: Any, relation: str) -> bool:
    """Whether the technique behind ``relation`` changes the client's directory.

    Read from the check registry's declared ``environment_change`` (the same
    metadata the policy summary and the built-ins are computed from), never a
    hand list: any writing class (reverted automatically, reverted at exit,
    manual cleanup, not reversible) counts, and so does an UNDECLARED one, which
    is treated as the worst case. A relation that is not a check (graph glue,
    a read-only technique) does not write.
    """
    try:
        check = _registry(shell).check_for_relation(canonical_relation(shell, relation))
    except Exception as exc:  # noqa: BLE001 - unknown means "may write"
        telemetry.capture_exception(exc)
        return True
    if check is None:
        return False
    change = str(check.environment_change or "")
    return change in WRITING_ENVIRONMENT_CHANGES or change == UNDECLARED


def first_pending_excluded_step(
    shell: Any, steps: Iterable[Any], *, counts: Callable[[str], bool]
) -> tuple[int, dict[str, Any]] | None:
    """Return ``(index, step)`` when the path's first pending step is excluded.

    ``counts`` decides which relations are executable steps (the readiness
    predicate of the caller). Steps already processed in an earlier scan are
    passed over: they will not execute again, so they do not decide whether the
    path can start. Index is 1-based, like the executor's step indices.
    """
    if not policy_active(shell):
        return None
    for idx, step in enumerate(steps or (), start=1):
        if not isinstance(step, dict):
            continue
        action = str(step.get("action") or "").strip().lower()
        if not action or not counts(action):
            continue
        if step_already_processed(step):
            continue
        if relation_excluded(shell, action):
            return idx, step
        return None
    return None


def excluded_relations_in(shell: Any, steps: Iterable[Any]) -> list[str]:
    """Distinct excluded relations of a path, in path order."""
    out: list[str] = []
    if not policy_active(shell):
        return out
    for step in steps or ():
        if not isinstance(step, dict):
            continue
        action = str(step.get("action") or "").strip()
        if action and action.lower() not in {a.lower() for a in out}:
            if relation_excluded(shell, action):
                out.append(action)
    return out


def check_title(shell: Any, check_id: str) -> str:
    """Client-facing title of a check (the id when unknown)."""
    check = _registry(shell).get(check_id)
    return check.title if check is not None and check.title else str(check_id)


def check_id_for(shell: Any, *, relation: str = "", check_id: str = "") -> str:
    """Resolve the check id behind a relation or return ``check_id`` as given."""
    if check_id:
        return check_id
    check = check_for_relation(shell, relation)
    if check is not None:
        return check.check_id
    canonical = canonical_relation(shell, relation)
    return f"step:{canonical}" if canonical else ""


def scan_policy_note(check_id: str) -> dict[str, str]:
    """The edge / step note recording a policy exclusion."""
    return {NOTE_REASON_KEY: NOT_EXECUTED_REASON, NOTE_CHECK_KEY: str(check_id)}


def refusals(shell: Any) -> list[dict[str, Any]]:
    """Every refusal recorded on ``shell`` in this session (oldest first)."""
    recorded = getattr(shell, _SHELL_REFUSALS_ATTR, None)
    return list(recorded) if isinstance(recorded, list) else []


def refused_only_for_operator(shell: Any, check_id: str) -> bool:
    """Public name of :func:`_refused_only_for_operator` (reason 2 vs reason 1)."""
    return _refused_only_for_operator(shell, check_id)


def _refused_only_for_operator(shell: Any, check_id: str) -> bool:
    """True when the policy enables ``check_id`` and only map-only refuses it."""
    try:
        from adscan_core.scan_policy.execution import (  # noqa: PLC0415
            DECISION_MAP_ONLY,
            execution_decision,
        )

        policy = gate.active_policy(shell)
        return (
            policy is not None
            and check_id in policy.effective_ids
            and execution_decision(shell) == DECISION_MAP_ONLY
        )
    except Exception:  # noqa: BLE001 - wording only
        return False


# ── the refusal path ─────────────────────────────────────────────────────────
def refuse(
    shell: Any,
    check_id: str,
    *,
    surface: str,
    domain: str = "",
    relation: str = "",
    from_label: str = "",
    to_label: str = "",
    step_status: str | None = None,
    event_recorder: Callable[[str, dict[str, Any]], None] | None = None,
) -> None:
    """Refuse one excluded check: one explanation, one record, one edge note.

    The explanation goes through :func:`notify_policy_skip` (first skip of a
    check in full, repeats collapsed, a short line for a repeat on an
    operator-requested surface); the record is kept once per
    ``(check, surface, from, to)``.

    Args:
        shell: The pentest shell.
        check_id: The excluded check id (resolved from ``relation`` when empty).
        surface: Which seam refused (``attack_path``, ``followup``, ``runner``,
            ``cve_probe``, ``job``, ``spray``, ...). Recorded for disclosure.
        domain: Domain of the attack-graph edge, when the refusal is a path step.
        relation: The attack-graph relation, when there is one.
        from_label / to_label: Edge endpoints; with ``domain`` set, the edge
            receives the ``excluded_by_scan_policy`` note.
        step_status: The step's current status, written back unchanged (the
            graph's status ordering never lowers a status, so a fresh step stays
            theoretical and a proven one stays proven).
        event_recorder: Optional ``(message, details) -> None`` callback that
            persists the attack-path execution event in the caller's vocabulary.
    """
    resolved_id = check_id_for(shell, relation=relation, check_id=check_id)
    title = check_title(shell, resolved_id) if resolved_id else (relation or "This check")
    target = str(to_label or "").strip()
    key = (resolved_id, surface, str(from_label or "").strip().lower(), target.lower())

    seen = getattr(shell, _SHELL_REFUSAL_KEYS_ATTR, None)
    if not isinstance(seen, set):
        seen = set()
        try:
            setattr(shell, _SHELL_REFUSAL_KEYS_ATTR, seen)
        except Exception:  # noqa: BLE001 - a read-only shell still refuses
            pass
    first_time = key not in seen
    seen.add(key)
    operator_required = _refused_only_for_operator(shell, resolved_id)
    suffix = OPERATOR_REQUIRED_SUFFIX if operator_required else REFUSAL_SUFFIX
    reason = REASON_OPERATOR_REQUIRED if operator_required else NOT_EXECUTED_REASON

    # The operator explanation goes through the skip-notice SSOT: the first skip
    # of a check names the policy and the command that turns it back on, a
    # repeat is collapsed, and a repeat the operator asked for directly (an
    # attack path they chose) still gets a short line so it never stops in
    # silence. A map-only refusal (no operator, ``adscan ci``) is not a policy
    # exclusion the operator can reverse from here; it keeps its own line.
    # The disclosure record is kept once per (check, surface, edge).
    if operator_required:
        if target:
            line = (
                f"{rich_markup_escape(title)} on {mark_sensitive(target, 'node')} "
                f"{suffix}"
            )
        else:
            line = f"{rich_markup_escape(title)} {suffix}"
        print_info(line)
    else:
        from adscan_internal.services.scan_policy_notice import (  # noqa: PLC0415
            notify_policy_skip,
        )

        operator_request = surface in OPERATOR_REQUEST_SURFACES
        # Inside an attack-path run the step result shows the same explanation
        # (attack_path_execution_run), so an inline line would say it twice.
        in_run = False
        if operator_request:
            try:
                from adscan_internal.services.attack_path_execution_run import (  # noqa: PLC0415
                    get_active_execution_run,
                )

                in_run = get_active_execution_run(shell) is not None
            except Exception:  # noqa: BLE001 - wording only
                in_run = False
        notify_policy_skip(
            shell,
            [resolved_id] if resolved_id else [],
            subject=title,
            key=resolved_id or title,
            target=target,
            operator_request=operator_request,
            inline=not in_run,
        )

    if first_time:
        record = {
            "check_id": resolved_id,
            "relation": str(relation or "").strip().lower(),
            "surface": surface,
            "domain": str(domain or "").strip(),
            "from": str(from_label or "").strip(),
            "to": target,
            "reason": reason,
            "at": time.time(),
        }
        recorded = getattr(shell, _SHELL_REFUSALS_ATTR, None)
        if not isinstance(recorded, list):
            recorded = []
            try:
                setattr(shell, _SHELL_REFUSALS_ATTR, recorded)
            except Exception:  # noqa: BLE001
                pass
        recorded.append(record)

    print_info_debug(
        "scan-policy refuse: "
        f"check={mark_sensitive(resolved_id or '?', 'detail')} surface={surface} "
        f"from={mark_sensitive(from_label or 'N/A', 'node')} "
        f"to={mark_sensitive(target or 'N/A', 'node')} first={first_time}"
    )

    notes = scan_policy_note(resolved_id)
    if domain and from_label and target and relation:
        try:
            from adscan_internal.services.attack_graph_service import (  # noqa: PLC0415
                update_edge_status_by_labels,
            )

            update_edge_status_by_labels(
                shell,
                domain,
                from_label=from_label,
                relation=relation,
                to_label=target,
                status=str(step_status or "theoretical").strip().lower() or "theoretical",
                notes=notes,
            )
        except Exception as exc:  # noqa: BLE001 - the note never breaks the scan
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    if event_recorder is not None:
        try:
            event_recorder(
                f"{title} {suffix}",
                {"check_id": resolved_id, "reason": reason, **notes},
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)


def refuse_relation(
    shell: Any,
    relation: str,
    *,
    surface: str,
    domain: str = "",
    from_label: str = "",
    to_label: str = "",
    step_status: str | None = None,
    event_recorder: Callable[[str, dict[str, Any]], None] | None = None,
) -> None:
    """:func:`refuse` keyed by an attack-step relation."""
    refuse(
        shell,
        "",
        surface=surface,
        domain=domain,
        relation=relation,
        from_label=from_label,
        to_label=to_label,
        step_status=step_status,
        event_recorder=event_recorder,
    )


def gate_relation_runner(shell: Any, relation: str, *, surface: str = "runner") -> bool:
    """Seam helper for a direct technique runner.

    Returns True when the runner may proceed; otherwise refuses (one line) and
    returns False so the runner returns its own "nothing done" sentinel.
    """
    if not relation_excluded(shell, relation):
        return True
    refuse_relation(shell, relation, surface=surface)
    return False


#: ``meta`` keys the executor's readiness overlay stamps on a path the active
#: policy cuts short (a pending step of it is excluded): the 1-based index of
#: the first such step, and its check id. Absent when the path can run end to
#: end or no policy is active.
META_CUT_SHORT_AT_KEY = "scan_policy_cut_short_at"
META_CUT_SHORT_CHECK_KEY = "scan_policy_cut_short_check_id"


def path_cut_short_by_policy(record: Any) -> bool:
    """True when the readiness overlay stamped ``record`` as cut short by the policy."""
    meta = record.get("meta") if isinstance(record, dict) else None
    return isinstance(meta, dict) and bool(meta.get(META_CUT_SHORT_AT_KEY))


#: Surface of a refusal made inside another technique's branch.
CHAINED_STEP_SURFACE = "chained_step"


def gate_chained_technique(
    shell: Any, technique: str, *, via_relation: str = "", target: str = ""
) -> bool:
    """Gate a technique reached through ANOTHER relation's branch.

    A path step is gated on its own relation before it runs, but several
    branches perform a different technique than the one the step names: a
    GenericAll over a group adds a member, a GenericAll over a domain replicates
    it, AllExtendedRights is remapped to ForceChangePassword / DCSync /
    ReadLAPSPassword, and a GenericAll over a user can fall back to a password
    reset. Each of those techniques has its own switch in the policy, and a
    client who switched one off must never see it run through a neighbouring
    switch. Every such branch asks here, with the technique it is about to
    perform.

    Returns True when the technique may run (always, without a policy). When the
    policy excludes it, the refusal is explained and recorded once (surface
    :data:`CHAINED_STEP_SURFACE`) and False is returned. No edge note is
    written: the graph edge is the parent relation's, not this technique's.

    Args:
        shell: The pentest shell.
        technique: The relation actually performed (``forcechangepassword``).
        via_relation: The branch that reached it (debug only).
        target: The object it would act on (disclosure record only).
    """
    if not relation_excluded(shell, technique):
        return True
    print_info_debug(
        "scan-policy chained technique refused: "
        f"technique={mark_sensitive(technique, 'detail')} "
        f"via={mark_sensitive(via_relation or 'N/A', 'detail')}"
    )
    refuse_relation(shell, technique, surface=CHAINED_STEP_SURFACE, to_label=target)
    try:
        setattr(shell, _SHELL_LAST_CHAINED_ATTR, str(technique or "").strip().lower())
    except Exception:  # noqa: BLE001 - a read-only shell still refused
        pass
    return False


# ── a step that ran nothing because the policy refused its technique ─────────
_SHELL_LAST_CHAINED_ATTR = "_scan_policy_last_chained_refusal"
_SHELL_STEP_NOT_EXECUTED_ATTR = "_scan_policy_step_not_executed"


def mark_step_not_executed(shell: Any, technique: str = "") -> None:
    """Record that the current attack step ran NOTHING because of the policy.

    Called at the exits where a branch gives up without performing any write or
    read because the technique it would perform is excluded (the chained
    refusals of the ACE dispatcher, the ForceChangePassword choke point, the
    GenericAll menu with no allowed technique left). A branch that refused one
    technique and then RAN another does not call this: that step was attempted.

    The attack-path executor consumes it (:func:`consume_step_not_executed`) and
    represents the step exactly like a step excluded directly: its status stays
    a not-run status and it carries the ``excluded_by_scan_policy`` note.

    Args:
        shell: The pentest shell.
        technique: The excluded technique; the last chained refusal when empty.
    """
    relation = str(technique or "").strip().lower() or str(
        getattr(shell, _SHELL_LAST_CHAINED_ATTR, "") or ""
    )
    if not relation:
        return
    try:
        setattr(
            shell,
            _SHELL_STEP_NOT_EXECUTED_ATTR,
            {"relation": relation, "check_id": check_id_for(shell, relation=relation)},
        )
    except Exception:  # noqa: BLE001
        pass


def consume_step_not_executed(shell: Any) -> dict[str, str] | None:
    """Return and clear the marker :func:`mark_step_not_executed` left, if any."""
    marker = getattr(shell, _SHELL_STEP_NOT_EXECUTED_ATTR, None)
    try:
        setattr(shell, _SHELL_STEP_NOT_EXECUTED_ATTR, None)
        setattr(shell, _SHELL_LAST_CHAINED_ATTR, "")
    except Exception:  # noqa: BLE001
        pass
    return dict(marker) if isinstance(marker, dict) and marker.get("relation") else None


def gate_check_runner(shell: Any, check_id: str, *, surface: str = "runner") -> bool:
    """Seam helper for a runner bound to a non-relation check (module, job)."""
    if not check_excluded(shell, check_id):
        return True
    refuse(shell, check_id, surface=surface)
    return False


#: Every source of a HARVESTED secret (a password ADscan reads in the directory
#: or in SYSVOL and can only confirm by signing in with it), keyed by the
#: ``credential_origin`` slug the harvest records, mapped to the check that
#: declares that sign-in. The check IS the verification: with it off, the
#: secret is never signed in with, whatever path read it (authenticated LDAP,
#: anonymous LDAP, a SAMR or SMB null session, SYSVOL over a guest session).
#: Release gate 14.0.0: with ``step:userdescription`` off, the unauthenticated
#: recon still read a description password over a SAMR null session and signed
#: in with it.
HARVESTED_SECRET_CHECKS: dict[str, str] = {
    "userdescription": "step:userdescription",
    "user_description": "step:userdescription",
    "gpp_cpassword": "step:gpppassword",
    "gpppassword": "step:gpppassword",
    "gpp_autologon": "module:quick_credential_wins.gpp_autologin",
    "gppautologon": "module:quick_credential_wins.gpp_autologin",
}
#: Refusal surface of a harvested secret kept from a sign-in.
HARVESTED_SECRET_SURFACE = "credential_harvest"
#: Finding-detail value recording why a harvested secret was not verified.
HARVESTED_SECRET_NOT_VERIFIED_BY_POLICY = "not_verified_scan_policy"


def harvested_secret_check(origin: str | None) -> str:
    """The check that declares the sign-in verifying a harvested secret, or ``""``."""
    return HARVESTED_SECRET_CHECKS.get(str(origin or "").strip().lower(), "")


def harvested_secret_excluded(shell: Any, origin: str | None) -> bool:
    """True when the active policy forbids signing in with a secret from ``origin``.

    Pure predicate (no notice): for a caller that only needs the answer, such as
    the ``add_credential`` backstop. Without a policy, or for an origin that is
    not a harvest source, it is False.
    """
    check_id = harvested_secret_check(origin)
    return bool(check_id) and check_excluded(shell, check_id)


def gate_harvested_secret_verification(
    shell: Any, origin: str | None, *, domain: str = ""
) -> bool:
    """Seam for every path that would sign in with a harvested secret.

    Returns True when the secret may be verified (saved and signed in with).
    When the active policy switches the source's check off, the refusal is
    explained once through the notice SSOT and False is returned: the caller
    then records what it read as a mapped, unverified finding, never a sign-in.
    """
    check_id = harvested_secret_check(origin)
    if not check_id or not check_excluded(shell, check_id):
        return True
    refuse(shell, check_id, surface=HARVESTED_SECRET_SURFACE, domain=domain)
    return False


def check_consented(
    shell: Any, check_id: str, *, prompt: str, surface: str = "runner"
) -> bool:
    """Consent seam of an optional check that asks the operator before it runs.

    When the active policy switches ``check_id`` off, nothing is asked and the
    refusal is explained once. Otherwise the yes/no question defaults to yes
    only when a scan policy is in force (and therefore enables the check): an
    unattended run resolves to the default, so it runs the check only under a
    policy that turns it on. Same contract as ``cli/smb.local_credential_reuse_consented``.

    Args:
        shell: The pentest shell.
        check_id: The registry check this question runs.
        prompt: The yes/no question for an interactive operator.
        surface: Refusal surface recorded for the disclosure.

    Returns:
        True when the check should run.
    """
    if not gate_check_runner(shell, check_id, surface=surface):
        return False
    from adscan_core.rich_output import confirm_ask  # noqa: PLC0415

    return bool(confirm_ask(prompt, default=policy_active(shell)))


__all__ = (
    "CHAINED_STEP_SURFACE",
    "check_consented",
    "META_CUT_SHORT_AT_KEY",
    "META_CUT_SHORT_CHECK_KEY",
    "EXECUTION_STATUS_EXCLUDED",
    "NOTE_CHECK_KEY",
    "NOTE_REASON_KEY",
    "NOT_EXECUTED_REASON",
    "OPERATOR_REQUEST_SURFACES",
    "OPERATOR_REQUIRED_SUFFIX",
    "REASON_OPERATOR_REQUIRED",
    "REFUSAL_SUFFIX",
    "canonical_relation",
    "check_excluded",
    "check_for_relation",
    "check_id_for",
    "check_title",
    "consume_step_not_executed",
    "cve_excluded",
    "excluded_relations_in",
    "first_pending_excluded_step",
    "gate_chained_technique",
    "gate_check_runner",
    "gate_harvested_secret_verification",
    "harvested_secret_check",
    "harvested_secret_excluded",
    "HARVESTED_SECRET_CHECKS",
    "HARVESTED_SECRET_NOT_VERIFIED_BY_POLICY",
    "HARVESTED_SECRET_SURFACE",
    "gate_relation_runner",
    "job_excluded",
    "mark_step_not_executed",
    "path_cut_short_by_policy",
    "policy_active",
    "refusals",
    "refuse",
    "refuse_relation",
    "relation_excluded",
    "relation_writes_directory",
    "pending_excluded_steps",
    "scan_policy_note",
    "step_already_processed",
    "step_excluded",
)
