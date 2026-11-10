"""Session scan controls: the scan policy and the scan pace of a workspace.

Two engine-wide controls are resolved at the same entry points and persisted in
the same workspace:

* the **scan policy** (which checks may run), resolved by
  :func:`adscan_core.scan_policy.resolve.resolve_policy` into
  ``shell.scan_policy``, the object every enforcement gate reads;
* the **scan pace** (how hard ADscan works the network), resolved by
  :func:`adscan_core.scan_pacing.resolve_pacing` and published with
  :func:`adscan_core.scan_pacing.set_active_pacing` (the shell-less bridge the
  engine consumers read), also kept on ``shell.scan_pacing``.

A policy CAPS the pace: a per-scan choice may be slower than the policy's pace,
never faster (scan-policy spec D-11, pacing spec § 4.3). The cap is applied by
the pacing resolver; this module only derives the ceiling from the policy.

Entry points, and nowhere else:

* :func:`apply_ci_scan_controls`: ``adscan ci``, after the workspace is open.
* :func:`apply_workspace_scan_controls`: workspace load (REPL ``start``,
  ``adscan execute``, ``workspace`` switches), from the persisted state.
* the REPL ``policy`` and ``set pacing`` commands, through :func:`set_policy`,
  :func:`clear_policy` and :func:`publish_pacing`.

The policy is also the single source of truth of the workspace TYPE. A policy
names the environment it is written for (``lab`` or ``real``,
:func:`adscan_core.scan_policy.policy.effective_environment`) and the type every
reader still consults (``ctf`` / ``audit``) is derived from it by
:func:`workspace_type`, the one accessor (``PentestShell.type`` is a property
over it). ``variables.json`` keeps a ``type`` key as a derived mirror for the
web and older readers; it is read back only to migrate a workspace saved before
the policy carried the environment (:func:`apply_workspace_scan_controls`).

Persistence: the policy (its definition, never the resolved sets, which depend
on the registry of the engine that reads it) and the pace ceiling live in
``<workspace>/scan_policy.json``; the pace REQUEST lives in ``variables.json``
under ``pacing`` (see ``workspaces/state.py``). A live scan writes into its
``.run_*`` execution workspace and the file is promoted with it.

Design: docs/superpowers/specs/2026-11-04-scan-policy-checks-by-family-design.md
§ 7.3-7.4 and docs/superpowers/specs/2026-11-04-scan-pacing-ssot-design.md § 4, § 6.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

from adscan_core.scan_pacing import (
    KNOBS_BY_KEY,
    UNLIMITED,
    PacingCeiling,
    PacingConfigError,
    PacingLevel,
    PacingRequest,
    PolicyRef,
    ResolvedPacing,
    parse_pacing_request,
    resolve_pacing,
    set_active_pacing,
    validate_knob_value,
)
from adscan_core.scan_pacing.pacing_model import parse_pacing_block, parse_profile_ref
from adscan_core.scan_pacing.pacing_profiles import (
    FittedPacing,
    PaceProfile,
    compose_pacing_request,
    fit_to_ceiling,
    lowered_sentence,
)
from adscan_core.scan_policy.policy import (
    ENVIRONMENTS,
    LEGACY_BASES,
    ScanPolicyDefinition,
    ScanPolicyError,
    builtin_definition,
    builtin_for_workspace_type,
    definition_to_section,
    effective_environment,
    effective_pacing,
    environment_for_workspace_type,
    parse_policy_definition,
    policy_display_name,
    workspace_type_for_environment,
)
from adscan_core.scan_policy.registry import CheckRegistry, load_registry
from adscan_core.scan_policy.resolve import ResolvedScanPolicy, resolve_policy

SCAN_POLICY_FILENAME = "scan_policy.json"
_FILE_SCHEMA_VERSION = 1

#: Where the policy of a run came from (disclosure + which one wins).
SOURCE_SCAN_CONFIG = "scan_config"
SOURCE_REPL = "repl"
SOURCE_WORKSPACE = "workspace"
SOURCE_UNREADABLE = "unreadable"
#: The built-in a workspace type selected: a workspace saved before the policy
#: carried the environment, or the ``set type`` / ``--type`` compatibility alias.
SOURCE_WORKSPACE_TYPE = "workspace_type"

#: Shell attributes this module owns.
ATTR_POLICY = "scan_policy"
ATTR_POLICY_SOURCE = "scan_policy_source"
ATTR_POLICY_CLEARED = "scan_policy_cleared"
ATTR_PACING = "scan_pacing"
ATTR_PACING_REQUEST = "scan_pacing_request"
ATTR_PACING_CEILING = "scan_pacing_ceiling"
#: True when an unattended run downgraded a saved Fast pace to Normal.
ATTR_PACING_FAST_DOWNGRADED = "scan_pacing_fast_downgraded"


class ScanControlsError(ValueError):
    """A scan policy or a pace cannot be applied; the run must not start."""


# ---------------------------------------------------------------------------
# Naming
# ---------------------------------------------------------------------------


# ``policy_display_name`` lives in ``adscan_core.scan_policy.policy`` (imported
# above) so the report's scope section and the web read the same name.


def short_digest(digest: str) -> str:
    """``sha256:1a2b3c4d5e6f`` from a full ``sha256:<hex>`` digest."""
    algo, _, hexpart = str(digest or "").partition(":")
    return f"{algo}:{hexpart[:12]}" if hexpart else str(digest or "")


# ---------------------------------------------------------------------------
# Policy resolution
# ---------------------------------------------------------------------------


def resolve_definition(
    definition: ScanPolicyDefinition,
    *,
    registry: CheckRegistry | None = None,
    legacy_disabled_phases: Iterable[str] = (),
    legacy_disabled_steps: Mapping[str, Iterable[str]] | None = None,
    strict: bool = True,
) -> ResolvedScanPolicy:
    """Resolve a definition, refusing ids this engine does not know when ``strict``.

    An unknown id in a policy is refused rather than skipped: a typo in
    ``disabled`` would otherwise let the very technique the client excluded run
    under their written authorization.
    """
    from adscan_internal.services.revert_permission import (  # noqa: PLC0415
        revert_permission_context,
    )

    resolved = resolve_policy(
        definition,
        registry or load_registry(),
        legacy_disabled_phases=legacy_disabled_phases,
        legacy_disabled_steps=legacy_disabled_steps,
        # Whether a cleanup account is supplied decides the checks whose change
        # only such an account can undo (reverted_when_permitted).
        revert_permission=revert_permission_context(),
    )
    if strict and resolved.unknown_ids:
        raise ScanControlsError(
            "The scan policy names check(s) this version of ADscan does not know: "
            f"{', '.join(resolved.unknown_ids)}."
        )
    return resolved


def pacing_ceiling_for_policy(resolved: ResolvedScanPolicy | None) -> PacingCeiling | None:
    """The pace ceiling a policy imposes, or ``None`` when it sets no pace."""
    pacing = effective_pacing(resolved.definition) if resolved is not None else None
    if not pacing:
        return None
    request = parse_pacing_request(pacing, source="policy")
    identity = resolved.definition.identity
    return PacingCeiling(
        level=request.level,
        overrides=request.overrides,
        policy=PolicyRef(
            policy_id=identity.policy_id,
            name=policy_display_name(resolved.definition),
            revision=identity.revision or None,
        ),
    )


def policy_pacing_request(resolved: ResolvedScanPolicy | None) -> PacingRequest | None:
    """The policy's own pace, used as the request when the scan chose none."""
    pacing = effective_pacing(resolved.definition) if resolved is not None else None
    if not pacing:
        return None
    return parse_pacing_request(pacing, source="policy")


# ---------------------------------------------------------------------------
# Persistence: <workspace>/scan_policy.json
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WorkspacePolicyRecord:
    """What a workspace persisted about its scan policy.

    Attributes:
        definition: The policy definition, or ``None`` when none applies.
        source: Where it was set (``scan_config`` or ``repl``).
        pacing_ceiling: The pace ceiling (from the policy or the scan config).
        cleared: The operator's ``policy clear`` record, kept for the next
            run's disclosure (scan-policy spec D-1), or ``None``.
        unreadable: True when a file exists but cannot be read; the caller then
            fails closed instead of running every check.
    """

    definition: ScanPolicyDefinition | None = None
    source: str = ""
    pacing_ceiling: PacingCeiling | None = None
    cleared: Mapping[str, Any] | None = None
    unreadable: bool = False


def policy_file(workspace_dir: str | os.PathLike[str]) -> Path:
    """Path of a workspace's persisted scan policy."""
    return Path(workspace_dir) / SCAN_POLICY_FILENAME


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_workspace_policy(workspace_dir: str | os.PathLike[str] | None) -> WorkspacePolicyRecord:
    """Read a workspace's persisted policy (absent file = no policy)."""
    if not workspace_dir:
        return WorkspacePolicyRecord()
    path = policy_file(workspace_dir)
    if not path.is_file():
        return WorkspacePolicyRecord()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, Mapping):
            raise ValueError("not a mapping")
        raw_definition = data.get("definition")
        definition = (
            parse_policy_definition(raw_definition) if raw_definition is not None else None
        )
        ceiling = None
        if data.get("pacing_ceiling") is not None:
            ceiling = parse_pacing_block({"ceiling": data["pacing_ceiling"]}).ceiling
        cleared = data.get("cleared")
        return WorkspacePolicyRecord(
            definition=definition,
            source=str(data.get("source") or ""),
            pacing_ceiling=ceiling,
            cleared=dict(cleared) if isinstance(cleared, Mapping) else None,
        )
    except (OSError, ValueError, ScanPolicyError, PacingConfigError):
        return WorkspacePolicyRecord(unreadable=True)


def _write_record(workspace_dir: str | os.PathLike[str], payload: Mapping[str, Any]) -> Path:
    path = policy_file(workspace_dir)
    from adscan_core.workspace_freeze import write_blocked  # noqa: PLC0415

    if write_blocked(path):
        # A frozen workspace (a recheck) keeps the scan's policy byte-identical.
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return path


def save_workspace_policy(
    workspace_dir: str | os.PathLike[str],
    resolved: ResolvedScanPolicy | None,
    *,
    source: str,
    pacing_ceiling: PacingCeiling | None = None,
) -> Path:
    """Persist the policy definition (and the pace ceiling) for this workspace.

    The resolved digest and registry version are written alongside for the
    operator and the disclosure; they are recomputed on every load.
    """
    payload: dict[str, Any] = {
        "schema_version": _FILE_SCHEMA_VERSION,
        "source": source,
        "saved_at": _utc_now(),
    }
    if resolved is not None:
        payload["definition"] = definition_to_section(resolved.definition)
        payload["name"] = policy_display_name(resolved.definition)
        payload["digest"] = resolved.digest
        payload["registry_version"] = resolved.registry_version
    if pacing_ceiling is not None:
        payload["pacing_ceiling"] = pacing_ceiling.to_dict()
    return _write_record(workspace_dir, payload)


def clear_workspace_policy(
    workspace_dir: str | os.PathLike[str], previous: ResolvedScanPolicy | None
) -> dict[str, Any]:
    """Remove the workspace policy, recording the clear for the next disclosure."""
    cleared: dict[str, Any] = {"cleared_by": "operator", "cleared_at": _utc_now()}
    if previous is not None:
        cleared["previous"] = {
            "name": policy_display_name(previous.definition),
            "digest": previous.digest,
            # Without a policy the workspace is still the environment the
            # cleared one was written for (see :func:`workspace_environment`).
            "environment": effective_environment(previous.definition),
        }
    _write_record(
        workspace_dir,
        {
            "schema_version": _FILE_SCHEMA_VERSION,
            "source": SOURCE_REPL,
            "saved_at": cleared["cleared_at"],
            "cleared": cleared,
        },
    )
    return cleared


#: Key the disclosure writes into the ``cleared`` record once a run has stated it.
CLEARED_DISCLOSED_AT_KEY = "disclosed_at"


def mark_policy_clear_disclosed(
    workspace_dir: str | os.PathLike[str] | None, *, disclosed_at: str | None = None
) -> bool:
    """Mark the workspace's ``policy clear`` record as stated in a run's disclosure.

    Contract (scan-policy spec D-1): the first run after an operator clears the
    policy discloses the clear in its coverage block, then calls this. Later runs
    see ``disclosed_at`` and no longer repeat it; a new policy replaces the whole
    record. Returns True when the record was updated. Best-effort.
    """
    if not workspace_dir:
        return False
    path = policy_file(workspace_dir)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    cleared = data.get("cleared") if isinstance(data, dict) else None
    if not isinstance(cleared, dict) or cleared.get(CLEARED_DISCLOSED_AT_KEY):
        return False
    cleared[CLEARED_DISCLOSED_AT_KEY] = disclosed_at or _utc_now()
    try:
        _write_record(workspace_dir, data)
    except OSError:
        return False
    return True


# ---------------------------------------------------------------------------
# Pacing
# ---------------------------------------------------------------------------


def format_knob_value(value: Any) -> str:
    """Canonical text of a knob value (``--pacing-set`` and the REPL)."""
    if value is True:
        return "on"
    if value is False:
        return "off"
    if isinstance(value, float):
        return f"{value:g}"
    return str(value)


def parse_pacing_assignments(items: Iterable[str] | None) -> dict[str, Any]:
    """Parse ``KNOB=VALUE`` items (``--pacing-set``); the last value of a knob wins.

    Raises:
        PacingConfigError: On a malformed item, an unknown knob or a bad value.
    """
    out: dict[str, Any] = {}
    for raw in items or ():
        key, sep, value = str(raw or "").partition("=")
        key = key.strip()
        if not sep or not key or not value.strip():
            raise PacingConfigError(
                f"--pacing-set expects KNOB=VALUE, got {raw!r} "
                "(for example max_parallel_hosts=4)"
            )
        out.pop(key, None)
        out[key] = validate_knob_value(key, value.strip())
    return out


def canonical_pacing_assignments(items: Iterable[str] | None) -> list[str]:
    """Canonical ``KNOB=VALUE`` list (validated, one entry per knob)."""
    return [f"{k}={format_knob_value(v)}" for k, v in parse_pacing_assignments(items).items()]


def cli_pacing_request(level: str | None, items: Iterable[str] | None) -> PacingRequest | None:
    """The CLI layer (``--pacing`` / ``--pacing-set``), or ``None`` when neither was given."""
    overrides = parse_pacing_assignments(items)
    if not level and not overrides:
        return None
    parsed_level = PacingLevel.coerce(level) if level else None
    if level and parsed_level is None:
        raise PacingConfigError(f"unknown pacing level {level!r}")
    return PacingRequest(
        level=parsed_level or PacingLevel.NORMAL,
        overrides=overrides,
        level_source="cli" if parsed_level is not None else "default",
        override_sources={key: "cli" for key in overrides},
    )


def publish_pacing(
    shell: Any,
    request: PacingRequest | None,
    ceiling: PacingCeiling | None,
    *,
    env: Mapping[str, str] | None = None,
) -> ResolvedPacing:
    """Resolve the pace and publish it for the engine (the only publish helper)."""
    resolved = resolve_pacing(request, ceiling=ceiling, env=env)
    set_active_pacing(resolved)
    setattr(shell, ATTR_PACING, resolved)
    setattr(shell, ATTR_PACING_CEILING, ceiling)
    return resolved


def session_pacing_ceiling(shell: Any) -> PacingCeiling | None:
    """The ceiling in force for this shell: the policy's pace, else a persisted one."""
    from_policy = pacing_ceiling_for_policy(getattr(shell, ATTR_POLICY, None))
    if from_policy is not None:
        return from_policy
    return getattr(shell, ATTR_PACING_CEILING, None)


def workspace_pacing_request(shell: Any) -> PacingRequest | None:
    """The pace the operator set for this workspace (REPL or a previous run)."""
    request = getattr(shell, ATTR_PACING_REQUEST, None)
    return request if isinstance(request, PacingRequest) else None


def pacing_request_for_save(shell: Any) -> dict[str, Any] | None:
    """The ``variables.json`` value of the workspace pace (``None`` = unset)."""
    request = workspace_pacing_request(shell)
    if request is None or (request.is_default and request.level_source == "default"):
        return None
    return request.to_dict()


def pacing_request_from_saved(raw: Any) -> PacingRequest | None:
    """Parse the ``variables.json`` value; a malformed value is ignored (pace is not a gate)."""
    if not isinstance(raw, Mapping) or not raw:
        return None
    try:
        request = parse_pacing_request(raw, source="workspace")
    except PacingConfigError:
        return None
    try:
        profile = parse_profile_ref(raw.get("profile"))
    except PacingConfigError:
        profile = None
    return replace(request, profile=profile) if profile is not None else request


def profile_lowered_message(fitted: FittedPacing, ceiling: PacingCeiling | None) -> str:
    """The line telling the user which profile values the policy lowered, or ``""``."""
    name = getattr(getattr(ceiling, "policy", None), "name", "") or ""
    return lowered_sentence(fitted.lowered, policy_name=name)


def apply_pace_profile(shell: Any, profile: PaceProfile) -> tuple[ResolvedPacing, FittedPacing]:
    """Make ``profile`` this workspace's pace (REPL ``pace use`` / ``set pacing.profile``).

    The profile REPLACES the workspace's pace. It is held to the policy's ceiling
    knob by knob (:func:`adscan_core.scan_pacing.fit_to_ceiling`), and what was
    lowered is recorded on the request's profile reference for the disclosure
    and returned so the caller can tell the user.
    """
    ceiling = session_pacing_ceiling(shell)
    fitted = fit_to_ceiling(profile.as_request(), ceiling)
    setattr(shell, ATTR_PACING_REQUEST, fitted.request)
    resolved = publish_pacing(shell, fitted.request, ceiling)
    return resolved, fitted


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AppliedScanControls:
    """What an entry point applied, for its one-screen summary."""

    policy: ResolvedScanPolicy | None
    policy_source: str
    pacing: ResolvedPacing
    warnings: tuple[str, ...] = ()
    fast_requested: bool = False


def _fail_closed_policy() -> ResolvedScanPolicy:
    """The policy applied when a persisted one cannot be read: run no technique."""
    from adscan_core.scan_policy.policy import BASE_DETECTION_ONLY, builtin_definition

    definition = builtin_definition(BASE_DETECTION_ONLY)
    return resolve_definition(
        replace(
            definition,
            identity=replace(definition.identity, name="Detection only (policy file unreadable)"),
        ),
        strict=False,
    )


def _migrate_workspace_type(
    workspace_dir: str | None,
    record: WorkspacePolicyRecord,
    stored_workspace_type: str | None,
) -> WorkspacePolicyRecord:
    """Carry a workspace saved with a ``type`` into its policy, once.

    * No policy and never cleared: the type selects its built-in (``ctf`` Lab /
      CTF, ``audit`` Audit), persisted so the next load reads the policy.
    * A first-generation policy (``full_validation``, ``detection_only``,
      ``safe_for_production``) that does not name its environment, in a CTF
      workspace: those bases read as a real environment, so the type the
      workspace was created with is written into the policy and the workspace
      stays a lab. Every other policy decides by itself: a current base
      implies its environment, and a policy that names one is never
      overridden, so a stale ``type`` mirror cannot contradict the policy.
    * A cleared policy without a recorded environment: the type is recorded in
      the clear, so the workspace keeps its environment without a policy.

    Best-effort on the write: a workspace that cannot be written keeps working
    from the in-memory result.
    """
    environment = environment_for_workspace_type(stored_workspace_type)
    if environment is None or record.unreadable:
        return record
    if record.definition is None and record.cleared is None:
        definition = builtin_definition(builtin_for_workspace_type(stored_workspace_type))
        migrated = replace(record, definition=definition, source=SOURCE_WORKSPACE_TYPE)
    elif (
        record.definition is not None
        and not record.definition.environment
        and record.definition.base in LEGACY_BASES
    ):
        if effective_environment(record.definition) == environment:
            return record
        migrated = replace(record, definition=replace(record.definition, environment=environment))
    elif record.definition is None and record.cleared is not None:
        previous = dict(record.cleared.get("previous") or {})
        if previous.get("environment") in ENVIRONMENTS:
            return record
        previous["environment"] = environment
        cleared = {**dict(record.cleared), "previous": previous}
        if workspace_dir:
            try:
                data = json.loads(policy_file(workspace_dir).read_text(encoding="utf-8"))
                data["cleared"] = cleared
                _write_record(workspace_dir, data)
            except (OSError, ValueError):
                pass
        return replace(record, cleared=cleared)
    else:
        return record
    if workspace_dir:
        try:
            save_workspace_policy(
                workspace_dir,
                resolve_definition(migrated.definition, strict=False),
                source=migrated.source or SOURCE_WORKSPACE_TYPE,
                pacing_ceiling=migrated.pacing_ceiling,
            )
        except OSError:
            pass
    return migrated


def apply_workspace_scan_controls(
    shell: Any,
    workspace_dir: str | None,
    *,
    stored_workspace_type: str | None = None,
) -> AppliedScanControls:
    """Load and apply a workspace's persisted policy and pace (workspace load).

    A workspace whose policy file exists but cannot be read is held to
    Detection only, never to "run everything": an unreadable written
    authorization must fail closed.

    ``stored_workspace_type`` is the ``type`` a workspace's ``variables.json``
    carries. It is only a migration input (:func:`_migrate_workspace_type`):
    once the policy is in place, the type is derived from it.
    """
    warnings: list[str] = []
    record = _migrate_workspace_type(
        workspace_dir, load_workspace_policy(workspace_dir), stored_workspace_type
    )
    setattr(shell, ATTR_POLICY_CLEARED, record.cleared)
    policy: ResolvedScanPolicy | None = None
    source = ""
    if record.unreadable:
        policy = _fail_closed_policy()
        source = SOURCE_UNREADABLE
        warnings.append(
            f"The scan policy file of this workspace ({SCAN_POLICY_FILENAME}) cannot be read. "
            "ADscan runs Detection only until you fix it or run 'policy clear'."
        )
    elif record.definition is not None:
        policy = resolve_definition(record.definition, strict=False)
        source = record.source or SOURCE_WORKSPACE
        for unknown in policy.unknown_ids:
            warnings.append(
                f"The workspace scan policy names '{unknown}', which this version of ADscan "
                "does not know; it has no effect."
            )
    setattr(shell, ATTR_POLICY, policy)
    setattr(shell, ATTR_POLICY_SOURCE, source)
    ceiling = pacing_ceiling_for_policy(policy) or record.pacing_ceiling
    request = workspace_pacing_request(shell) or policy_pacing_request(policy)
    pacing = publish_pacing(shell, request, ceiling)
    return AppliedScanControls(policy, source, pacing, tuple(warnings))


def apply_ci_scan_controls(
    shell: Any,
    *,
    scan_config: Any,
    cli_level: Optional[str] = None,
    cli_assignments: Iterable[str] | None = None,
    workspace_dir: str | None = None,
    non_interactive: bool = True,
    pace_profile: PaceProfile | None = None,
) -> AppliedScanControls:
    """Resolve and apply the run's policy and pace (``adscan ci``).

    Called after the workspace is open, so the workspace's persisted state has
    already been applied by :func:`apply_workspace_scan_controls`; the scan
    config's explicit sections win over it, and the CLI flags win over the scan
    config's pace (still capped by the ceiling).

    Pace precedence (:func:`adscan_core.scan_pacing.compose_pacing_request`):
    the CLI flags, then a saved profile (``--pace-profile``, fitted to the
    ceiling, every lowered value named in a warning) or the scan config's pace,
    then the policy's own. A pace saved in the workspace by an interactive
    session is not used: an unattended run follows the policy it names.

    Raises:
        ScanControlsError: On an unknown check id, a malformed pace flag, or a
            pace profile together with a scan config ``pacing`` section.
    """
    from adscan_internal.services.scan_config import pacing_request_is_explicit

    warnings: list[str] = []
    phases = getattr(scan_config, "phases", None)
    legacy_phases = tuple(getattr(phases, "disabled", ()) or ())
    legacy_steps = dict(getattr(phases, "steps", {}) or {})

    checks = getattr(scan_config, "checks", None)
    explicit_policy = checks is not None and not checks.is_default
    policy: ResolvedScanPolicy | None
    if explicit_policy:
        policy = resolve_definition(
            checks.definition,
            legacy_disabled_phases=legacy_phases,
            legacy_disabled_steps=legacy_steps,
        )
        source = SOURCE_SCAN_CONFIG
    else:
        persisted: ResolvedScanPolicy | None = getattr(shell, ATTR_POLICY, None)
        source = getattr(shell, ATTR_POLICY_SOURCE, "") or ""
        if persisted is not None and source != SOURCE_UNREADABLE:
            # Re-resolve so this run's legacy phase/step disables fold in.
            policy = resolve_definition(
                persisted.definition,
                legacy_disabled_phases=legacy_phases,
                legacy_disabled_steps=legacy_steps,
                strict=False,
            )
        else:
            policy = persisted
    for message in policy.warnings if policy is not None else ():
        warnings.append(message)
    setattr(shell, ATTR_POLICY, policy)
    setattr(shell, ATTR_POLICY_SOURCE, source)

    # Pace: scan config request or a saved profile (or the workspace's, or the
    # policy's), then the CLI layer; capped by the scan config's ceiling or the
    # policy's.
    pacing_block = getattr(scan_config, "pacing", None)
    explicit_pacing = pacing_block is not None and pacing_request_is_explicit(pacing_block)
    if pace_profile is not None and explicit_pacing:
        raise ScanControlsError(
            "Give the scan pace once: either --pace-profile or a 'pacing' section in "
            "--scan-config, not both."
        )
    fast_downgraded = False
    try:
        cli_layer = cli_pacing_request(cli_level, cli_assignments)
    except PacingConfigError as exc:
        raise ScanControlsError(str(exc)) from exc
    ceiling = (
        pacing_block.ceiling
        if pacing_block is not None and pacing_block.ceiling is not None
        else pacing_ceiling_for_policy(policy) or getattr(shell, ATTR_PACING_CEILING, None)
    )
    base: PacingRequest | None
    if explicit_pacing:
        base = pacing_block.request
    elif pace_profile is not None:
        # The profile replaces the workspace's and the policy's pace, held to
        # the ceiling knob by knob; the user is told what was lowered.
        fitted = fit_to_ceiling(pace_profile.as_request(), ceiling)
        base = fitted.request
        message = profile_lowered_message(fitted, ceiling)
        if message:
            warnings.append(message)
    else:
        # No pace given for this run: the policy it names decides (Lab / CTF
        # Fast, Audit Normal, Production-sensitive Polite), always within the
        # ceiling. A pace saved in the workspace is the interactive operator's
        # choice and is not carried into an unattended run; when it asked for
        # more than the policy, the run says so (and the report states it).
        base = policy_pacing_request(policy)
        saved = workspace_pacing_request(shell)
        cli_level_given = cli_layer is not None and cli_layer.level_source == "cli"
        if (
            saved is not None
            and non_interactive
            and saved.level == PacingLevel.FAST
            and not cli_level_given
            and (base is None or base.level != PacingLevel.FAST)
        ):
            warnings.append(
                "The workspace is set to the Fast pace, which an unattended run does not "
                "carry over. This run uses its scan policy's pace; pass --pacing fast to "
                "choose Fast."
            )
            fast_downgraded = True
    request = compose_pacing_request(profile=base, run=cli_layer)
    pacing = publish_pacing(shell, request, ceiling)
    # Read by the report's assessment-pace paragraph, which states the downgrade.
    setattr(shell, ATTR_PACING_FAST_DOWNGRADED, fast_downgraded)

    # Persist: an explicit policy or ceiling, and an explicit pace request.
    if workspace_dir and (explicit_policy or (pacing_block is not None and pacing_block.ceiling)):
        save_workspace_policy(
            workspace_dir,
            policy if policy is not None and source != SOURCE_UNREADABLE else None,
            source=source or SOURCE_SCAN_CONFIG,
            pacing_ceiling=ceiling if pacing_ceiling_for_policy(policy) is None else None,
        )
    if explicit_pacing or cli_layer is not None or pace_profile is not None:
        setattr(shell, ATTR_PACING_REQUEST, request)

    return AppliedScanControls(
        policy,
        source,
        pacing,
        tuple(warnings),
        fast_requested=pacing.level == PacingLevel.FAST,
    )


def set_policy(
    shell: Any,
    definition: ScanPolicyDefinition | None,
    *,
    workspace_dir: str,
    source: str = SOURCE_REPL,
) -> tuple[ResolvedScanPolicy | None, ResolvedPacing]:
    """Set (or, with ``None``, clear) the workspace policy from the REPL and re-publish the pace.

    ``source`` records where the policy came from (the REPL, or the workspace
    type alias / workspace creation).

    Raises:
        ScanControlsError: When the definition names an unknown check.
    """
    previous: ResolvedScanPolicy | None = getattr(shell, ATTR_POLICY, None)
    if definition is None:
        cleared = clear_workspace_policy(workspace_dir, previous)
        setattr(shell, ATTR_POLICY, None)
        setattr(shell, ATTR_POLICY_SOURCE, "")
        setattr(shell, ATTR_POLICY_CLEARED, cleared)
        setattr(shell, ATTR_PACING_CEILING, None)
        resolved = None
    else:
        resolved = resolve_definition(definition)
        save_workspace_policy(workspace_dir, resolved, source=source)
        setattr(shell, ATTR_POLICY, resolved)
        setattr(shell, ATTR_POLICY_SOURCE, source)
        setattr(shell, ATTR_POLICY_CLEARED, None)
        # The new policy replaces whatever pace ceiling the previous one carried.
        setattr(shell, ATTR_PACING_CEILING, None)
    ceiling = session_pacing_ceiling(shell)
    request = workspace_pacing_request(shell) or policy_pacing_request(resolved)
    pacing = publish_pacing(shell, request, ceiling)
    return resolved, pacing


# ---------------------------------------------------------------------------
# Workspace type: derived from the policy (the one accessor)
# ---------------------------------------------------------------------------


def workspace_environment(shell: Any) -> str | None:
    """The environment this shell's workspace is (``lab`` / ``real``), from its policy.

    The active policy decides. A workspace whose policy was cleared stays the
    environment of the policy it cleared. ``None`` before a workspace has a
    policy (no workspace open yet).
    """
    policy = getattr(shell, ATTR_POLICY, None)
    definition = getattr(policy, "definition", None)
    if definition is not None:
        return effective_environment(definition)
    cleared = getattr(shell, ATTR_POLICY_CLEARED, None)
    previous = cleared.get("previous") if isinstance(cleared, Mapping) else None
    environment = previous.get("environment") if isinstance(previous, Mapping) else None
    return environment if environment in ENVIRONMENTS else None


def workspace_type(shell: Any) -> str | None:
    """``ctf`` or ``audit`` for this shell's workspace, derived from its policy.

    THE accessor every reader of the workspace type goes through
    (``PentestShell.type`` is a property over it, and telemetry's
    ``workspace_type`` is read from it), so no stored value can disagree with
    the policy that decides what runs.
    """
    return workspace_type_for_environment(workspace_environment(shell))


def adopt_policy(
    shell: Any,
    definition: ScanPolicyDefinition,
    *,
    workspace_dir: str | None = None,
    source: str = SOURCE_REPL,
) -> ResolvedScanPolicy:
    """Make ``definition`` the workspace's policy: persisted when the workspace exists.

    Without a workspace directory yet (an entry point that opens it later) the
    policy is held in memory for this run. The pace is not published then: the
    entry point publishes it once the workspace is open (``apply_*_scan_controls``),
    so an in-memory choice never leaves a process-wide pace behind.

    Raises:
        ScanControlsError: When the definition names an unknown check.
    """
    directory = workspace_dir or getattr(shell, "current_workspace_dir", None)
    if directory and os.path.isdir(str(directory)):
        resolved, _ = set_policy(shell, definition, workspace_dir=str(directory), source=source)
        return resolved
    resolved = resolve_definition(definition)
    setattr(shell, ATTR_POLICY, resolved)
    setattr(shell, ATTR_POLICY_SOURCE, source)
    setattr(shell, ATTR_POLICY_CLEARED, None)
    setattr(shell, ATTR_PACING_CEILING, None)
    return resolved


def stamp_unattended_entry(shell: Any, entry: str) -> None:
    """Stamp a non-interactive entry point (``ci`` / ``execute``) on ``shell``.

    The operator is present when the remote decision bridge is connected (the
    web worker): a policy that decides each step during the scan then asks the
    person at the console. Without it nobody can answer, and such a policy maps
    the attack steps without executing them.
    """
    from adscan_core.scan_policy.execution import stamp_run_entry  # noqa: PLC0415

    try:
        from adscan_internal.interactive_requests import (  # noqa: PLC0415
            is_remote_interaction_enabled,
        )

        operator = bool(is_remote_interaction_enabled())
    except Exception:  # noqa: BLE001 - no bridge means no operator
        operator = False
    stamp_run_entry(shell, entry, operator_present=operator)


def print_execution_decision(shell: Any) -> None:
    """One operator line stating how this run treats attack steps."""
    from adscan_core.rich_output import print_info, print_warning  # noqa: PLC0415
    from adscan_core.scan_policy.execution import (  # noqa: PLC0415
        DECISION_ATTENDED,
        DECISION_MAP_ONLY,
        DECISION_UNATTENDED,
        MAP_ONLY_START_STATEMENT,
        execution_decision,
    )

    decision = execution_decision(shell)
    if decision == DECISION_UNATTENDED:
        print_info("Attack steps: the policy's enabled steps run unattended.")
    elif decision == DECISION_ATTENDED:
        print_info("Attack steps: the operator decides each step from the console.")
    elif decision == DECISION_MAP_ONLY:
        print_warning(MAP_ONLY_START_STATEMENT)


def is_unlimited(value: Any) -> bool:
    """True for the ``unlimited`` knob value."""
    return value == UNLIMITED


__all__ = [
    "ATTR_PACING",
    "ATTR_PACING_CEILING",
    "ATTR_PACING_FAST_DOWNGRADED",
    "ATTR_PACING_REQUEST",
    "apply_pace_profile",
    "profile_lowered_message",
    "CLEARED_DISCLOSED_AT_KEY",
    "ATTR_POLICY",
    "ATTR_POLICY_CLEARED",
    "ATTR_POLICY_SOURCE",
    "AppliedScanControls",
    "KNOBS_BY_KEY",
    "SCAN_POLICY_FILENAME",
    "SOURCE_WORKSPACE_TYPE",
    "ScanControlsError",
    "adopt_policy",
    "WorkspacePolicyRecord",
    "apply_ci_scan_controls",
    "apply_workspace_scan_controls",
    "canonical_pacing_assignments",
    "clear_workspace_policy",
    "cli_pacing_request",
    "format_knob_value",
    "is_unlimited",
    "load_workspace_policy",
    "mark_policy_clear_disclosed",
    "pacing_ceiling_for_policy",
    "pacing_request_for_save",
    "pacing_request_from_saved",
    "parse_pacing_assignments",
    "policy_display_name",
    "policy_file",
    "policy_pacing_request",
    "print_execution_decision",
    "publish_pacing",
    "resolve_definition",
    "save_workspace_policy",
    "workspace_environment",
    "workspace_type",
    "session_pacing_ceiling",
    "set_policy",
    "short_digest",
    "stamp_unattended_entry",
    "workspace_pacing_request",
]
