"""Typed scan-configuration model and loader (the ``--scan-config`` contract).

A scan configuration lets a client shape a scan *before* (or instead of)
deciding interactively during the run: disable optional phases, skip or scope
trust enumeration, and choose whether attack paths are executed.

This module is the single source of truth for the config schema. Two producers
target it — the web "Create New Scan" form (which builds the object and writes
it to a file the Celery worker passes via ``--scan-config``) and a hand-written
YAML/JSON file for CLI/CI users. One consumer reads it: ``adscan ci`` through
:func:`load_scan_config`.

Hard invariant: an **absent** config (no file, or an empty file) yields
:data:`DEFAULT_SCAN_CONFIG` — every policy defaults to ``interactive`` and no
phase is disabled — which is byte-for-byte today's behavior. The config only
ever *removes* interactivity or *narrows* scope; it never silently changes a
default.

The schema (all keys optional)::

    phases:
      disabled: [password_spraying, share_credential_hunt]
      steps:                  # disable individual subphases (steps) of a phase
        quick_credential_wins:
          disabled: [timeroast]            # drop just Timeroast, keep LDAP/GPP
        password_spraying:
          disabled: [blank, pre2k]         # spray strategies to skip
    trust_enumeration:
      policy: selected        # skip | all | selected | interactive (default)
      domains: [essos.local]  # only consulted when policy == selected
    attack_paths:
      policy: interactive     # none | all | selected | interactive (default)
      selected: []            # path ids/targets, only when policy == selected
    audit_extras:
      target_scope: domain_controllers     # default | domain_controllers | all_hosts
    host_cap: 150           # max hosts actively scanned (0 = unlimited)
    cracking:
      effort: balanced       # fast | balanced | thorough (default: balanced)
      wordlist: ''            # escape hatch: an explicit wordlist path, bypasses effort tiering
    poisoning:
      enabled: true           # broadcast poisoning on/off (absent = workspace-type default)

Unknown keys raise :class:`ScanConfigError` — a typo must fail loud, never be
silently ignored. The web mirrors this same valid-set so both sides validate
identically (CLI<->web lockstep, contract test).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Valid sets — the web form MUST mirror these exactly (contract).
# ---------------------------------------------------------------------------

# Trust-enumeration policies.
TRUST_POLICY_SKIP = "skip"
TRUST_POLICY_ALL = "all"
TRUST_POLICY_SELECTED = "selected"
TRUST_POLICY_INTERACTIVE = "interactive"
TRUST_POLICIES: frozenset[str] = frozenset(
    {
        TRUST_POLICY_SKIP,
        TRUST_POLICY_ALL,
        TRUST_POLICY_SELECTED,
        TRUST_POLICY_INTERACTIVE,
    }
)

# Attack-path execution policies.
ATTACK_PATH_POLICY_NONE = "none"
ATTACK_PATH_POLICY_ALL = "all"
ATTACK_PATH_POLICY_SELECTED = "selected"
ATTACK_PATH_POLICY_INTERACTIVE = "interactive"
ATTACK_PATH_POLICIES: frozenset[str] = frozenset(
    {
        ATTACK_PATH_POLICY_NONE,
        ATTACK_PATH_POLICY_ALL,
        ATTACK_PATH_POLICY_SELECTED,
        ATTACK_PATH_POLICY_INTERACTIVE,
    }
)

# CVE-verification target scope (the ``audit_extras`` phase option). ``default``
# is the sentinel for "the operator did not touch this control" — it preserves
# today's behavior (audit scans DCs *and* every host). ``domain_controllers``
# narrows the scan to DCs only; ``all_hosts`` forces the every-host scan.
CVE_TARGET_SCOPE_DEFAULT = "default"
CVE_TARGET_SCOPE_DCS = "domain_controllers"
CVE_TARGET_SCOPE_ALL = "all_hosts"
CVE_TARGET_SCOPES: frozenset[str] = frozenset(
    {CVE_TARGET_SCOPE_DEFAULT, CVE_TARGET_SCOPE_DCS, CVE_TARGET_SCOPE_ALL}
)

# Active-host cap. Bounds every ACTIVE host operation (port scan + SMB enrichment
# + per-service sweeps) to at most this many hosts, ordered representative-first
# (Tier 0 / DCs / ADCS first), so a positive cap always covers the highest-value
# hosts and bounds the wall-clock at scale (~2k-host estates). The directory graph
# (LDAP) is always mapped in full regardless of the cap. Default 150 = the
# published competitor (Pentera) PoV scope ("up to 150 endpoints", one-day
# assessment) and ~one /24 subnet / single AD site. ``0`` (the sentinel) means
# unlimited — byte-for-byte today's full sweep.
HOST_CAP_DEFAULT = 150
HOST_CAP_UNLIMITED = 0

# Cracking-effort profiles (the time-budget engine — see
# docs/superpowers/specs/2026-07-07-cracking-effort-engine-design.md).
# Intentionally NOT imported from cracking_wordlist_policy.EFFORT_LEVELS —
# scan_config.py stays dependency-free (no adscan_internal.services imports)
# so the web's standalone contract test can import it cheaply; the two are
# locked together by test_web_cracking_effort_levels_match_engine.
CRACKING_EFFORT_FAST = "fast"
CRACKING_EFFORT_BALANCED = "balanced"
CRACKING_EFFORT_THOROUGH = "thorough"
CRACKING_EFFORT_DEFAULT = CRACKING_EFFORT_BALANCED
CRACKING_EFFORT_LEVELS: frozenset[str] = frozenset(
    {CRACKING_EFFORT_FAST, CRACKING_EFFORT_BALANCED, CRACKING_EFFORT_THOROUGH}
)

# Top-level config keys (anything else is a typo -> ScanConfigError).
_TOP_LEVEL_KEYS: frozenset[str] = frozenset(
    {
        "phases",
        "trust_enumeration",
        "attack_paths",
        "audit_extras",
        "host_cap",
        "cracking",
        "poisoning",
    }
)
_PHASES_KEYS: frozenset[str] = frozenset({"disabled", "steps"})
_TRUST_KEYS: frozenset[str] = frozenset({"policy", "domains"})
_ATTACK_PATH_KEYS: frozenset[str] = frozenset({"policy", "selected"})
_AUDIT_EXTRAS_KEYS: frozenset[str] = frozenset({"target_scope"})
_STEPS_KEYS: frozenset[str] = frozenset({"disabled"})
_CRACKING_KEYS: frozenset[str] = frozenset({"effort", "wordlist"})
_POISONING_KEYS: frozenset[str] = frozenset({"enabled"})


class ScanConfigError(ValueError):
    """Raised when a scan-config file is malformed or has unknown/invalid keys."""


# ---------------------------------------------------------------------------
# Typed model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PhasesConfig:
    """Phase-toggle section of a scan config.

    Attributes:
        disabled: Phase ids the operator asked to skip. Only ids that map to an
            *optional* :class:`~adscan_internal.services.scan_phases.ScanPhase`
            are honored; a request to disable a mandatory phase is refused with
            a warning by :func:`scan_phases.build_scan_plan` (never silently
            dropped). Unknown ids are kept here verbatim and surfaced as a
            warning at plan-build time.
        steps: Per-phase subphase (step-level) disables, keyed by phase id. The
            value is the tuple of subphase ids the operator disabled within that
            phase (e.g. ``{"quick_credential_wins": ("timeroast",)}`` to drop
            only Timeroast while keeping the LDAP / GPP quick-wins). Only ids
            that map to an *optional*
            :class:`~adscan_internal.services.scan_phases.Subphase` are honored;
            a request to disable a mandatory subphase is refused with a warning
            at plan-build time. Empty by default → no step is disabled.
    """

    disabled: tuple[str, ...] = ()
    steps: "dict[str, tuple[str, ...]]" = field(default_factory=dict)

    def disabled_subphases(self, phase_id: str) -> frozenset[str]:
        """Return the disabled subphase ids requested under ``phase_id``."""
        return frozenset(self.steps.get(phase_id, ()))


@dataclass(frozen=True)
class TrustEnumerationConfig:
    """Trust-enumeration section of a scan config.

    Attributes:
        policy: One of :data:`TRUST_POLICIES`. ``interactive`` (default) keeps
            today's behavior. ``skip`` short-circuits enumeration. ``all``
            enumerates every discovered trust. ``selected`` enumerates only the
            partner domains listed in ``domains``.
        domains: Partner domains to enumerate when ``policy == selected``;
            ignored for every other policy. Lower-cased on load.
    """

    policy: str = TRUST_POLICY_INTERACTIVE
    domains: tuple[str, ...] = ()


@dataclass(frozen=True)
class AttackPathsConfig:
    """Attack-path execution section of a scan config.

    Attributes:
        policy: One of :data:`ATTACK_PATH_POLICIES`. ``interactive`` (default)
            keeps today's during-scan offer. ``none`` skips execution. ``all``
            executes every viable path. ``selected`` executes only the entries
            in ``selected``.
        selected: Path ids/targets to execute when ``policy == selected``;
            ignored for every other policy.
    """

    policy: str = ATTACK_PATH_POLICY_INTERACTIVE
    selected: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuditExtrasConfig:
    """CVE-verification (``audit_extras`` phase) section of a scan config.

    Attributes:
        target_scope: One of :data:`CVE_TARGET_SCOPES`. ``default`` (the
            sentinel) keeps today's behavior — the audit scans domain
            controllers *and* every host. ``domain_controllers`` narrows the CVE
            scan to DCs only; ``all_hosts`` forces the every-host scan. Only a
            non-``default`` value changes anything, so an absent config stays a
            byte-for-byte no-op.
    """

    target_scope: str = CVE_TARGET_SCOPE_DEFAULT


@dataclass(frozen=True)
class CrackingConfig:
    """Offline-cracking effort section of a scan config.

    Attributes:
        effort: One of :data:`CRACKING_EFFORT_LEVELS`. ``balanced`` (default)
            matches today's audit auto-crack behavior upgraded to rules-aware
            tiering. ``fast`` stays near-instant everywhere; ``thorough``
            always runs as a background job and auto-downgrades on CPU-only
            hardware (see the cracking-effort-engine design spec).
        wordlist: Optional escape hatch — an explicit wordlist file path that
            bypasses effort-tier resolution entirely and is passed straight
            to hashcat. Empty (default) defers to the effort tier.
    """

    effort: str = CRACKING_EFFORT_DEFAULT
    wordlist: str = ""


@dataclass(frozen=True)
class PoisoningConfig:
    """Broadcast-poisoning (LLMNR / NBT-NS / mDNS) background-job toggle.

    Poisoning runs as a **background job** (it must wait for a victim to resolve
    a bad name), never as a sequential scan phase — so this is a sibling of
    ``cracking``, NOT an entry in ``phases.disabled``. ``enabled`` is
    tri-state:

    * ``None`` (default) — use the workspace-type default (audit auto-launches,
      ctf does not). An absent section is therefore a no-op that reproduces
      today's behavior exactly.
    * ``True`` — force the background poisoning job on, overriding the type
      default.
    * ``False`` — force it off, overriding the type default.

    The gate that consumes this is
    :func:`adscan_internal.services.background_jobs.scan_seam.maybe_launch_poisoning_job`.
    The hard opt-out env var ``ADSCAN_NO_POISONING=1`` still takes precedence
    over an explicit ``True`` (a monitored/out-of-scope engagement kill switch).

    Attributes:
        enabled: ``None`` = workspace-type default; ``True`` = force on;
            ``False`` = force off.
    """

    enabled: Optional[bool] = None


@dataclass(frozen=True)
class ScanConfig:
    """A fully-resolved scan configuration.

    :data:`DEFAULT_SCAN_CONFIG` is the all-defaults instance returned for an
    absent/empty config — identical to today's interactive behavior.
    """

    phases: PhasesConfig = field(default_factory=PhasesConfig)
    trust_enumeration: TrustEnumerationConfig = field(
        default_factory=TrustEnumerationConfig
    )
    attack_paths: AttackPathsConfig = field(default_factory=AttackPathsConfig)
    audit_extras: AuditExtrasConfig = field(default_factory=AuditExtrasConfig)
    # Max hosts ACTIVELY scanned (port scan + SMB enrichment + per-service
    # sweeps), representative-first (Tier 0 first). ``HOST_CAP_DEFAULT`` (150)
    # bounds active scanning on large estates; ``HOST_CAP_UNLIMITED`` (0) restores
    # the full sweep. The directory graph (LDAP) is always mapped in full.
    host_cap: int = HOST_CAP_DEFAULT
    cracking: CrackingConfig = field(default_factory=CrackingConfig)
    # Broadcast-poisoning background-job toggle (sibling of ``cracking``, NOT a
    # phase). ``enabled is None`` = workspace-type default (audit on, ctf off);
    # so an absent section is a no-op.
    poisoning: PoisoningConfig = field(default_factory=PoisoningConfig)

    # -- convenience predicates used by the gated decision points -----------

    @property
    def is_default(self) -> bool:
        """True when this config requests no change from today's behavior."""
        return (
            not self.phases.disabled
            and not self.phases.steps
            and self.trust_enumeration.policy == TRUST_POLICY_INTERACTIVE
            and self.attack_paths.policy == ATTACK_PATH_POLICY_INTERACTIVE
            and self.audit_extras.target_scope == CVE_TARGET_SCOPE_DEFAULT
            and self.host_cap == HOST_CAP_DEFAULT
            and self.cracking.effort == CRACKING_EFFORT_DEFAULT
            and not self.cracking.wordlist
            and self.poisoning.enabled is None
        )

    def disabled_phase_ids(self) -> frozenset[str]:
        """Return the requested-disabled phase ids as a set."""
        return frozenset(self.phases.disabled)


DEFAULT_SCAN_CONFIG = ScanConfig()


# ---------------------------------------------------------------------------
# Parsing / validation
# ---------------------------------------------------------------------------


def _require_mapping(value: Any, *, where: str) -> dict[str, Any]:
    """Return ``value`` as a dict or raise a clear :class:`ScanConfigError`."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ScanConfigError(
            f"'{where}' must be a mapping, got {type(value).__name__}."
        )
    return value


def _reject_unknown_keys(
    mapping: dict[str, Any], allowed: frozenset[str], *, where: str
) -> None:
    """Raise if ``mapping`` carries a key outside ``allowed``."""
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise ScanConfigError(
            f"Unknown key(s) under '{where}': {', '.join(unknown)}. "
            f"Allowed keys: {', '.join(sorted(allowed))}."
        )


def _coerce_str_list(value: Any, *, where: str) -> tuple[str, ...]:
    """Coerce a YAML/JSON scalar-or-list into a tuple of non-empty strings."""
    if value is None:
        return ()
    if isinstance(value, str):
        items = [value]
    elif isinstance(value, (list, tuple)):
        items = list(value)
    else:
        raise ScanConfigError(
            f"'{where}' must be a string or a list of strings, "
            f"got {type(value).__name__}."
        )
    out: list[str] = []
    for item in items:
        if not isinstance(item, str):
            raise ScanConfigError(
                f"'{where}' entries must be strings, got {type(item).__name__}."
            )
        text = item.strip()
        if text:
            out.append(text)
    return tuple(out)


def _parse_phase_steps(raw: Any) -> dict[str, tuple[str, ...]]:
    """Parse ``phases.steps`` — a mapping of phase id → disabled subphase ids.

    Shape::

        phases:
          steps:
            quick_credential_wins:
              disabled: [timeroast]
            password_spraying:
              disabled: [blank, pre2k]

    Each phase entry is a mapping whose only key is ``disabled`` (a string or a
    list of subphase ids). A phase with no disabled steps is dropped so an empty
    section is equivalent to no section (keeps ``is_default`` honest).
    """
    mapping = _require_mapping(raw, where="phases.steps")
    out: dict[str, tuple[str, ...]] = {}
    for phase_id, value in mapping.items():
        phase_key = str(phase_id).strip()
        if not phase_key:
            continue
        section = _require_mapping(value, where=f"phases.steps.{phase_key}")
        _reject_unknown_keys(
            section, _STEPS_KEYS, where=f"phases.steps.{phase_key}"
        )
        disabled = _coerce_str_list(
            section.get("disabled"),
            where=f"phases.steps.{phase_key}.disabled",
        )
        if disabled:
            out[phase_key] = disabled
    return out


def _parse_phases(raw: Any) -> PhasesConfig:
    mapping = _require_mapping(raw, where="phases")
    _reject_unknown_keys(mapping, _PHASES_KEYS, where="phases")
    disabled = _coerce_str_list(mapping.get("disabled"), where="phases.disabled")
    steps = _parse_phase_steps(mapping.get("steps"))
    return PhasesConfig(disabled=disabled, steps=steps)


def _parse_audit_extras(raw: Any) -> AuditExtrasConfig:
    mapping = _require_mapping(raw, where="audit_extras")
    _reject_unknown_keys(mapping, _AUDIT_EXTRAS_KEYS, where="audit_extras")
    target_scope = (
        str(mapping.get("target_scope", CVE_TARGET_SCOPE_DEFAULT) or CVE_TARGET_SCOPE_DEFAULT)
        .strip()
        .lower()
    )
    if target_scope not in CVE_TARGET_SCOPES:
        raise ScanConfigError(
            f"Invalid audit_extras.target_scope '{target_scope}'. "
            f"Valid values: {', '.join(sorted(CVE_TARGET_SCOPES))}."
        )
    return AuditExtrasConfig(target_scope=target_scope)


def _parse_trust(raw: Any) -> TrustEnumerationConfig:
    mapping = _require_mapping(raw, where="trust_enumeration")
    _reject_unknown_keys(mapping, _TRUST_KEYS, where="trust_enumeration")
    policy = str(
        mapping.get("policy", TRUST_POLICY_INTERACTIVE) or TRUST_POLICY_INTERACTIVE
    ).strip().lower()
    if policy not in TRUST_POLICIES:
        raise ScanConfigError(
            f"Invalid trust_enumeration.policy '{policy}'. "
            f"Valid values: {', '.join(sorted(TRUST_POLICIES))}."
        )
    domains = tuple(
        d.lower()
        for d in _coerce_str_list(
            mapping.get("domains"), where="trust_enumeration.domains"
        )
    )
    if policy == TRUST_POLICY_SELECTED and not domains:
        raise ScanConfigError(
            "trust_enumeration.policy is 'selected' but no 'domains' were listed."
        )
    return TrustEnumerationConfig(policy=policy, domains=domains)


def _parse_attack_paths(raw: Any) -> AttackPathsConfig:
    mapping = _require_mapping(raw, where="attack_paths")
    _reject_unknown_keys(mapping, _ATTACK_PATH_KEYS, where="attack_paths")
    policy = str(
        mapping.get("policy", ATTACK_PATH_POLICY_INTERACTIVE)
        or ATTACK_PATH_POLICY_INTERACTIVE
    ).strip().lower()
    if policy not in ATTACK_PATH_POLICIES:
        raise ScanConfigError(
            f"Invalid attack_paths.policy '{policy}'. "
            f"Valid values: {', '.join(sorted(ATTACK_PATH_POLICIES))}."
        )
    selected = _coerce_str_list(
        mapping.get("selected"), where="attack_paths.selected"
    )
    if policy == ATTACK_PATH_POLICY_SELECTED and not selected:
        raise ScanConfigError(
            "attack_paths.policy is 'selected' but no 'selected' entries were listed."
        )
    return AttackPathsConfig(policy=policy, selected=selected)


def _parse_cracking(raw: Any) -> CrackingConfig:
    mapping = _require_mapping(raw, where="cracking")
    _reject_unknown_keys(mapping, _CRACKING_KEYS, where="cracking")
    effort = str(
        mapping.get("effort", CRACKING_EFFORT_DEFAULT) or CRACKING_EFFORT_DEFAULT
    ).strip().lower()
    if effort not in CRACKING_EFFORT_LEVELS:
        raise ScanConfigError(
            f"Invalid cracking.effort '{effort}'. "
            f"Valid values: {', '.join(sorted(CRACKING_EFFORT_LEVELS))}."
        )
    wordlist = str(mapping.get("wordlist") or "").strip()
    return CrackingConfig(effort=effort, wordlist=wordlist)


def _parse_poisoning(raw: Any) -> PoisoningConfig:
    mapping = _require_mapping(raw, where="poisoning")
    _reject_unknown_keys(mapping, _POISONING_KEYS, where="poisoning")
    enabled = mapping.get("enabled")
    if enabled is not None and not isinstance(enabled, bool):
        raise ScanConfigError(
            f"'poisoning.enabled' must be a boolean or absent, "
            f"got {type(enabled).__name__}."
        )
    return PoisoningConfig(enabled=enabled)


def _parse_host_cap(raw: Any) -> int:
    """Parse the top-level ``host_cap`` scalar (a non-negative integer).

    Absent → :data:`HOST_CAP_DEFAULT`. ``0`` is the explicit "unlimited"
    sentinel. A negative or non-integer value fails loud.
    """
    if raw is None:
        return HOST_CAP_DEFAULT
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise ScanConfigError(
            f"'host_cap' must be a non-negative integer, got {type(raw).__name__}."
        )
    if raw < 0:
        raise ScanConfigError(
            f"'host_cap' must be >= 0 (0 = unlimited), got {raw}."
        )
    return raw


def parse_scan_config(data: Any) -> ScanConfig:
    """Validate a parsed YAML/JSON object into a :class:`ScanConfig`.

    Args:
        data: The object produced by ``yaml.safe_load`` / ``json.loads``.
            ``None`` or an empty mapping yields :data:`DEFAULT_SCAN_CONFIG`.

    Returns:
        A validated :class:`ScanConfig`.

    Raises:
        ScanConfigError: When the object is not a mapping, carries an unknown
            top-level key, or any section is malformed.
    """
    if data is None:
        return DEFAULT_SCAN_CONFIG
    mapping = _require_mapping(data, where="<root>")
    if not mapping:
        return DEFAULT_SCAN_CONFIG
    _reject_unknown_keys(mapping, _TOP_LEVEL_KEYS, where="<root>")
    return ScanConfig(
        phases=_parse_phases(mapping.get("phases")),
        trust_enumeration=_parse_trust(mapping.get("trust_enumeration")),
        attack_paths=_parse_attack_paths(mapping.get("attack_paths")),
        audit_extras=_parse_audit_extras(mapping.get("audit_extras")),
        host_cap=_parse_host_cap(mapping.get("host_cap")),
        cracking=_parse_cracking(mapping.get("cracking")),
        poisoning=_parse_poisoning(mapping.get("poisoning")),
    )


def load_scan_config(path: str | Path | None) -> ScanConfig:
    """Load and validate a scan-config file (YAML or JSON).

    Args:
        path: Path to the config file. ``None`` or an empty string returns
            :data:`DEFAULT_SCAN_CONFIG` (= today's behavior).

    Returns:
        A validated :class:`ScanConfig`.

    Raises:
        ScanConfigError: When the file is missing, unreadable, not valid
            YAML/JSON, or fails schema validation.
    """
    if not path:
        return DEFAULT_SCAN_CONFIG

    config_path = Path(path)
    if not config_path.is_file():
        raise ScanConfigError(f"Scan config file not found: {config_path}")

    try:
        text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ScanConfigError(
            f"Could not read scan config file {config_path}: {exc}"
        ) from exc

    if not text.strip():
        return DEFAULT_SCAN_CONFIG

    # YAML is a superset of JSON, so yaml.safe_load parses both. We import here
    # so the module stays importable in any context even if PyYAML is absent
    # (it is a hard dependency, but the import is cheap and locally scoped).
    import yaml

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ScanConfigError(
            f"Scan config file {config_path} is not valid YAML/JSON: {exc}"
        ) from exc

    return parse_scan_config(data)
