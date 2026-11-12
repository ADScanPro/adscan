"""Scan-policy definitions and the three built-ins.

A *definition* is what gets saved, attached to an authorization and carried in
the scan config: a base, explicit enables and disables (check ids or
``family:<id>`` selectors), what to do with checks added by a later release, the
attack-step execution mode, and an opaque pacing block. It is resolved against a
registry by :mod:`adscan_core.scan_policy.resolve`; this module never looks at a
registry except through the base-rule predicates.

The built-ins are defined by check METADATA, never by hand-picked lists, so a new
catalog entry lands in the right built-in by what it declares:

* **Lab / CTF** (``lab_ctf``): every check ADscan can run, at the Fast pace.
* **Audit** (``audit``): what reverts on its own; off what needs a manual
  cleanup, cannot be undone or can lock accounts (the check's ``availability``),
  at the Normal pace.
* **Production-sensitive** (``production_sensitive``): no directory write, no
  lockout-counting attempt, no interference, at the Polite pace, deciding each
  attack step during the scan. The Enterprise web default.

The first-generation bases (``full_validation``, ``detection_only``,
``safe_for_production``) stay valid so saved policies, scan-config files and
``builtin:<id>`` references keep working; they are not offered as built-ins.

Design: docs/superpowers/specs/2026-11-04-scan-policy-checks-by-family-design.md § 6
and docs/superpowers/specs/2026-11-04-scan-policy-two-groups-three-states.md § 3.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from adscan_core.scan_pacing.pacing_levels import PRODUCTION_SAFE_LEVEL, PacingLevel
from adscan_core.scan_pacing.pacing_model import PacingConfigError, parse_pacing_request
from adscan_core.scan_policy.model import (
    AVAILABILITY_DEFAULT,
    ENV_NONE,
    GROUP_COLLECTION,
    INTERFERENCE_NONE,
    KIND_DETECTION,
    LOCKOUT_NONE,
    LOCKOUT_NOT_APPLICABLE,
    CheckDefinition,
)
from adscan_core.scan_policy.settings import PolicySettingError, parse_settings

# ── Bases ────────────────────────────────────────────────────────────────────
BASE_LAB_CTF = "lab_ctf"
BASE_AUDIT = "audit"
BASE_PRODUCTION_SENSITIVE = "production_sensitive"
#: First-generation bases, kept for back-compat (saved policies, scan configs).
BASE_FULL_VALIDATION = "full_validation"
BASE_DETECTION_ONLY = "detection_only"
BASE_SAFE_FOR_PRODUCTION = "safe_for_production"

#: The built-ins offered to a client, in the order they are offered.
BUILTIN_IDS: tuple[str, ...] = (BASE_LAB_CTF, BASE_AUDIT, BASE_PRODUCTION_SENSITIVE)
LEGACY_BASES: tuple[str, ...] = (BASE_FULL_VALIDATION, BASE_DETECTION_ONLY, BASE_SAFE_FOR_PRODUCTION)
BASES: tuple[str, ...] = BUILTIN_IDS + LEGACY_BASES

#: A legacy built-in reference that now names a current built-in. A definition
#: keeps its own base (its digest must not move); a REFERENCE to the legacy
#: built-in (``builtin:safe_for_production``) resolves to the current one.
LEGACY_BUILTIN_ALIASES: dict[str, str] = {
    BASE_FULL_VALIDATION: BASE_LAB_CTF,
    BASE_SAFE_FOR_PRODUCTION: BASE_PRODUCTION_SENSITIVE,
}

NEW_CHECKS_FOLLOW_BASE = "follow_base"
NEW_CHECKS_DISABLED = "disabled"
NEW_CHECKS_VALUES: tuple[str, ...] = (NEW_CHECKS_FOLLOW_BASE, NEW_CHECKS_DISABLED)

# ── Attack-step execution mode ───────────────────────────────────────────────
#: Run exactly the enabled attack steps, without asking. Honoured only by an
#: unattended run (``adscan ci``, the web worker); an interactive ``start``
#: always decides each step live.
EXECUTION_UNATTENDED = "unattended"
#: Preselect nothing: the operator decides each attack step during the scan. A
#: run with no operator maps the steps without executing them, and says so.
EXECUTION_ATTENDED = "attended"
EXECUTION_MODES: tuple[str, ...] = (EXECUTION_UNATTENDED, EXECUTION_ATTENDED)
EXECUTION_MODE_LABELS: dict[str, str] = {
    EXECUTION_UNATTENDED: "Unattended",
    EXECUTION_ATTENDED: "Decide during scan",
}
EXECUTION_MODE_DESCRIPTIONS: dict[str, str] = {
    EXECUTION_UNATTENDED: (
        "ADscan executes exactly the attack steps this policy enables, without "
        "asking. Turning a step on means you want it to run on its own."
    ),
    EXECUTION_ATTENDED: (
        "No step is preselected. An operator decides each attack step as the scan "
        "reaches it. A run with no operator maps the steps and executes none."
    ),
}

#: Syntax of a check id or a family selector in a policy (registry-agnostic).
CHECK_SELECTOR_PATTERN = re.compile(r"^(step|finding|probe|module|family):[a-z0-9_.-]+$")

#: The pacing level the production-sensitive built-in selects, imported from
#: the pacing SSOT (docs/superpowers/specs/2026-11-04-scan-pacing-ssot-design.md
#: § 3.2, decision D1) so a rename there cannot leave the built-in pointing at a
#: level that no longer exists. A test asserts the description names this level.
SAFE_FOR_PRODUCTION_PACING_LEVEL: str | None = PRODUCTION_SAFE_LEVEL.value

#: The pace each base implies (its default and ceiling). The first-generation
#: ``full_validation`` and ``detection_only`` never set a pace and keep not
#: setting one, so a saved policy built on them runs exactly as it did.
BASE_PACING_LEVELS: dict[str, str] = {
    BASE_LAB_CTF: PacingLevel.FAST.value,
    BASE_AUDIT: PacingLevel.NORMAL.value,
    BASE_PRODUCTION_SENSITIVE: PRODUCTION_SAFE_LEVEL.value,
    BASE_SAFE_FOR_PRODUCTION: PRODUCTION_SAFE_LEVEL.value,
}

#: The execution mode a base implies when the definition does not name one.
#: Every first-generation definition ran unattended in ``ci``, so it keeps doing so.
BASE_EXECUTION_MODES: dict[str, str] = {
    BASE_LAB_CTF: EXECUTION_UNATTENDED,
    BASE_AUDIT: EXECUTION_UNATTENDED,
    BASE_PRODUCTION_SENSITIVE: EXECUTION_ATTENDED,
}

#: The environment a policy is written for. It is the single source of truth of
#: what used to be the workspace type: ``lab`` (a disposable lab or CTF, where
#: ADscan may leave changes and goes after flags) or ``real`` (a client's
#: environment). The workspace type every reader still consults (``ctf`` /
#: ``audit``) is DERIVED from it (:func:`workspace_type_for_environment`); no
#: other stored value says which of the two a workspace is.
ENVIRONMENT_LAB = "lab"
ENVIRONMENT_REAL = "real"
ENVIRONMENTS: tuple[str, ...] = (ENVIRONMENT_LAB, ENVIRONMENT_REAL)
ENVIRONMENT_LABELS: dict[str, str] = {
    ENVIRONMENT_LAB: "Lab or CTF",
    ENVIRONMENT_REAL: "Real environment",
}
ENVIRONMENT_DESCRIPTIONS: dict[str, str] = {
    ENVIRONMENT_LAB: (
        "A disposable lab or CTF box. Flags are collected and the defaults favour "
        "finishing the box."
    ),
    ENVIRONMENT_REAL: (
        "A client's environment. The defaults favour leaving it as it was found."
    ),
}

#: The environment each base is written for when a definition does not name one.
#: Every base other than Lab / CTF is for a real environment, the first-generation
#: ``full_validation`` included: it was the default of every workspace, and a CTF
#: workspace that saved one is stamped ``lab`` when it is migrated
#: (``adscan_internal.services.scan_controls``).
BASE_ENVIRONMENTS: dict[str, str] = {BASE_LAB_CTF: ENVIRONMENT_LAB}

#: The workspace type an environment stands for (telemetry, the web and the
#: on-disk ``variables.json`` still carry these two values).
WORKSPACE_TYPE_CTF = "ctf"
WORKSPACE_TYPE_AUDIT = "audit"
_WORKSPACE_TYPE_BY_ENVIRONMENT: dict[str, str] = {
    ENVIRONMENT_LAB: WORKSPACE_TYPE_CTF,
    ENVIRONMENT_REAL: WORKSPACE_TYPE_AUDIT,
}

#: Password attempts (founder decision 2026-11-05, "Margen de intentos de
#: contraseña configurable en la política"). A policy may carry
#: ``password_attempts: {reserve_margin, unknown_threshold, ignore_threshold}``;
#: absent means today's behaviour. The spray eligibility SSOT
#: (``adscan_internal.services.spray_policy_service.resolve_password_attempt_rules``)
#: is the only consumer.
#:
#: * ``reserve_margin``: failed attempts kept in reserve below each account's
#:   lockout threshold. Default 2 (threshold 5: at most 3 failed attempts). For a
#:   real environment the minimum is 1, because reaching the threshold IS the
#:   lockout; a lab may use 0.
#: * ``unknown_threshold``: what to do when the threshold cannot be read.
#:   ``conservative`` assumes threshold 3 and one attempt per account per hour;
#:   ``attempt_anyway`` sprays without that limit and is honoured only for a lab
#:   (a real-environment policy is always conservative). Default: the
#:   environment's (lab ``attempt_anyway``, real ``conservative``), which is what
#:   a CTF and an audit workspace did before the policy carried it.
#: * ``ignore_threshold``: lab only; spray as if no account could lock.
PASSWORD_ATTEMPTS_KEYS: frozenset[str] = frozenset(
    {"reserve_margin", "unknown_threshold", "ignore_threshold"}
)
DEFAULT_RESERVE_MARGIN = 2
REAL_ENVIRONMENT_MIN_RESERVE_MARGIN = 1
MAX_RESERVE_MARGIN = 20
UNKNOWN_THRESHOLD_CONSERVATIVE = "conservative"
UNKNOWN_THRESHOLD_ATTEMPT_ANYWAY = "attempt_anyway"
UNKNOWN_THRESHOLD_VALUES: tuple[str, ...] = (
    UNKNOWN_THRESHOLD_CONSERVATIVE,
    UNKNOWN_THRESHOLD_ATTEMPT_ANYWAY,
)
#: The threshold assumed when it cannot be read (conservative handling).
CONSERVATIVE_ASSUMED_THRESHOLD = 3
_ENVIRONMENT_UNKNOWN_THRESHOLD_DEFAULTS: dict[str, str] = {
    ENVIRONMENT_LAB: UNKNOWN_THRESHOLD_ATTEMPT_ANYWAY,
    ENVIRONMENT_REAL: UNKNOWN_THRESHOLD_CONSERVATIVE,
}

#: Keys a policy's pacing block may carry: the request shape only. The ceiling a
#: scan applies is derived from the policy, never written into it.
_PACING_KEYS = frozenset({"level", "overrides"})


class ScanPolicyError(ValueError):
    """A policy definition is malformed."""


@dataclass(frozen=True)
class PolicyIdentity:
    """Who the policy is, for disclosure only. Never read by resolution logic."""

    policy_id: str = ""
    name: str = ""
    revision: int = 0
    modified_for_this_scan: bool = False


@dataclass(frozen=True)
class ScanPolicyDefinition:
    """A saved or inline scan policy.

    Attributes:
        base: One of :data:`BASES`.
        enabled: Check ids or ``family:<id>`` selectors switched on over the base.
        disabled: Check ids or ``family:<id>`` selectors switched off.
        new_checks: :data:`NEW_CHECKS_DISABLED` keeps a check introduced after
            ``saved_at_registry_version`` off until someone enables it.
        saved_at_registry_version: Registry version the policy was saved against.
        pacing: OPAQUE pacing block owned by the pacing spec; stored, digested
            and disclosed here, never interpreted.
        execution_mode: :data:`EXECUTION_UNATTENDED` or
            :data:`EXECUTION_ATTENDED`; empty means the base's default
            (:func:`effective_execution_mode`).
        environment: :data:`ENVIRONMENT_LAB` or :data:`ENVIRONMENT_REAL`; empty
            means the base's (:func:`effective_environment`).
        password_attempts: The validated ``password_attempts`` block (only the
            keys the policy sets), or ``None`` for today's behaviour
            (:func:`effective_password_attempts`).
        settings: The behaviour settings the policy sets explicitly (only those
            keys; :mod:`adscan_core.scan_policy.settings`), or ``None`` for the
            environment's defaults.
        identity: Disclosure-only identity.
    """

    base: str = BASE_FULL_VALIDATION
    enabled: tuple[str, ...] = ()
    disabled: tuple[str, ...] = ()
    new_checks: str = NEW_CHECKS_FOLLOW_BASE
    saved_at_registry_version: int = 0
    pacing: Mapping[str, Any] | None = None
    identity: PolicyIdentity = field(default_factory=PolicyIdentity)
    execution_mode: str = ""
    environment: str = ""
    password_attempts: Mapping[str, Any] | None = None
    settings: Mapping[str, str] | None = None

    @property
    def is_default(self) -> bool:
        """True when this definition is today's behaviour (full validation)."""
        return (
            self.base == BASE_FULL_VALIDATION
            and not self.enabled
            and not self.disabled
            and self.new_checks == NEW_CHECKS_FOLLOW_BASE
            and not self.pacing
            and not self.execution_mode
            and not self.environment
            and not self.password_attempts
            and not self.settings
        )

    def canonical(self) -> dict[str, Any]:
        """Canonical JSON-ready form (sorted lists): the digest input.

        ``execution_mode`` and ``environment`` are carried only when set, so
        the digest of a definition written before either existed does not move.
        """
        out: dict[str, Any] = {
            "base": self.base,
            "enabled": sorted(set(self.enabled)),
            "disabled": sorted(set(self.disabled)),
            "new_checks": self.new_checks,
            "saved_at_registry_version": int(self.saved_at_registry_version),
            "pacing": dict(self.pacing) if self.pacing else None,
        }
        if self.execution_mode:
            out["execution_mode"] = self.execution_mode
        if self.environment:
            out["environment"] = self.environment
        if self.password_attempts:
            out["password_attempts"] = dict(sorted(self.password_attempts.items()))
        if self.settings:
            out["settings"] = dict(sorted(self.settings.items()))
        return out


# ── Base rules: functions of check metadata ──────────────────────────────────


def _every_check(check: CheckDefinition) -> bool:
    return True


def _detection_only(check: CheckDefinition) -> bool:
    # By family, not by dependency closure: a closure would switch the coercion
    # probes on (CVE detections need them), the opposite of what the name says.
    return check.kind == KIND_DETECTION or check.family == "collection"


def _production_sensitive(check: CheckDefinition) -> bool:
    if check.kind == KIND_DETECTION:
        return True
    return (
        check.environment_change == ENV_NONE
        and check.lockout_risk in {LOCKOUT_NOT_APPLICABLE, LOCKOUT_NONE}
        and check.service_interference == INTERFERENCE_NONE
    )


def _audit(check: CheckDefinition) -> bool:
    if check.kind == KIND_DETECTION or check.group == GROUP_COLLECTION:
        return True
    # ``availability`` is derived at registry build from the declared safety
    # axes: reverting on its own is on, manual cleanup / not reversible /
    # possible lockout / undeclared is off.
    return check.availability == AVAILABILITY_DEFAULT


BASE_RULES: dict[str, Callable[[CheckDefinition], bool]] = {
    BASE_LAB_CTF: _every_check,
    BASE_AUDIT: _audit,
    BASE_PRODUCTION_SENSITIVE: _production_sensitive,
    BASE_FULL_VALIDATION: _every_check,
    BASE_DETECTION_ONLY: _detection_only,
    BASE_SAFE_FOR_PRODUCTION: _production_sensitive,
}

#: Client-facing names of the bases. A first-generation base keeps the name it
#: was saved under, so a disclosure of an older policy still matches the
#: authorization it was signed against.
BUILTIN_LABELS: dict[str, str] = {
    BASE_LAB_CTF: "Lab / CTF",
    BASE_AUDIT: "Audit",
    BASE_PRODUCTION_SENSITIVE: "Production-sensitive",
    BASE_FULL_VALIDATION: "Full validation",
    BASE_DETECTION_ONLY: "Detection only",
    BASE_SAFE_FOR_PRODUCTION: "Safe for production",
}

#: Client-facing descriptions. Each sentence is a claim about what the built-in
#: resolves to, and ``tests/unit/scan_policy/test_builtin_descriptions_true.py``
#: holds every claim to the computed coverage ("every check", "runs no attack
#: step", "send no unguarded password attempts"), so a description cannot drift from its counts.
BUILTIN_DESCRIPTIONS: dict[str, str] = {
    BASE_LAB_CTF: (
        "Every check ADscan can run, including attack steps that leave changes to "
        "clean up or cannot be undone, at the Fast pace. For labs and CTFs."
    ),
    BASE_AUDIT: (
        "The attack steps whose changes roll back on their own, and the "
        "vulnerability checks that send no unguarded password attempts, at the Normal "
        "pace. Steps whose change only a cleanup account can undo, such as those that "
        "request a certificate from your CA, run when you supply one and ADscan "
        "confirms it can undo that change. Steps that need a manual cleanup, cannot be "
        "undone or send unguarded password attempts stay off until you turn them on."
    ),
    BASE_PRODUCTION_SENSITIVE: (
        # The level name is the one SAFE_FOR_PRODUCTION_PACING_LEVEL resolves to.
        "Only the checks that change nothing in your directory, send no unguarded "
        "password attempts and do not make other systems authenticate to the scanner, "
        "at the Polite pace. An operator decides each attack step during the scan."
    ),
    BASE_FULL_VALIDATION: (
        "Every check ADscan can run, including techniques that write to your "
        "environment."
    ),
    BASE_DETECTION_ONLY: (
        "Collects the directory and evaluates the detections that read what it "
        "collected. Runs no attack step and no probe, so a weakness only a probe or "
        "an attack step can find is not assessed."
    ),
    BASE_SAFE_FOR_PRODUCTION: (
        "Only the checks that change nothing in your directory, send no unguarded "
        "password attempts and do not make other systems authenticate to the scanner, "
        "at the Polite pace recommended for production networks."
    ),
}

#: The built-in a workspace type preselects (the CLI start selector) and the
#: one the consent rule falls back to when a run carries no policy. Workspace
#: type keeps its other meanings; it is no longer the safety switch.
_WORKSPACE_TYPE_BUILTINS: dict[str, str] = {"ctf": BASE_LAB_CTF}


def builtin_for_workspace_type(workspace_type: str | None) -> str:
    """The built-in id a workspace saved with a retired ``type`` is migrated to.

    Only the workspace-load migration reads it
    (``adscan_internal.services.scan_controls._migrate_workspace_type``):
    ``ctf`` (a disposable lab) maps to Lab / CTF; every other value, an unknown
    one included, to Audit.
    """
    return _WORKSPACE_TYPE_BUILTINS.get(str(workspace_type or "").strip().lower(), BASE_AUDIT)


def builtin_for_environment(environment: str | None) -> str:
    """The built-in for a policy environment: Lab / CTF for a lab, Audit otherwise.

    What a workspace without a policy of its own preselects, and the policy the
    consent rule falls back to when a run carries none (an unknown environment
    reads as real, the conservative side).
    """
    return BASE_LAB_CTF if str(environment or "").strip().lower() == ENVIRONMENT_LAB else BASE_AUDIT


def canonical_builtin_id(builtin_id: str) -> str:
    """The current built-in a (possibly legacy) built-in id names."""
    key = str(builtin_id or "").strip().lower()
    return LEGACY_BUILTIN_ALIASES.get(key, key)


def effective_execution_mode(definition: ScanPolicyDefinition) -> str:
    """The attack-step execution mode a definition asks for."""
    if definition.execution_mode in EXECUTION_MODES:
        return definition.execution_mode
    return BASE_EXECUTION_MODES.get(definition.base, EXECUTION_UNATTENDED)


def effective_environment(definition: ScanPolicyDefinition | None) -> str:
    """The environment a definition is written for (its own, else its base's)."""
    if definition is None:
        return ""
    if definition.environment in ENVIRONMENTS:
        return definition.environment
    return BASE_ENVIRONMENTS.get(definition.base, ENVIRONMENT_REAL)


def workspace_type_for_environment(environment: str | None) -> str | None:
    """``ctf`` for a lab, ``audit`` for a real environment, ``None`` when unknown."""
    return _WORKSPACE_TYPE_BY_ENVIRONMENT.get(str(environment or "").strip().lower())


def workspace_type_for_definition(definition: ScanPolicyDefinition | None) -> str | None:
    """The workspace type a policy makes its workspace (``None`` without a policy)."""
    return workspace_type_for_environment(effective_environment(definition))


def environment_for_workspace_type(workspace_type: str | None) -> str | None:
    """The environment a (legacy) workspace type stands for, ``None`` when unknown."""
    token = str(workspace_type or "").strip().lower()
    for environment, kind in _WORKSPACE_TYPE_BY_ENVIRONMENT.items():
        if kind == token:
            return environment
    return None


def parse_environment(value: Any, *, where: str = "checks.environment") -> str:
    """Validate an environment; ``None`` or empty means the base's."""
    if value is None:
        return ""
    token = str(value).strip().lower()
    if not token:
        return ""
    if token not in ENVIRONMENTS:
        raise ScanPolicyError(f"'{where}' must be one of {', '.join(ENVIRONMENTS)}.")
    return token


def parse_password_attempts(
    raw: Any, *, environment: str, where: str = "checks.password_attempts"
) -> dict[str, Any] | None:
    """Validate a ``password_attempts`` block for a policy of ``environment``.

    Returns only the keys it sets (``None`` for an absent or empty block).
    ``unknown_threshold: attempt_anyway`` is accepted on any policy and applied
    only to a lab (:func:`effective_password_attempts`).

    Raises:
        ScanPolicyError: On an unknown key, a value of the wrong type, a margin
            below the environment's minimum, or ``ignore_threshold`` on a policy
            for a real environment.
    """
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise ScanPolicyError(f"'{where}' must be a mapping.")
    if not raw:
        return None
    unknown = sorted(str(k) for k in raw if str(k) not in PASSWORD_ATTEMPTS_KEYS)
    if unknown:
        raise ScanPolicyError(
            f"Unknown key(s) in '{where}': {', '.join(unknown)}. "
            f"Valid: {', '.join(sorted(PASSWORD_ATTEMPTS_KEYS))}."
        )
    out: dict[str, Any] = {}
    real = environment != ENVIRONMENT_LAB
    if raw.get("reserve_margin") is not None:
        value = raw["reserve_margin"]
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise ScanPolicyError(f"'{where}.reserve_margin' must be a whole number.")
        try:
            margin = int(str(value).strip())
        except ValueError as exc:
            raise ScanPolicyError(f"'{where}.reserve_margin' must be a whole number.") from exc
        minimum = REAL_ENVIRONMENT_MIN_RESERVE_MARGIN if real else 0
        if margin < minimum:
            raise ScanPolicyError(
                f"'{where}.reserve_margin' must be at least {minimum} for a policy for a "
                "real environment: reaching an account's lockout threshold locks it, so "
                "at least one attempt must stay in reserve."
                if real
                else f"'{where}.reserve_margin' cannot be negative."
            )
        if margin > MAX_RESERVE_MARGIN:
            raise ScanPolicyError(f"'{where}.reserve_margin' is at most {MAX_RESERVE_MARGIN}.")
        out["reserve_margin"] = margin
    if raw.get("unknown_threshold") is not None:
        token = str(raw["unknown_threshold"]).strip().lower()
        if token not in UNKNOWN_THRESHOLD_VALUES:
            raise ScanPolicyError(
                f"'{where}.unknown_threshold' must be one of {', '.join(UNKNOWN_THRESHOLD_VALUES)}."
            )
        out["unknown_threshold"] = token
    if raw.get("ignore_threshold") is not None:
        flag = raw["ignore_threshold"]
        if not isinstance(flag, bool):
            raise ScanPolicyError(f"'{where}.ignore_threshold' must be true or false.")
        if flag and real:
            raise ScanPolicyError(
                f"'{where}.ignore_threshold' is allowed only on a policy for a lab: on a "
                "real environment it would lock accounts."
            )
        if flag:
            out["ignore_threshold"] = True
    return out or None


def effective_password_attempts(
    definition: ScanPolicyDefinition | None, *, environment: str | None = None
) -> dict[str, Any]:
    """The password-attempt rules a policy imposes, defaults and the floor applied.

    ``environment`` overrides the definition's (a run without a policy passes
    the workspace's). Returns ``reserve_margin``, ``unknown_threshold``,
    ``ignore_threshold``, ``environment``, ``declared`` (the policy set at least
    one key) and ``unknown_threshold_forced`` (the policy asked to attempt
    anyway, which a real environment never does).
    """
    env = environment or (effective_environment(definition) if definition else ENVIRONMENT_REAL)
    if env not in ENVIRONMENTS:
        env = ENVIRONMENT_REAL
    block = dict(definition.password_attempts or {}) if definition is not None else {}
    lab = env == ENVIRONMENT_LAB
    margin = int(block.get("reserve_margin", DEFAULT_RESERVE_MARGIN))
    if not lab:
        margin = max(margin, REAL_ENVIRONMENT_MIN_RESERVE_MARGIN)
    asked = block.get("unknown_threshold")
    unknown = asked or _ENVIRONMENT_UNKNOWN_THRESHOLD_DEFAULTS[env]
    forced = False
    if not lab and unknown != UNKNOWN_THRESHOLD_CONSERVATIVE:
        unknown, forced = UNKNOWN_THRESHOLD_CONSERVATIVE, True
    return {
        "reserve_margin": margin,
        "unknown_threshold": unknown,
        "ignore_threshold": bool(lab and block.get("ignore_threshold")),
        "environment": env,
        "declared": bool(block),
        "unknown_threshold_forced": forced,
    }


def password_attempts_line(
    rules: Mapping[str, Any] | None, *, sends_password_attempts: bool | None = None
) -> str:
    """One client-facing sentence stating the password-attempt rule a run used.

    ``sends_password_attempts`` is whether any check the policy runs sends a
    password attempt (``summary.policy_sends_password_attempts``). When it is
    ``False`` the rule is stated as conditional ("If you turn on a
    password-guessing check, it stops ..."): printed flat, it sat under
    "Nothing it runs sends password attempts" and read as a contradiction.
    ``None`` (not known) keeps the flat wording.
    """
    if not isinstance(rules, Mapping) or not rules:
        return ""
    scoped = sends_password_attempts is False
    if rules.get("ignore_threshold"):
        if scoped:
            return (
                "The scan policy is for a lab and ignores the account lockout threshold, "
                "so a password-guessing check, if you turn one on, may lock accounts."
            )
        return (
            "The scan policy is for a lab and ignores the account lockout threshold, "
            "so password guessing may lock accounts."
        )
    margin = int(rules.get("reserve_margin") or 0)
    subject = "If you turn on a password-guessing check, it" if scoped else "Password guessing"
    if margin > 0:
        head = (
            f"{subject} stops {margin} attempt{'s' if margin != 1 else ''} short "
            "of each account's lockout threshold."
        )
    else:
        head = (
            f"{subject} may reach each account's lockout threshold, which the "
            "scan policy allows because it is for a lab."
        )
    if rules.get("unknown_threshold") == UNKNOWN_THRESHOLD_ATTEMPT_ANYWAY:
        tail = (
            " Where the threshold cannot be read, the lab policy lets guessing go ahead "
            "without the one-attempt-per-hour limit."
        )
    else:
        tail = (
            " Where the threshold cannot be read, ADscan assumes a threshold of "
            f"{CONSERVATIVE_ASSUMED_THRESHOLD} and makes one attempt per account per hour."
        )
    return head + tail


def builtin_definition(base: str) -> ScanPolicyDefinition:
    """The definition of a built-in policy (a legacy id gives its legacy definition)."""
    if base not in BASE_RULES:
        raise ScanPolicyError(f"Unknown built-in policy '{base}'.")
    level = BASE_PACING_LEVELS.get(base)
    pacing: dict[str, Any] | None = {"level": level} if level else None
    return ScanPolicyDefinition(
        base=base,
        pacing=pacing,
        execution_mode=BASE_EXECUTION_MODES.get(base, ""),
        identity=PolicyIdentity(policy_id=f"builtin:{base}", name=BUILTIN_LABELS[base]),
    )


# ── Parsing ──────────────────────────────────────────────────────────────────


def _selector_list(value: Any, *, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        raise ScanPolicyError(f"'{where}' must be a list of check ids.")
    out: list[str] = []
    for item in value:
        token = str(item or "").strip().lower()
        if not token:
            continue
        if not CHECK_SELECTOR_PATTERN.match(token):
            raise ScanPolicyError(
                f"'{where}' entry '{item}' is not a check id or 'family:<id>' selector."
            )
        out.append(token)
    return tuple(dict.fromkeys(out))


_ALLOWED_KEYS = frozenset(
    {
        "base",
        "enabled",
        "disabled",
        "new_checks",
        "saved_at_registry_version",
        "pacing",
        "policy",
        "execution_mode",
        "environment",
        "password_attempts",
        "settings",
    }
)


def parse_execution_mode(value: Any, *, where: str = "checks.execution_mode") -> str:
    """Validate an execution mode; ``None`` or empty means the base's default."""
    if value is None:
        return ""
    token = str(value).strip().lower()
    if not token:
        return ""
    if token not in EXECUTION_MODES:
        raise ScanPolicyError(f"'{where}' must be one of {', '.join(EXECUTION_MODES)}.")
    return token


def parse_policy_definition(data: Any) -> ScanPolicyDefinition:
    """Validate a mapping (the scan-config ``checks`` section) into a definition.

    Only shape and syntax are validated here; unknown ids and locked checks are
    a registry question, answered by :func:`adscan_core.scan_policy.resolve.resolve_policy`.

    Raises:
        ScanPolicyError: On an unknown key, an unknown base, a bad selector, or a
            malformed pacing / identity block.
    """
    if data is None:
        return ScanPolicyDefinition()
    if not isinstance(data, Mapping):
        raise ScanPolicyError("'checks' must be a mapping.")
    unknown = sorted(set(data) - _ALLOWED_KEYS)
    if unknown:
        raise ScanPolicyError(f"Unknown key(s) in 'checks': {', '.join(unknown)}.")
    base = str(data.get("base") or BASE_FULL_VALIDATION).strip().lower()
    if base not in BASE_RULES:
        raise ScanPolicyError(f"'checks.base' must be one of {', '.join(BASES)}.")
    new_checks = str(data.get("new_checks") or NEW_CHECKS_FOLLOW_BASE).strip().lower()
    if new_checks not in NEW_CHECKS_VALUES:
        raise ScanPolicyError(
            f"'checks.new_checks' must be one of {', '.join(NEW_CHECKS_VALUES)}."
        )
    try:
        saved_at = int(data.get("saved_at_registry_version") or 0)
    except (TypeError, ValueError) as exc:
        raise ScanPolicyError("'checks.saved_at_registry_version' must be an integer.") from exc
    pacing = _parse_policy_pacing(data.get("pacing"))
    environment = parse_environment(data.get("environment"))
    raw_identity = data.get("policy") or {}
    if not isinstance(raw_identity, Mapping):
        raise ScanPolicyError("'checks.policy' must be a mapping.")
    try:
        revision = int(raw_identity.get("revision") or 0)
    except (TypeError, ValueError) as exc:
        raise ScanPolicyError("'checks.policy.revision' must be an integer.") from exc
    identity = PolicyIdentity(
        policy_id=str(raw_identity.get("id") or ""),
        name=str(raw_identity.get("name") or ""),
        revision=revision,
        modified_for_this_scan=bool(raw_identity.get("modified_for_this_scan", False)),
    )
    return ScanPolicyDefinition(
        base=base,
        enabled=_selector_list(data.get("enabled"), where="checks.enabled"),
        disabled=_selector_list(data.get("disabled"), where="checks.disabled"),
        new_checks=new_checks,
        saved_at_registry_version=saved_at,
        pacing=pacing,
        identity=identity,
        execution_mode=parse_execution_mode(data.get("execution_mode")),
        environment=environment,
        password_attempts=parse_password_attempts(
            data.get("password_attempts"),
            environment=environment or BASE_ENVIRONMENTS.get(base, ENVIRONMENT_REAL),
        ),
        settings=_parse_settings(
            data.get("settings"),
            environment=environment or BASE_ENVIRONMENTS.get(base, ENVIRONMENT_REAL),
        ),
    )


def _parse_settings(raw: Any, *, environment: str) -> dict[str, str] | None:
    """Validate the ``settings`` block through the settings SSOT."""
    try:
        return parse_settings(raw, environment=environment)
    except PolicySettingError as exc:
        raise ScanPolicyError(str(exc)) from exc


def _parse_policy_pacing(raw: Any) -> dict[str, Any] | None:
    """Validate a policy's pacing block through the pacing SSOT's validator.

    The policy layer stores, digests and discloses the block without
    interpreting it, but a block naming an unknown level or knob fails here, at
    the boundary, rather than when a scan later applies it as a ceiling.
    """
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise ScanPolicyError("'checks.pacing' must be a mapping.")
    if not raw:
        return None
    unknown = sorted(str(k) for k in raw if str(k) not in _PACING_KEYS)
    if unknown:
        raise ScanPolicyError(
            f"Unknown key(s) in 'checks.pacing': {', '.join(unknown)}. "
            f"Valid: {', '.join(sorted(_PACING_KEYS))}."
        )
    try:
        request = parse_pacing_request(raw, source="policy")
    except PacingConfigError as exc:
        raise ScanPolicyError(f"'checks.pacing': {exc}") from exc
    return request.to_dict()


def effective_pacing(definition: ScanPolicyDefinition) -> dict[str, Any] | None:
    """The pace a policy imposes: its own block, else the one its base implies.

    The base rule includes the pace (spec § 6.2): a policy built on a base with
    a pace is capped at that level even when its definition carries no pacing
    block, so a hand-written ``checks: {base: production_sensitive}`` means the
    same as the built-in of that name.
    """
    if definition.pacing:
        return dict(definition.pacing)
    level = BASE_PACING_LEVELS.get(definition.base)
    if level:
        return {"level": level}
    return None


def policy_display_name(definition: ScanPolicyDefinition) -> str:
    """Client-facing name of a policy: its saved name, else the built-in it extends.

    The one place the name is worded, so the REPL, the persisted workspace
    record, the report's scope section and the web scan detail say the same.
    """
    identity = definition.identity
    customised = bool(definition.enabled or definition.disabled)
    if identity.name:
        if identity.modified_for_this_scan:
            return f"{identity.name} (modified)"
        return identity.name
    label = BUILTIN_LABELS.get(definition.base, definition.base)
    return f"{label} (customised)" if customised else label


def definition_to_section(definition: ScanPolicyDefinition) -> dict[str, Any]:
    """Serialise a definition to the scan-config ``checks`` section shape.

    The inverse of :func:`parse_policy_definition`
    (``parse_policy_definition(definition_to_section(d)) == d``). Defaults are
    omitted, so the default definition serialises to ``{}``.
    """
    out: dict[str, Any] = {}
    if definition.base != BASE_FULL_VALIDATION:
        out["base"] = definition.base
    if definition.enabled:
        out["enabled"] = list(definition.enabled)
    if definition.disabled:
        out["disabled"] = list(definition.disabled)
    if definition.new_checks != NEW_CHECKS_FOLLOW_BASE:
        out["new_checks"] = definition.new_checks
    if definition.saved_at_registry_version:
        out["saved_at_registry_version"] = int(definition.saved_at_registry_version)
    if definition.pacing:
        out["pacing"] = dict(definition.pacing)
    if definition.execution_mode:
        out["execution_mode"] = definition.execution_mode
    if definition.environment:
        out["environment"] = definition.environment
    if definition.password_attempts:
        out["password_attempts"] = dict(definition.password_attempts)
    if definition.settings:
        out["settings"] = dict(definition.settings)
    identity = definition.identity
    policy: dict[str, Any] = {}
    if identity.policy_id:
        policy["id"] = identity.policy_id
    if identity.name:
        policy["name"] = identity.name
    if identity.revision:
        policy["revision"] = int(identity.revision)
    if identity.modified_for_this_scan:
        policy["modified_for_this_scan"] = True
    if policy:
        out["policy"] = policy
    return out


__all__ = (
    "BASES",
    "BASE_AUDIT",
    "BASE_DETECTION_ONLY",
    "BASE_EXECUTION_MODES",
    "BASE_FULL_VALIDATION",
    "BASE_LAB_CTF",
    "BASE_PACING_LEVELS",
    "BASE_PRODUCTION_SENSITIVE",
    "BASE_RULES",
    "BASE_SAFE_FOR_PRODUCTION",
    "BUILTIN_DESCRIPTIONS",
    "BUILTIN_IDS",
    "BUILTIN_LABELS",
    "CHECK_SELECTOR_PATTERN",
    "EXECUTION_ATTENDED",
    "EXECUTION_MODES",
    "EXECUTION_MODE_DESCRIPTIONS",
    "EXECUTION_MODE_LABELS",
    "EXECUTION_UNATTENDED",
    "LEGACY_BASES",
    "LEGACY_BUILTIN_ALIASES",
    "NEW_CHECKS_DISABLED",
    "NEW_CHECKS_FOLLOW_BASE",
    "NEW_CHECKS_VALUES",
    "PolicyIdentity",
    "SAFE_FOR_PRODUCTION_PACING_LEVEL",
    "BASE_ENVIRONMENTS",
    "CONSERVATIVE_ASSUMED_THRESHOLD",
    "DEFAULT_RESERVE_MARGIN",
    "MAX_RESERVE_MARGIN",
    "PASSWORD_ATTEMPTS_KEYS",
    "REAL_ENVIRONMENT_MIN_RESERVE_MARGIN",
    "UNKNOWN_THRESHOLD_ATTEMPT_ANYWAY",
    "UNKNOWN_THRESHOLD_CONSERVATIVE",
    "UNKNOWN_THRESHOLD_VALUES",
    "ENVIRONMENTS",
    "ENVIRONMENT_DESCRIPTIONS",
    "ENVIRONMENT_LAB",
    "ENVIRONMENT_LABELS",
    "ENVIRONMENT_REAL",
    "WORKSPACE_TYPE_AUDIT",
    "WORKSPACE_TYPE_CTF",
    "ScanPolicyDefinition",
    "ScanPolicyError",
    "builtin_definition",
    "builtin_for_environment",
    "builtin_for_workspace_type",
    "canonical_builtin_id",
    "definition_to_section",
    "effective_environment",
    "effective_execution_mode",
    "effective_pacing",
    "effective_password_attempts",
    "environment_for_workspace_type",
    "parse_environment",
    "parse_execution_mode",
    "parse_password_attempts",
    "password_attempts_line",
    "parse_policy_definition",
    "policy_display_name",
    "workspace_type_for_definition",
    "workspace_type_for_environment",
)
