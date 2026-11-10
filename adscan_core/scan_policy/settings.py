"""Scan-policy behaviour settings: how a scan works, decided by the active policy.

The check toggles decide WHAT may run. These settings decide HOW the scan
behaves around them: what it aims at, how far it reaches on its own, what the
operator is asked and what each prompt preselects. Before they existed every
one of these behaviours was a comparison against the binary workspace type
(``ctf`` / ``audit``), so a custom policy could not change any of them.

Each setting declares one value per environment. The built-ins carry no
explicit settings, so Lab / CTF resolves to the lab values and Audit and
Production-sensitive to the real-environment values: exactly the behaviour the
workspace type used to select. A custom policy overrides any setting in its
``settings`` block, within the values its environment allows (a policy for a
real environment never expands the scope on its own, never plants bait
unattended and never sends a hash to an online lookup without asking).

Read a setting through :func:`policy_setting` (a shell) or
:func:`setting_value` (a definition). A new behaviour that would branch on the
workspace type is added here instead; the structural test
``tests/unit/scan_policy/test_no_workspace_type_decisions.py`` fails CI when a
new type comparison appears outside its allow-list.

Stdlib only; never imports ``adscan_internal``.

Design: docs/superpowers/specs/2026-11-05-scan-policy-settings-replace-workspace-type.md
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

_LAB = "lab"
_REAL = "real"

# ── Setting keys and values ──────────────────────────────────────────────────
OBJECTIVE = "objective"
OBJECTIVE_DOMAIN_COMPROMISE = "domain_compromise"
OBJECTIVE_FULL_ASSESSMENT = "full_assessment"

SCOPE_EXPANSION = "scope_expansion"
SCOPE_EXPANSION_AUTOMATIC = "automatic"
SCOPE_EXPANSION_ASK = "ask"

DEFAULT_REACH = "default_reach"
DEFAULT_REACH_WIDE = "wide"
DEFAULT_REACH_BOUNDED = "bounded"

OPERATOR_PROMPTS = "operator_prompts"
OPERATOR_PROMPTS_ANSWER_DEFAULTS = "answer_defaults"
OPERATOR_PROMPTS_ASK = "ask"

CRACKING_WORDLIST = "cracking_wordlist"
CRACKING_WORDLIST_ROCKYOU = "rockyou"
CRACKING_WORDLIST_REAL_WORLD = "real_world"

CRACKING_EFFORT = "cracking_effort"
CRACKING_EFFORT_FAST = "fast"
CRACKING_EFFORT_BALANCED = "balanced"
CRACKING_EFFORT_THOROUGH = "thorough"

ONLINE_HASH_LOOKUP = "online_hash_lookup"
ONLINE_HASH_LOOKUP_ON = "on"
ONLINE_HASH_LOOKUP_ASK = "ask"
ONLINE_HASH_LOOKUP_OFF = "off"

POISONING = "poisoning"
POISONING_ON = "on"
POISONING_OFF = "off"

WRITESHARE_BAIT = "writeshare_bait"
WRITESHARE_BAIT_AUTOMATIC = "automatic"
WRITESHARE_BAIT_ASK = "ask"

REMOTE_EXECUTION = "remote_execution"
REMOTE_EXECUTION_SPEED = "speed"
REMOTE_EXECUTION_LOW_FOOTPRINT = "low_footprint"

# What a scan leaves in the directory. Read by
# ``adscan_internal.services.durable_change_policy`` (reversion, CA key backup)
# and ``machine_account_provisioning_service`` (the retained account), below an
# explicit per-run choice (scan config, ``set auto_revert``, ``--auto-revert``,
# the ``ADSCAN_*`` env overrides), which still wins.
AUTO_REVERT = "auto_revert"
AUTO_REVERT_ON = "on"
AUTO_REVERT_OFF = "off"

MACHINE_ACCOUNT = "machine_account"
MACHINE_ACCOUNT_REVERT_EACH_RUN = "revert_each_run"
MACHINE_ACCOUNT_RETAIN_ONE = "retain_one"

CA_KEY_BACKUP = "ca_key_backup"
CA_KEY_BACKUP_OFF = "off"
CA_KEY_BACKUP_ON = "on"


@dataclass(frozen=True)
class PolicySetting:
    """One behaviour setting.

    Attributes:
        key: The YAML / API key.
        label: Client-facing name.
        description: One sentence on what the setting changes.
        choices: ``(value, label, description)`` in display order.
        lab_default: The value a lab policy uses unless it sets one.
        real_default: The value a policy for a real environment uses.
        real_values: The values a policy for a real environment may set (the
            safety floor). Empty means every choice.
    """

    key: str
    label: str
    description: str
    choices: tuple[tuple[str, str, str], ...]
    lab_default: str
    real_default: str
    real_values: tuple[str, ...] = ()

    @property
    def values(self) -> tuple[str, ...]:
        return tuple(value for value, _label, _description in self.choices)

    def allowed_for(self, environment: str | None) -> tuple[str, ...]:
        """The values a policy for ``environment`` may set."""
        if environment == _LAB or not self.real_values:
            return self.values
        return self.real_values

    def default_for(self, environment: str | None) -> str:
        """The value a policy for ``environment`` uses when it sets none."""
        return self.lab_default if environment == _LAB else self.real_default

    def value_label(self, value: str) -> str:
        for choice, label, _description in self.choices:
            if choice == value:
                return label
        return value


SETTINGS: tuple[PolicySetting, ...] = (
    PolicySetting(
        key=OBJECTIVE,
        label="Objective",
        description=(
            "What the scan works towards, control of the domain or every exposure "
            "ADscan can assess."
        ),
        choices=(
            (
                OBJECTIVE_DOMAIN_COMPROMISE,
                "Domain compromise",
                "Stops the work a compromised domain makes redundant, skips "
                "unauthenticated enumeration once a credential works and leaves out "
                "the phases that only report exposure.",
            ),
            (
                OBJECTIVE_FULL_ASSESSMENT,
                "Full assessment",
                "Keeps assessing after the domain is compromised and runs every "
                "exposure phase, CVE verification and directory hygiene included.",
            ),
        ),
        lab_default=OBJECTIVE_DOMAIN_COMPROMISE,
        real_default=OBJECTIVE_FULL_ASSESSMENT,
    ),
    PolicySetting(
        key=SCOPE_EXPANSION,
        label="Scope expansion",
        description=(
            "Whether ADscan opens pivots, follows trusted domains and widens the "
            "attack-path search on its own."
        ),
        choices=(
            (
                SCOPE_EXPANSION_AUTOMATIC,
                "Automatic",
                "Opens pivots and follows newly found trusted domains without asking.",
            ),
            (
                SCOPE_EXPANSION_ASK,
                "Ask first",
                "Asks before reaching a network or a domain that was not in the "
                "original scope.",
            ),
        ),
        lab_default=SCOPE_EXPANSION_AUTOMATIC,
        real_default=SCOPE_EXPANSION_ASK,
        real_values=(SCOPE_EXPANSION_ASK,),
    ),
    PolicySetting(
        key=DEFAULT_REACH,
        label="Default reach",
        description=(
            "How much ADscan selects for you when a step offers a choice of targets "
            "or depth."
        ),
        choices=(
            (
                DEFAULT_REACH_WIDE,
                "Wide",
                "Preselects every share, every analysis phase and every host a step "
                "can reach.",
            ),
            (
                DEFAULT_REACH_BOUNDED,
                "Bounded",
                "Preselects the highest-risk targets and the lighter analysis phases. "
                "The rest stays one choice away.",
            ),
        ),
        lab_default=DEFAULT_REACH_WIDE,
        real_default=DEFAULT_REACH_BOUNDED,
    ),
    PolicySetting(
        key=OPERATOR_PROMPTS,
        label="Operator prompts",
        description="Whether an interactive scan asks its questions or takes their defaults.",
        choices=(
            (
                OPERATOR_PROMPTS_ANSWER_DEFAULTS,
                "Take the defaults",
                "Starts in auto mode, so each question takes its default answer.",
            ),
            (
                OPERATOR_PROMPTS_ASK,
                "Ask",
                "Asks the operator each question.",
            ),
        ),
        lab_default=OPERATOR_PROMPTS_ANSWER_DEFAULTS,
        real_default=OPERATOR_PROMPTS_ASK,
    ),
    PolicySetting(
        key=CRACKING_WORDLIST,
        label="Cracking wordlist",
        description="The wordlist password cracking starts from.",
        choices=(
            (
                CRACKING_WORDLIST_ROCKYOU,
                "Public breach list",
                "rockyou, where most lab passwords come from.",
            ),
            (
                CRACKING_WORDLIST_REAL_WORLD,
                "Real-world base",
                "A curated base of corporate passwords, and the operator chooses the "
                "wordlist.",
            ),
        ),
        lab_default=CRACKING_WORDLIST_ROCKYOU,
        real_default=CRACKING_WORDLIST_REAL_WORLD,
    ),
    PolicySetting(
        key=CRACKING_EFFORT,
        label="Cracking effort",
        description="How long password cracking keeps trying before it stops.",
        choices=(
            (CRACKING_EFFORT_FAST, "Fast", "A few seconds per hash type."),
            (CRACKING_EFFORT_BALANCED, "Balanced", "Adds rules within a bounded time."),
            (CRACKING_EFFORT_THOROUGH, "Thorough", "The full rule ladder."),
        ),
        lab_default=CRACKING_EFFORT_FAST,
        real_default=CRACKING_EFFORT_BALANCED,
    ),
    PolicySetting(
        key=ONLINE_HASH_LOOKUP,
        label="Online hash lookup",
        description=(
            "Whether a recovered hash may be looked up in a public online database."
        ),
        choices=(
            (ONLINE_HASH_LOOKUP_ON, "On", "Looks hashes up without asking."),
            (
                ONLINE_HASH_LOOKUP_ASK,
                "Ask",
                "Asks the operator first. An unattended scan never sends one.",
            ),
            (ONLINE_HASH_LOOKUP_OFF, "Off", "No hash leaves the scanner."),
        ),
        lab_default=ONLINE_HASH_LOOKUP_ON,
        real_default=ONLINE_HASH_LOOKUP_ASK,
        real_values=(ONLINE_HASH_LOOKUP_ASK, ONLINE_HASH_LOOKUP_OFF),
    ),
    PolicySetting(
        key=POISONING,
        label="Name-resolution poisoning",
        description=(
            "Whether the poisoning listener starts on its own when the policy "
            "enables it."
        ),
        choices=(
            (POISONING_ON, "Start it", "Starts the listener when the scan begins."),
            (
                POISONING_OFF,
                "Offer it",
                "Leaves it off. An interactive scan offers to start it.",
            ),
        ),
        lab_default=POISONING_OFF,
        real_default=POISONING_ON,
    ),
    PolicySetting(
        key=WRITESHARE_BAIT,
        label="Writable-share bait",
        description=(
            "Whether ADscan plants a capture file on writable shares when the policy "
            "enables it."
        ),
        choices=(
            (
                WRITESHARE_BAIT_AUTOMATIC,
                "Automatic",
                "Plants it on every writable share without asking.",
            ),
            (
                WRITESHARE_BAIT_ASK,
                "Ask",
                "Asks first, never plants it unattended and stops once a credential "
                "is rejected.",
            ),
        ),
        lab_default=WRITESHARE_BAIT_AUTOMATIC,
        real_default=WRITESHARE_BAIT_ASK,
        real_values=(WRITESHARE_BAIT_ASK,),
    ),
    PolicySetting(
        key=REMOTE_EXECUTION,
        label="Remote execution",
        description=(
            "Which way of running a command on a host ADscan tries first when "
            "several would work."
        ),
        choices=(
            (
                REMOTE_EXECUTION_SPEED,
                "Fastest first",
                "Tries the quickest methods first, even the ones endpoint "
                "protection notices more easily.",
            ),
            (
                REMOTE_EXECUTION_LOW_FOOTPRINT,
                "Lowest footprint first",
                "Ranks methods by how little they leave behind and how rarely "
                "endpoint protection flags them.",
            ),
        ),
        lab_default=REMOTE_EXECUTION_SPEED,
        real_default=REMOTE_EXECUTION_LOW_FOOTPRINT,
        real_values=(REMOTE_EXECUTION_LOW_FOOTPRINT,),
    ),
    PolicySetting(
        key=AUTO_REVERT,
        label="Directory changes",
        description=(
            "Whether ADscan undoes the changes it made in the directory on its own."
        ),
        choices=(
            (
                AUTO_REVERT_ON,
                "Revert them",
                "Undoes every change and re-reads each object to confirm it is gone. "
                "Anything it cannot confirm is listed with the command to run.",
            ),
            (
                AUTO_REVERT_OFF,
                "Keep them",
                "Leaves every change in place and reports it as kept.",
            ),
        ),
        lab_default=AUTO_REVERT_OFF,
        real_default=AUTO_REVERT_ON,
        # A saved policy for a real environment always reverts: residue in a
        # client's directory is never a reusable default. Keeping changes in one
        # run stays an explicit per-run choice.
        real_values=(AUTO_REVERT_ON,),
    ),
    PolicySetting(
        key=MACHINE_ACCOUNT,
        label="Computer account between scans",
        description=(
            "Whether the computer account ADscan creates is removed after each scan "
            "or one is kept and reused."
        ),
        choices=(
            (
                MACHINE_ACCOUNT_REVERT_EACH_RUN,
                "Remove it",
                "Every scan creates the account it needs and removes it at the end.",
            ),
            (
                MACHINE_ACCOUNT_RETAIN_ONE,
                "Keep one",
                "For continuous validation agreed with the client. One account named "
                "ADSCAN followed by 8 characters is reused and named in every report. "
                "Applies only while reverting is on.",
            ),
        ),
        lab_default=MACHINE_ACCOUNT_REVERT_EACH_RUN,
        real_default=MACHINE_ACCOUNT_REVERT_EACH_RUN,
    ),
    PolicySetting(
        key=CA_KEY_BACKUP,
        label="Certificate authority key backup",
        description=(
            "Whether an unattended scan runs the step that copies a certificate "
            "authority's private key."
        ),
        choices=(
            (
                CA_KEY_BACKUP_OFF,
                "Skip it",
                "Skips the step and reports the path as not exercised. A copy of the "
                "key stays valid until the CA key is rotated.",
            ),
            (
                CA_KEY_BACKUP_ON,
                "Run it",
                "Copies the key when an executed path reaches the step.",
            ),
        ),
        lab_default=CA_KEY_BACKUP_ON,
        real_default=CA_KEY_BACKUP_OFF,
        # A copy of a CA key cannot be withdrawn without rotating the key, so a
        # saved policy for a real environment never runs it unattended.
        real_values=(CA_KEY_BACKUP_OFF,),
    ),
)

SETTINGS_BY_KEY: dict[str, PolicySetting] = {s.key: s for s in SETTINGS}
SETTING_KEYS: tuple[str, ...] = tuple(SETTINGS_BY_KEY)


class PolicySettingError(ValueError):
    """A ``settings`` block names an unknown setting or a value it cannot take."""


def parse_settings(
    raw: Any, *, environment: str, where: str = "checks.settings"
) -> dict[str, str] | None:
    """Validate a ``settings`` block for a policy of ``environment``.

    Returns only the keys it sets (``None`` for an absent or empty block).

    Raises:
        PolicySettingError: On an unknown key, an unknown value, or a value the
            environment does not allow.
    """
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise PolicySettingError(f"'{where}' must be a mapping.")
    out: dict[str, str] = {}
    for key, value in raw.items():
        name = str(key or "").strip().lower()
        setting = SETTINGS_BY_KEY.get(name)
        if setting is None:
            raise PolicySettingError(
                f"Unknown setting '{key}' in '{where}'. Valid: {', '.join(SETTING_KEYS)}."
            )
        if value is None or not str(value).strip():
            continue
        token = str(value).strip().lower()
        if token not in setting.values:
            raise PolicySettingError(
                f"'{where}.{name}' must be one of {', '.join(setting.values)}."
            )
        if token not in setting.allowed_for(environment):
            raise PolicySettingError(
                f"'{where}.{name}: {token}' is allowed only on a policy for a lab. "
                f"A policy for a real environment may use {', '.join(setting.allowed_for(environment))}."
            )
        out[name] = token
    return dict(sorted(out.items())) or None


def effective_settings(
    explicit: Mapping[str, Any] | None, *, environment: str | None
) -> dict[str, str]:
    """Every setting's value: the explicit one when allowed, else the environment's."""
    block = explicit if isinstance(explicit, Mapping) else {}
    out: dict[str, str] = {}
    for setting in SETTINGS:
        value = str(block.get(setting.key) or "").strip().lower()
        if value not in setting.allowed_for(environment):
            value = setting.default_for(environment)
        out[setting.key] = value
    return out


def setting_value(definition: Any, key: str, *, environment: str | None = None) -> str:
    """The value of ``key`` for a policy definition (``None`` = a real environment).

    ``environment`` overrides the definition's.
    """
    setting = SETTINGS_BY_KEY[key]
    from adscan_core.scan_policy.policy import effective_environment  # noqa: PLC0415

    env = environment or (effective_environment(definition) if definition is not None else "")
    explicit = getattr(definition, "settings", None) if definition is not None else None
    return effective_settings(explicit, environment=env or _REAL)[setting.key]


def _shell_definition_and_environment(shell: Any) -> tuple[Any, str | None]:
    """The active policy definition on ``shell`` and its environment.

    Reads the resolved policy the scan controls installed. A workspace whose
    policy was cleared keeps the environment it had. A shell that carries no
    policy at all (a test double, or a session before a workspace is open)
    falls back to its legacy ``type`` attribute, the one place this module reads
    it.
    """
    from adscan_core.scan_policy.policy import (  # noqa: PLC0415
        ENVIRONMENTS,
        ScanPolicyDefinition,
        effective_environment,
        environment_for_workspace_type,
    )

    policy = getattr(shell, "scan_policy", None)
    definition = getattr(policy, "definition", None)
    if isinstance(definition, ScanPolicyDefinition):
        return definition, effective_environment(definition)
    cleared = getattr(shell, "scan_policy_cleared", None)
    if isinstance(cleared, Mapping):
        previous = cleared.get("previous")
        if isinstance(previous, Mapping) and previous.get("environment") in ENVIRONMENTS:
            return None, str(previous["environment"])
    try:
        legacy = getattr(shell, "type", None)
    except Exception:  # noqa: BLE001 - an unreadable shell reads as unknown
        legacy = None
    return None, environment_for_workspace_type(legacy if isinstance(legacy, str) else None)


def policy_setting(shell: Any, key: str) -> str:
    """The value of setting ``key`` for the policy active on ``shell``.

    Never raises: an unreadable shell gets the real-environment value, the
    conservative one.
    """
    setting = SETTINGS_BY_KEY[key]
    try:
        definition, environment = _shell_definition_and_environment(shell)
    except Exception:  # noqa: BLE001
        return setting.real_default
    explicit = getattr(definition, "settings", None) if definition is not None else None
    return effective_settings(explicit, environment=environment)[key]


def policy_sets(shell: Any, key: str) -> bool:
    """Whether the active policy sets ``key`` itself, as opposed to inheriting its environment's value.

    Lets a resolver say where a value came from ("the policy" vs "the
    environment's default") in its log line. Never raises.
    """
    try:
        definition, environment = _shell_definition_and_environment(shell)
    except Exception:  # noqa: BLE001
        return False
    explicit = getattr(definition, "settings", None) if definition is not None else None
    if not isinstance(explicit, Mapping) or key not in explicit:
        return False
    setting = SETTINGS_BY_KEY[key]
    return str(explicit[key]).strip().lower() in setting.allowed_for(environment)


def policy_environment(shell: Any) -> str | None:
    """The environment of the policy active on ``shell`` (``lab`` / ``real``), or ``None``."""
    try:
        return _shell_definition_and_environment(shell)[1]
    except Exception:  # noqa: BLE001
        return None


def is_lab(shell: Any) -> bool:
    """Whether the active policy is for a lab (bucket (c) readers: genuinely environment)."""
    return policy_environment(shell) == _LAB


# ── Convenience predicates (one per recurring question) ──────────────────────
def aims_at_domain_compromise(shell: Any) -> bool:
    """Whether the policy's objective is domain compromise."""
    return policy_setting(shell, OBJECTIVE) == OBJECTIVE_DOMAIN_COMPROMISE


def runs_full_assessment(shell: Any, *, require_environment: bool = False) -> bool:
    """Whether the policy's objective is a full assessment.

    ``require_environment`` fails closed when the shell carries no policy
    environment at all: the password-guessing techniques that only a full
    assessment runs (month/season and variation spraying) never run on a
    session whose environment is unknown.
    """
    if require_environment and policy_environment(shell) is None:
        return False
    return policy_setting(shell, OBJECTIVE) == OBJECTIVE_FULL_ASSESSMENT


def domain_compromise_reached(shell: Any, domain: str) -> bool:
    """Whether the policy aims at domain compromise and ``domain`` is compromised.

    The question every "stop, the objective is reached" gate asks.
    """
    if not aims_at_domain_compromise(shell):
        return False
    try:
        domains_data = getattr(shell, "domains_data", None) or {}
        record = domains_data.get(domain, {}) if isinstance(domains_data, Mapping) else {}
        return str(record.get("auth") or "").strip().lower() == "pwned"
    except Exception:  # noqa: BLE001
        return False


def expands_scope_automatically(shell: Any) -> bool:
    """Whether the policy opens pivots and follows trusts without asking."""
    return policy_setting(shell, SCOPE_EXPANSION) == SCOPE_EXPANSION_AUTOMATIC


def prefers_fast_remote_execution(shell: Any) -> bool:
    """Whether the policy ranks the fastest remote-execution methods first."""
    return policy_setting(shell, REMOTE_EXECUTION) == REMOTE_EXECUTION_SPEED


def reaches_wide(shell: Any) -> bool:
    """Whether the policy preselects every target a step can reach."""
    return policy_setting(shell, DEFAULT_REACH) == DEFAULT_REACH_WIDE


def scan_phase_family(shell: Any) -> str:
    """The phase-registry key the scan policy's objective selects: the objective itself.

    The phase registry (``adscan_internal.services.scan_phases``) maps
    ``full_assessment`` to the phase set with the full-assessment phases
    (unauthenticated attack surface, CVE verification) and accepts the legacy
    ``audit`` / ``ctf`` keys older ``scan_progress`` records persisted.
    """
    return policy_setting(shell, OBJECTIVE)


def settings_lines(definition: Any, *, environment: str | None = None) -> list[str]:
    """``Label: value`` for every setting (``policy show``)."""
    from adscan_core.scan_policy.policy import effective_environment  # noqa: PLC0415

    env = environment or (effective_environment(definition) if definition is not None else _REAL)
    explicit = getattr(definition, "settings", None) if definition is not None else None
    values = effective_settings(explicit, environment=env)
    return [f"{s.label}: {s.value_label(values[s.key])}" for s in SETTINGS]


def changed_settings(definition: Any, *, environment: str | None = None) -> dict[str, str]:
    """The settings whose value differs from the environment's default."""
    from adscan_core.scan_policy.policy import effective_environment  # noqa: PLC0415

    env = environment or (effective_environment(definition) if definition is not None else _REAL)
    explicit = getattr(definition, "settings", None) if definition is not None else None
    values = effective_settings(explicit, environment=env)
    return {
        s.key: values[s.key] for s in SETTINGS if values[s.key] != s.default_for(env)
    }


def changed_settings_line(changed: Mapping[str, str] | None) -> str:
    """One client-facing sentence naming the behaviour a policy changed, or ``""``.

    A built-in changes nothing, so its disclosure is unchanged.
    """
    if not isinstance(changed, Mapping) or not changed:
        return ""
    parts = []
    for key, value in changed.items():
        setting = SETTINGS_BY_KEY.get(str(key))
        if setting is None:
            continue
        parts.append(f"{setting.label.lower()} to {setting.value_label(str(value)).lower()}")
    if not parts:
        return ""
    listed = parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]
    return f"The scan policy departs from its environment's defaults. It sets {listed}."


def settings_catalog() -> list[dict[str, Any]]:
    """The settings as data, for the web editor and the CLI help."""
    return [
        {
            "key": s.key,
            "label": s.label,
            "description": s.description,
            "choices": [
                {"value": value, "label": label, "description": description}
                for value, label, description in s.choices
            ],
            "defaults": {_LAB: s.lab_default, _REAL: s.real_default},
            "allowed": {_LAB: list(s.allowed_for(_LAB)), _REAL: list(s.allowed_for(_REAL))},
        }
        for s in SETTINGS
    ]


__all__ = (
    "AUTO_REVERT",
    "AUTO_REVERT_OFF",
    "AUTO_REVERT_ON",
    "CA_KEY_BACKUP",
    "CA_KEY_BACKUP_OFF",
    "CA_KEY_BACKUP_ON",
    "MACHINE_ACCOUNT",
    "MACHINE_ACCOUNT_RETAIN_ONE",
    "MACHINE_ACCOUNT_REVERT_EACH_RUN",
    "policy_sets",
    "CRACKING_EFFORT",
    "CRACKING_EFFORT_BALANCED",
    "CRACKING_EFFORT_FAST",
    "CRACKING_EFFORT_THOROUGH",
    "CRACKING_WORDLIST",
    "CRACKING_WORDLIST_REAL_WORLD",
    "CRACKING_WORDLIST_ROCKYOU",
    "DEFAULT_REACH",
    "DEFAULT_REACH_BOUNDED",
    "DEFAULT_REACH_WIDE",
    "OBJECTIVE",
    "OBJECTIVE_DOMAIN_COMPROMISE",
    "OBJECTIVE_FULL_ASSESSMENT",
    "ONLINE_HASH_LOOKUP",
    "ONLINE_HASH_LOOKUP_ASK",
    "ONLINE_HASH_LOOKUP_OFF",
    "ONLINE_HASH_LOOKUP_ON",
    "OPERATOR_PROMPTS",
    "OPERATOR_PROMPTS_ANSWER_DEFAULTS",
    "OPERATOR_PROMPTS_ASK",
    "POISONING",
    "POISONING_OFF",
    "POISONING_ON",
    "REMOTE_EXECUTION",
    "REMOTE_EXECUTION_LOW_FOOTPRINT",
    "REMOTE_EXECUTION_SPEED",
    "SCOPE_EXPANSION",
    "SCOPE_EXPANSION_ASK",
    "SCOPE_EXPANSION_AUTOMATIC",
    "SETTINGS",
    "SETTINGS_BY_KEY",
    "SETTING_KEYS",
    "WRITESHARE_BAIT",
    "WRITESHARE_BAIT_ASK",
    "WRITESHARE_BAIT_AUTOMATIC",
    "PolicySetting",
    "PolicySettingError",
    "aims_at_domain_compromise",
    "changed_settings",
    "changed_settings_line",
    "domain_compromise_reached",
    "effective_settings",
    "expands_scope_automatically",
    "is_lab",
    "parse_settings",
    "policy_environment",
    "policy_setting",
    "prefers_fast_remote_execution",
    "reaches_wide",
    "runs_full_assessment",
    "scan_phase_family",
    "setting_value",
    "settings_catalog",
    "settings_lines",
)
