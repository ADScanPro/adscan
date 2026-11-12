"""Single source of truth for ADscan's scan plan — chapters, phases, weights.

ADscan's scan is rendered to the operator (CLI) and to the customer (the web
Enterprise product) as a sequence of phases grouped into a small number of
high-level *chapters*. Before this module owned the whole contract, three
uncorrelated phase definitions had drifted apart:

    1. The CLI chapter strip (this module's ``SCAN_PHASES``).
    2. The structured event stream the web consumes
       (``adscan_internal.cli.ci_events.PHASE_CATALOG``) — which used DIFFERENT
       ids (``trust_enumeration`` vs ``topology_and_trusts``, ``graph_collection``
       vs ``domain_collection``), invented phases that were never emitted, and
       silently dropped ``share_credential_hunt`` / ``quick_credential_wins`` /
       ``password_spraying`` / CVE.
    3. A hand-written TypeScript list in the web frontend that drifted from both.

This module is now the ONE plan everyone derives from:

    * ``SCAN_PHASES`` — the ordered, command-keyed registry. Each phase declares
      its stable ``phase_id`` (shared verbatim with the structured stream and
      the web), its ``chapter`` (the high-level group), a display ``title`` /
      ``subtitle``, a ``weight`` for weight-based percent, and which commands it
      applies to.
    * ``CHAPTERS`` — the ordered high-level groups (Setup, Collection,
      Exploitation, Post-Processing). The web renders the two-level pipeline
      (chapters on top, phases below) directly from this.
    * ``build_scan_plan(command)`` — derives the ordered chapters→phases tree
      for one command (``ci`` / ``ci_unauth`` / ``start_auth`` / ``start_unauth``
      / ``audit``). The phase SETS legitimately differ per command; they are all
      derived here, never re-hardcoded elsewhere.

``ci_events.PHASE_CATALOG`` is now a *derived view* of this registry (label,
order, percent), so a phase added here propagates to the structured stream and —
via the declared ``scan_plan`` event — to the web with zero frontend edits.
"""

from __future__ import annotations

from dataclasses import dataclass

from adscan_core.compliance_frameworks import FRAMEWORK_KEYS
from adscan_core.report_options import REPORT_DEFAULT_THEME as _REPORT_DEFAULT_THEME
from adscan_core.report_options import REPORT_THEMES as _REPORT_THEMES


def _warn(message: str) -> None:
    """Emit an operator-facing warning (best-effort, never blocks plan build)."""
    try:
        from adscan_core.rich_output import print_warning

        print_warning(message)
    except Exception:  # noqa: BLE001 — plan build must never fail on output
        pass


# ---------------------------------------------------------------------------
# Chapters — the high-level groups (two-level pipeline, top row)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Chapter:
    """One high-level chapter grouping a run of phases.

    Attributes:
        chapter_id: Stable identifier shared with the web renderer.
        label: Display label for the chapter pill.
        icon: Lucide icon name the web maps to a React component. Purely a
            presentation hint; unknown names fall back to a default glyph.
    """

    chapter_id: str
    label: str
    icon: str


CHAPTERS: tuple[Chapter, ...] = (
    Chapter(chapter_id="setup", label="Setup", icon="Settings2"),
    Chapter(chapter_id="collection", label="Collection", icon="Database"),
    Chapter(chapter_id="exploitation", label="Exploitation", icon="Target"),
    Chapter(chapter_id="postprocessing", label="Post-Processing", icon="FileCheck2"),
)

_CHAPTERS_BY_ID: dict[str, Chapter] = {c.chapter_id: c for c in CHAPTERS}
_CHAPTER_ORDER: dict[str, int] = {c.chapter_id: i for i, c in enumerate(CHAPTERS)}


# ---------------------------------------------------------------------------
# Commands — the entry points whose phase sets legitimately differ
# ---------------------------------------------------------------------------

# Canonical command keys. ``audit`` is authenticated + the audit-only phases.
COMMAND_CI_AUTH = "ci"
COMMAND_CI_UNAUTH = "ci_unauth"
COMMAND_START_AUTH = "start_auth"
COMMAND_START_UNAUTH = "start_unauth"
COMMAND_AUDIT = "audit"

_AUTH_COMMANDS = frozenset(
    {COMMAND_CI_AUTH, COMMAND_START_AUTH, COMMAND_AUDIT}
)
_UNAUTH_COMMANDS = frozenset({COMMAND_CI_UNAUTH, COMMAND_START_UNAUTH})


# ---------------------------------------------------------------------------
# Phases — the canonical registry (order is the rendered order)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PhaseConfigOption:
    """One configurable knob a phase exposes (per-phase config descriptor).

    This is the presentation + validation contract the web "Create New Scan"
    form reads to render each phase's inline options, and the same descriptor
    the engine ships on every ``build_scan_plan`` phase. The descriptor only
    DESCRIBES the option; the chosen VALUES flow through the
    :mod:`~adscan_internal.services.scan_config` model and drive the engine
    knobs already honored elsewhere (phase disable, trust policy, attack-path
    policy, reporting frameworks/theme).

    Attributes:
        key: Stable option key (e.g. ``policy``, ``frameworks``, ``theme``).
        kind: One of ``toggle`` (bool), ``enum`` (single choice), or
            ``multiselect`` (subset of ``choices``).
        label: Human-readable label for the form control.
        choices: Allowed values for ``enum`` / ``multiselect`` (empty for
            ``toggle``).
        default: The default value (a bool for ``toggle``, a member of
            ``choices`` for ``enum``, a list/tuple of members for
            ``multiselect``).
    """

    key: str
    kind: str
    label: str
    choices: tuple[str, ...] = ()
    default: object = None


@dataclass(frozen=True)
class Subphase:
    """One optional child step of a phase (the third, expandable nesting level).

    A phase declares ``subphases`` only when the engine actually runs meaningful
    sub-steps the operator/client may want to expand. A phase with no subphases
    renders as a leaf — subphases are never invented for phases that don't have
    real sub-steps.

    Attributes:
        subphase_id: Stable identifier, unique within its parent phase.
        title: Display title for the expanded breakdown row.
        subtitle: One-line description of the sub-step.
        optional: When True the subphase can be turned off individually via the
            scan config (``phases.steps.<phase_id>.disabled``). Structural /
            unsafe sub-steps (e.g. collection internals) keep ``optional=False``
            and can never be disabled — a request to disable one is refused with
            a warning at plan-build time, never silently dropped. The web form
            renders exactly the ``optional=True`` subphases as nested toggles,
            derived dynamically from this registry.
        config_options: Optional per-subphase config descriptor (same shape as a
            phase's). Empty for the common case.
    """

    subphase_id: str
    title: str
    subtitle: str
    optional: bool = False
    config_options: tuple[PhaseConfigOption, ...] = ()


@dataclass(frozen=True)
class ScanPhase:
    """Metadata for one scan phase.

    Attributes:
        phase_id: Stable identifier; shared verbatim with the structured event
            stream, the declared ``scan_plan`` event, and the web.
        title: Display title rendered in the chapter banner and the web pill.
        subtitle: One-line description shown under the title.
        chapter: ``chapter_id`` of the high-level group this phase belongs to.
        weight: Relative weight used for weight-based progress percent. The
            cumulative weight up to (and including) a phase, over the plan's
            total weight, gives the percent at that phase's completion.
        commands: The command keys this phase applies to.
        subphases: Optional ordered child steps (third nesting level). Empty for
            leaf phases.
        optional: When True, the phase can be turned off via a scan config
            (``phases.disabled``). Mandatory phases (preflight + the collection
            backbone) keep ``optional=False`` and can never be disabled — a
            request to disable one is refused with a warning, never silently
            dropped. The web form lists exactly the ``optional=True`` phases as
            toggles (derived dynamically from this registry).
        configurable: When True, the phase appears in the web "Create New Scan"
            config form. This is the SSOT for which phases are user-facing — the
            frontend never decides. Every OPERATIONAL phase (collection,
            exploitation, the pre-auth surface) is ``configurable``; pure-infra
            phases (DNS setup, credential/domain setup, network preflight,
            reporting, CTEM reconciliation) are not. A mandatory-but-configurable
            phase renders as "Always runs" (no toggle); an optional one renders
            with an enable toggle. Defaults to ``optional`` so optional phases
            are configurable unless explicitly overridden.
        conditional: When True, the phase runs only when a RUNTIME condition is
            met during the scan, not on every run of the command it belongs to.
            The canonical case is the post-compromise remaining-paths re-offer,
            which fires only after the domain has been compromised mid-scan. The
            phase is part of the declared plan (so the web renders it up front),
            but it stays subdued until its ``phase`` event arrives; if the scan
            reaches a terminal status without that event, the web marks it "not
            applicable" rather than leaving it stuck pending. A conditional phase
            is excluded from the weight-based progress total so a run where the
            condition never fires still reaches 100% — the engine never emits the
            phase event in that case, so its weight must not hold progress back.
    """

    phase_id: str
    title: str
    subtitle: str
    chapter: str
    weight: int
    commands: frozenset[str]
    subphases: tuple[Subphase, ...] = ()
    optional: bool = False
    config_options: tuple[PhaseConfigOption, ...] = ()
    configurable: bool = False
    conditional: bool = False


# All authenticated-capable commands (auth + audit) share the auth setup +
# collection + analysis + exploitation backbone; audit adds two extra phases;
# the unauth commands run only the pre-auth surface.
_ALL_AUTH = frozenset({COMMAND_CI_AUTH, COMMAND_START_AUTH, COMMAND_AUDIT})
_ALL_UNAUTH = frozenset({COMMAND_CI_UNAUTH, COMMAND_START_UNAUTH})
_AUDIT_ONLY = frozenset({COMMAND_AUDIT})
_EVERY = _ALL_AUTH | _ALL_UNAUTH


# ---------------------------------------------------------------------------
# Config valid-sets — the single source the per-phase ``config_options``
# descriptor (and the future web form) read.
#
# The trust / attack-path policy choices mirror
# :mod:`adscan_internal.services.scan_config`; the reporting frameworks/theme
# choices come from the framework registry (``adscan_core.compliance_frameworks``)
# and the theme choices mirror ``deliver._VALID_REPORT_THEMES``.
# The contract test asserts both, so the CLI flags, the engine, and the web
# form can never drift.
# ---------------------------------------------------------------------------

TRUST_POLICY_CHOICES: tuple[str, ...] = (
    "origin_only",
    "skip",
    "all",
    "selected",
    "interactive",
)
# What the form OFFERS, as opposed to what the engine ACCEPTS. ``skip`` is a
# back-compat alias of ``origin_only`` (see scan_config.py): a saved config that
# says "skip" must keep parsing, but offering both renders two buttons with one
# meaning, and "Skip" reads as "trust mapping is skipped", which it no longer is.
TRUST_POLICY_ALIASES: frozenset[str] = frozenset({"skip"})
TRUST_POLICY_FORM_CHOICES: tuple[str, ...] = tuple(
    choice for choice in TRUST_POLICY_CHOICES if choice not in TRUST_POLICY_ALIASES
)
ATTACK_PATH_POLICY_CHOICES: tuple[str, ...] = (
    "none",
    "all",
    "selected",
    "interactive",
)
# Read from the framework registry (adscan_core.compliance_frameworks), the one
# place the framework list is declared.
REPORT_FRAMEWORK_CHOICES: tuple[str, ...] = FRAMEWORK_KEYS
# The theme SSOT (adscan_core is importable everywhere the descriptor is read,
# the appliance backend included).
REPORT_THEME_CHOICES: tuple[str, ...] = _REPORT_THEMES
REPORT_THEME_DEFAULT: str = _REPORT_DEFAULT_THEME

# CVE-verification target scope (the ``audit_extras`` phase option). Mirrors
# :mod:`adscan_internal.services.scan_config` (``CVE_TARGET_SCOPES``). The
# descriptor default is ``domain_controllers`` (the conservative, low-noise
# scope the form presents as selected); the engine treats an absent config as
# today's behavior regardless (the model's ``default`` sentinel handles that, so
# the form-visible default never narrows a scan the operator did not configure).
CVE_TARGET_SCOPE_CHOICES: tuple[str, ...] = ("domain_controllers", "all_hosts")
CVE_TARGET_SCOPE_DEFAULT: str = "domain_controllers"


SCAN_PHASES: tuple[ScanPhase, ...] = (
    # ── Setup ──────────────────────────────────────────────────────────────
    ScanPhase(
        phase_id="dns_validation",
        title="DNS Validation",
        subtitle="Confirm directory name resolution before deeper analysis.",
        chapter="setup",
        weight=2,
        commands=_EVERY,
    ),
    ScanPhase(
        phase_id="dns_configuration",
        title="DNS Configuration",
        subtitle="Apply the resolver settings required for reliable access.",
        chapter="setup",
        weight=2,
        commands=_ALL_AUTH,
    ),
    ScanPhase(
        phase_id="network_preflight",
        title="Network Preflight",
        subtitle="Check the assessment path can reach the expected scope.",
        chapter="setup",
        weight=2,
        commands=_ALL_UNAUTH,
    ),
    ScanPhase(
        phase_id="credential_setup",
        title="Credential Setup",
        subtitle="Prepare the initial authentication context for the run.",
        chapter="setup",
        weight=2,
        commands=_ALL_AUTH,
    ),
    ScanPhase(
        phase_id="domain_setup",
        title="Domain Setup",
        subtitle="Establish the target domain context and starting identity.",
        chapter="setup",
        weight=2,
        commands=_EVERY,
    ),
    # ── Collection ─────────────────────────────────────────────────────────
    ScanPhase(
        phase_id="topology_and_trusts",
        title="Topology & Trusts",
        subtitle="Map domain topology and enumerate trust relationships.",
        chapter="collection",
        weight=5,
        commands=_ALL_AUTH,
        configurable=True,
        config_options=(
            PhaseConfigOption(
                key="policy",
                kind="enum",
                label="Trust enumeration",
                choices=TRUST_POLICY_FORM_CHOICES,
                default="interactive",
            ),
            PhaseConfigOption(
                key="domains",
                kind="multiselect",
                label="Trust domains (when policy is 'selected')",
                choices=(),  # populated at form time from discovered trusts
                default=(),
            ),
        ),
    ),
    ScanPhase(
        phase_id="domain_collection",
        title="Domain Collection",
        subtitle="Native LDAP/SMB collector: graph, sessions, ACLs.",
        chapter="collection",
        weight=12,
        commands=_ALL_AUTH,
        configurable=True,
        # Selectable collectors for the Domain Collection phase. The LDAP pass
        # (graph, ACLs, memberships, ADCS/PKI) is the mandatory base — it builds
        # the attack graph and the computer list the SMB/MSSQL collectors below
        # consume, so it always runs and can never be disabled. The SMB (SAMR /
        # SRVSVC) and MSSQL collectors are individually toggleable: a client can
        # run an LDAP-only fast pass, or LDAP plus a subset of the host-touching
        # collectors. The ids match the engine gating in
        # ``adscan_internal.cli._collection_selector`` (samr / shares / mssql).
        subphases=(
            Subphase(
                subphase_id="ldap",
                title="Directory Graph & ACLs",
                subtitle="Graph, group memberships, security descriptors, and PKI. Always runs.",
            ),
            Subphase(
                subphase_id="samr",
                title="Sessions & Local Admins",
                subtitle="Logged-on sessions and local administrator membership per host.",
                optional=True,
            ),
            Subphase(
                subphase_id="shares",
                title="Shares & Share Permissions",
                subtitle="Network shares and their access-control entries per host.",
                optional=True,
            ),
            Subphase(
                subphase_id="mssql",
                title="MSSQL Authorization",
                subtitle="SQL Server logins, roles, and sysadmin membership.",
                optional=True,
            ),
        ),
    ),
    ScanPhase(
        phase_id="domain_analysis",
        title="Domain Intelligence",
        subtitle="Host inventory and identity enumeration.",
        chapter="collection",
        weight=10,
        commands=_ALL_AUTH,
        configurable=True,
        subphases=(
            Subphase(
                subphase_id="port_scan",
                title="Port Scan",
                subtitle="Service-port reachability sweep across the discovered estate.",
            ),
            Subphase(
                subphase_id="host_inventory",
                title="Host Inventory",
                subtitle="Reachability and role classification across the estate.",
            ),
            Subphase(
                subphase_id="identity_inventory",
                title="Identity Inventory",
                subtitle="Users, service accounts, and privileged group membership.",
            ),
            Subphase(
                subphase_id="ntlm_auth_type_sweep",
                title="NTLM Auth-Type Sweep",
                subtitle="Per-host NetNTLMv1/v2 downgrade exposure across reachable hosts.",
                optional=True,
            ),
        ),
    ),
    # ── Exploitation ───────────────────────────────────────────────────────
    ScanPhase(
        phase_id="attack_paths_discovery",
        title="Attack Paths Discovery",
        subtitle="Compute reachable paths from the owned set.",
        chapter="exploitation",
        weight=12,
        commands=_ALL_AUTH,
        optional=True,
        configurable=True,
        # No per-scan execution control: how attack steps run is the scan
        # policy's execution mode (unattended / decide during scan), not a phase
        # option (scan-policy two-groups spec § 4). ``attack_paths.policy`` stays
        # accepted in a scan-config file for CLI back-compat.
    ),
    ScanPhase(
        phase_id="quick_credential_wins",
        title="Quick Credential Wins",
        subtitle="Low-noise credential discovery (Timeroast, LDAP, GPP).",
        chapter="exploitation",
        weight=8,
        commands=_ALL_AUTH,
        optional=True,
        configurable=True,
        subphases=(
            Subphase(
                subphase_id="timeroast",
                title="Timeroast Candidate Check",
                subtitle="Computer-account password hashes via Kerberos timestamps.",
                optional=True,
            ),
            Subphase(
                subphase_id="ldap_descriptions",
                title="LDAP Description Parsing",
                subtitle="Credentials left in directory description fields.",
                optional=True,
            ),
            Subphase(
                subphase_id="gpp_autologin",
                title="GPP Autologin Search",
                subtitle="Autologon credentials in Group Policy Preferences.",
                optional=True,
            ),
            Subphase(
                subphase_id="gpp_passwords",
                title="GPP Password Search",
                subtitle="Reversibly-encrypted passwords in SYSVOL policy files.",
                optional=True,
            ),
        ),
    ),
    ScanPhase(
        phase_id="password_spraying",
        title="Password Spraying",
        subtitle="Spray validated wordlists across the user base.",
        chapter="exploitation",
        weight=8,
        commands=_ALL_AUTH,
        optional=True,
        configurable=True,
        # Spray STRATEGIES exposed as individually-toggleable subphases. The
        # client can drop a single strategy (e.g. skip the pre2k computer-account
        # spray) without disabling the whole phase. The ids match the spray
        # coverage selector / pre2k step the execution loop gates.
        subphases=(
            Subphase(
                subphase_id="pre2k",
                title="Pre-2000 Computer Accounts",
                subtitle="Spray legacy computer accounts whose password equals the name.",
                optional=True,
            ),
            Subphase(
                subphase_id="blank",
                title="Blank Password",
                subtitle="Test accounts that may have an empty password.",
                optional=True,
            ),
            Subphase(
                subphase_id="useraspass",
                title="Username as Password",
                subtitle="Spray each account with its own username as the password.",
                optional=True,
            ),
            Subphase(
                subphase_id="reuse",
                title="Credential Reuse",
                subtitle="Replay already-recovered passwords across the user base.",
                optional=True,
            ),
            Subphase(
                subphase_id="month_season",
                title="Month/Season + Year",
                subtitle="Spray predictable seasonal passwords (March2026, Verano2026).",
                optional=True,
            ),
        ),
    ),
    ScanPhase(
        phase_id="share_credential_hunt",
        title="SMB Share Exposure",
        subtitle=(
            "Capture hashes on writable shares; hunt credentials on readable ones."
        ),
        chapter="exploitation",
        weight=8,
        commands=_ALL_AUTH,
        optional=True,
        configurable=True,
    ),
    ScanPhase(
        phase_id="unauthenticated_attack_surface",
        title="Unauthenticated Attack Surface",
        subtitle="Pre-auth attack surface review.",
        chapter="exploitation",
        # Audit runs it as an extra; the unauth commands run it as the main phase.
        weight=10,
        commands=_AUDIT_ONLY | _ALL_UNAUTH,
        # Operational phase — must appear in the config form. Marked optional so a
        # client who does not want the pre-auth attack-surface review can skip it
        # via ``scan_config.phases.disabled`` (renders as an enable toggle).
        # Default behavior is unchanged: optional phases default to enabled, so an
        # absent config still runs it — which is essential for the unauth commands
        # (ci_unauth / start_unauth), where this IS the main phase. The execution
        # entry is gated by ``phase_is_enabled`` so disabling it actually skips it.
        optional=True,
        configurable=True,
    ),
    ScanPhase(
        phase_id="audit_extras",
        title="CVE Verification",
        subtitle=(
            "Read-only vulnerability detection on DCs (native CVE catalog). "
            "No exploitation."
        ),
        chapter="exploitation",
        weight=6,
        commands=_AUDIT_ONLY,
        optional=True,
        configurable=True,
        config_options=(
            PhaseConfigOption(
                key="target_scope",
                kind="enum",
                label="CVE scan scope",
                choices=CVE_TARGET_SCOPE_CHOICES,
                default=CVE_TARGET_SCOPE_DEFAULT,
            ),
        ),
    ),
    ScanPhase(
        phase_id="post_compromise_validation",
        title="Exposure Validation",
        subtitle=(
            "Runs only when the domain is already compromised: re-offers the "
            "remaining unvalidated attack paths for review."
        ),
        chapter="exploitation",
        # Conditional phases are excluded from the progress total (see
        # build_scan_plan), so the weight is informational only.
        weight=6,
        commands=_AUDIT_ONLY,
        # Not optional (the operator cannot toggle it off — it is gated by a
        # runtime condition, not a config flag) and not configurable (it never
        # appears in the Create New Scan form). It IS conditional: declared in
        # the plan but activated only by its runtime phase event.
        conditional=True,
    ),
    # ── Post-Processing ────────────────────────────────────────────────────
    ScanPhase(
        phase_id="report_generation",
        title="Reporting",
        subtitle="Compile findings, render the report, and stage artefacts.",
        chapter="postprocessing",
        weight=6,
        commands=_EVERY,
        config_options=(
            PhaseConfigOption(
                key="frameworks",
                kind="multiselect",
                label="Compliance frameworks",
                choices=REPORT_FRAMEWORK_CHOICES,
                default=(),
            ),
            PhaseConfigOption(
                key="theme",
                kind="enum",
                label="Report theme",
                choices=REPORT_THEME_CHOICES,
                default=REPORT_THEME_DEFAULT,
            ),
        ),
    ),
    ScanPhase(
        phase_id="ctem_reconciliation",
        title="Post-Processing",
        subtitle="Reconcile findings, exposure paths, and asset intelligence.",
        chapter="postprocessing",
        weight=3,
        commands=_EVERY,
    ),
)


_PHASES_BY_ID: dict[str, ScanPhase] = {p.phase_id: p for p in SCAN_PHASES}


# ---------------------------------------------------------------------------
# Command → scan-type mapping (legacy ``scan_type`` strings)
# ---------------------------------------------------------------------------


#: Phase-family keys older ``scan_progress`` records persisted, read as the
#: objective they stood for (the legacy workspace-type vocabulary).
_LEGACY_PHASE_FAMILIES: dict[str, str] = {
    "audit": "full_assessment",
    "ctf": "domain_compromise",
}


def command_for_scan_type(scan_type: str, *, authenticated: bool = True) -> str:
    """Map a phase family to a canonical command key.

    ``scan_type`` is the scan policy's objective
    (:func:`adscan_core.scan_policy.settings.scan_phase_family`):
    ``full_assessment`` unlocks the two full-assessment-only phases. A legacy
    persisted key (``audit`` / ``ctf``) reads as the objective it stood for;
    anything else is the domain-compromise set. ``authenticated`` selects
    between the auth and unauth command families.
    """
    if not authenticated:
        return COMMAND_START_UNAUTH
    token = str(scan_type or "").strip().lower()
    family = _LEGACY_PHASE_FAMILIES.get(token, token)
    if family == "full_assessment":
        return COMMAND_AUDIT
    return COMMAND_START_AUTH


# ---------------------------------------------------------------------------
# Plan derivation
# ---------------------------------------------------------------------------


def phases_for_command(command: str) -> tuple[ScanPhase, ...]:
    """Return the ordered phases that apply to ``command``."""
    return tuple(p for p in SCAN_PHASES if command in p.commands)


def optional_phases_for_command(command: str) -> tuple[ScanPhase, ...]:
    """Return the toggleable (``optional=True``) phases for ``command``.

    The web form derives its phase-toggle list from exactly this set, so a new
    optional phase appears as a toggle with zero frontend edits.
    """
    return tuple(p for p in phases_for_command(command) if p.optional)


def configurable_phases_for_command(command: str) -> tuple[ScanPhase, ...]:
    """Return the user-facing (``configurable=True``) phases for ``command``.

    The web "Create New Scan" form renders EVERY phase in this set — mandatory
    ones as "Always runs", optional ones with an enable toggle. This is the SSOT
    for which phases appear in the form; the frontend never filters. A new
    operational phase marked ``configurable`` surfaces with zero frontend edits.
    """
    return tuple(p for p in phases_for_command(command) if p.configurable)


def optional_subphases(phase_id: str) -> tuple[Subphase, ...]:
    """Return the individually-toggleable (``optional=True``) subphases of a phase."""
    phase = _PHASES_BY_ID.get(phase_id)
    if phase is None:
        return ()
    return tuple(s for s in phase.subphases if s.optional)


def resolve_disabled_subphases(
    phase_id: str,
    disabled: "frozenset[str] | set[str] | tuple[str, ...] | None",
) -> tuple[frozenset[str], list[str]]:
    """Split a requested set of disabled subphase ids into honored vs refused.

    A subphase id is honored only when it belongs to ``phase_id`` AND is
    ``optional=True``. A mandatory subphase (structural collection internals) is
    refused; an unknown id is reported. Mirrors :func:`resolve_disabled_phases`
    at the subphase level.
    """
    requested = set(disabled or ())
    if not requested:
        return frozenset(), []

    phase = _PHASES_BY_ID.get(phase_id)
    by_id = {s.subphase_id: s for s in (phase.subphases if phase else ())}
    optional_ids = {sid for sid, s in by_id.items() if s.optional}

    honored: set[str] = set()
    warnings: list[str] = []
    for sub_id in sorted(requested):
        if sub_id in optional_ids:
            honored.add(sub_id)
        elif sub_id in by_id:
            warnings.append(
                f"Subphase '{phase_id}.{sub_id}' is mandatory and cannot be "
                "disabled; it will still run."
            )
        else:
            warnings.append(
                f"Unknown subphase id '{phase_id}.{sub_id}' in scan config; "
                "ignored."
            )
    return frozenset(honored), warnings


def _scan_policy_allows_subphase(shell: object, phase_id: str, subphase_id: str) -> bool:
    """Policy verdict for a subphase: True without a policy, fail closed with one."""
    from adscan_core.scan_policy.gate import active_policy, subphase_allowed

    if active_policy(shell) is None:
        return True
    return subphase_allowed(shell, phase_id, subphase_id)


def _scan_policy_allows_phase(shell: object, phase_id: str) -> bool:
    """Policy verdict for a whole phase: True without a policy, fail closed with one."""
    from adscan_core.scan_policy.gate import active_policy, phase_allowed

    if active_policy(shell) is None:
        return True
    return phase_allowed(shell, phase_id)


def subphase_is_enabled(shell: object, phase_id: str, subphase_id: str) -> bool:
    """Return False when ``phase_id.subphase_id`` was disabled by the config.

    The single gate the per-subphase entry points consult (spray strategies,
    the quick-win sub-steps) so they SKIP when a ``--scan-config`` disabled them.
    Only OPTIONAL subphases can be disabled — a mandatory one always returns
    True. Best-effort and fail-open: any error, a missing config, or an unknown
    id yields True so the no-op default path stays byte-for-byte today's
    behavior. Mirrors :func:`phase_is_enabled` one level down.

    Scan policy (``shell.scan_policy``, spec 2026-11-04 § 7.2 S5): when a policy
    is set, a subphase bound to a check the policy excludes returns False, and
    that branch fails CLOSED. The config check below still applies on top.

    Args:
        shell: The pentest shell; ``shell.scan_config`` is consulted when set.
        phase_id: The canonical parent phase id.
        subphase_id: The subphase id within that phase.

    Returns:
        True when the subphase should run; False only when it is an optional
        subphase explicitly listed under
        ``scan_config.phases.steps[phase_id].disabled``.
    """
    # Scan-policy branch (fail closed): with a resolved policy on the shell, a
    # subphase bound to an excluded check does not run, and the legacy config
    # check below still ANDs in (most restrictive wins). With no policy this
    # branch is a no-op and the fail-open behaviour is byte-identical.
    if not _scan_policy_allows_subphase(shell, phase_id, subphase_id):
        return False
    try:
        config = getattr(shell, "scan_config", None)
        if config is None:
            return True
        phases = getattr(config, "phases", None)
        steps = getattr(phases, "steps", None)
        if not steps:
            return True
        disabled = set(steps.get(phase_id, ()))
        if subphase_id not in disabled:
            return True
        phase = _PHASES_BY_ID.get(phase_id)
        if phase is None:
            return True
        sub = next(
            (s for s in phase.subphases if s.subphase_id == subphase_id), None
        )
        # Only honor the disable for an OPTIONAL subphase.
        return not (sub is not None and sub.optional)
    except Exception:  # noqa: BLE001 — gate must never break the scan
        return True


def resolve_cve_target_scope(shell: object) -> str:
    """Resolve the CVE-verification target scope from the shell's scan config.

    Returns one of ``default`` (the model sentinel — keep today's behavior),
    ``domain_controllers``, or ``all_hosts``. The ``audit_extras`` CVE entry
    point reads this to decide whether to add the every-host scan pass.
    Fail-open to ``default`` so an absent/broken config is a no-op.
    """
    try:
        config = getattr(shell, "scan_config", None)
        scope = getattr(getattr(config, "audit_extras", None), "target_scope", None)
        return str(scope) if scope else "default"
    except Exception:  # noqa: BLE001 — gate must never break the scan
        return "default"


def resolve_disabled_phases(
    command: str, disabled: "frozenset[str] | set[str] | tuple[str, ...] | None"
) -> tuple[frozenset[str], list[str]]:
    """Split a requested-disabled id set into honored vs refused.

    A phase id is honored only when it applies to ``command`` AND is
    ``optional=True``. Everything else is refused — a mandatory phase
    (preflight, collection backbone, reporting) can never be disabled, and an
    unknown id is reported rather than silently ignored.

    Args:
        command: The canonical command key (``ci`` / ``audit`` / ...).
        disabled: Phase ids the operator asked to disable.

    Returns:
        ``(honored_ids, warnings)`` where ``honored_ids`` is the set of phase
        ids that will actually be filtered out, and ``warnings`` is a list of
        human-readable strings for every refused/unknown id (the caller is
        expected to surface these, never drop them silently).
    """
    requested = set(disabled or ())
    if not requested:
        return frozenset(), []

    applicable = {p.phase_id: p for p in phases_for_command(command)}
    optional_ids = {pid for pid, p in applicable.items() if p.optional}

    honored: set[str] = set()
    warnings: list[str] = []
    for phase_id in sorted(requested):
        if phase_id in optional_ids:
            honored.add(phase_id)
        elif phase_id in applicable:
            warnings.append(
                f"Phase '{phase_id}' is mandatory and cannot be disabled; "
                "it will still run."
            )
        else:
            warnings.append(
                f"Unknown phase id '{phase_id}' in scan config "
                f"(not part of the '{command}' plan); ignored."
            )
    return frozenset(honored), warnings


def phase_is_enabled(shell: object, phase_id: str) -> bool:
    """Return False when ``phase_id`` was disabled by the shell's scan config.

    The single gate the optional-phase entry points consult so they SKIP when a
    ``--scan-config`` disabled them. Only OPTIONAL phases can be disabled — a
    mandatory phase always returns True regardless of the config (a config
    asking to disable it is refused at plan-build time, never honored here).

    Best-effort and fail-open: any error, a missing config, or an unknown phase
    id yields True so a config problem never silently drops a phase (the no-op
    default path stays byte-for-byte today's behavior).

    Scan policy (``shell.scan_policy``, spec 2026-11-04 § 7.2 S5): when a policy
    is set, a phase whose every bound check is excluded returns False, and that
    branch fails CLOSED. The preset and config checks below still apply on top.

    Args:
        shell: The pentest shell; ``shell.scan_config`` is consulted when set.
        phase_id: The canonical phase id to check.

    Returns:
        True when the phase should run; False only when it is an optional phase
        explicitly listed in ``scan_config.phases.disabled``.
    """
    # Scan-policy branch (fail closed): a phase whose every bound check the
    # policy excludes does not run. No policy: no-op, today's behaviour.
    if not _scan_policy_allows_phase(shell, phase_id):
        return False
    try:
        # Session phase preset (interactive resume front door) — an explicit
        # enabled set of OPTIONAL phase ids. None (the default) means "no preset",
        # so every phase runs and trust-pivot / CI enumeration is unaffected. Only
        # OPTIONAL phases are ever gated; a mandatory phase always runs.
        preset = getattr(shell, "_phase_preset_enabled", None)
        if preset is not None:
            phase = _PHASES_BY_ID.get(phase_id)
            if phase is not None and phase.optional and phase_id not in preset:
                return False
        config = getattr(shell, "scan_config", None)
        if config is None:
            return True
        disabled = getattr(getattr(config, "phases", None), "disabled", None)
        if not disabled:
            return True
        if phase_id not in set(disabled):
            return True
        phase = _PHASES_BY_ID.get(phase_id)
        # Only honor the disable for an OPTIONAL phase. A mandatory phase stays
        # on even if (mistakenly) listed — the warning was already emitted at
        # plan-build time.
        return not (phase is not None and phase.optional)
    except Exception:  # noqa: BLE001 — gate must never break the scan
        return True


def phases_enabled_for_run(shell: object, phase_ids: tuple[str, ...]) -> tuple[str, ...]:
    """Return the subset of ``phase_ids`` this run is configured to run.

    A read for verdicts about a finished run (did a phase the run MEANT to run
    complete?), never a skip: the run that skipped a disabled phase already
    announced it through ``announce_phase_skip``. Order is preserved.
    """
    return tuple(phase_id for phase_id in phase_ids if phase_is_enabled(shell, phase_id))


def _serialize_config_options(
    options: "tuple[PhaseConfigOption, ...]",
) -> list[dict]:
    """Serialize a config-option descriptor tuple to JSON-safe dicts.

    Shared by phases and subphases so both nesting levels emit an identical
    ``{key, kind, label, choices, default}`` shape the form renders.
    """
    return [
        {
            "key": option.key,
            "kind": option.kind,
            "label": option.label,
            "choices": list(option.choices),
            "default": (
                list(option.default)
                if isinstance(option.default, (list, tuple))
                else option.default
            ),
        }
        for option in options
    ]


def build_scan_plan(command: str, config: object | None = None) -> dict:
    """Build the declared plan for ``command`` as a JSON-serializable dict.

    The plan is the contract the web renders: an ordered list of chapters, each
    carrying its ordered phases with cumulative weight-based percent. The same
    dict is emitted up-front as the ``scan_plan`` structured event and served by
    the ``/scans/{id}/plan`` backstop endpoint.

    Shape::

        {
          "command": "audit",
          "total_weight": 96,
          "chapters": [
            {"id": "setup", "label": "Setup", "icon": "Settings2",
             "phases": [
               {"id": "dns_validation", "title": "DNS Validation",
                "subtitle": "...", "order": 1, "weight": 2,
                "cumulative_percent": 2.1}, ...]},
            ...
          ],
          "phases": [ ...flat ordered list, same phase dicts... ]
        }

    A phase that declares child steps carries an optional ``subphases`` list
    (the third, expandable nesting level)::

        {"id": "domain_analysis", "title": "Domain Intelligence", ...,
         "subphases": [
            {"id": "host_inventory", "title": "Host Inventory",
             "subtitle": "...", "order": 1}, ...]}

    Leaf phases omit ``subphases`` entirely — the web renders them as before.

    When ``config`` is provided (a
    :class:`~adscan_internal.services.scan_config.ScanConfig`), its
    ``phases.disabled`` set filters out the matching OPTIONAL phases so the
    declared plan the web renders already reflects what will actually run. A
    request to disable a mandatory phase is refused (the phase stays in the
    plan); the refusal warnings are emitted via ``print_warning`` so they are
    never silently dropped. ``config=None`` (the default) is a no-op and the
    plan is byte-for-byte identical to before this parameter existed.
    """
    phases = phases_for_command(command)

    disabled_ids = getattr(getattr(config, "phases", None), "disabled", None)
    if disabled_ids:
        honored, warnings = resolve_disabled_phases(command, disabled_ids)
        for warning in warnings:
            _warn(warning)
        if honored:
            phases = tuple(p for p in phases if p.phase_id not in honored)

    # Per-phase subphase (step-level) disables, honored only for OPTIONAL
    # subphases; a mandatory-subphase disable is refused with a warning. The
    # declared plan the web renders already reflects the surviving subphases.
    steps_config: dict = getattr(getattr(config, "phases", None), "steps", None) or {}

    # Conditional phases are excluded from the progress total: they run only
    # when a runtime condition fires, so a normal run never emits their phase
    # event. Counting their weight would cap a clean run below 100%. Their
    # cumulative_percent is pinned to the prior non-conditional phase's value so
    # the declared plan still carries a sensible (non-regressing) number.
    total_weight = sum(p.weight for p in phases if not p.conditional) or 1

    flat: list[dict] = []
    cumulative = 0
    for index, phase in enumerate(phases):
        if not phase.conditional:
            cumulative += phase.weight
        phase_dict: dict = {
            "id": phase.phase_id,
            "title": phase.title,
            "subtitle": phase.subtitle,
            "chapter": phase.chapter,
            "order": index + 1,
            "weight": phase.weight,
            "cumulative_percent": round(cumulative / total_weight * 100.0, 1),
            "optional": phase.optional,
            "configurable": phase.configurable,
            "conditional": phase.conditional,
        }
        if phase.config_options:
            phase_dict["config_options"] = _serialize_config_options(
                phase.config_options
            )
        if phase.subphases:
            disabled_subs: frozenset[str] = frozenset()
            requested_subs = steps_config.get(phase.phase_id)
            if requested_subs:
                honored_subs, sub_warnings = resolve_disabled_subphases(
                    phase.phase_id, requested_subs
                )
                for warning in sub_warnings:
                    _warn(warning)
                disabled_subs = honored_subs
            sub_list: list[dict] = []
            sub_order = 0
            for sub in phase.subphases:
                if sub.subphase_id in disabled_subs:
                    continue
                sub_order += 1
                sub_dict: dict = {
                    "id": sub.subphase_id,
                    "title": sub.title,
                    "subtitle": sub.subtitle,
                    "order": sub_order,
                    "optional": sub.optional,
                }
                if sub.config_options:
                    sub_dict["config_options"] = _serialize_config_options(
                        sub.config_options
                    )
                sub_list.append(sub_dict)
            if sub_list:
                phase_dict["subphases"] = sub_list
        flat.append(phase_dict)

    chapters: list[dict] = []
    for chapter in CHAPTERS:
        chapter_phases = [p for p in flat if p["chapter"] == chapter.chapter_id]
        if not chapter_phases:
            continue
        chapters.append(
            {
                "id": chapter.chapter_id,
                "label": chapter.label,
                "icon": chapter.icon,
                "phases": chapter_phases,
            }
        )

    return {
        "command": command,
        "total_weight": total_weight,
        "chapters": chapters,
        "phases": flat,
    }


# ---------------------------------------------------------------------------
# Public lookups (kept for existing callers)
# ---------------------------------------------------------------------------


def phases_for_scan_type(scan_type: str) -> tuple[ScanPhase, ...]:
    """Return the ordered phases that apply to ``scan_type`` (auth family).

    Retained for callers that pass the legacy ``LdapShell.type`` string. It maps
    the scan type to the auth command and derives the phases from the registry.
    """
    return phases_for_command(command_for_scan_type(scan_type, authenticated=True))


def get_phase(phase_id: str) -> ScanPhase | None:
    """Return the :class:`ScanPhase` for ``phase_id`` or ``None``."""
    return _PHASES_BY_ID.get(phase_id)


def phase_order(phase_id: str) -> int:
    """Return the 1-based global order of ``phase_id`` in the registry.

    Used to stamp ``phase_order`` on structured events so the web can sort and
    detect regressions without re-deriving the order itself.
    """
    for index, phase in enumerate(SCAN_PHASES):
        if phase.phase_id == phase_id:
            return index + 1
    return 0


def emit_chapter(phase_id: str, scan_type: str = "default") -> None:
    """Render the CLI chapter banner for ``phase_id`` AND emit the phase event.

    This is the single transition point: it renders the operator-facing chapter
    strip and ALSO fires the structured ``phase`` event with the SAME canonical
    ``phase_id``, so the CLI strip and the web current-phase highlight never
    drift. Silently no-ops when ``phase_id`` is unknown or not visible for this
    scan type — phase emission must never block the underlying enumeration step.
    """
    phase = _PHASES_BY_ID.get(phase_id)
    if phase is None:
        return

    visible = phases_for_scan_type(scan_type)
    try:
        index = visible.index(phase)
    except ValueError:
        # Phase exists but is not visible for this scan_type — still emit the
        # structured event (the web plan may include it), but skip the strip.
        _emit_phase_event(phase_id)
        return

    _emit_phase_event(phase_id)

    from adscan_core.rich_output_collection import (
        PhaseChapter,
        print_phase_chapter,
    )

    print_phase_chapter(
        PhaseChapter(
            number=index + 1,
            title=phase.title,
            subtitle=phase.subtitle,
            all_phases=tuple(p.title for p in visible),
        )
    )


def _emit_phase_event(phase_id: str) -> None:
    """Fire the structured ``phase`` event for ``phase_id`` (best-effort)."""
    try:
        from adscan_internal.cli.ci_events import emit_phase

        emit_phase(phase_id)
    except Exception:  # noqa: BLE001 — telemetry must never block the scan
        pass


def phase_titles(scan_type: str = "default") -> tuple[str, ...]:
    """Return the ordered tuple of phase titles for the given scan type."""
    return tuple(p.title for p in phases_for_scan_type(scan_type))


# ---------------------------------------------------------------------------
# Scan-policy bindings (docs/superpowers/specs/2026-11-04-scan-policy-checks-
# by-family-design.md § 4.4.2 and § 6.5). Phases stay the "how and when" layer;
# a subphase or phase that IS a check declares which check id gates it here, and
# the work that is not a catalog technique declares its own safety axes below.
# ---------------------------------------------------------------------------

#: ``(phase_id, subphase_id) -> check id``. Every OPTIONAL subphase is bound
#: (structural test). A mandatory subphase is bound only when it is surfaced as a
#: locked check (the directory graph and the port scan always run and say so).
SUBPHASE_CHECK_BINDINGS: dict[tuple[str, str], str] = {
    ("domain_collection", "ldap"): "module:domain_collection.ldap",
    ("domain_collection", "samr"): "module:domain_collection.samr",
    ("domain_collection", "shares"): "module:domain_collection.shares",
    ("domain_collection", "mssql"): "module:domain_collection.mssql",
    ("domain_analysis", "port_scan"): "module:domain_analysis.port_scan",
    ("domain_analysis", "ntlm_auth_type_sweep"): "module:domain_analysis.ntlm_auth_type_sweep",
    ("quick_credential_wins", "timeroast"): "step:timeroasting",
    ("quick_credential_wins", "ldap_descriptions"): "step:userdescription",
    ("quick_credential_wins", "gpp_autologin"): "module:quick_credential_wins.gpp_autologin",
    ("quick_credential_wins", "gpp_passwords"): "step:gpppassword",
    ("password_spraying", "pre2k"): "step:computerpre2k",
    ("password_spraying", "blank"): "step:blankpassword",
    ("password_spraying", "useraspass"): "step:useraspass",
    ("password_spraying", "reuse"): "module:password_spraying.reuse",
    ("password_spraying", "month_season"): "module:password_spraying.month_season",
}

#: Check id of the local credential reuse validation (a recovered local
#: credential tried against the same local account on the other hosts). Gated
#: in ``PentestShell.ask_for_local_cred_reuse`` and ``cli/smb.run_local_cred_reuse``.
LOCAL_CREDENTIAL_REUSE_CHECK_ID = "module:local_credential_reuse"

# ── Network pivot (family ``lateral_movement``) ──────────────────────────────
#: Opening a network pivot through a compromised host so ADscan can reach an
#: otherwise-unreachable network segment (``services/pivot_service.py``,
#: ``orchestrate_ligolo_pivot_tunnel``). It UPLOADS a tunnel agent to the pivot
#: host (ledger kind ``file_uploaded``, removed by the Ligolo artifact cleanup
#: service at stop or listed for manual cleanup) AND opens a local 443/8443
#: listener that routes traffic into the pivoted segment. Because it writes to a
#: client host and opens a listener, it is off in Production-sensitive by
#: construction (the deployment that must write nothing and open no listener);
#: on in Audit, still behind the scope-expansion consent; on in Lab/CTF. Gated
#: at the single seam every pivot caller converges on
#: (``orchestrate_ligolo_pivot_tunnel``) and in the pre-search predicate
#: ``is_pivoting_enabled``.
NETWORK_PIVOT_CHECK_ID = "module:network_pivot"

# ── Connection posture probes (family ``connection_posture``) ────────────────
#: One check per proactive posture probe of ``services/posture_probe.py``. The
#: probes run before the scan connects (``posture_orchestration.ensure_posture_fresh``)
#: and learn which signing, encryption and authentication settings a domain
#: controller enforces, so the first connection is built right. Each one is
#: gated on its own in ``probe_unauth`` / ``probe_auth`` (and in the per-DC LDAP
#: security audit, which runs the LDAP signing and channel binding probes). A
#: probe switched off leaves its category UNKNOWN: nothing is cached for it, and
#: the reactive layer (transport signals on a real failure) learns it the first
#: time an operation needs it. ``ADSCAN_NO_POSTURE_PROBE`` still switches every
#: probe off at once.
POSTURE_PROBE_LDAPS_AVAILABLE = "module:connection_posture.ldaps_available"
POSTURE_PROBE_STARTTLS = "module:connection_posture.starttls"
POSTURE_PROBE_LDAP_SIGNING = "module:connection_posture.ldap_signing"
POSTURE_PROBE_LDAP_CHANNEL_BINDING = "module:connection_posture.ldap_channel_binding"
POSTURE_PROBE_NTLM_ENABLED = "module:connection_posture.ntlm_enabled"
POSTURE_PROBE_KERBEROS_RC4 = "module:connection_posture.kerberos_rc4"
POSTURE_PROBE_KERBEROS_SALT = "module:connection_posture.kerberos_salt"
POSTURE_PROBE_SMB_SIGNING = "module:connection_posture.smb_signing"

#: Posture category (``domain_posture.ConstraintCategory`` value) -> the check
#: that gates the probe answering it. ``kerberos_aes_only`` has no check of its
#: own: the same RC4-only AS-REQ answers both, so ``kerberos_rc4`` gates it.
POSTURE_PROBE_CHECK_BY_CATEGORY: dict[str, str] = {
    "ldaps_available": POSTURE_PROBE_LDAPS_AVAILABLE,
    "ldap_starttls_available": POSTURE_PROBE_STARTTLS,
    "ldap_signing": POSTURE_PROBE_LDAP_SIGNING,
    "ldap_channel_binding": POSTURE_PROBE_LDAP_CHANNEL_BINDING,
    "ntlm_authentication": POSTURE_PROBE_NTLM_ENABLED,
    "kerberos_rc4": POSTURE_PROBE_KERBEROS_RC4,
    "kerberos_aes_only": POSTURE_PROBE_KERBEROS_RC4,
    "kerberos_etype_probe_needed": POSTURE_PROBE_KERBEROS_SALT,
    "smb_signing": POSTURE_PROBE_SMB_SIGNING,
}

# ── Checks run with each credential obtained (family ``new_credential``) ─────
#: Signing in to every in-scope host as an account ADscan holds, over SMB,
#: WinRM, RDP (CredSSP) and SQL Server, to learn where it is accepted and with
#: which rights (``cli/privileges.run_service_access_sweep``). Runs for each
#: credential obtained: the scan account at start, every credential a step
#: yields (the "Check New Host Access" follow-up), owned users after a pivot.
NEW_CREDENTIAL_HOST_ACCESS_CHECK_ID = "module:new_credential.host_access"
#: Re-running the share collection (listing and effective access) as each
#: account obtained during the scan. The share listing itself is owned by
#: ``module:domain_collection.shares``; this check gates only the re-run, so it
#: runs when BOTH are on (declared through ``same_action_as``).
NEW_CREDENTIAL_SHARE_ACCESS_CHECK_ID = "module:new_credential.share_access"
#: Offering, when an account is obtained, to spray that account's own password
#: across the domain. The spray itself is owned by ``module:password_spraying.reuse``
#: (owned-credential reuse); this check gates only the trigger, so it runs when
#: BOTH are on (declared through ``same_action_as``).
NEW_CREDENTIAL_PASSWORD_REUSE_CHECK_ID = "module:new_credential.password_reuse"
#: The host-access service leg that is another check's action: the SQL Server
#: leg is the same Windows-authenticated login the ``module:domain_collection.mssql``
#: collection makes, so it runs only when that check is on too (enforced per
#: service in ``run_service_access_sweep``).
NEW_CREDENTIAL_HOST_ACCESS_SERVICE_OWNERS: dict[str, str] = {
    "mssql": "module:domain_collection.mssql",
}

#: Mandatory subphases that are deliberately NOT checks (pure pipeline steps
#: with no traffic of their own beyond what the bound checks already send).
SUBPHASES_NOT_CHECKS: frozenset[tuple[str, str]] = frozenset(
    {
        ("domain_analysis", "host_inventory"),
        ("domain_analysis", "identity_inventory"),
    }
)


@dataclass(frozen=True)
class ModuleCheckDeclaration:
    """Safety declaration for an active module that is not a catalog technique.

    Mirrors the catalog's declaration discipline: every axis is explicit and the
    ``undeclared`` sentinel is the only default-like value. ``events_from_relation``
    reuses a catalog technique's ``detection_event_ids`` when the module runs the
    SAME executor (so the declaration cannot drift); otherwise ``event_ids``
    stays ``None`` (undeclared).

    Attributes:
        check_id: Registry id (``module:<phase>.<subphase>`` or ``module:<job>``).
        family: Family id from ``adscan_core.scan_policy.families``.
        title: Client-facing check title.
        environment_change_kinds: Ledger change kinds the module writes (``()``
            declares "writes nothing"; ``None`` is undeclared).
        lockout_risk: As on the attack-step catalog.
        lockout_guard: Guard id when ``bounded``.
        service_interference: ``none`` | ``transient`` | ``undeclared``.
        locked_state: ``always_runs`` for mandatory collection, else ``""``.
        phases: Whole phases this check also gates.
        jobs: Background job kinds this check gates.
        events_from_relation: Catalog relation whose events this module shares.
        event_ids: Explicit events, ``None`` when undeclared.
        group: Scan-policy group (``attack_steps`` | ``vulnerabilities``). Empty
            means derived: family ``collection`` is the collection block, every
            other module is an attack step (it produces something only by
            running). Declared ``vulnerabilities`` for a module that observes a
            configuration rather than attacking it.
        no_native_events: The module sends nothing a Windows Security event
            records (a TLS or SMB negotiation with no sign-in). ``event_ids``
            stays ``None``.
        same_action_as: Another module check that owns the network action this
            one re-runs (a follow-up trigger). Its events, lockout and
            interference are reused instead of declared twice, and it becomes a
            requirement: this check runs only when the owner is on too.
    """

    check_id: str
    family: str
    title: str
    environment_change_kinds: tuple[str, ...] | None
    lockout_risk: str
    lockout_guard: str = ""
    service_interference: str = "undeclared"
    locked_state: str = ""
    phases: tuple[str, ...] = ()
    jobs: tuple[str, ...] = ()
    events_from_relation: str = ""
    event_ids: tuple[str, ...] | None = None
    group: str = ""
    no_native_events: bool = False
    same_action_as: str = ""


MODULE_CHECK_DECLARATIONS: tuple[ModuleCheckDeclaration, ...] = (
    ModuleCheckDeclaration(
        check_id="module:domain_collection.ldap",
        family="collection",
        title="Directory Graph & ACLs",
        environment_change_kinds=(),
        lockout_risk="not_applicable",
        service_interference="none",
        locked_state="always_runs",
        # LDAP reads of the directory as the scan account (4662 where directory
        # access auditing covers the objects).
        event_ids=("4624", "4662"),
    ),
    ModuleCheckDeclaration(
        check_id="module:domain_analysis.port_scan",
        family="collection",
        title="Port Scan",
        environment_change_kinds=(),
        lockout_risk="not_applicable",
        service_interference="none",
        locked_state="always_runs",
    ),
    ModuleCheckDeclaration(
        check_id="module:domain_collection.samr",
        family="collection",
        title="Sessions & Local Admins",
        environment_change_kinds=(),
        lockout_risk="not_applicable",
        service_interference="none",
        # SAMR and session enumeration over SMB named pipes; reading a local
        # group's members logs 4799 on the host.
        event_ids=("4624", "5145", "4799"),
    ),
    ModuleCheckDeclaration(
        check_id="module:domain_collection.shares",
        family="collection",
        title="Shares & Share Permissions",
        environment_change_kinds=(),
        lockout_risk="not_applicable",
        service_interference="none",
        # Share listing and share security over SMB (SRVSVC on IPC$).
        event_ids=("4624", "5145"),
    ),
    ModuleCheckDeclaration(
        check_id="module:domain_collection.mssql",
        family="collection",
        title="MSSQL Authorization",
        environment_change_kinds=(),
        lockout_risk="not_applicable",
        service_interference="none",
        # A Windows-authenticated login to each SQL Server instance.
        event_ids=("4624",),
    ),
    # Coerces each host to authenticate to an ADscan capture listener to read
    # whether it answers with NetNTLMv1 or v2 (services/ntlm_capture_workflow.py).
    ModuleCheckDeclaration(
        check_id="module:domain_analysis.ntlm_auth_type_sweep",
        family="coercion_relay",
        title="NTLM Auth-Type Sweep",
        environment_change_kinds=(),
        lockout_risk="not_applicable",
        service_interference="transient",
        group="vulnerabilities",
        # The coercion calls it makes: the scanner's network logon on each host
        # and the named-pipe access (cve_scanner CVE_EVENT_DECLARATIONS).
        event_ids=("4624", "5145"),
    ),
    # Owned-credential reuse and month/season run through the same user-spray
    # executors as the wordlist spray (per-type eligibility + lockout margin).
    ModuleCheckDeclaration(
        check_id="module:password_spraying.reuse",
        family="password_attacks",
        title="Credential Reuse",
        environment_change_kinds=(),
        lockout_risk="bounded",
        lockout_guard="spray_eligibility",
        service_interference="none",
        events_from_relation="passwordspray",
    ),
    # A local credential recovered from one host (SAM dump, LAPS read, a share,
    # a stored local credential) is tried against the local account of the same
    # name on every other enabled host (cli/smb.py run_local_cred_reuse). Each
    # sign-in is an NTLM logon into the target's OWN SAM (is_local_account), so
    # no domain account is ever counted; the host's local lockout policy applies
    # and its counter cannot be read remotely, so the auth attempt guard keys
    # the attempt to the host (auth_attempt_guard.local_realm) and counts its
    # own failures per local account per host. Reads only: no directory or host
    # change. Every target logs the logon (4624 / 4625) and the local NTLM
    # credential validation (4776).
    ModuleCheckDeclaration(
        check_id=LOCAL_CREDENTIAL_REUSE_CHECK_ID,
        family="password_attacks",
        title="Local Credential Reuse Across Hosts",
        environment_change_kinds=(),
        lockout_risk="bounded",
        lockout_guard="host_local_attempt_count",
        service_interference="none",
        event_ids=("4624", "4625", "4776"),
    ),
    ModuleCheckDeclaration(
        check_id="module:password_spraying.month_season",
        family="password_attacks",
        title="Month/Season + Year",
        environment_change_kinds=(),
        lockout_risk="bounded",
        lockout_guard="spray_eligibility",
        service_interference="none",
        events_from_relation="passwordspray",
    ),
    # Same SYSVOL walk and credential ingestion as the GPP cpassword search.
    ModuleCheckDeclaration(
        check_id="module:quick_credential_wins.gpp_autologin",
        family="credentials_exposed",
        title="GPP Autologin Search",
        environment_change_kinds=(),
        lockout_risk="bounded",
        lockout_guard="single_attempt_per_candidate",
        service_interference="none",
        events_from_relation="gpppassword",
    ),
    # Step 2 of the share-exposure phase: loot readable shares and validate each
    # discovered credential once (cli/smb.py, ``passwordinshares`` origin). Step 1
    # (bait on writable shares) is ``module:writeshare_bait``.
    ModuleCheckDeclaration(
        check_id="module:share_credential_hunt",
        family="credentials_exposed",
        title="Readable-Share Credential Hunt",
        environment_change_kinds=(),
        lockout_risk="bounded",
        lockout_guard="single_attempt_per_candidate",
        service_interference="none",
        phases=("share_credential_hunt",),
        events_from_relation="readshare",
    ),
    ModuleCheckDeclaration(
        check_id="module:unauthenticated_attack_surface",
        family="unauthenticated",
        title="Unauthenticated Attack Surface",
        environment_change_kinds=(),
        lockout_risk="not_applicable",
        service_interference="none",
        phases=("unauthenticated_attack_surface",),
        group="vulnerabilities",
    ),
    # Background job: answers broadcast name-resolution queries (LLMNR / NBT-NS /
    # mDNS) so a client authenticates to the scanner.
    ModuleCheckDeclaration(
        check_id="module:poisoning",
        family="coercion_relay",
        title="Broadcast Name Poisoning",
        environment_change_kinds=(),
        lockout_risk="not_applicable",
        service_interference="transient",
        jobs=("poisoning",),
    ),
    # Background job and share-exposure Step 1: plants a bait file on writable
    # shares (ledger kind ``file_uploaded``, removed at stop or listed for manual
    # cleanup: services/post_exploitation/ntlmv2_share_capture_service.py).
    ModuleCheckDeclaration(
        check_id="module:writeshare_bait",
        family="coercion_relay",
        title="Writable-Share Bait Files",
        environment_change_kinds=("file_uploaded",),
        lockout_risk="not_applicable",
        service_interference="transient",
        jobs=("writeshare_bait",),
        # The uploaded file (services/change_kind_events.py, file_uploaded).
        event_ids=("5145",),
    ),
    # Opens a network pivot through a compromised host (Ligolo,
    # services/pivot_service.orchestrate_ligolo_pivot_tunnel). It uploads a
    # tunnel agent to the pivot host (ledger kind ``file_uploaded``, removed by
    # ligolo_artifact_cleanup_service at stop or listed for manual cleanup) and
    # opens a local 443/8443 listener that routes traffic into the otherwise
    # unreachable segment. Gated at that single seam (every WinRM/MSSQL caller
    # converges there) and in is_pivoting_enabled. A write plus a listener, so it
    # is off in Production-sensitive; on in Audit behind the scope-expansion ask;
    # on in Lab/CTF.
    ModuleCheckDeclaration(
        check_id=NETWORK_PIVOT_CHECK_ID,
        family="lateral_movement",
        title="Network Pivot Tunnel",
        environment_change_kinds=("file_uploaded",),
        lockout_risk="not_applicable",
        service_interference="transient",
        # The staged agent file on the pivot host (file_uploaded, 5145) and the
        # remote process that runs it (WinRM / xp_cmdshell, 4688).
        event_ids=("5145", "4688"),
    ),
    # Rotation of an account ADscan already holds a valid password for, when the
    # domain refuses the logon until the password is changed
    # (STATUS_PASSWORD_MUST_CHANGE). It is the same write as ForceChangePassword
    # (ledger kind ``password_changed``), so it shares that family and the policy
    # decides both in one place. Gated in adscan.py
    # (_maybe_change_password_after_must_change) through
    # directory_change_consent.confirm_directory_change(check_id=...).
    ModuleCheckDeclaration(
        check_id="module:password_rotation_on_required_change",
        family="password_changes",
        title="Password Rotation When the Domain Requires a New Password",
        environment_change_kinds=("password_changed",),
        lockout_risk="none",
        service_interference="none",
        event_ids=("4723", "4724"),
    ),
    # Detection confirmations that change the environment. The passive ADCS
    # detector finds the ESC15 / ESC9 / ESC10 candidates by reading; confirming
    # one enrolls a self-subject certificate on the client's CA (ledger kind
    # ``issued_certificate``: revoked at the final pass when a credential may,
    # listed for manual revocation otherwise). Their own checks, so the policy decides the write apart
    # from the detection: off, the finding is reported confirmation-pending.
    # Attack-steps group (the module default): a vulnerability check never writes,
    # and the policy summary's write sentence names attack steps only, so a write
    # filed under vulnerabilities would be hidden from the client's disclosure.
    # Gated by services/detection_change_gate.authorize_detection_change.
    ModuleCheckDeclaration(
        check_id="module:adcs_esc15_confirmation",
        family="adcs",
        title="ADCS ESC15 Confirmation Enrollment",
        environment_change_kinds=("issued_certificate",),
        lockout_risk="not_applicable",
        service_interference="none",
        event_ids=("4886", "4887"),
    ),
    # The ESC9 / ESC10 canary also authenticates with the issued certificate
    # (PKINIT as the scan account) to observe the domain's binding enforcement.
    # It runs only when the registry read of that setting was indeterminate.
    ModuleCheckDeclaration(
        check_id="module:adcs_esc9_confirmation",
        family="adcs",
        title="ADCS ESC9 / ESC10 Confirmation Enrollment",
        environment_change_kinds=("issued_certificate",),
        lockout_risk="not_applicable",
        service_interference="none",
        event_ids=("4886", "4887", "4768"),
    ),
    # ── Connection posture probes (services/posture_probe.py) ────────────────
    # U1: a TCP connection and TLS handshake on 636. No LDAP message is sent and
    # nobody signs in, so no Security event records it.
    ModuleCheckDeclaration(
        check_id=POSTURE_PROBE_LDAPS_AVAILABLE,
        family="connection_posture",
        title="LDAPS Availability Probe",
        environment_change_kinds=(),
        lockout_risk="not_applicable",
        service_interference="none",
        group="vulnerabilities",
        no_native_events=True,
    ),
    # U4: an anonymous LDAP session on 389 and the StartTLS extended request. It
    # never binds, so no sign-in event.
    ModuleCheckDeclaration(
        check_id=POSTURE_PROBE_STARTTLS,
        family="connection_posture",
        title="StartTLS Availability Probe",
        environment_change_kinds=(),
        lockout_risk="not_applicable",
        service_interference="none",
        group="vulnerabilities",
        no_native_events=True,
    ),
    # U2: an unsigned NTLM LDAP bind on 389 as a random account that does not
    # exist (``adscan-probe-<hex>``), so the DC logs a failed logon (4625) and an
    # NTLM credential validation (4776) for that name. Nothing can lock: the
    # account does not exist. A5 (authenticated tiebreaker, with credentials)
    # binds as the scan account with its verified credential: 4624, and over
    # Kerberos 4768 / 4769.
    ModuleCheckDeclaration(
        check_id=POSTURE_PROBE_LDAP_SIGNING,
        family="connection_posture",
        title="LDAP Signing Probe",
        environment_change_kinds=(),
        lockout_risk="none",
        service_interference="none",
        group="vulnerabilities",
        event_ids=("4625", "4776", "4624", "4768", "4769"),
    ),
    # U3 (LDAPS) and U3b (StartTLS, only when 636 is closed): the same
    # non-existent-account NTLM bind without channel binding (4625, 4776). A6,
    # only when NTLM is disabled, binds over LDAPS with Kerberos as the scan
    # account (4768, 4769, 4624).
    ModuleCheckDeclaration(
        check_id=POSTURE_PROBE_LDAP_CHANNEL_BINDING,
        family="connection_posture",
        title="LDAP Channel Binding Probe",
        environment_change_kinds=(),
        lockout_risk="none",
        service_interference="none",
        group="vulnerabilities",
        event_ids=("4625", "4776", "4624", "4768", "4769"),
    ),
    # A3: an SMB session setup with NTLM on the DC as a random account that does
    # not exist; the scan account's credential is not used. 4625 and 4776 for
    # that name; nothing can lock.
    ModuleCheckDeclaration(
        check_id=POSTURE_PROBE_NTLM_ENABLED,
        family="connection_posture",
        title="NTLM Availability Probe",
        environment_change_kinds=(),
        lockout_risk="none",
        service_interference="none",
        group="vulnerabilities",
        event_ids=("4625", "4776"),
    ),
    # A1: one AS-REQ as the scan account offering only RC4, with its verified
    # password; the answer settles both RC4 support and AES-only enforcement.
    # 4768 (issued with encryption type 0x17, or refused with "encryption type
    # not supported").
    ModuleCheckDeclaration(
        check_id=POSTURE_PROBE_KERBEROS_RC4,
        family="connection_posture",
        title="Kerberos RC4 and AES-only Probe",
        environment_change_kinds=(),
        lockout_risk="not_applicable",
        service_interference="none",
        group="vulnerabilities",
        event_ids=("4768",),
    ),
    # A2: an AS-REQ for the scan account with no pre-authentication, to read the
    # salt the KDC advertises in its "pre-authentication required" answer. No
    # password is sent, and that answer is part of every normal Kerberos logon,
    # so domain controllers do not record it as a failure.
    ModuleCheckDeclaration(
        check_id=POSTURE_PROBE_KERBEROS_SALT,
        family="connection_posture",
        title="Kerberos Salt Probe",
        environment_change_kinds=(),
        lockout_risk="not_applicable",
        service_interference="none",
        group="vulnerabilities",
        no_native_events=True,
    ),
    # A4: an SMB NEGOTIATE with the DC, read before any sign-in (no event). Only
    # when the negotiate read fails, a session setup as the scan account with its
    # verified credential (4624).
    ModuleCheckDeclaration(
        check_id=POSTURE_PROBE_SMB_SIGNING,
        family="connection_posture",
        title="SMB Signing Probe",
        environment_change_kinds=(),
        lockout_risk="not_applicable",
        service_interference="none",
        group="vulnerabilities",
        event_ids=("4624",),
    ),
    # ── Checks run with each credential obtained ──────────────────────────────
    # Signs in as the account on every in-scope host over SMB, WinRM, RDP
    # (CredSSP / NLA) and SQL Server, one session per service per host, and
    # reads what it may do there. Only with a credential the domain already
    # accepted: the sweep mints one ticket first (sweep_credential.resolve_sweep_credential)
    # and a failed mint aborts it, and the auth attempt guard never re-sends a
    # secret the domain rejected, so a password changed during the scan costs at
    # most one failed attempt for that account, not one per host. Each host logs
    # the network logon (4624, 4625 on a rejection); the DC logs the ticket
    # requests (4768, 4769) or the NTLM validation (4776).
    ModuleCheckDeclaration(
        check_id=NEW_CREDENTIAL_HOST_ACCESS_CHECK_ID,
        family="new_credential",
        title="Host Access Check for Each Credential",
        environment_change_kinds=(),
        lockout_risk="not_applicable",
        service_interference="none",
        event_ids=("4624", "4625", "4768", "4769", "4776"),
    ),
    # Re-runs the share collection (listing and effective access) as each
    # account obtained. Same action as the collector's share collection, so its
    # traffic, events, lockout and interference are that check's.
    ModuleCheckDeclaration(
        check_id=NEW_CREDENTIAL_SHARE_ACCESS_CHECK_ID,
        family="new_credential",
        title="Share Access Mapping for Each Credential",
        environment_change_kinds=(),
        lockout_risk="",
        same_action_as="module:domain_collection.shares",
    ),
    # Sprays the obtained account's own password across the domain's other
    # accounts. Same action as the owned-credential reuse spray, so its traffic,
    # events and lockout guard (spray eligibility) are that check's.
    ModuleCheckDeclaration(
        check_id=NEW_CREDENTIAL_PASSWORD_REUSE_CHECK_ID,
        family="new_credential",
        title="Password Reuse Spray for Each Credential",
        environment_change_kinds=(),
        lockout_risk="",
        same_action_as="module:password_spraying.reuse",
    ),
)

#: Network actions inside the proactive posture phase that are NOT a posture
#: probe check, each with the reason. ``probe_password_policy`` reads the domain
#: password policy over LDAP as the scan account: the same directory read the
#: mandatory collection makes, and the lockout guard depends on it, so no policy
#: switches it off. Locked by ``tests/unit/scan_policy/test_network_actions_are_checks.py``.
POSTURE_PHASE_ACTIONS_NOT_CHECKS: dict[str, str] = {
    "probe_password_policy": (
        "LDAP read of the domain password policy as the scan account, the same "
        "directory read the mandatory collection makes; the lockout guard needs it."
    ),
}
