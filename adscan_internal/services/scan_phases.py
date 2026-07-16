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
# choices mirror the deliver/ci CLI valid sets
# (``adscan_internal.cli.deliver._VALID_FRAMEWORK_KEYS`` / ``_VALID_REPORT_THEMES``).
# The contract test asserts both, so the CLI flags, the engine, and the web
# form can never drift.
# ---------------------------------------------------------------------------

TRUST_POLICY_CHOICES: tuple[str, ...] = ("skip", "all", "selected", "interactive")
ATTACK_PATH_POLICY_CHOICES: tuple[str, ...] = (
    "none",
    "all",
    "selected",
    "interactive",
)
REPORT_FRAMEWORK_CHOICES: tuple[str, ...] = (
    "ens",
    "nis2",
    "iso27001",
    "dora",
    "pci_dss",
)
REPORT_THEME_CHOICES: tuple[str, ...] = (
    "corporate_light",
    "premium_dark",
    "editorial",
)
REPORT_THEME_DEFAULT: str = "corporate_light"

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
                choices=TRUST_POLICY_CHOICES,
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
        subtitle="Native LDAP/SMB collector — graph, sessions, ACLs.",
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
                subtitle="Graph, group memberships, security descriptors, and PKI — always runs.",
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
        config_options=(
            PhaseConfigOption(
                key="policy",
                kind="enum",
                label="Attack-path execution",
                choices=ATTACK_PATH_POLICY_CHOICES,
                default="interactive",
            ),
            PhaseConfigOption(
                key="selected",
                kind="multiselect",
                label="Attack paths (when policy is 'selected')",
                choices=(),  # populated at form time from discovered paths
                default=(),
            ),
        ),
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


def command_for_scan_type(scan_type: str, *, authenticated: bool = True) -> str:
    """Map a legacy ``LdapShell.type`` value to a canonical command key.

    ``scan_type`` is the value of ``LdapShell.type`` (``"audit"`` / ``"ctf"`` /
    ``"default"``). ``authenticated`` selects between the auth and unauth
    command families. ``"audit"`` unlocks the two audit-only phases.
    """
    if not authenticated:
        return COMMAND_START_UNAUTH
    if scan_type == "audit":
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


def subphase_is_enabled(shell: object, phase_id: str, subphase_id: str) -> bool:
    """Return False when ``phase_id.subphase_id`` was disabled by the config.

    The single gate the per-subphase entry points consult (spray strategies,
    the quick-win sub-steps) so they SKIP when a ``--scan-config`` disabled them.
    Only OPTIONAL subphases can be disabled — a mandatory one always returns
    True. Best-effort and fail-open: any error, a missing config, or an unknown
    id yields True so the no-op default path stays byte-for-byte today's
    behavior. Mirrors :func:`phase_is_enabled` one level down.

    Args:
        shell: The pentest shell; ``shell.scan_config`` is consulted when set.
        phase_id: The canonical parent phase id.
        subphase_id: The subphase id within that phase.

    Returns:
        True when the subphase should run; False only when it is an optional
        subphase explicitly listed under
        ``scan_config.phases.steps[phase_id].disabled``.
    """
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

    Args:
        shell: The pentest shell; ``shell.scan_config`` is consulted when set.
        phase_id: The canonical phase id to check.

    Returns:
        True when the phase should run; False only when it is an optional phase
        explicitly listed in ``scan_config.phases.disabled``.
    """
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
