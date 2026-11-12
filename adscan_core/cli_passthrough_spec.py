"""Single source of truth for the container pass-through CLI surface.

The PyPI launcher (``adscan_launcher/``) is the entry point users actually
invoke. For the container-only commands ``ci``, ``execute`` and ``doctor`` the
launcher does not own the flags: it forwards every token verbatim to the
containerized runtime parser (``adscan.py`` and ``adscan_internal/cli/*``),
which is the real flag SSOT. Because the launcher forwards through
``argparse.REMAINDER``, its own ``--help`` cannot see any of those flags, so a
user who runs ``adscan ci --help`` learns nothing about the arguments the run
actually requires (the ``{auth,unauth}`` positional, ``--policy``, and so on).

This module declares that pass-through surface once, in a package both the host
launcher and the container can import (``adscan_core``). The launcher renders it
into a ``--help`` epilog so the arguments and real invocation examples are
visible, while still forwarding through ``REMAINDER`` (no re-declaration, no
drift). A contract test locks the container parsers against these specs, so a
new runtime argument cannot ship without also surfacing in the launcher help.

The launcher-owned flags (``--pull-timeout``, ``--offline``, ``--no-telemetry``,
``--scan-config``, ``--allow-low-memory``) are NOT described here: they are
consumed at the launcher seam and translated into container environment
variables, so the launcher declares them as real arguments and native ``--help``
already shows them.
"""

from __future__ import annotations

from dataclasses import dataclass

from adscan_core.report_options import REPORT_OPTIONS
from adscan_core.scan_pacing.pacing_levels import ORDERED_LEVELS


@dataclass(frozen=True)
class PassthroughArg:
    """One argument of a container pass-through command.

    Attributes:
        names: Option strings (``("--interface", "-i")``) or, for a positional, the
            single dest name (``("mode",)``).
        help: One-line, user-facing description.
        required: Whether the runtime parser requires the argument.
        run_required: Whether the RUN requires it although the parser does not,
            because the runtime enforces it after parsing (``ci --policy``: a
            ``checks`` section in ``--scan-config`` names the policy instead).
            Shown as required in the epilog and the usage hint; the contract
            test compares only ``required`` with the parser.
        choices: Allowed values, or ``None`` when the argument is free-form.
        metavar: Placeholder shown for a value-taking option (``"CIDR"``). A flag
            with neither ``choices`` nor ``metavar`` is treated as a boolean
            switch that takes no value.
        positional: ``True`` for a positional argument.
    """

    names: tuple[str, ...]
    help: str
    required: bool = False
    run_required: bool = False
    choices: tuple[str, ...] | None = None
    metavar: str | None = None
    positional: bool = False

    @property
    def primary(self) -> str:
        """The canonical name (first long option, or the positional dest)."""
        return self.names[0]

    @property
    def takes_value(self) -> bool:
        """Whether the argument consumes a value (vs. a boolean switch)."""
        return self.positional or bool(self.choices) or self.metavar is not None

    def value_token(self) -> str:
        """The value placeholder rendered after the flag (``{a,b}`` or META)."""
        if self.choices:
            return "{" + ",".join(self.choices) + "}"
        return self.metavar or self.primary.lstrip("-").replace("-", "_").upper()

    def usage_token(self) -> str:
        """The left column shown in the epilog (names plus any value token)."""
        if self.positional:
            return self.value_token()
        joined = ", ".join(self.names)
        if self.takes_value:
            return f"{joined} {self.value_token()}"
        return joined


@dataclass(frozen=True)
class PassthroughCommand:
    """A container command whose flags are forwarded through the launcher."""

    name: str
    summary: str
    args: tuple[PassthroughArg, ...]
    examples: tuple[str, ...]

    def required_args(self) -> tuple[PassthroughArg, ...]:
        return tuple(
            a for a in self.args if (a.required or a.run_required) and not a.positional
        )

    def optional_args(self) -> tuple[PassthroughArg, ...]:
        return tuple(
            a for a in self.args if not (a.required or a.run_required) and not a.positional
        )

    def positional_args(self) -> tuple[PassthroughArg, ...]:
        return tuple(a for a in self.args if a.positional)


def _report_option_passthrough_args() -> tuple[PassthroughArg, ...]:
    """The deliverable options of ``ci``, rendered from the shared model."""
    return tuple(
        PassthroughArg(
            option.flags,
            option.help,
            choices=option.choices,
            metavar=None if option.switch else (option.metavar or "VALUE"),
        )
        for option in REPORT_OPTIONS
    )


# ── ci ────────────────────────────────────────────────────────────────────────
# Mirrors the container ``ci`` subparser in ``adscan.py`` (``add_ci_subparser``).
# Locked by tests/unit/launcher/test_passthrough_spec_contract.py.
CI_PASSTHROUGH = PassthroughCommand(
    name="ci",
    summary="Arguments forwarded to the ADscan runtime after `ci`:",
    args=(
        PassthroughArg(
            ("mode",),
            "Scan mode: authenticated or unauthenticated.",
            required=True,
            choices=("auth", "unauth"),
            positional=True,
        ),
        PassthroughArg(
            ("--policy",),
            "The scan policy the run follows: lab_ctf, audit, production_sensitive or "
            "a saved policy (see `adscan policy list`). It decides what runs and, "
            "unless a pace is given, the scan pace. A 'checks' section in "
            "--scan-config names it instead.",
            run_required=True,
            metavar="NAME",
        ),
        PassthroughArg(
            ("--interface", "-i"),
            "Network interface (e.g. eth0, tun0) for broadcast poisoning. Omit it "
            "to poison every interface with a known AD host behind it; name one "
            "to limit poisoning to that interface.",
            metavar="IFACE",
        ),
        PassthroughArg(
            ("--hosts",),
            "Target CIDR or range. Required for unauth mode.",
            metavar="CIDR",
        ),
        PassthroughArg(
            ("--domain",),
            "AD domain to scan. Required for auth mode.",
            metavar="DOMAIN",
        ),
        PassthroughArg(
            ("--dc-ip",),
            "Domain controller IP. Required for auth mode; for unauth it skips host discovery.",
            metavar="IP",
        ),
        PassthroughArg(
            ("--dns-server",),
            "AD-zone DNS server IP for segmented networks (separate from the DC). "
            "Feeds only the resolver; defaults to --dc-ip when omitted.",
            metavar="IP",
        ),
        PassthroughArg(("--username", "-u"), "Username for auth mode.", metavar="USER"),
        PassthroughArg(("--password", "-p"), "Password or NT hash for auth mode.", metavar="SECRET"),
        PassthroughArg(
            ("--workspace", "-w"),
            "Workspace name (ci-<domain>-<date> if omitted). Kept after the run.",
            metavar="NAME",
        ),
        PassthroughArg(
            ("--ephemeral",),
            "Delete the workspace this run creates when it ends (needs --output with "
            "--generate-report).",
        ),
        PassthroughArg(("--output",), "Copy the generated report into this host folder.", metavar="DIR"),
        PassthroughArg(("--show-structural",), "Show the structural band in the Tactical Findings panel."),
        PassthroughArg(
            ("--read-only", "--no-attack-paths"),
            "Map and report attack paths without executing them (read-only).",
        ),
        PassthroughArg(
            ("--pacing",),
            "Scan pace: how hard ADscan works the network (default: normal). "
            "A scan policy can cap it.",
            choices=tuple(level.value for level in ORDERED_LEVELS),
        ),
        PassthroughArg(
            ("--pacing-set",),
            "Set one pace setting, e.g. max_parallel_hosts=4. Repeatable.",
            metavar="KNOB=VALUE",
        ),
        PassthroughArg(
            ("--pace-profile",),
            "Start the pace from a saved pace profile (see `adscan pace list`); "
            "--pacing and --pacing-set adjust it and the scan policy still caps it.",
            metavar="NAME",
        ),
        PassthroughArg(
            ("--generate-report",),
            "Render the deliverable after a successful scan, through the same pipeline "
            "and options as `adscan deliver` (requires a report license). Default: the "
            "Security Assessment Report alone; widen it with --only. A completed scan "
            "whose deliverable does not render exits 4; its results stand.",
        ),
        PassthroughArg(
            ("--auto-revert",),
            "Undo ADscan's directory changes on its own, for this run (default: the "
            "scan policy's auto_revert setting).",
            choices=("on", "off"),
        ),
        # The deliverable options are not re-declared: they come from the shared
        # report-options model the container `ci` and `deliver` parsers register.
        *_report_option_passthrough_args(),
        PassthroughArg(("--verbose", "-v"), "Verbose output."),
        PassthroughArg(("--debug", "-d"), "Debug output."),
    ),
    examples=(
        "adscan ci unauth --policy audit --dc-ip 10.0.0.1",
        "adscan ci unauth --policy lab_ctf --interface eth0 --dc-ip 10.0.0.1",
        "adscan ci auth --policy audit --interface eth0 --domain corp.local "
        "--dc-ip 10.0.0.1 -u alice -p 'S3cr3t!'",
        "adscan ci auth --policy audit --interface eth0 --domain corp.local "
        "--dc-ip 10.0.0.1 --dns-server 10.0.0.53 -u alice -p 'S3cr3t!'",
        "adscan ci auth --policy 'Corp production' --domain corp.local --dc-ip 10.0.0.1 "
        "-u alice -p 'S3cr3t!'",
        "adscan ci auth --policy 'Corp production' --domain corp.local --dc-ip 10.0.0.1 "
        "-u alice -p 'S3cr3t!' --pace-profile 'Slow WAN site'",
        "adscan ci auth --policy audit --domain corp.local --dc-ip 10.0.0.1 -u alice "
        "-p 'S3cr3t!' --generate-report --only report,playbook --frameworks nis2 "
        "--client 'Corp' --branding whitelabel --output ./deliverables",
    ),
)


# ── execute ─────────────────────────────────────────────────────────────────
# Mirrors adscan_internal/cli/execute.py::add_execute_subparser.
EXECUTE_PASSTHROUGH = PassthroughCommand(
    name="execute",
    summary=(
        "Run one REPL verb (PRO; every verb is also a command in `adscan start`); "
        "arguments forwarded to the ADscan runtime:"
    ),
    args=(
        PassthroughArg(
            ("verb",),
            "REPL verb to run (see `adscan execute --list`).",
            positional=True,
            metavar="VERB",
        ),
        PassthroughArg(("--list",), "List the verbs available to `execute` and exit."),
        PassthroughArg(("--domain", "-d"), "Target domain.", metavar="DOMAIN"),
        PassthroughArg(("--dc-ip",), "Domain controller IP for the target domain.", metavar="IP"),
        PassthroughArg(
            ("--dns-server",),
            "AD-zone DNS server IP for segmented networks (separate from the DC). "
            "Feeds only the resolver; defaults to --dc-ip when omitted.",
            metavar="IP",
        ),
        PassthroughArg(("--username", "-u"), "Auth username (for verbs that authenticate).", metavar="USER"),
        PassthroughArg(("--password", "-p"), "Auth password or hash.", metavar="SECRET"),
        PassthroughArg(
            ("--workspace", "-w"),
            "Workspace name (exec-<domain>-<date> if omitted). Kept after the run.",
            metavar="NAME",
        ),
        PassthroughArg(("--interface", "-i"), "Network interface (myip auto-config).", metavar="IFACE"),
        PassthroughArg(("--ephemeral",), "Delete the workspace this run creates when it ends."),
        PassthroughArg(("--verbose", "-v"), "Verbose output."),
    ),
    examples=(
        "adscan execute --list",
        "adscan execute kerberoast -d corp.local --dc-ip 10.0.0.1 -u alice -p 'S3cr3t!'",
        "adscan execute kerberoast -d corp.local --dc-ip 10.0.0.1 --dns-server 10.0.0.53 "
        "-u alice -p 'S3cr3t!'",
        # A verb's OWN flags are not declared here (this spec mirrors the
        # `execute` subparser, and the contract test rejects an entry the
        # subparser has no action for): they forward through the REMAINDER
        # after `--`. One example, because a declaration nobody can see how to
        # type is a feature nobody uses.
        "adscan execute compliance_scope -w Lab-Demo -- "
        "--profile general --levels C=medio,I=medio,T=bajo,A=medio,D=bajo",
        "adscan execute attack_paths -d corp.local -w Lab-Demo -- "
        "alice --terminal-relations forcechangepassword",
    ),
)


# ── doctor ──────────────────────────────────────────────────────────────────
# Mirrors adscan_internal/cli/doctor.py::add_doctor_subparser.
DOCTOR_PASSTHROUGH = PassthroughCommand(
    name="doctor",
    summary="Arguments forwarded to the ADscan runtime health check:",
    args=(
        PassthroughArg(("--domain", "-d"), "Target domain to validate.", metavar="DOMAIN"),
        PassthroughArg(("--dc-ip",), "Domain controller IP for the target domain.", metavar="IP"),
        PassthroughArg(
            ("--dns-server",),
            "AD-zone DNS server IP for segmented networks (separate from the DC). "
            "The DNS check queries it; --dc-ip stays the connectivity target.",
            metavar="IP",
        ),
        PassthroughArg(
            ("--trusts",),
            "Trusted domains to validate besides the origin (needs -u/-p): "
            "origin_only (default), all, selected, interactive (ask which to validate).",
            metavar="SCOPE",
            choices=("origin_only", "all", "selected", "interactive"),
        ),
        PassthroughArg(
            ("--trust-domains",),
            "Comma-separated trusted domains to validate (with --trusts selected).",
            metavar="DOMAINS",
        ),
        PassthroughArg(("--username", "-u"), "Auth username (enables the auth check).", metavar="USER"),
        PassthroughArg(("--password", "-p"), "Auth password or hash.", metavar="SECRET"),
        PassthroughArg(
            ("--workspace", "-w"),
            "Named workspace to check from (kept). Omitted: a throwaway one, deleted after.",
            metavar="NAME",
        ),
        PassthroughArg(("--interface", "-i"), "Network interface (myip auto-config).", metavar="IFACE"),
        PassthroughArg(("--json",), "Emit one structured JSON object instead of the human matrix."),
        PassthroughArg(("--verbose", "-v"), "Verbose output."),
    ),
    examples=(
        "adscan doctor -d corp.local --dc-ip 10.0.0.1",
        "adscan doctor -d corp.local --dc-ip 10.0.0.1 -u alice -p 'S3cr3t!'",
        "adscan doctor -d corp.local --dc-ip 10.0.0.1 --dns-server 10.0.0.53",
        "adscan doctor -d corp.local --dc-ip 10.0.0.1 -u alice -p 'S3cr3t!' --trusts all",
    ),
)


# ── policy ──────────────────────────────────────────────────────────────────
# Mirrors adscan_internal/cli/scan_policy_library.py::add_policy_subparser. The
# launcher mounts an imported file read-only and an export file read-write
# (one file each, never a directory) and rewrites both paths, so host paths work.
POLICY_PASSTHROUGH = PassthroughCommand(
    name="policy",
    summary="Saved scan policies; arguments forwarded to the ADscan runtime:",
    args=(
        PassthroughArg(
            ("action",),
            "The action: list, show, create, edit, save, delete, export, import, use "
            "(applies a policy to a workspace; needs --workspace), or review-new to review "
            "the checks a saved policy gained since it was saved. create and edit walk "
            "you through the choices when you give no flags.",
            choices=(
                "list", "show", "create", "edit", "save", "delete", "export", "import",
                "review-new", "use",
            ),
            positional=True,
        ),
        PassthroughArg(
            ("target",),
            "The target policy name, or the file to import.",
            positional=True,
            metavar="NAME|FILE",
        ),
        PassthroughArg(
            ("--from",),
            "Policy to start from (create). Default: Full validation.",
            metavar="POLICY",
        ),
        PassthroughArg(("--exclude",), "Check id or family to switch off (create). Repeatable.", metavar="CHECK"),
        PassthroughArg(("--include",), "Check id or family to switch on (create). Repeatable.", metavar="CHECK"),
        PassthroughArg(
            ("--pacing",),
            "The policy's pace: its default and its limit (create).",
            choices=tuple(level.value for level in ORDERED_LEVELS),
        ),
        PassthroughArg(
            ("--pacing-set",),
            "A pace setting KNOB=VALUE saved in the policy (create). Repeatable; the same "
            "settings as `adscan ci --pacing-set`, for example max_parallel_hosts=4.",
            metavar="KNOB=VALUE",
        ),
        PassthroughArg(
            ("--reserve-margin",),
            "Failed attempts kept below each account's lockout threshold (create). "
            "Default 2; at least 1 unless the policy is for a lab.",
            metavar="N",
        ),
        PassthroughArg(
            ("--unknown-threshold",),
            "When the lockout threshold cannot be read (create): conservative or "
            "attempt_anyway (lab only).",
            choices=("conservative", "attempt_anyway"),
        ),
        PassthroughArg(
            ("--ignore-threshold",),
            "Spray as if no account could lock (create). Lab policies only.",
        ),
        PassthroughArg(
            ("--set",),
            "A behaviour setting KEY=VALUE (create). Repeatable: objective, "
            "scope_expansion, default_reach, operator_prompts, cracking_wordlist, "
            "cracking_effort, online_hash_lookup, poisoning, writeshare_bait.",
            metavar="KEY=VALUE",
        ),
        PassthroughArg(
            ("--environment",),
            "What the policy is for, lab or real (create); it is the workspace type.",
            choices=("lab", "real"),
        ),
        PassthroughArg(("--description",), "Description (create, import).", metavar="TEXT"),
        PassthroughArg(("--name",), "Save an imported policy under this name.", metavar="NAME"),
        PassthroughArg(("--output", "-o"), "Write the export to FILE instead of the screen.", metavar="FILE"),
        PassthroughArg(
            ("--format",),
            "Export format: yaml (default) or json (the body the web API accepts).",
            choices=("yaml", "json"),
        ),
        PassthroughArg(("--checks",), "Show every check with its safety lines (show)."),
        PassthroughArg(("--force",), "Replace a saved policy of the same name."),
        PassthroughArg(("--yes",), "Delete without asking."),
        PassthroughArg(
            ("--scope",),
            "Where create, save and import write it: workspace or global. Default: ask "
            "when a workspace is named, otherwise global.",
            choices=("workspace", "global"),
        ),
        PassthroughArg(
            ("--workspace", "-w"),
            "Use this workspace's policies; create, save and import can write there, "
            "and use applies a policy to it.",
            metavar="NAME",
        ),
    ),
    examples=(
        "adscan policy list",
        "adscan policy create 'Corp production'",
        "adscan policy edit 'Corp production' --pacing polite",
        "adscan policy use 'Corp production' -w Corp-Assessment",
        "adscan policy show safe_for_production --checks",
        "adscan policy create 'Corp production' --from safe_for_production "
        "--exclude step:kerberoasting --pacing polite --pacing-set max_parallel_hosts=2",
        "adscan policy export 'Corp production' --output corp-production.yaml",
        "adscan policy import corp-production.yaml -w Corp-Assessment",
    ),
)


# ── pace ────────────────────────────────────────────────────────────────────
# Mirrors adscan_internal/cli/pace_profile_cmd.py::add_pace_subparser. Reads and
# writes only the profile stores (global state dir or a workspace), so no file
# mount is needed.
PACE_PASSTHROUGH = PassthroughCommand(
    name="pace",
    summary="Saved pace profiles; arguments forwarded to the ADscan runtime:",
    args=(
        PassthroughArg(
            ("action",),
            "The action: list, show, create, edit, save, use, delete, export or import. "
            "create and edit walk you through the choices when you give no flags; use and "
            "save act on a workspace and need --workspace.",
            choices=("list", "show", "create", "edit", "save", "use", "delete", "export", "import"),
            positional=True,
        ),
        PassthroughArg(
            ("target",), "The target profile name, or the file to import.",
            positional=True, metavar="NAME|FILE",
        ),
        PassthroughArg(
            ("--level",),
            "The profile's pace level (create, edit).",
            choices=tuple(level.value for level in ORDERED_LEVELS),
        ),
        PassthroughArg(
            ("--set",),
            "One pace setting KNOB=VALUE (create, edit). Repeatable; the same settings as "
            "`adscan ci --pacing-set`, for example max_parallel_hosts=4.",
            metavar="KNOB=VALUE",
        ),
        PassthroughArg(("--from",), "Profile to start from (create).", metavar="PROFILE"),
        PassthroughArg(("--description",), "Description (create, edit, save, import).", metavar="TEXT"),
        PassthroughArg(("--name",), "Save an imported profile under this name.", metavar="NAME"),
        PassthroughArg(("--output", "-o"), "Write the export to FILE instead of the screen.", metavar="FILE"),
        PassthroughArg(("--force",), "Replace a saved profile of the same name."),
        PassthroughArg(
            ("--scope",),
            "Where create, save and import write it: workspace or global. Default: ask "
            "when a workspace is named, otherwise global.",
            choices=("workspace", "global"),
        ),
        PassthroughArg(
            ("--workspace", "-w"),
            "Use this workspace's profiles; create, save and import can write there, "
            "and use and save act on it.",
            metavar="NAME",
        ),
        PassthroughArg(("--yes",), "Delete without asking."),
    ),
    examples=(
        "adscan pace list",
        "adscan pace create 'Slow WAN site'",
        "adscan pace use 'Slow WAN site' -w Corp-Assessment",
        "adscan pace export 'Slow WAN site' --output slow-wan.yaml",
        "adscan pace create 'Slow WAN site' --level polite --set max_parallel_hosts=4 "
        "--set max_requests_per_second=20",
        "adscan pace show 'Slow WAN site'",
        "adscan ci auth ... --policy 'Corp production' --pace-profile 'Slow WAN site'",
    ),
)


# ── run ─────────────────────────────────────────────────────────────────────
# Mirrors adscan_internal/cli/run_plan.py::add_run_subparser. The launcher
# mounts the plan file and each file it references read-only and the events
# file read-write (never a whole directory) and rewrites both paths, so host
# paths work.
RUN_PASSTHROUGH = PassthroughCommand(
    name="run",
    summary="Arguments forwarded to the ADscan runtime after `run`:",
    args=(
        PassthroughArg(
            ("--plan",),
            "RunPlan JSON file (schema adscan.run_plan/1). Credentials are "
            "references: env:NAME or file:<path> relative to the plan's directory.",
            required=True,
            metavar="FILE",
        ),
        PassthroughArg(
            ("--events-file",),
            "Append the versioned event stream (adscan.events/1) to FILE, one JSON line per event.",
            metavar="FILE",
        ),
        PassthroughArg(("--verbose", "-v"), "Verbose output."),
        PassthroughArg(("--debug", "-d"), "Enable debug mode."),
    ),
    examples=(
        "adscan run --plan ./run/plan.json",
        "adscan run --plan ./run/plan.json --events-file ./run/events.jsonl",
    ),
)


# ── engagement ──────────────────────────────────────────────────────────────
# Mirrors adscan_internal/cli/engagement.py::add_engagement_subparser. Reads the
# engagement ledger a workspace keeps across recorded runs (PRO). Writes only
# inside the workspace (export), so no file mount is needed.
ENGAGEMENT_PASSTHROUGH = PassthroughCommand(
    name="engagement",
    summary="Engagement history; arguments forwarded to the ADscan runtime:",
    args=(
        PassthroughArg(
            ("action",),
            "status, history or export.",
            choices=("status", "history", "export"),
            positional=True,
        ),
        PassthroughArg(("--workspace", "-w"), "Workspace name.", required=True, metavar="NAME"),
        PassthroughArg(("--finding",), "history: a finding key or finding id.", metavar="KEY|ID"),
        PassthroughArg(("--item",), "history: a ledger item id.", metavar="ID"),
        PassthroughArg(("--domain",), "Only this domain.", metavar="DOMAIN"),
        PassthroughArg(
            ("--kind",),
            "status: findings (default), steps or all.",
            choices=("findings", "steps", "all"),
        ),
        PassthroughArg(("--json",), "Print JSON instead of a table."),
    ),
    examples=(
        "adscan engagement status -w Corp-Assessment",
        "adscan engagement history -w Corp-Assessment --finding kerberoast",
        "adscan engagement export -w Corp-Assessment",
    ),
)


# ── recheck ─────────────────────────────────────────────────────────────────
# Mirrors adscan_internal/cli/recheck.py::add_recheck_subparser. Re-verifies
# ledger items (PRO). Writes only inside the workspace, so no file mount.
RECHECK_PASSTHROUGH = PassthroughCommand(
    name="recheck",
    summary="Re-verification; arguments forwarded to the ADscan runtime:",
    args=(
        PassthroughArg(("--workspace", "-w"), "Workspace name.", required=True, metavar="NAME"),
        PassthroughArg(
            ("--all",),
            "Every open finding and attack step (the default with no target, read-only).",
        ),
        PassthroughArg(("--finding",), "A finding key (for example kerberoast) or id.", metavar="KEY|ID"),
        PassthroughArg(("--step",), "An attack step id (8+ characters).", metavar="ID"),
        PassthroughArg(
            ("--path",),
            "An attack path id: the id the report prints next to the path (8+ characters).",
            metavar="ID",
        ),
        PassthroughArg(("--object",), "With --finding: only this affected object (a SID). Repeatable.",
                       metavar="ID"),
        PassthroughArg(
            ("--filter",),
            "With --all or --finding: domain=<domain>,status=open|remediated|not_reevaluated|all.",
            metavar="EXPR",
        ),
        PassthroughArg(
            ("--depth",),
            "observe (read-only, default), exercise (re-perform a step) or walk (a path).",
            choices=("observe", "exercise", "walk"),
        ),
        PassthroughArg(("--walk",), "With --path: same as --depth walk."),
        PassthroughArg(
            ("--username", "-u", "--user"),
            "Read with this account instead of the workspace's (user, user@domain or DOMAIN\\user). "
            "This run only; never stored.",
            metavar="USER",
        ),
        PassthroughArg(("--password", "-p"), "Password or NT hash of --username.", metavar="SECRET"),
        PassthroughArg(("--json",), "Print only the result document, as JSON, on stdout."),
    ),
    examples=(
        "adscan recheck -w Corp-Assessment",
        "adscan recheck -w Corp-Assessment -u retest.user -p '<password>'",
        "adscan recheck -w Corp-Assessment --finding kerberoast --json",
        "adscan recheck -w Corp-Assessment --finding kerberoast",
        "adscan recheck -w Corp-Assessment --step 3f9a1c2b7d4e --depth exercise",
        "adscan recheck -w Corp-Assessment --path 8c41d0e95a7b --walk",
    ),
)


CONTAINER_PASSTHROUGH_SPECS: dict[str, PassthroughCommand] = {
    CI_PASSTHROUGH.name: CI_PASSTHROUGH,
    EXECUTE_PASSTHROUGH.name: EXECUTE_PASSTHROUGH,
    DOCTOR_PASSTHROUGH.name: DOCTOR_PASSTHROUGH,
    POLICY_PASSTHROUGH.name: POLICY_PASSTHROUGH,
    PACE_PASSTHROUGH.name: PACE_PASSTHROUGH,
    RUN_PASSTHROUGH.name: RUN_PASSTHROUGH,
    ENGAGEMENT_PASSTHROUGH.name: ENGAGEMENT_PASSTHROUGH,
    RECHECK_PASSTHROUGH.name: RECHECK_PASSTHROUGH,
}


def render_required_usage_hint(spec: PassthroughCommand) -> str:
    """Render a one-line "here is the shape the run needs" usage hint.

    Sourced from the same spec the launcher ``--help`` epilog renders, so the
    hint a user sees when they omit a required argument cannot drift from the
    documented surface. The mode positional and every required option are shown
    as literal tokens; the mode-specific optional pair (``--domain``/``--dc-ip``)
    is bracketed as the usual next thing to supply.

    Args:
        spec: The command specification (``CI_PASSTHROUGH``).

    Returns:
        A single ``adscan <cmd> <shape>`` line, no trailing newline.
    """
    tokens = [f"adscan {spec.name}"]
    for arg in spec.positional_args():
        tokens.append(arg.value_token().replace(",", "|"))
    for arg in spec.required_args():
        tokens.append(f"{arg.primary} {arg.value_token().replace(',', '|')}")
    optional_by_name = {a.primary: a for a in spec.optional_args()}
    trailing = [name for name in ("--domain", "--dc-ip") if name in optional_by_name]
    if trailing:
        bracketed = " ".join(f"{name} {optional_by_name[name].value_token()}" for name in trailing)
        tokens.append(f"[{bracketed}]")
    return " ".join(tokens)


def _render_section(title: str, args: tuple[PassthroughArg, ...], pad: int) -> list[str]:
    if not args:
        return []
    lines = [f"  {title}:"]
    for arg in args:
        token = arg.usage_token()
        lines.append(f"    {token.ljust(pad)}  {arg.help}")
    return lines


def render_passthrough_epilog(spec: PassthroughCommand) -> str:
    """Render a container command's pass-through surface as a --help epilog.

    Meant for an argparse subparser configured with
    ``formatter_class=argparse.RawDescriptionHelpFormatter`` so the layout is
    preserved verbatim. Groups the arguments (positional, required, optional)
    and appends real invocation examples.

    Args:
        spec: The command specification to render.

    Returns:
        A ready-to-use ``epilog`` string.
    """
    positional = spec.positional_args()
    required = spec.required_args()
    optional = spec.optional_args()

    pad = max((len(a.usage_token()) for a in spec.args), default=0)
    pad = min(pad, 34)

    lines: list[str] = [spec.summary, ""]
    lines += _render_section("positional", positional, pad)
    lines += _render_section("required", required, pad)
    lines += _render_section("optional", optional, pad)

    lines += ["", "examples:"]
    for example in spec.examples:
        lines.append(f"  {example}")

    return "\n".join(lines)
