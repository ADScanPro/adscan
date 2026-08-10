"""Single source of truth for the container pass-through CLI surface.

The PyPI launcher (``adscan_launcher/``) is the entry point users actually
invoke. For the container-only commands ``ci``, ``execute`` and ``doctor`` the
launcher does not own the flags: it forwards every token verbatim to the
containerized runtime parser (``adscan.py`` and ``adscan_internal/cli/*``),
which is the real flag SSOT. Because the launcher forwards through
``argparse.REMAINDER``, its own ``--help`` cannot see any of those flags, so a
user who runs ``adscan ci --help`` learns nothing about the arguments the run
actually requires (the ``{auth,unauth}`` positional, ``--type``, ``--interface``,
and so on).

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


@dataclass(frozen=True)
class PassthroughArg:
    """One argument of a container pass-through command.

    Attributes:
        names: Option strings (``("--type", "-t")``) or, for a positional, the
            single dest name (``("mode",)``).
        help: One-line, user-facing description.
        required: Whether the runtime parser requires the argument.
        choices: Allowed values, or ``None`` when the argument is free-form.
        metavar: Placeholder shown for a value-taking option (``"CIDR"``). A flag
            with neither ``choices`` nor ``metavar`` is treated as a boolean
            switch that takes no value.
        positional: ``True`` for a positional argument.
    """

    names: tuple[str, ...]
    help: str
    required: bool = False
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
        return tuple(a for a in self.args if a.required and not a.positional)

    def optional_args(self) -> tuple[PassthroughArg, ...]:
        return tuple(a for a in self.args if not a.required and not a.positional)

    def positional_args(self) -> tuple[PassthroughArg, ...]:
        return tuple(a for a in self.args if a.positional)


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
            ("--type", "-t"),
            "Engagement type: a CTF lab or a client audit.",
            required=True,
            choices=("ctf", "audit"),
        ),
        PassthroughArg(
            ("--interface", "-i"),
            "Network interface ADscan scans from (e.g. eth0, tun0).",
            required=True,
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
        PassthroughArg(("--username", "-u"), "Username for auth mode.", metavar="USER"),
        PassthroughArg(("--password", "-p"), "Password or NT hash for auth mode.", metavar="SECRET"),
        PassthroughArg(("--workspace", "-w"), "Workspace name (random if omitted).", metavar="NAME"),
        PassthroughArg(("--keep-workspace",), "Keep the auto-created workspace after the scan."),
        PassthroughArg(("--show-structural",), "Show the structural band in the Tactical Findings panel."),
        PassthroughArg(
            ("--generate-report",),
            "Generate the PDF report after a successful scan (requires a report license).",
        ),
        PassthroughArg(
            ("--only",),
            "Deliverables to render with --generate-report (default: report).",
            metavar="LIST",
        ),
        PassthroughArg(("--report-format",), "Report format.", choices=("pdf",)),
        PassthroughArg(
            ("--frameworks",),
            "Compliance frameworks: ens,nis2,iso27001,dora,pci_dss (default: ens).",
            metavar="LIST",
        ),
        PassthroughArg(("--report-engine",), "PDF engine.", choices=("chromium",)),
        PassthroughArg(("--report-renderer",), "Attack-path renderer.", choices=("cytoscape",)),
        PassthroughArg(("--report-template",), "Report template.", choices=("premium",)),
        PassthroughArg(
            ("--report-theme",),
            "Report theme.",
            choices=("premium_dark", "corporate_light"),
        ),
        PassthroughArg(
            ("--display-name",),
            "Client-facing name shown on the report cover.",
            metavar="NAME",
        ),
        PassthroughArg(
            ("--client-logo",),
            "Client logo (PNG/SVG/JPG) shown beside the ADscan mark on the report cover.",
            metavar="PATH",
        ),
        PassthroughArg(("--verbose", "-v"), "Verbose output."),
        PassthroughArg(("--debug", "-d"), "Debug output."),
    ),
    examples=(
        "adscan ci unauth --type audit --interface eth0 --dc-ip 10.0.0.1",
        "adscan ci auth --type audit --interface eth0 --domain corp.local "
        "--dc-ip 10.0.0.1 -u alice -p 'S3cr3t!'",
    ),
)


# ── execute ─────────────────────────────────────────────────────────────────
# Mirrors adscan_internal/cli/execute.py::add_execute_subparser.
EXECUTE_PASSTHROUGH = PassthroughCommand(
    name="execute",
    summary="Run one REPL verb; arguments forwarded to the ADscan runtime:",
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
        PassthroughArg(("--username", "-u"), "Auth username (for verbs that authenticate).", metavar="USER"),
        PassthroughArg(("--password", "-p"), "Auth password or hash.", metavar="SECRET"),
        PassthroughArg(("--workspace", "-w"), "Named workspace to persist into (default: ephemeral).", metavar="NAME"),
        PassthroughArg(("--interface", "-i"), "Network interface (myip auto-config).", metavar="IFACE"),
        PassthroughArg(("--keep-workspace",), "Keep an auto-created ephemeral workspace on exit."),
        PassthroughArg(("--verbose", "-v"), "Verbose output."),
    ),
    examples=(
        "adscan execute --list",
        "adscan execute kerberoast -d corp.local --dc-ip 10.0.0.1 -u alice -p 'S3cr3t!'",
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
        PassthroughArg(("--username", "-u"), "Auth username (enables the auth check).", metavar="USER"),
        PassthroughArg(("--password", "-p"), "Auth password or hash.", metavar="SECRET"),
        PassthroughArg(("--workspace", "-w"), "Named workspace to use (default: ephemeral).", metavar="NAME"),
        PassthroughArg(("--interface", "-i"), "Network interface (myip auto-config).", metavar="IFACE"),
        PassthroughArg(("--keep-workspace",), "Keep an auto-created ephemeral workspace on exit."),
        PassthroughArg(("--json",), "Emit one structured JSON object instead of the human matrix."),
        PassthroughArg(("--verbose", "-v"), "Verbose output."),
    ),
    examples=(
        "adscan doctor -d corp.local --dc-ip 10.0.0.1",
        "adscan doctor -d corp.local --dc-ip 10.0.0.1 -u alice -p 'S3cr3t!'",
    ),
)


CONTAINER_PASSTHROUGH_SPECS: dict[str, PassthroughCommand] = {
    CI_PASSTHROUGH.name: CI_PASSTHROUGH,
    EXECUTE_PASSTHROUGH.name: EXECUTE_PASSTHROUGH,
    DOCTOR_PASSTHROUGH.name: DOCTOR_PASSTHROUGH,
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
