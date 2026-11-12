"""Single source of truth for the options that describe a deliverable.

One scan should produce the branded deliverable in one command, so the options
that describe a deliverable (which documents, which compliance frameworks, the
theme, the branding posture, the client identity, the composition seams, the
output formats) are declared ONCE here and registered on every surface that
renders one:

* the container ``ci`` subparser (``adscan.py`` ``add_ci_subparser``), whose
  ``--generate-report`` renders through the kit pipeline of ``deliver``;
* the container ``deliver`` subparser (``adscan_internal/cli/deliver.py``),
  which the REPL ``deliver`` command reuses verbatim;
* the host launcher's ``deliver`` parser (``adscan_launcher/cli.py``), which
  declares them under ``ws_*`` dests and forwards them with
  :func:`forward_report_options`;
* the launcher ``ci --help`` epilog, through
  ``adscan_core.cli_passthrough_spec`` (``ci`` forwards through REMAINDER).

Before this module each surface declared its own copy, and they had drifted:
the launcher rejected ``--theme editorial`` while the container advertised it,
``ci`` had no ``--branding`` at all, and the launcher refused four ``deliver``
flags the platform worker sends. The option set is now one tuple, and
``tests/unit/core/test_report_options_contract.py`` fails when any surface
stops declaring it.

The module lives in ``adscan_core`` because the host launcher and the LITE
container must import it (the PRO-only ``deliver`` module is stripped from the
LITE image). It imports only the standard library and the framework registry
(``adscan_core.compliance_frameworks``). The value vocabularies it
carries (deliverable slugs, branding postures, ``--emit`` values) are the
CLI-facing mirror of the engine SSOTs, and the contract test binds each one to
its engine definition. The framework keys are not mirrored: they are the
registry's own.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from adscan_core.compliance_frameworks import FRAMEWORK_KEYS

# ---------------------------------------------------------------------------
# Value vocabularies (bound to the engine SSOTs by the contract test)
# ---------------------------------------------------------------------------

#: Internal kit slugs, in canonical kit order. Mirrors
#: ``adscan_internal.cli.deliver.DELIVERABLE_SLUGS``.
REPORT_DELIVERABLE_SLUGS: tuple[str, ...] = (
    "executive",
    "playbook",
    "coverage-matrix",
    "password-hygiene",
)

#: Public ``--only`` names that resolve to an internal slug. ``report`` is the
#: name users are told to type. ``deliver.py`` imports this mapping.
REPORT_ONLY_ALIASES: Mapping[str, str] = {"report": "executive"}

#: Retired ``--only`` names and what they render as now. The standalone MITRE
#: Remediation Checklist was retired on 2026-11-11 (it was unreachable from the
#: kit). A pinned ``--only checklist`` still resolves, to the report, with one
#: notice line. It is never offered in help, choices or error text.
RETIRED_REPORT_ONLY: Mapping[str, str] = {"checklist": "executive"}

RETIRED_REPORT_ONLY_NOTICE: str = (
    "The standalone checklist deliverable is retired; --only checklist renders "
    "the Security Assessment Report instead."
)

#: The deliverable names shown in help text (public alias first).
REPORT_PUBLIC_DELIVERABLES: tuple[str, ...] = (
    "report",
    "playbook",
    "coverage-matrix",
    "password-hygiene",
)

#: What ``ci --generate-report`` renders when ``--only`` is omitted: the
#: Security Assessment Report alone. ``deliver`` defaults to the full kit.
CI_DEFAULT_ONLY: str = "report"

#: Compliance framework keys, read from the framework registry
#: (``adscan_core.compliance_frameworks``), the one place they are declared.
REPORT_FRAMEWORK_KEYS: tuple[str, ...] = FRAMEWORK_KEYS

#: Branding postures. Mirrors
#: ``adscan_internal.services.report_branding.VALID_BRANDING_POSTURES``.
BRANDING_POSTURES: tuple[str, ...] = ("adscan", "cobrand", "whitelabel")

#: Security Assessment Report output formats. ``deliver.py`` imports this.
REPORT_EMIT_VALUES: tuple[str, ...] = ("pdf", "html", "data")

#: The themes a deliverable renders in: the single source of truth every surface
#: reads (``deliver``, ``ci``, the REPL, the scan-config descriptor, the web
#: schemas). A ``.css`` path applies a bring-your-own skin, which is why the
#: theme options carry no argparse ``choices`` (:func:`resolve_report_theme`
#: validates them).
REPORT_THEMES: tuple[str, ...] = ("corporate_light", "editorial")

#: Kept as the advertised name; the offered set and the rendered set are one.
REPORT_ADVERTISED_THEMES: tuple[str, ...] = REPORT_THEMES

#: What a deliverable renders in when no theme is chosen.
REPORT_DEFAULT_THEME: str = "corporate_light"

#: Short names an operator may type.
REPORT_THEME_ALIASES: dict[str, str] = {"light": "corporate_light", "warm": "editorial"}

#: Retired themes and what they render as now. The dark theme (``premium_dark``,
#: alias ``dark``) was retired on 2026-11-11: it was unreadable in the report
#: (light text on light panels) and no install was seen choosing it. A script, a
#: stored web scan or an ``ADSCAN_PDF_THEME`` that still names it keeps working
#: and renders the default theme, with one notice line.
RETIRED_REPORT_THEMES: dict[str, str] = {
    "premium_dark": REPORT_DEFAULT_THEME,
    "dark": REPORT_DEFAULT_THEME,
}

RETIRED_REPORT_THEME_NOTICE: str = (
    "The dark report theme is retired; the deliverables render with the "
    "corporate_light theme instead."
)

#: The closed vocabulary a theme choice is reported in (telemetry, logs): one of
#: the rendered themes, ``custom`` for a bring-your-own ``.css`` skin (never its
#: path), or ``default`` when nothing was chosen.
REPORT_THEME_TELEMETRY_VALUES: tuple[str, ...] = (*REPORT_THEMES, "custom", "default")


@dataclass(frozen=True)
class ReportThemeChoice:
    """A theme request resolved to what will render.

    Attributes:
        theme: A name from :data:`REPORT_THEMES`, a ``.css`` path, or ``""``
            when nothing was requested (the caller applies its default).
        notice: The one line to print when a retired theme was requested.
        custom: ``True`` for a bring-your-own ``.css`` skin.
    """

    theme: str
    notice: str | None = None
    custom: bool = False


def resolve_report_theme(raw: str | None) -> ReportThemeChoice:
    """Resolve a requested theme name to the theme that renders.

    Aliases expand, a retired theme maps to its replacement with a notice, a
    ``.css`` path is kept verbatim, and an unknown name falls back to
    :data:`REPORT_DEFAULT_THEME` (the kit must always render).
    """
    token = (raw or "").strip()
    if not token:
        return ReportThemeChoice("")
    if token.lower().endswith(".css"):
        return ReportThemeChoice(token, custom=True)
    key = token.lower()
    if key in RETIRED_REPORT_THEMES:
        return ReportThemeChoice(RETIRED_REPORT_THEMES[key], RETIRED_REPORT_THEME_NOTICE)
    key = REPORT_THEME_ALIASES.get(key, key)
    return ReportThemeChoice(key if key in REPORT_THEMES else REPORT_DEFAULT_THEME)


def report_theme_telemetry_value(theme: str | None) -> str:
    """The theme as one value of :data:`REPORT_THEME_TELEMETRY_VALUES`.

    A custom skin is reported as ``custom``, never by its path.
    """
    choice = resolve_report_theme(theme)
    if choice.custom:
        return "custom"
    return choice.theme or "default"

_THEME_METAVAR = "{" + ",".join(REPORT_ADVERTISED_THEMES) + "}"

#: What ``--emit`` produces when omitted: the PDF and its HTML twin.
REPORT_DEFAULT_EMIT: tuple[str, ...] = ("pdf", "html")


def parse_only_slugs(raw: str | None) -> tuple[str, ...]:
    """Resolve an ``--only`` value to internal kit slugs, in kit order.

    Args:
        raw: The comma-separated value, or ``None``/empty for every deliverable.

    Returns:
        The selected slugs (aliases resolved), in :data:`REPORT_DELIVERABLE_SLUGS`
        order. Empty input selects all of them.

    Raises:
        ValueError: A token is neither a slug nor an alias. The message names
            the bad token and the accepted set.
    """
    if raw is None or not raw.strip():
        return REPORT_DELIVERABLE_SLUGS
    tokens = [tok.strip().lower() for tok in raw.split(",") if tok.strip()]
    if not tokens:
        return REPORT_DELIVERABLE_SLUGS
    normalised = [
        REPORT_ONLY_ALIASES.get(tok, RETIRED_REPORT_ONLY.get(tok, tok)) for tok in tokens
    ]
    invalid = [tok for tok in normalised if tok not in REPORT_DELIVERABLE_SLUGS]
    if invalid:
        allowed = ", ".join(list(REPORT_DELIVERABLE_SLUGS) + list(REPORT_ONLY_ALIASES))
        raise ValueError(
            f"--only: unknown deliverable(s): {', '.join(invalid)}. "
            f"Use one of: {allowed}."
        )
    selected = set(normalised)
    return tuple(slug for slug in REPORT_DELIVERABLE_SLUGS if slug in selected)


def parse_emit_values(raw: str | None) -> tuple[str, ...]:
    """Resolve an ``--emit`` value to output formats, in canonical order.

    Omitting the flag returns :data:`REPORT_DEFAULT_EMIT`.

    Raises:
        ValueError: A token is not one of :data:`REPORT_EMIT_VALUES`.
    """
    if raw is None or not raw.strip():
        return REPORT_DEFAULT_EMIT
    tokens = [tok.strip().lower() for tok in raw.split(",") if tok.strip()]
    if not tokens:
        return REPORT_DEFAULT_EMIT
    invalid = [tok for tok in tokens if tok not in REPORT_EMIT_VALUES]
    if invalid:
        raise ValueError(
            f"--emit: unknown format(s): {', '.join(invalid)}. "
            f"Use a comma-separated list of: {', '.join(REPORT_EMIT_VALUES)}."
        )
    selected = set(tokens)
    return tuple(fmt for fmt in REPORT_EMIT_VALUES if fmt in selected)


# ---------------------------------------------------------------------------
# The option model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReportOption:
    """One option that describes a deliverable.

    Attributes:
        flags: Option strings, canonical long form first.
        dest: The namespace attribute the container parsers store it under.
        help: One-line, user-facing description.
        metavar: Value placeholder for a value-taking option.
        choices: Allowed values, or ``None`` when free-form.
        switch: ``True`` for a boolean flag that takes no value.
    """

    flags: tuple[str, ...]
    dest: str
    help: str
    metavar: str | None = None
    choices: tuple[str, ...] | None = None
    switch: bool = False

    @property
    def primary(self) -> str:
        """The canonical flag (``--only``)."""
        return self.flags[0]


REPORT_OPTIONS: tuple[ReportOption, ...] = (
    ReportOption(
        ("--only",),
        "only",
        "Deliverables to render, comma-separated: "
        f"{', '.join(REPORT_PUBLIC_DELIVERABLES)} (executive is the earlier name of "
        "report). `ci --generate-report` renders the report alone unless you widen "
        "it; `deliver` renders the full kit.",
        metavar="LIST",
    ),
    ReportOption(
        ("--frameworks",),
        "frameworks",
        "Compliance frameworks, comma-separated: "
        f"{', '.join(REPORT_FRAMEWORK_KEYS)}, or none when the organisation "
        "follows none of them (the report then carries no compliance mapping). "
        "No default; a policy for a real environment requires an answer. On `ci` "
        "the scan also maps its findings onto them at scan end, with or without "
        "a report.",
        metavar="LIST",
    ),
    ReportOption(
        ("--theme",),
        "theme",
        "Visual theme for every deliverable: editorial or corporate_light "
        "(default). A path to a .css file applies your own skin.",
        metavar=_THEME_METAVAR,
    ),
    ReportOption(
        ("--report-theme",),
        "report_theme",
        "Earlier name for --theme, still accepted.",
        metavar=_THEME_METAVAR,
    ),
    ReportOption(
        ("--branding",),
        "branding",
        "Branding posture: adscan, cobrand (default) or whitelabel. whitelabel "
        "needs the white-label entitlement; without it the deliverable is cobranded.",
        choices=BRANDING_POSTURES,
    ),
    ReportOption(
        ("--client",),
        "client",
        "Client name on the cover and in the kit metadata (default: the "
        "workspace name).",
        metavar="NAME",
    ),
    ReportOption(
        ("--engagement",),
        "engagement",
        "Engagement code embedded in the kit metadata.",
        metavar="CODE",
    ),
    ReportOption(
        ("--client-logo",),
        "client_logo",
        "Client logo (PNG, SVG or JPG) placed on the cover; kept and reused on "
        "later runs.",
        metavar="PATH",
    ),
    ReportOption(
        ("--client-cover",),
        "client_cover",
        "HTML fragment, or a directory of per-deliverable fragments, that "
        "replaces the cover page. Needs the composition_seams entitlement.",
        metavar="PATH",
    ),
    ReportOption(
        ("--client-back",),
        "client_back",
        "HTML fragment, or a directory of per-deliverable fragments, rendered as "
        "a closing back page. Needs the composition_seams entitlement.",
        metavar="PATH",
    ),
    ReportOption(
        ("--emit",),
        "emit",
        "Security Assessment Report outputs, comma-separated: "
        f"{', '.join(REPORT_EMIT_VALUES)}. The PDF and HTML are always produced; "
        "data adds report_model.json and needs the data_export entitlement.",
        metavar="LIST",
    ),
    ReportOption(
        ("--no-navigator",),
        "no_navigator",
        "Leave the MITRE ATT&CK Navigator extras out of the kit ZIP.",
        switch=True,
    ),
)

#: Every flag string the model declares.
REPORT_OPTION_FLAGS: frozenset[str] = frozenset(
    flag for option in REPORT_OPTIONS for flag in option.flags
)

#: Every dest the model declares.
REPORT_OPTION_DESTS: tuple[str, ...] = tuple(option.dest for option in REPORT_OPTIONS)


def add_report_arguments(parser: argparse.ArgumentParser, *, dest_prefix: str = "") -> None:
    """Register every :data:`REPORT_OPTIONS` entry on ``parser``.

    Args:
        parser: The subparser to extend (``ci``, ``deliver``, launcher ``deliver``).
        dest_prefix: Prefix for the namespace dest. The host launcher passes
            ``"ws_"`` so the forwarded values never collide with its own
            ``--output``/``--theme`` handling; the container parsers pass nothing.
    """
    for option in REPORT_OPTIONS:
        kwargs: dict[str, Any] = {"dest": f"{dest_prefix}{option.dest}", "help": option.help}
        if option.switch:
            kwargs["action"] = "store_true"
        else:
            kwargs["default"] = None
            if option.choices:
                kwargs["choices"] = option.choices
            if option.metavar:
                kwargs["metavar"] = option.metavar
        parser.add_argument(*option.flags, **kwargs)


def report_option_values(ns: argparse.Namespace, *, dest_prefix: str = "") -> dict[str, Any]:
    """Read every model option off ``ns``, keyed by the container dest.

    Missing attributes read as ``None`` (``False`` for a switch), so a namespace
    built by hand (the run-plan entry, a test) needs no knowledge of the model.
    """
    values: dict[str, Any] = {}
    for option in REPORT_OPTIONS:
        raw = getattr(ns, f"{dest_prefix}{option.dest}", None)
        values[option.dest] = bool(raw) if option.switch else raw
    return values


def forward_report_options(
    ns: argparse.Namespace,
    *,
    dest_prefix: str = "",
    exclude: Iterable[str] = (),
) -> list[str]:
    """Turn the model options set on ``ns`` back into argv tokens.

    Used by the host launcher to forward ``deliver`` options into the container,
    and by the legacy host-side ``ci`` docker mode. An option that is unset,
    empty or a ``False`` switch is omitted, so the receiving parser applies its
    own default.

    Args:
        ns: The parsed namespace.
        dest_prefix: The prefix the options were registered with.
        exclude: Dests the caller forwards itself (the launcher stages
            ``client_logo`` into the mounted volume before forwarding it).

    Returns:
        ``["--flag", "value", "--switch", ...]`` in model order.
    """
    skipped = set(exclude)
    argv: list[str] = []
    for option in REPORT_OPTIONS:
        if option.dest in skipped:
            continue
        value = getattr(ns, f"{dest_prefix}{option.dest}", None)
        if option.switch:
            if value:
                argv.append(option.primary)
            continue
        if value is None or str(value).strip() == "":
            continue
        argv.extend([option.primary, str(value)])
    return argv


# ---------------------------------------------------------------------------
# Retired ``ci`` report flags: still parsed, one warning line each
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RetiredReportFlag:
    """A ``ci`` report flag kept for existing scripts.

    Usage is read off the parsed value (anything other than ``default``), not
    recorded by a custom action, so a namespace rebuilt from a run plan reports
    the same notices as one parsed from flags.

    Attributes:
        flags: Option strings.
        dest: Namespace dest, unchanged from before so existing readers work.
        notice: The one warning line printed when the flag is used, or ``None``
            when the flag still means exactly what the model does
            (``--report-format pdf``: the report is a PDF).
        choices: The values it used to accept (still enforced).
        metavar: Value placeholder when ``choices`` is ``None``.
        default: The value the parser stored before the model existed.
    """

    flags: tuple[str, ...]
    dest: str
    notice: str | None
    choices: tuple[str, ...] | None = None
    metavar: str | None = None
    default: str | None = None


CI_RETIRED_REPORT_FLAGS: tuple[RetiredReportFlag, ...] = (
    RetiredReportFlag(("--report-format",), "report_format", None, choices=("pdf",), default="pdf"),
    RetiredReportFlag(
        ("--report-engine",),
        "report_engine",
        "--report-engine is deprecated and has no effect: reports always render "
        "with Chromium.",
        choices=("chromium",),
    ),
    RetiredReportFlag(
        ("--report-renderer",),
        "report_renderer",
        "--report-renderer is deprecated and has no effect: attack paths always "
        "render with the built-in renderer.",
        choices=("cytoscape",),
    ),
    RetiredReportFlag(
        ("--report-template",),
        "report_template",
        "--report-template is deprecated and has no effect: the report always "
        "uses the premium template.",
        choices=("premium",),
    ),
    RetiredReportFlag(
        ("--display-name",),
        "display_name",
        "--display-name is deprecated: use --client, which names the client on "
        "every deliverable.",
        metavar="NAME",
    ),
)


def add_ci_report_arguments(parser: argparse.ArgumentParser) -> None:
    """Register the deliverable options on the container ``ci`` subparser.

    The shared model, plus two ``ci`` rules: ``--only`` defaults to the report
    alone (:data:`CI_DEFAULT_ONLY`, where ``deliver`` defaults to the full kit),
    and the retired report flags stay parsed, hidden from ``--help``, so
    existing scripts keep working and get one warning line instead.
    """
    add_report_arguments(parser)
    parser.set_defaults(only=CI_DEFAULT_ONLY)
    for flag in CI_RETIRED_REPORT_FLAGS:
        kwargs: dict[str, Any] = {
            "dest": flag.dest,
            "default": flag.default,
            "help": argparse.SUPPRESS,
        }
        if flag.choices:
            kwargs["choices"] = flag.choices
        if flag.metavar:
            kwargs["metavar"] = flag.metavar
        parser.add_argument(*flag.flags, **kwargs)


def report_deprecation_notices(ns: argparse.Namespace) -> list[str]:
    """The warning lines for the retired report flags and theme set on ``ns``."""
    notices: list[str] = []
    for flag in CI_RETIRED_REPORT_FLAGS:
        if flag.notice is None:
            continue
        value = getattr(ns, flag.dest, flag.default)
        if value is not None and value != flag.default and str(value).strip():
            notices.append(flag.notice)
    if retired_theme_requested(ns):
        notices.append(RETIRED_REPORT_THEME_NOTICE)
    if retired_only_requested(getattr(ns, "only", None)):
        notices.append(RETIRED_REPORT_ONLY_NOTICE)
    return notices


def retired_only_requested(raw: str | None) -> bool:
    """Whether an ``--only`` value names a retired deliverable."""
    if not raw:
        return False
    return any(tok.strip().lower() in RETIRED_REPORT_ONLY for tok in raw.split(","))


def retired_theme_requested(ns: argparse.Namespace) -> bool:
    """Whether ``--theme`` or ``--report-theme`` on ``ns`` names a retired theme."""
    return any(
        resolve_report_theme(getattr(ns, dest, None)).notice
        for dest in ("theme", "report_theme")
    )


__all__ = (
    "BRANDING_POSTURES",
    "CI_DEFAULT_ONLY",
    "CI_RETIRED_REPORT_FLAGS",
    "REPORT_ADVERTISED_THEMES",
    "REPORT_DEFAULT_EMIT",
    "REPORT_DEFAULT_THEME",
    "REPORT_THEMES",
    "REPORT_THEME_ALIASES",
    "REPORT_THEME_TELEMETRY_VALUES",
    "RETIRED_REPORT_ONLY",
    "RETIRED_REPORT_ONLY_NOTICE",
    "RETIRED_REPORT_THEMES",
    "RETIRED_REPORT_THEME_NOTICE",
    "ReportThemeChoice",
    "resolve_report_theme",
    "report_theme_telemetry_value",
    "REPORT_DELIVERABLE_SLUGS",
    "REPORT_EMIT_VALUES",
    "REPORT_FRAMEWORK_KEYS",
    "REPORT_ONLY_ALIASES",
    "REPORT_OPTIONS",
    "REPORT_OPTION_DESTS",
    "REPORT_OPTION_FLAGS",
    "REPORT_PUBLIC_DELIVERABLES",
    "ReportOption",
    "RetiredReportFlag",
    "add_ci_report_arguments",
    "add_report_arguments",
    "forward_report_options",
    "parse_emit_values",
    "parse_only_slugs",
    "report_deprecation_notices",
    "report_option_values",
    "retired_only_requested",
    "retired_theme_requested",
)
