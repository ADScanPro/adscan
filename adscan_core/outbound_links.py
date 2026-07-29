"""Outbound adscanpro.com links — single source of truth for CLI attribution.

Every link to the public site that ADscan renders (host launcher **and**
container runtime) is composed here from a *placement* identifier rather than
written as a URL literal at the call site. A call site asks for "the PRO link
from the post-scan report panel"; it cannot forget the tracking parameters,
cannot spell the host two different ways, and cannot glue a sentence period
onto the end of a URL.

Why it lives in ``adscan_core``: the same links are emitted from
``adscan_launcher`` (host), ``adscan_internal`` (container) and ``adscan.py``,
and ``adscan_core`` is the one package all three may import.

The scheme
----------

``https://adscanpro.com/<path>?utm_source=cli&utm_medium=<placement>``

* Host is always the apex ``adscanpro.com``. ``www.adscanpro.com`` answers with
  a 308 to the apex, so a ``www`` link would only split the same click across
  two hostnames in analytics.
* ``utm_source`` is always ``cli``.
* ``utm_medium`` **is** the placement name, so the tracking value is readable
  in a report without a lookup table and cannot drift from the call site.

Placement names are part of a live analytics series. Renaming one starts a new
series and orphans its history, so treat every name in :data:`_PLACEMENTS` as
immutable once shipped. Add new ones freely; the set is small and descriptive
by design.

Rendering
---------

Terminal output shows a clean URL and carries the tracking parameters in the
hyperlink target, so the operator never reads a query string:

* Rich markup: :func:`cta_markup` -> ``[link=<attributed>]adscanpro.com/pro[/link]``
* Rich ``Text``: :func:`cta_link_style` -> ``"bold cyan link <attributed>"``
* Plain text (argparse help, and anywhere no hyperlink can survive):
  :func:`cta_url`, which is the attributed URL itself.

Never place a bare URL inside square brackets in a Rich-rendered string: Rich
reads ``[/opt/...]`` as a closing tag and raises ``MarkupError``. The helpers
here only ever emit ``[link=...]`` (an opening tag) and escape their label.
"""

from __future__ import annotations

from dataclasses import dataclass

from rich.markup import escape

__all__ = [
    "ADSCAN_SITE_HOST",
    "ADSCAN_SITE_URL",
    "UTM_SOURCE",
    "cta_display",
    "cta_display_url",
    "cta_link_style",
    "cta_markup",
    "cta_url",
    "known_placements",
]

#: Canonical public host. ``www.adscanpro.com`` 308-redirects here, so this is
#: the only spelling that should ever reach a user or an analytics report.
ADSCAN_SITE_HOST = "adscanpro.com"

#: Canonical public origin.
ADSCAN_SITE_URL = f"https://{ADSCAN_SITE_HOST}"

#: ``utm_source`` for every link the command line emits.
UTM_SOURCE = "cli"


@dataclass(frozen=True, slots=True)
class _Placement:
    """One outbound destination, addressed by a placement name.

    Attributes:
        path: Site path, leading slash included (e.g. ``"/pro"``).
        fragment: Optional anchor, no ``#`` (e.g. ``"virtualenv-setup"``).
            Kept separate because the query string must precede the fragment.
    """

    path: str
    fragment: str = ""


# Placement -> destination. The key doubles as the ``utm_medium`` value.
#
# The five names carried over from the pre-SSOT links — first_run,
# help_command, check_failed, help_not_found, victory_domain_compromised —
# plus victory_da_compromise, install_error and the three *_preflight_failed
# values already have months of history behind them. Do not rename them.
_PLACEMENTS: dict[str, _Placement] = {
    # ── Commercial call to action (/pro) ────────────────────────────────────
    # The upsell panel shown when a LITE user reaches for a PRO deliverable.
    "pro_upsell_panel": _Placement("/pro"),
    # "Exposure report ready" panel at the end of a scan, and the upgrade
    # links inside the LITE HTML/PDF report it announces.
    "report_ready_panel": _Placement("/pro"),
    "lite_report": _Placement("/pro"),
    # Post-scan hint when attack paths were proven end to end.
    "scan_complete_paths": _Placement("/pro"),
    # Session summary on exit, after a session that produced findings.
    "session_summary": _Placement("/pro"),
    # Domain Admin proven — the promotion panel at peak goodwill.
    "victory_da_compromise": _Placement("/pro"),
    # `adscan demo` closing panels.
    "demo_closing": _Placement("/pro"),
    # The two "Get beta access" lines shown when a PRO-only import is absent.
    "beta_access_graph_validation": _Placement("/pro"),
    "beta_access_report_init": _Placement("/pro"),
    # ── Share (/share) ──────────────────────────────────────────────────────
    "victory_domain_compromised": _Placement("/share"),
    # ── Documentation (/docs) ───────────────────────────────────────────────
    # Shell intro banner.
    "intro_banner": _Placement("/docs"),
    # Getting-started panel in a workspace that has not scanned yet.
    "first_run": _Placement("/docs"),
    # `help` with no argument.
    "help_command": _Placement("/docs"),
    # Unrecognised input at the shell prompt.
    "unknown_command_hint": _Placement("/docs"),
    # `help <unknown>` — the command reference.
    "help_not_found": _Placement("/docs/commands"),
    # `adscan demo` next-steps panel.
    "demo_next_steps": _Placement("/docs"),
    # Telemetry disclosure row in the install summary.
    "telemetry_notice": _Placement("/docs/telemetry"),
    # `adscan ci --help`: where to report a wrong autonomous decision.
    "ci_help_debug": _Placement("/docs"),
    # Image pull failed after retries.
    "image_pull_failed": _Placement("/docs"),
    # ── Troubleshooting (/docs/guides/troubleshooting) ──────────────────────
    "check_failed": _Placement("/docs/guides/troubleshooting"),
    "start_preflight_failed": _Placement("/docs/guides/troubleshooting"),
    "ci_preflight_failed": _Placement("/docs/guides/troubleshooting"),
    "execute_preflight_failed": _Placement("/docs/guides/troubleshooting"),
    "install_error": _Placement("/docs/guides/troubleshooting", "virtualenv-setup"),
    "host_helper_failed": _Placement(
        "/docs/guides/troubleshooting", "host-helper-docker-mode"
    ),
    # ── Install / platform support ──────────────────────────────────────────
    "docker_missing": _Placement("/docs/getting-started/installation"),
    "unsupported_os": _Placement("/docs/getting-started/system-requirements"),
    "unsupported_platform": _Placement("/docs/getting-started/system-requirements"),
    "unsupported_wsl": _Placement("/docs/getting-started/system-requirements"),
    "unsupported_arch": _Placement("/docs/getting-started/system-requirements"),
}


def _resolve(placement: str) -> _Placement:
    """Return the destination for ``placement``.

    Args:
        placement: A key of :data:`_PLACEMENTS`.

    Returns:
        The matching :class:`_Placement`.

    Raises:
        KeyError: When the placement is not registered. Placements are static
            literals, and ``tests/unit/core/test_outbound_links_ssot.py``
            checks every one used in the trees, so this cannot reach a user.
    """
    try:
        return _PLACEMENTS[placement]
    except KeyError:
        raise KeyError(
            f"Unknown outbound link placement {placement!r}. "
            f"Register it in adscan_core/outbound_links.py."
        ) from None


def cta_url(placement: str) -> str:
    """Return the attributed URL for ``placement``.

    This is what a hyperlink should point at, and what plain-text contexts
    (argparse help) print verbatim.

    Args:
        placement: A registered placement name.

    Returns:
        e.g. ``https://adscanpro.com/pro?utm_source=cli&utm_medium=demo_closing``
    """
    target = _resolve(placement)
    url = f"{ADSCAN_SITE_URL}{target.path}?utm_source={UTM_SOURCE}&utm_medium={placement}"
    if target.fragment:
        url = f"{url}#{target.fragment}"
    return url


def cta_display(placement: str) -> str:
    """Return the short, human-readable form: ``adscanpro.com/pro``.

    Args:
        placement: A registered placement name.

    Returns:
        Host and path, with no scheme and no tracking parameters.
    """
    return f"{ADSCAN_SITE_HOST}{_resolve(placement).path}"


def cta_display_url(placement: str) -> str:
    """Return the clean absolute URL: ``https://adscanpro.com/pro``.

    For copy that already shows the scheme. Pair it with
    :func:`cta_link_style` so the visible text stays clean while the hyperlink
    carries the attribution.

    Args:
        placement: A registered placement name.

    Returns:
        Scheme, host and path, with no tracking parameters.
    """
    return f"{ADSCAN_SITE_URL}{_resolve(placement).path}"


def cta_markup(placement: str, label: str | None = None) -> str:
    """Return Rich markup for a hyperlink to ``placement``.

    Args:
        placement: A registered placement name.
        label: Visible text. Defaults to :func:`cta_display`. It is escaped, so
            a path-shaped label cannot raise ``MarkupError``.

    Returns:
        e.g. ``[link=https://adscanpro.com/docs?...]adscanpro.com/docs[/link]``
    """
    text = cta_display(placement) if label is None else label
    return f"[link={cta_url(placement)}]{escape(text)}[/link]"


def cta_link_style(placement: str, base_style: str = "") -> str:
    """Return a Rich style string that hyperlinks a ``Text`` span.

    Args:
        placement: A registered placement name.
        base_style: Optional style prefix, e.g. ``"bold bright_cyan"``.

    Returns:
        e.g. ``"bold bright_cyan link https://adscanpro.com/pro?..."``
    """
    link = f"link {cta_url(placement)}"
    return f"{base_style} {link}".strip() if base_style else link


def known_placements() -> frozenset[str]:
    """Return every registered placement name."""
    return frozenset(_PLACEMENTS)
