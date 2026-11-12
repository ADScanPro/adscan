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

The scheme: a clean ``/go/<slug>`` link, redirected by the site
---------------------------------------------------------------

What the CLI prints, and what every hyperlink points at, is a short clean URL::

    https://adscanpro.com/go/<slug>

The public site answers it with a temporary (307) redirect to the real page,
WITH the tracking parameters::

    https://adscanpro.com/<path>?utm_source=<source>&utm_medium=<placement>
        &utm_campaign=<door>#<fragment>

Temporary on purpose (decided 2026-11-12): a browser caches a permanent
redirect for good, so retargeting a slug would never reach anyone who already
clicked it. A 307 is re-asked on every click and the destination stays data.

A few placements land OUTSIDE the site, on an allow-listed external page such
as the GitHub releases page (:data:`_EXTERNAL_PREFIXES`). Those redirect to the
exact URL with no UTM parameters: they would mean nothing to a third party's
analytics and only make the URL longer. The ``/go`` hop still keeps the link
the CLI printed retargetable.

Why a redirect instead of printing the attributed URL directly: a terminal
shows a query string as noise, a plain-text context (argparse help, a terminal
without OSC 8 hyperlinks, a pasted log) used to show the bare path and lose the
attribution, and a link already printed by a shipped CLI could never be
retargeted. A ``/go`` slug fixes all three: the text is short, a copied or
typed URL still attributes, and the destination lives in data the site owns.

The two sides never drift because they read ONE table: :func:`export_go_links`
emits every slug with its destination, ``scripts/export_go_links.py`` writes it
to ``adscan-site/data/go_links.json``, and the site generates its redirects from
that file (guarded by its ``check-generated-data.mjs`` registry and its own
test). ``tests/unit/core/test_outbound_links_ssot.py`` checks the CLI side.

* Host is always the apex ``adscanpro.com``. ``www.adscanpro.com`` answers with
  a 308 to the apex, so a ``www`` link would only split the same click across
  two hostnames in analytics.
* ``utm_source`` is ``cli`` for the terminal, and ``report`` for a link that
  lives inside a generated document. That distinction is the whole point of
  the field here: the exposure report is routinely forwarded, so a click on
  its PRO link usually comes from a *reader* who never ran ADscan — a
  different person, on a different day, from the operator at the prompt.
  Attributing both to ``cli`` collapses those two into one number and makes it
  impossible to tell whether the free report converts on its own.
* ``utm_medium`` **is** the placement name, so the tracking value is readable
  in a report without a lookup table and cannot drift from the call site.
* ``utm_campaign`` is the commercial *door* the link opens (``pro``,
  ``enterprise``, ``partner``, ``learn``, ``docs``…), so a report can group
  every placement by where the operator was sent.
* A surface with many placements of its own declares a shared ``medium``
  (the GitHub README: ``utm_source=github&utm_medium=readme``, the series the
  README has carried since before this table). The placement name then rides
  in ``utm_content`` instead, so it is still in every URL and still readable
  without a lookup table, and one PostHog filter on the medium still groups
  the whole surface.

The README links live here too
------------------------------

The public README (also the PyPI project page) links to the site from about a
dozen places, and it is the biggest source of PRO leads. Its links are
``/go/<slug>`` like the CLI's, for the same three reasons: an older copy of the
README (a PyPI release page, a fork, a cached mirror) can never be edited, so
only a redirect keeps its links alive when a page moves; the site's build
guard checks every destination against the pages it actually built; and each
placement gets its own attribution. ``tests/unit/test_readme_outbound_links.py``
fails CI on an adscanpro.com link in ``README.md`` that is not a registered
README slug, and on a README placement the README no longer uses.

Placement names AND slugs are part of a live analytics series and of URLs
already printed by shipped builds. Renaming a placement starts a new series and
orphans its history; renaming or deleting a slug breaks every link an older
CLI already printed. Treat both as immutable once shipped. Add new ones freely.

Rendering
---------

* Rich markup: :func:`cta_markup` -> ``[link=https://adscanpro.com/go/x]adscanpro.com/go/x[/link]``
* Rich ``Text``: :func:`cta_link_style` -> ``"bold cyan link https://adscanpro.com/go/x"``
* Plain text: :func:`cta_display` (``adscanpro.com/go/x``) or
  :func:`cta_display_url` / :func:`cta_url` (``https://adscanpro.com/go/x``).
  All of them attribute, because the attribution lives in the redirect.

Never place a bare URL inside square brackets in a Rich-rendered string: Rich
reads ``[/opt/...]`` as a closing tag and raises ``MarkupError``. The helpers
here only ever emit ``[link=...]`` (an opening tag) and escape their label.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from rich.markup import escape

if TYPE_CHECKING:
    # Type-only import so the ``"CtaLane"`` forward-ref annotation resolves for
    # linters/checkers without a runtime import cycle (the enum is imported
    # lazily inside ``cta_placement_for_lane`` at call time).
    from adscan_core.operator_role import CtaLane

__all__ = [
    "ADSCAN_SITE_HOST",
    "ADSCAN_SITE_URL",
    "GO_LINKS_SCHEMA_VERSION",
    "GO_PATH_PREFIX",
    "UTM_MEDIUM_README",
    "UTM_SOURCE",
    "UTM_SOURCE_GITHUB",
    "UTM_SOURCE_REPORT",
    "cta_destination_path",
    "cta_destination_url",
    "cta_display",
    "cta_display_url",
    "cta_link_style",
    "cta_markup",
    "cta_placement_for_lane",
    "cta_url",
    "export_go_links",
    "is_external",
    "known_placements",
    "lane_placements",
    "readme_placements",
]

#: Canonical public host. ``www.adscanpro.com`` 308-redirects here, so this is
#: the only spelling that should ever reach a user or an analytics report.
ADSCAN_SITE_HOST = "adscanpro.com"

#: Canonical public origin.
ADSCAN_SITE_URL = f"https://{ADSCAN_SITE_HOST}"

#: Site path under which every clean CLI link lives. The site redirects
#: ``/go/<slug>`` to the attributed destination.
GO_PATH_PREFIX = "/go"

#: Version of the exported slug table (``export_go_links``). Bump only on a
#: shape change the site's redirect generator must learn about.
#: 3 (2026-11-12): rows carry ``utm_content``; ``utm_medium`` may be a shared
#: surface medium (``readme``) instead of the placement name.
GO_LINKS_SCHEMA_VERSION = 3

#: ``utm_source`` for a link the command line emits — the operator clicks it
#: from their own terminal, during their own run.
UTM_SOURCE = "cli"

#: ``utm_source`` for a link embedded in a generated document. The reader is
#: often not the operator: the exposure report is built to be forwarded, so
#: this click typically comes from whoever received the PDF.
UTM_SOURCE_REPORT = "report"

#: ``utm_source`` for a link in the public repository's README.
UTM_SOURCE_GITHUB = "github"

#: Shared ``utm_medium`` of every README placement (its placement name goes in
#: ``utm_content``). The README has used this value since before the SSOT.
UTM_MEDIUM_README = "readme"

#: A slug is lowercase kebab-case: short to read in a terminal, safe in a URL,
#: and unambiguous to type.
_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

# ``utm_campaign`` values: the door each link opens.
_PRO = "pro"
_ENTERPRISE = "enterprise"
_PARTNER = "partner"
_LEARN = "learn"
_DOCS = "docs"
_SUPPORT = "support"
_INSTALL = "install"
_SHARE = "share"
_DOWNLOAD = "download"
_BRAND = "brand"

# Destinations shared by several placements.
_PATH_PRO = "/pro"
_PATH_DEMO = "/get-a-demo"
_PATH_PARTNERS = "/partners"
_PARTNERS_APPLY = "apply"
_PATH_PARTNER_GUIDE = "/docs/guides/platform-integration"
_PATH_LABS = "/docs/labs"
_PATH_TROUBLESHOOTING = "/docs/guides/troubleshooting"
_PATH_REQUIREMENTS = "/docs/getting-started/system-requirements"

#: The only external destinations a ``/go`` slug may redirect to. A placement
#: whose path is an absolute URL must start with one of these, so a typo or a
#: copied third-party link can never turn the site into an open redirect.
_EXTERNAL_PREFIXES: tuple[str, ...] = ("https://github.com/ADScanPro/",)

#: Community Windows bundle: the latest GitHub release.
_URL_GITHUB_RELEASES = "https://github.com/ADScanPro/adscan/releases/latest"


@dataclass(frozen=True, slots=True)
class _Placement:
    """One outbound destination, addressed by a placement name.

    Attributes:
        slug: The ``/go/<slug>`` path segment the CLI prints. Unique across the
            registry and immutable once shipped (an older CLI already printed it).
        path: Site path the slug redirects to, leading slash included
            (e.g. ``"/pro"``), or an absolute ``https://`` URL on an
            allow-listed external host (:data:`_EXTERNAL_PREFIXES`), which is
            redirected to verbatim, with no UTM parameters and no fragment.
        campaign: ``utm_campaign`` — the door this link opens.
        fragment: Optional anchor, no ``#`` (e.g. ``"virtualenv-setup"``).
            Kept separate because the query string must precede the fragment.
        source: ``utm_source`` for this placement. Defaults to the terminal;
            set it to :data:`UTM_SOURCE_REPORT` for a link that ships inside a
            document rather than being printed at the prompt.
        medium: Shared ``utm_medium`` of a surface with many placements (the
            README). Empty (the default) means ``utm_medium`` is the placement
            name; when set, the placement name goes in ``utm_content``.
    """

    slug: str
    path: str
    campaign: str
    fragment: str = ""
    source: str = UTM_SOURCE
    medium: str = ""


def _readme(slug: str, path: str, campaign: str) -> _Placement:
    """A README placement: ``utm_source=github&utm_medium=readme``."""
    return _Placement(
        slug, path, campaign, source=UTM_SOURCE_GITHUB, medium=UTM_MEDIUM_README
    )


# Placement -> destination. The key doubles as the ``utm_medium`` value, or as
# ``utm_content`` for a placement that declares a shared ``medium``.
#
# The five names carried over from the pre-SSOT links — first_run,
# help_command, check_failed, help_not_found, victory_domain_compromised —
# plus victory_da_compromise, install_error and the three *_preflight_failed
# values already have months of history behind them. Do not rename them.
_PLACEMENTS: dict[str, _Placement] = {
    # ── PRO door (/pro): a consultancy or MSSP that audits clients' AD ──────
    # The upsell panel shown when a LITE user reaches for a PRO deliverable.
    "pro_upsell_panel": _Placement("pro-gate", _PATH_PRO, _PRO),
    # "Exposure report ready" panel at the end of a scan — printed at the
    # prompt, so the operator is the one who clicks.
    "report_ready_panel": _Placement("pro-report-ready", _PATH_PRO, _PRO),
    # The upgrade links *inside* the generated LITE HTML/PDF report. Separate
    # source: this document gets forwarded, and a click on it is evidence the
    # free report converts a reader who never touched the command line.
    "lite_report": _Placement(
        "pro-report", _PATH_PRO, _PRO, source=UTM_SOURCE_REPORT
    ),
    # Post-scan hint when attack paths were proven end to end.
    "scan_complete_paths": _Placement("pro-paths", _PATH_PRO, _PRO),
    # Session summary on exit, after a session that produced findings.
    "session_summary": _Placement("pro-summary", _PATH_PRO, _PRO),
    # Domain Admin proven — the promotion panel at peak goodwill.
    "victory_da_compromise": _Placement("pro-victory", _PATH_PRO, _PRO),
    # `adscan demo` closing panels.
    "demo_closing": _Placement("pro-demo", _PATH_PRO, _PRO),
    # The "Get beta access" line shown when a PRO-only import is absent.
    # (``beta_access_graph_validation`` was retired when attack-graph finding
    # validation moved into the tier-shared derivation and stopped being a
    # PRO-only capability.)
    "beta_access_report_init": _Placement("pro-access", _PATH_PRO, _PRO),
    # ── Enterprise door (/get-a-demo): security team, sysadmin or CISO of ───
    # the organization that OWNS the directory. The pitch is continuous
    # validation and a board/auditor-ready report, not a CLI to run themselves.
    "pro_gate_enterprise_demo": _Placement("demo-gate", _PATH_DEMO, _ENTERPRISE),
    "report_ready_enterprise_demo": _Placement(
        "demo-report-ready", _PATH_DEMO, _ENTERPRISE
    ),
    # The Enterprise-lane door INSIDE the generated LITE report — the
    # report-sourced sibling of ``lite_report``.
    "lite_report_enterprise_demo": _Placement(
        "demo-report", _PATH_DEMO, _ENTERPRISE, source=UTM_SOURCE_REPORT
    ),
    "scan_complete_enterprise_demo": _Placement(
        "demo-paths", _PATH_DEMO, _ENTERPRISE
    ),
    "session_summary_enterprise_demo": _Placement(
        "demo-summary", _PATH_DEMO, _ENTERPRISE
    ),
    "victory_enterprise_demo": _Placement("demo-victory", _PATH_DEMO, _ENTERPRISE),
    # ── Partner door (/partners): a platform, PTaaS vendor or MSSP that wants ─
    # to embed or resell ADscan in its own service. The terminal surfaces land
    # on the application form; the gate also offers the engineering guide,
    # because the command a platform reaches for first is `adscan ci`.
    "pro_gate_partner": _Placement(
        "partner-gate", _PATH_PARTNERS, _PARTNER, fragment=_PARTNERS_APPLY
    ),
    "pro_gate_partner_guide": _Placement(
        "partner-guide", _PATH_PARTNER_GUIDE, _PARTNER
    ),
    "report_ready_partner": _Placement(
        "partner-report-ready", _PATH_PARTNERS, _PARTNER, fragment=_PARTNERS_APPLY
    ),
    # Inside a forwarded document the reader is not necessarily applying, so
    # this one lands on the top of the partners page.
    "lite_report_partner": _Placement(
        "partner-report", _PATH_PARTNERS, _PARTNER, source=UTM_SOURCE_REPORT
    ),
    "scan_complete_partner": _Placement(
        "partner-paths", _PATH_PARTNERS, _PARTNER, fragment=_PARTNERS_APPLY
    ),
    "session_summary_partner": _Placement(
        "partner-summary", _PATH_PARTNERS, _PARTNER, fragment=_PARTNERS_APPLY
    ),
    "victory_partner": _Placement(
        "partner-victory", _PATH_PARTNERS, _PARTNER, fragment=_PARTNERS_APPLY
    ),
    # ── Learning (docs and labs, no sales door): student, CTF, learning ─────
    "pro_gate_learn": _Placement("learn-gate", _PATH_LABS, _LEARN),
    "report_ready_learn": _Placement("learn-report-ready", _PATH_LABS, _LEARN),
    "lite_report_learn": _Placement(
        "learn-report", _PATH_LABS, _LEARN, source=UTM_SOURCE_REPORT
    ),
    "victory_learn": _Placement("learn-victory", _PATH_LABS, _LEARN),
    # ── Share (/share) ──────────────────────────────────────────────────────
    "victory_domain_compromised": _Placement("share", "/share", _SHARE),
    # ── Documentation (/docs) ───────────────────────────────────────────────
    # Shell intro banner.
    "intro_banner": _Placement("docs", "/docs", _DOCS),
    # Getting-started panel in a workspace that has not scanned yet.
    "first_run": _Placement("docs-start", "/docs", _DOCS),
    # `help` with no argument.
    "help_command": _Placement("docs-help", "/docs", _DOCS),
    # Unrecognised input at the shell prompt.
    "unknown_command_hint": _Placement("docs-unknown", "/docs", _DOCS),
    # `help <unknown>` — the command reference.
    "help_not_found": _Placement("commands", "/docs/commands", _DOCS),
    # `adscan demo` next-steps panel.
    "demo_next_steps": _Placement("docs-demo", "/docs", _DOCS),
    # Telemetry disclosure row in the install summary.
    "telemetry_notice": _Placement("telemetry", "/docs/telemetry", _DOCS),
    # The guidance the retired workspace type (`ci --type`, `set type`) and a
    # `ci` run with no policy print: the scan-policies guide.
    "legacy_type_notice": _Placement(
        "scan-policies", "/docs/guides/scan-policies", _DOCS
    ),
    # `adscan ci --help`: where to report a wrong autonomous decision.
    "ci_help_debug": _Placement("docs-ci", "/docs", _DOCS),
    # Image pull failed after retries.
    "image_pull_failed": _Placement("docs-pull", "/docs", _DOCS),
    # ── Troubleshooting (/docs/guides/troubleshooting) ──────────────────────
    "check_failed": _Placement("fix-check", _PATH_TROUBLESHOOTING, _SUPPORT),
    "start_preflight_failed": _Placement(
        "fix-start", _PATH_TROUBLESHOOTING, _SUPPORT
    ),
    "ci_preflight_failed": _Placement("fix-ci", _PATH_TROUBLESHOOTING, _SUPPORT),
    "execute_preflight_failed": _Placement(
        "fix-execute", _PATH_TROUBLESHOOTING, _SUPPORT
    ),
    # The "virtualenv-setup" anchor it used to carry no longer exists in the
    # guide; "installation-issues" is the section that answers an install error.
    "install_error": _Placement(
        "fix-install", _PATH_TROUBLESHOOTING, _SUPPORT, fragment="installation-issues"
    ),
    "host_helper_failed": _Placement(
        "fix-host-helper",
        _PATH_TROUBLESHOOTING,
        _SUPPORT,
        fragment="host-helper-docker-mode",
    ),
    # ── Download / update ─────────────────────────────────────────────────────
    # Where the self-contained Windows-native bundle is published: the latest
    # GitHub release. Shown when `adscan update`/`upgrade` runs on Windows,
    # which does not self-update. (It pointed at /download until 2026-11-12, a
    # page the site never had.)
    "windows_update_download": _Placement(
        "windows", _URL_GITHUB_RELEASES, _DOWNLOAD
    ),
    # ── Install / platform support ──────────────────────────────────────────
    "docker_missing": _Placement(
        "install-docker", "/docs/getting-started/installation", _INSTALL
    ),
    "unsupported_os": _Placement("requirements-os", _PATH_REQUIREMENTS, _INSTALL),
    "unsupported_platform": _Placement(
        "requirements-platform", _PATH_REQUIREMENTS, _INSTALL
    ),
    "unsupported_wsl": _Placement("requirements-wsl", _PATH_REQUIREMENTS, _INSTALL),
    "unsupported_arch": _Placement(
        "requirements-arch", _PATH_REQUIREMENTS, _INSTALL
    ),
    # ── Brand credit ────────────────────────────────────────────────────────
    # Brand attribution in the footer of a generated deliverable (the MITRE
    # Navigator bundle) — a "Generated by ADscan" credit, not an upsell, so it
    # points at the site root. Attributed like every other outbound link so a
    # click from a forwarded deliverable is not lost to the unattributed bucket.
    "report_footer": _Placement(
        "credit", "/", _BRAND, source=UTM_SOURCE_REPORT
    ),
    # ── GitHub README (also the PyPI project page) ──────────────────────────
    # Not printed by the CLI: README.md links to these, and
    # tests/unit/test_readme_outbound_links.py keeps the two in step. The
    # campaign values are the ones the README already used before /go
    # (docs_cta, install_cta, pro_cta, report_hero, ctf_<box>), so their
    # series continue; the placement name in utm_content tells apart two links
    # that open the same door from different spots.
    "readme_hero_docs": _readme("gh-docs", "/docs", "docs_cta"),
    "readme_hero_forest": _readme(
        "gh-forest", "/docs/labs/htb/forest", "ctf_forest"
    ),
    "readme_hero_sample": _readme("gh-sample", "/samples", "sample_cta"),
    "readme_hero_pro": _readme("gh-pro", _PATH_PRO, "pro_cta"),
    "readme_install_docs": _readme(
        "gh-install", "/docs/getting-started/installation", "install_cta"
    ),
    "readme_compare": _readme("gh-compare", "/docs/lite-vs-pro", "compare_cta"),
    "readme_table_pro": _readme("gh-pro-table", _PATH_PRO, "pro_cta"),
    "readme_usage_forest": _readme(
        "gh-lab-forest", "/docs/labs/htb/forest", "ctf_forest"
    ),
    "readme_usage_active": _readme(
        "gh-lab-active", "/docs/labs/htb/active", "ctf_active"
    ),
    "readme_usage_cicada": _readme(
        "gh-lab-cicada", "/docs/labs/htb/cicada", "ctf_cicada"
    ),
    "readme_report_image": _readme("gh-report", _PATH_PRO, "report_hero"),
    "readme_report_pro": _readme("gh-pro-report", _PATH_PRO, "pro_cta"),
    "readme_footer_site": _readme("gh-site", "/", "site_cta"),
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
    """Return the clean link for ``placement``: ``https://adscanpro.com/go/<slug>``.

    This is what a hyperlink points at and what plain-text contexts (argparse
    help) print verbatim. The attribution rides in the site's redirect, so the
    URL carries no query string and still attributes when copied or typed.

    Args:
        placement: A registered placement name.

    Returns:
        e.g. ``https://adscanpro.com/go/pro-demo``
    """
    return f"{ADSCAN_SITE_URL}{GO_PATH_PREFIX}/{_resolve(placement).slug}"


def is_external(placement: str) -> bool:
    """True when ``placement`` redirects off the site (an allow-listed URL)."""
    return _resolve(placement).path.startswith("https://")


def cta_destination_path(placement: str) -> str:
    """Return where ``/go/<slug>`` redirects.

    For a site page, the attributed site-relative destination: path, then the
    three UTM parameters, then the fragment (the query string must precede the
    fragment, or the browser keeps the parameters inside the anchor and
    analytics never sees them). For an external placement, the absolute URL
    verbatim, with no UTM parameters.

    Args:
        placement: A registered placement name.

    Returns:
        e.g. ``/pro?utm_source=cli&utm_medium=demo_closing&utm_campaign=pro``
        or ``https://github.com/ADScanPro/adscan/releases/latest``.

    Raises:
        ValueError: An external path outside :data:`_EXTERNAL_PREFIXES`.
    """
    target = _resolve(placement)
    if is_external(placement):
        if not target.path.startswith(_EXTERNAL_PREFIXES):
            raise ValueError(
                f"{placement} redirects to {target.path}, which is not an "
                f"allow-listed external destination ({_EXTERNAL_PREFIXES})."
            )
        return target.path
    path = (
        f"{target.path}?utm_source={target.source}"
        f"&utm_medium={_utm_medium(placement)}&utm_campaign={target.campaign}"
    )
    content = _utm_content(placement)
    if content:
        path = f"{path}&utm_content={content}"
    if target.fragment:
        path = f"{path}#{target.fragment}"
    return path


def _utm_medium(placement: str) -> str:
    """``utm_medium``: the surface's shared medium, else the placement name."""
    return _resolve(placement).medium or placement


def _utm_content(placement: str) -> str | None:
    """``utm_content``: the placement name when a shared medium hides it."""
    return placement if _resolve(placement).medium else None


def cta_destination_url(placement: str) -> str:
    """Return the absolute URL ``/go/<slug>`` redirects to."""
    destination = cta_destination_path(placement)
    if is_external(placement):
        return destination
    return f"{ADSCAN_SITE_URL}{destination}"


def cta_display(placement: str) -> str:
    """Return the short, human-readable form: ``adscanpro.com/go/<slug>``.

    Args:
        placement: A registered placement name.

    Returns:
        Host and ``/go`` path, with no scheme and no tracking parameters.
    """
    return f"{ADSCAN_SITE_HOST}{GO_PATH_PREFIX}/{_resolve(placement).slug}"


def cta_display_url(placement: str) -> str:
    """Return the clean absolute URL: ``https://adscanpro.com/go/<slug>``.

    For copy that already shows the scheme. Identical to :func:`cta_url` now
    that the attribution lives in the redirect; kept as its own name because
    call sites read it as "the visible form".

    Args:
        placement: A registered placement name.

    Returns:
        Scheme, host and ``/go`` path.
    """
    return cta_url(placement)


def cta_markup(placement: str, label: str | None = None) -> str:
    """Return Rich markup for a hyperlink to ``placement``.

    Args:
        placement: A registered placement name.
        label: Visible text. Defaults to :func:`cta_display`. It is escaped, so
            a path-shaped label cannot raise ``MarkupError``.

    Returns:
        e.g. ``[link=https://adscanpro.com/go/docs]adscanpro.com/go/docs[/link]``
    """
    text = cta_display(placement) if label is None else label
    return f"[link={cta_url(placement)}]{escape(text)}[/link]"


def cta_link_style(placement: str, base_style: str = "") -> str:
    """Return a Rich style string that hyperlinks a ``Text`` span.

    Args:
        placement: A registered placement name.
        base_style: Optional style prefix, e.g. ``"bold bright_cyan"``.

    Returns:
        e.g. ``"bold bright_cyan link https://adscanpro.com/go/pro-gate"``
    """
    link = f"link {cta_url(placement)}"
    return f"{base_style} {link}".strip() if base_style else link


def known_placements() -> frozenset[str]:
    """Return every registered placement name."""
    return frozenset(_PLACEMENTS)


def readme_placements() -> frozenset[str]:
    """Return the placements ``README.md`` links to (``utm_source=github``)."""
    return frozenset(
        name
        for name, target in _PLACEMENTS.items()
        if target.source == UTM_SOURCE_GITHUB
    )


def export_go_links() -> list[dict[str, Any]]:
    """Return the ``/go`` slug table the public site builds its redirects from.

    One row per placement, ordered by slug so the exported file diffs cleanly.
    ``destination`` is site-relative (path, UTM query, fragment) so the site
    redirects on its own host, or, when ``external`` is true, the absolute
    allow-listed URL with the ``utm_*`` fields set to ``None`` (nothing is
    appended to a third party's URL). ``utm_content`` is ``None`` too for a
    placement whose name is already its ``utm_medium``.

    Returns:
        A list of plain dicts, JSON-serialisable.
    """
    rows = []
    for placement, target in _PLACEMENTS.items():
        external = is_external(placement)
        rows.append(
            {
                "slug": target.slug,
                "placement": placement,
                "destination": cta_destination_path(placement),
                "external": external,
                "path": target.path,
                "fragment": target.fragment,
                "utm_source": None if external else target.source,
                "utm_medium": None if external else _utm_medium(placement),
                "utm_campaign": None if external else target.campaign,
                "utm_content": None if external else _utm_content(placement),
            }
        )
    return sorted(rows, key=lambda row: row["slug"])


# ── Role-aware commercial CTA: lane x surface -> placement ──────────────────
#
# A peak-value surface (the PRO gate, the report-ready panel, the in-report
# close, the Domain Admin victory panel, the session summary, the scan-complete
# hint) shows ONE commercial next step, and which one depends on who is at the
# prompt (``adscan_core.operator_role.resolve_cta_lane``). The surface is named
# by its PRO-lane placement; each lane maps it to its own placement so a click
# is attributed to the surface it came from. ``None`` means "this lane gets no
# commercial line on this surface" (the learning lane on the two hints that
# only ever carry a sales ask).
_LANE_SURFACES: dict[str, dict[str, str | None]] = {
    "pro_upsell_panel": {
        "pro": "pro_upsell_panel",
        "enterprise": "pro_gate_enterprise_demo",
        "partner": "pro_gate_partner",
        "learn": "pro_gate_learn",
    },
    "report_ready_panel": {
        "pro": "report_ready_panel",
        "enterprise": "report_ready_enterprise_demo",
        "partner": "report_ready_partner",
        "learn": "report_ready_learn",
    },
    "lite_report": {
        "pro": "lite_report",
        "enterprise": "lite_report_enterprise_demo",
        "partner": "lite_report_partner",
        "learn": "lite_report_learn",
    },
    "victory_da_compromise": {
        "pro": "victory_da_compromise",
        "enterprise": "victory_enterprise_demo",
        "partner": "victory_partner",
        "learn": "victory_learn",
    },
    "session_summary": {
        "pro": "session_summary",
        "enterprise": "session_summary_enterprise_demo",
        "partner": "session_summary_partner",
        "learn": None,
    },
    "scan_complete_paths": {
        "pro": "scan_complete_paths",
        "enterprise": "scan_complete_enterprise_demo",
        "partner": "scan_complete_partner",
        "learn": None,
    },
}


def lane_placements() -> frozenset[str]:
    """Return every placement reachable through :func:`cta_placement_for_lane`."""
    return frozenset(
        placement
        for lanes in _LANE_SURFACES.values()
        for placement in lanes.values()
        if placement is not None
    )


def cta_placement_for_lane(
    lane: "CtaLane", *, surface: str = "pro_upsell_panel"
) -> str | None:
    """Map a commercial CTA lane and a surface to a placement key.

    Args:
        lane: A :class:`~adscan_core.operator_role.CtaLane` value.
        surface: The surface, named by its PRO-lane placement
            (``"pro_upsell_panel"``, ``"report_ready_panel"``,
            ``"lite_report"``, ``"victory_da_compromise"``,
            ``"session_summary"``, ``"scan_complete_paths"``).

    Returns:
        A placement key present in :data:`_PLACEMENTS`, or ``None`` when this
        lane carries no commercial line on this surface.

    Raises:
        KeyError: For a surface not registered in :data:`_LANE_SURFACES`.
            Surfaces are static literals, covered by the unit tests.
    """
    lanes = _LANE_SURFACES[surface]
    value = getattr(lane, "value", lane)
    return lanes.get(str(value), lanes["pro"])
