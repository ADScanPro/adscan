"""``adscan deliver`` — render the full Client Deliverable Kit.

Generates the PRO PDFs in parallel and packages them into a single ZIP under
``<workspace>/deliverables/<stamp>-adscan-kit.zip``, where ``<stamp>`` is the
UTC second the run opened (``2026-10-07T091500Z``). One kit per RUN, not per
day: two delivers in one afternoon leave two complete, independently
deliverable kits rather than the second overwriting the first. Each kit is a
coherent triple sharing that stamp::

    deliverables/staging/run-<stamp>/      the rendered files for that run
    deliverables/<stamp>-adscan-kit.zip    the kit handed to the client
    deliverables/<stamp>-manifest.json     that kit's own index, kept for good
    deliverables/manifest.json             pointer to the LATEST kit

A kit's ZIP is never pruned. The staging directories are (see
``ADSCAN_DELIVER_KEEP_RUNS``) because they are the intermediate.

The PDFs in the ZIP:

* Security Assessment Report     (live engagement assessment)
* AD Hardening Playbook          (bonus, value-stack)
* AD Control Coverage Report     (proof-of-coverage / board-ready control assurance)
* AD Password Hygiene Report     (CONDITIONAL: only when credential recovery ran)

The hygiene report is dropped from the kit rather than shipped empty when no
recovery was attempted, so a kit missing it means that run recovered nothing,
never that the kit is broken. ``_drop_unsupportable_items`` owns that call and
the Security Assessment Report's pointer to it is set from the POST-drop item
list, so the cross-reference can never dangle.

The standalone MITRE Remediation Checklist was retired — its ATT&CK lens
is now folded into the Security Assessment Report. ``--only checklist``
still resolves (aliased to the main report) so pinned customer scripts do
not break.

This command is **PRO only**. In LITE, the canonical PRO upsell panel
is rendered via :func:`adscan_core.pro_upsell.render_pro_upsell_panel`
and the function returns ``2`` (matches argparse "usage error" so the
shell does not treat it as a crash).

The generators run concurrently (``asyncio.gather`` over a thread
pool) — sequential rendering would Time-Delay the operator without any
quality gain.
"""

from __future__ import annotations

from adscan_core.version import get_version

import argparse
import asyncio
import json
import os
import time
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from adscan_core import telemetry, tier
from adscan_core.rich_output import (
    print_error,
    print_info,
    print_info_debug,
    print_panel,
    print_success,
    print_warning,
)
from adscan_core.rich_output import print_exception
from adscan_internal.cli.common import (
    _FRAMEWORK_KEY_MAP,
    _VALID_FRAMEWORK_KEYS,
    _parse_frameworks,
    _resolve_workspace,
)
from adscan_internal.services.compliance_scope import (
    announce_compliance_scope,
    resolve_compliance_scope,
)


class KitArtifactError(RuntimeError):
    """A kit artefact the run was about to ship was not produced by this run.

    Raised instead of silently substituting a file from an earlier run or
    silently omitting a requested deliverable. Both are worse for the client
    than a failed run, because neither is distinguishable from a correct kit:
    the first puts two different scans' figures in one ZIP, the second hands
    over a kit that is quietly missing a document. See § Staging below.
    """


# ---------------------------------------------------------------------------
# Kit definition — single source of truth for what ships in the ZIP.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _KitItem:
    """One artefact in the Client Deliverable Kit.

    Attributes:
        slug: Short selector used by ``--only`` and ``manifest.json``.
        filename: On-disk filename inside the staging dir and ZIP.
        title: Human title (displayed in panels).
        bonus_key: Bonus renderer key, or ``None`` for the executive
            assessment which uses its own generator.
        cover_title: The per-deliverable title the composition seam fills into
            the client cover/back ``{{DOCUMENT_TITLE}}`` token (generic and
            professional, not AD-anchored), so one authored client cover brands
            every kit PDF with that PDF's own name.
        cover_subtitle: The per-deliverable subtitle filling the client
            cover/back ``{{DOCUMENT_SUBTITLE}}`` token.
    """

    slug: str
    filename: str
    title: str
    bonus_key: str | None  # None → executive assessment (separate generator).
    cover_title: str = ""
    cover_subtitle: str = ""


_KIT: tuple[_KitItem, ...] = (
    # Slug stays ``executive`` so existing callers (``--only executive``,
    # the web Celery task's selection dict, every customer-side script)
    # keep working. The artefact itself is now the *full* assessment
    # (executive section + technical section + attack paths) — the
    # ``executive`` profile shipped an attack-path-stripped variant
    # that operators were already supplementing manually with the full
    # ``report.pdf``. See ``_render_assessment_async`` for the bake.
    _KitItem(
        "executive",
        "Security_Assessment_Report.pdf",
        "Security Assessment Report",
        None,
        cover_title="Active Directory Security Assessment",
        cover_subtitle=(
            "End-to-end analysis of the attack paths and privilege escalations "
            "identified across the internal environment, with a prioritised "
            "remediation roadmap."
        ),
    ),
    _KitItem(
        "playbook",
        "AD_Hardening_Playbook.pdf",
        "AD Hardening Playbook",
        "playbook",
        cover_title="AD Hardening Playbook",
        cover_subtitle=(
            "Step-by-step remediation runbooks for the exposures identified "
            "during the assessment, prioritised by impact."
        ),
    ),
    # The standalone MITRE Remediation Checklist (slug ``checklist``) was
    # retired in e6e0355c — its ATT&CK lens is now folded into the main
    # Security Assessment Report, so a separate PDF was redundant. The
    # ``checklist`` slug is kept resolving via ``_ONLY_ALIASES`` (→ the main
    # report) so pinned ``--only checklist`` scripts do not error.
    # Slug stays ``coverage-matrix`` for back-compat (``--only coverage-matrix``,
    # the web Celery task selection, customer scripts); the artefact it renders
    # is the AD Control Coverage Report (sourced from control_evidence).
    _KitItem(
        "coverage-matrix",
        "AD_Control_Coverage_Report.pdf",
        "AD Control Coverage Report",
        "coverage-matrix",
        cover_title="AD Control Coverage Report",
        cover_subtitle=(
            "Control-by-control coverage of the assessment mapped against the "
            "selected compliance frameworks."
        ),
    ),
    # CONDITIONAL kit document. It renders the password-hygiene analysis
    # (recovery rate, per-tier coverage, reuse groups) and so exists ONLY
    # when credential recovery actually ran — ``_drop_unsupportable_items``
    # removes it when the workspace carries no recovery block, exactly as it
    # does the Coverage Report. The entry list therefore VARIES between runs by
    # design: a kit missing this document means "this run recovered nothing",
    # never a broken kit. The SAR cross-references it only when it was produced.
    _KitItem(
        "password-hygiene",
        "AD_Password_Hygiene_Report.pdf",
        "AD Password Hygiene Report",
        "password-hygiene",
        cover_title="AD Password Hygiene Report",
        cover_subtitle=(
            "The strength and reuse of the account passwords recovered during "
            "the assessment, with the remediation to run."
        ),
    ),
)

_VALID_SLUGS: tuple[str, ...] = tuple(item.slug for item in _KIT)

# ---------------------------------------------------------------------------
# Public deliverable SSOT — the single source of truth the rest of the
# product (REPL, CI, and the cross-boundary web contract test) reads instead
# of re-deriving the slug set. The slugs were hand-copied in five places
# before this — the same drift gap that caused the ``--frameworks``/``nis2``
# mismatch. ``tests/unit/test_cli_web_deliverable_contract.py`` now binds the
# web copies to these so future drift fails CI.
# ---------------------------------------------------------------------------

#: Selectable deliverable slugs, in canonical kit order. Mirrors ``_VALID_SLUGS``
#: (kept as a clean public name so callers never reach into the private alias).
DELIVERABLE_SLUGS: tuple[str, ...] = _VALID_SLUGS

#: ``{slug: human title}`` for every selectable deliverable — drives the
#: deliverable checkbox labels (the operator picks titles, we map back to slugs).
DELIVERABLE_LABELS: dict[str, str] = {item.slug: item.title for item in _KIT}

#: Default deliverable selection: everything. A human-facing deliver run ships
#: the full kit unless the operator deselects; automation (CI) overrides this
#: with an explicit ``--only`` and never inherits the full kit by accident.
DEFAULT_DELIVERABLE_SLUGS: tuple[str, ...] = DELIVERABLE_SLUGS

# ``--only`` aliases. The slug ``executive`` is preserved internally for
# back-compat (web Celery task, ``Sample_Kit.zip``, every customer script
# pinned to ``--only executive``), but the artefact it renders is now the
# **full** Security Assessment Report. ``--only report`` is the public,
# semantically correct alias we direct users to. Add new aliases here when
# the public vocabulary drifts ahead of the internal slug — never rename
# the slug itself in this codebase.
# ``checklist`` → ``executive``: the standalone MITRE Remediation Checklist was
# retired (folded into the main report). A pinned ``--only checklist`` now renders
# the Security Assessment Report (which carries the ATT&CK lens) instead of erroring.
_ONLY_ALIASES: dict[str, str] = {"report": "executive", "checklist": "executive"}


# ---------------------------------------------------------------------------
# Compliance frameworks — single source of truth for the kit
# ---------------------------------------------------------------------------
#
# Mirrors ``do_generate_report`` (adscan.py). When this list changes here,
# update both. Tests in ``tests/unit/cli/test_deliver_command.py`` lock the
# parity. Adding a new framework requires the orchestrator + Coverage
# Matrix bonus to know about it — do not add a label here in isolation.

# ENS and NIS2 are DISTINCT compliance regimes (ENS = Spanish public sector /
# CCN-CERT; NIS2 = EU critical-infrastructure directive) and are selectable
# independently — a client may need NIS2 but not ENS. They share findings/
# attack-path semantics, which is modularized in the content layer, not by
# collapsing them into one key.
#
# ``_FRAMEWORK_KEY_MAP`` / ``_VALID_FRAMEWORK_KEYS`` live in
# ``adscan_internal.cli.common`` (imported above) — LITE-safe home shared with
# ``_parse_frameworks``/``_resolve_workspace`` so ``report``/``writeup`` never
# need to import this PRO-flow module (LITE strips ``deliver.py``; see
# ``report_cmd.py``'s docstring for the full story).
#
# There is NO framework default, on any entry point: the empty tuple is the
# "nothing was chosen" sentinel, not a silent choice. A compliance section
# asserts a conformance verdict, so the regime is an explicit scoping input the
# operator supplies and ADscan never infers. For an AUDIT engagement an empty
# selection is REFUSED outright (the requiredness gate in the shared resolver
# ``adscan_internal/services/compliance_scope.py``, which ``adscan ci`` /
# ``adscan report`` call too); for a ctf or unclassified workspace it renders
# with no compliance mapping and says so. Kept in lockstep with the web SSOT
# (``app.schemas.report_config.DEFAULT_FRAMEWORKS``); the cross-boundary
# contract test ``tests/unit/test_cli_web_framework_contract.py`` asserts the
# two defaults match.
_DEFAULT_FRAMEWORKS: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# ``--emit`` — which Security Assessment Report output formats to produce.
# ---------------------------------------------------------------------------
#
# ``pdf`` and ``html`` are the two outputs the SAR render path has always
# produced. ``data`` adds ``report_model.json`` (the branding-invariant
# derived-data export, see ``report_model_export.py``) alongside them, gated
# by the ``data_export`` entitlement so an un-entitled install never emits it
# even if the operator asks for it. The DEFAULT is exactly the pre-``--emit``
# behaviour (``pdf,html``) so an invocation that omits the flag — including
# the web Enterprise product's Celery worker, which shells out to
# ``adscan deliver`` without ``--emit`` — renders byte-identically to before
# this flag existed.
_VALID_EMIT_VALUES: tuple[str, ...] = ("pdf", "html", "data")
_DEFAULT_EMIT: tuple[str, ...] = ("pdf", "html")


def _parse_emit(raw: str | None) -> tuple[str, ...]:
    """Parse the comma-separated ``--emit`` value into a validated tuple.

    Args:
        raw: Raw ``--emit`` flag value, or ``None``/empty for the default.

    Returns:
        A tuple of unique emit tokens from :data:`_VALID_EMIT_VALUES`, in
        canonical order. Omitting the flag (``None``) returns
        :data:`_DEFAULT_EMIT` unchanged — the behaviour-preservation contract.

    Raises:
        ValueError: If any token is not one of :data:`_VALID_EMIT_VALUES`.
    """
    if raw is None or not raw.strip():
        return _DEFAULT_EMIT
    tokens = [tok.strip().lower() for tok in raw.split(",") if tok.strip()]
    if not tokens:
        return _DEFAULT_EMIT
    invalid = [tok for tok in tokens if tok not in _VALID_EMIT_VALUES]
    if invalid:
        raise ValueError(
            f"--emit: unknown format(s): {', '.join(invalid)}. "
            f"Use a comma-separated list of: {', '.join(_VALID_EMIT_VALUES)}."
        )
    selected = set(tokens)
    return tuple(fmt for fmt in _VALID_EMIT_VALUES if fmt in selected)


# ---------------------------------------------------------------------------
# Workspace + metadata resolution
# ---------------------------------------------------------------------------


def _is_inside_shell() -> bool:
    """Return ``True`` when invoked from inside the running PentestShell.

    The shell sets ``ADSCAN_INSIDE_SHELL=1`` before dispatching, so we
    can decide whether to take the workspace from the active session
    rather than prompting.
    """
    return os.environ.get("ADSCAN_INSIDE_SHELL", "").strip() == "1"


def _resolve_client_meta(args: argparse.Namespace) -> tuple[str, str]:
    """Resolve ``(client_name, engagement_code)`` from flags or prompt.

    Both are optional. If neither flag is present and we have a TTY, a
    single questionary panel asks for both with blank defaults. Empty
    answers are accepted — the kit metadata will read "—".
    """
    client = (getattr(args, "client", None) or "").strip()
    engagement = (getattr(args, "engagement", None) or "").strip()
    if client or engagement:
        return client, engagement

    from adscan_internal.interaction import is_non_interactive as _is_non_interactive

    if _is_non_interactive() or getattr(args, "_prompts_prefilled", False):
        return "", ""

    try:
        from questionary import text  # type: ignore[import-untyped]

        client = (text("Client name (optional):").ask() or "").strip()
        engagement = (text("Engagement code (optional):").ask() or "").strip()
    except Exception:  # noqa: BLE001
        return client, engagement
    return client, engagement


class _LogoImportShell:
    """Minimal shell surface the host file-picker helpers read.

    ``deliver`` runs as a standalone CLI command with no ``PentestShell``, but the
    host-helper file picker only needs the current workspace directory (to import
    the picked host file into it) and falls back to the module-level container-
    runtime check when the shell lacks ``_is_full_adscan_container_runtime``.
    """

    def __init__(self, workspace_dir: Path) -> None:
        self.current_workspace_dir = str(workspace_dir)


def _pick_client_logo_host_path(workspace_dir: Path) -> str:
    """Interactively select a client logo from the host, imported into the volume.

    Uses the shared host-helper GUI picker (the same one the cracking wordlist
    flow uses), then a manual host-path prompt as a fallback, then imports the
    chosen file into ``<workspace>/branding/`` through the host helper so the
    container can read it. Returns the container-visible path, or ``""``.
    """
    from adscan_internal.cli.host_file_picker import (
        maybe_import_host_file_to_workspace,
        select_host_file_via_gui,
    )
    from adscan_internal.services.client_logo import (
        SUPPORTED_LOGO_SUFFIXES,
        is_supported_logo_suffix,
    )

    shim = _LogoImportShell(workspace_dir)
    picked = (
        select_host_file_via_gui(
            shim,
            title="Select the client logo (host file)",
            initial_dir=str(Path.home()),
            log_prefix="client_logo",
        )
        or ""
    ).strip()
    if not picked:
        try:
            from questionary import text  # type: ignore[import-untyped]

            picked = (
                text(
                    "Client logo — full host path "
                    f"({', '.join(SUPPORTED_LOGO_SUFFIXES)}), blank to skip:"
                ).ask()
                or ""
            ).strip()
        except Exception:  # noqa: BLE001
            picked = ""
    if not picked:
        return ""
    if not is_supported_logo_suffix(picked):
        print_warning(
            "Unsupported logo file type; keeping the ADscan mark only. "
            f"Supported: {', '.join(SUPPORTED_LOGO_SUFFIXES)}."
        )
        return ""
    return (
        maybe_import_host_file_to_workspace(
            shim,
            domain="client",
            source_path=picked,
            dest_dir="branding",
            log_prefix="client_logo",
        )
        or ""
    ).strip()


def _prefill_client_logo(args: argparse.Namespace) -> None:
    """Interactively pick a client logo in the SYNC context (before the loop).

    Like the client/engagement/theme prompts, the host GUI picker and the
    questionary fallback spin their own prompt_toolkit ``Application`` and must
    run OUTSIDE ``asyncio.run``'s loop (see :func:`_prefill_interactive_inputs`).
    Runs only when no ``--client-logo`` flag was given, nothing is persisted yet,
    and the session is interactive; the chosen container path is written back to
    ``args.client_logo`` so :func:`_resolve_and_persist_client_logo` persists it.
    Best-effort: a cosmetic logo never blocks a delivery.
    """
    from adscan_internal.interaction import is_non_interactive as _is_non_interactive
    from adscan_internal.services.client_logo import resolve_client_logo_path

    if (getattr(args, "client_logo", None) or "").strip():
        return
    if _is_non_interactive():
        return
    if resolve_client_logo_path():
        return
    try:
        from adscan_core.rich_output import confirm_ask

        if not confirm_ask("Add a client logo to the report cover?", default=False):
            return
        workspace = _resolve_workspace(args)
        if workspace is None or not workspace.is_dir():
            return
        picked = _pick_client_logo_host_path(workspace)
        if picked:
            args.client_logo = picked
    except Exception as exc:  # noqa: BLE001 — cosmetic; never block delivery
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def _resolve_and_persist_client_logo(args: argparse.Namespace) -> None:
    """Persist the resolved client logo for the report cover and later reuse.

    The value comes from the ``--client-logo`` flag (the launcher already staged
    the file into the mounted volume and forwards a container-visible path) or
    from :func:`_prefill_client_logo`. It is written to ``config.json`` via the
    shared SSOT so later ``deliver`` / ``ci`` runs reuse it without re-selecting.
    This is non-interactive and safe to call from the async delivery path.
    """
    from adscan_internal.services.client_logo import (
        SUPPORTED_LOGO_SUFFIXES,
        is_supported_logo_suffix,
        resolve_client_logo_path,
        save_client_logo_setting,
    )

    explicit = (getattr(args, "client_logo", None) or "").strip()
    if not explicit:
        return
    if not is_supported_logo_suffix(explicit):
        print_warning(
            "Unsupported --client-logo file type; keeping the ADscan mark only. "
            f"Supported: {', '.join(SUPPORTED_LOGO_SUFFIXES)}."
        )
        return
    save_client_logo_setting(explicit)
    if resolve_client_logo_path(explicit):
        print_info("Client logo applied to the report cover.")
    else:
        print_warning(
            "Client logo file was not found; the report keeps the ADscan mark only."
        )


def _parse_only(raw: str | None) -> tuple[_KitItem, ...]:
    """Filter ``_KIT`` by a comma-separated slug list.

    Args:
        raw: Raw ``--only`` value, or ``None`` for "all four".

    Returns:
        Tuple of selected ``_KitItem`` in canonical kit order.

    Raises:
        ValueError: If any token is not a valid kit slug, with a
            message naming the invalid token and the allowed set.
    """
    if raw is None or not raw.strip():
        return _KIT
    tokens = [tok.strip().lower() for tok in raw.split(",") if tok.strip()]
    if not tokens:
        return _KIT
    # Resolve aliases (e.g. ``report`` → ``executive``) before validation so
    # public-facing names never reach the slug check. Unknown tokens still
    # raise — the alias map is intentionally narrow.
    normalised = [_ONLY_ALIASES.get(tok, tok) for tok in tokens]
    invalid = [tok for tok in normalised if tok not in _VALID_SLUGS]
    if invalid:
        allowed = ", ".join(list(_VALID_SLUGS) + list(_ONLY_ALIASES.keys()))
        raise ValueError(
            f"--only: unknown deliverable(s): {', '.join(invalid)}. "
            f"Use one of: {allowed}."
        )
    selected_slugs = set(normalised)
    return tuple(item for item in _KIT if item.slug in selected_slugs)


def _resolve_frameworks(args: argparse.Namespace) -> list[str]:
    """Resolve compliance frameworks from the flag or the interactive picker.

    Order:
        1. ``--frameworks`` flag value, validated via :func:`_parse_frameworks`.
           An explicit selection always wins.
        2. Interactive questionary checkbox in TTY contexts, SKIPPED for a
           ``ctf`` workspace (a lab has no regulatory regime, so there is
           nothing to ask).
        3. Nothing selected (:data:`_DEFAULT_FRAMEWORKS`, which is empty).

    The final selection then goes through the shared resolver
    (``services/compliance_scope.resolve_compliance_scope``) that
    ``adscan ci``/``adscan report`` also call, so the requiredness answer is
    identical on every entry point: an ``audit`` workspace with no framework
    raises, everything else renders with no compliance mapping and says so.

    Raises:
        ValueError: ``--frameworks`` carried an unknown value, OR this is an
            audit engagement and no framework was selected. Both are surfaced
            by the caller as a clean exit-2 error.
    """
    from adscan_internal.services.compliance_scope import (
        missing_framework_error,
        resolve_compliance_scope,
        resolve_engagement_type,
    )

    workspace_dir = getattr(args, "workspace", None)
    engagement_type = resolve_engagement_type(
        shell=getattr(args, "_shell", None), workspace_dir=workspace_dir
    )

    raw = getattr(args, "frameworks", None)
    selection = _parse_frameworks(raw)
    if selection is None:
        selection = _pick_frameworks_interactively(args, engagement_type)

    # The ENS scope is a SECOND question, and it depends on the answer to the
    # first one: it is only worth asking once ENS is in the selection. So it
    # hangs off the resolved selection here rather than inside the framework
    # picker, and it covers an explicit ``--frameworks ens`` as well as the
    # picker (an operator at a TTY who named the framework on the command line
    # is exactly as able to answer it). Its own guards cover ctf and the
    # non-interactive path; a workspace that already declares a scope is shown
    # it and confirmed, never re-asked the questions.
    from adscan_internal.cli.compliance_scope_wizard import maybe_declare_ens_scope

    maybe_declare_ens_scope(
        workspace_dir=workspace_dir,
        frameworks=selection,
        engagement_type=engagement_type,
        shell=getattr(args, "_shell", None),
        prompts_prefilled=bool(getattr(args, "_prompts_prefilled", False)),
    )

    scope = resolve_compliance_scope(
        explicit=selection,
        workspace_dir=workspace_dir,
        engagement_type=engagement_type,
    )
    if scope.missing_required:
        raise ValueError(
            missing_framework_error(
                rerender_hint="adscan deliver --frameworks <keys>"
            )
        )
    return list(scope.frameworks)


def _pick_frameworks_interactively(
    args: argparse.Namespace, engagement_type: str | None
) -> list[str]:
    """Ask the operator which frameworks apply. Empty when it cannot ask.

    Returns :data:`_DEFAULT_FRAMEWORKS` (empty) in non-interactive contexts,
    when the prompts were already resolved by the sync prefill, for a ``ctf``
    workspace (no regulatory regime, so no prompt), or when the operator
    cancels or deselects everything. Never substitutes a framework.

    Routed through ``questionary_checkbox_values`` rather than raw
    ``questionary.checkbox(...).ask()``: a raw prompt has no non-interactive
    default and blocks on stdin, which is the CI hang the centralized helpers
    exist to prevent. The guard above returns first today, so the raw call was
    latent rather than live, and ``default_values=[]`` keeps the resolved
    answer identical: no framework is ever substituted.
    """
    from adscan_core.rich_output import questionary_checkbox_values
    from adscan_internal.interaction import is_non_interactive as _is_non_interactive
    from adscan_internal.services.compliance_scope import CTF_ENGAGEMENT

    if engagement_type == CTF_ENGAGEMENT:
        return list(_DEFAULT_FRAMEWORKS)
    if _is_non_interactive() or getattr(args, "_prompts_prefilled", False):
        return list(_DEFAULT_FRAMEWORKS)

    selected = questionary_checkbox_values(
        title="Select compliance frameworks to include in the kit:",
        options=list(_FRAMEWORK_KEY_MAP.keys()),
        default_values=[],
        shell=getattr(args, "_shell", None),
    )

    if not selected:
        return list(_DEFAULT_FRAMEWORKS)

    return [
        _FRAMEWORK_KEY_MAP[label] for label in selected if label in _FRAMEWORK_KEY_MAP
    ]


def _resolve_deliverables(
    args: argparse.Namespace, *, shell: object | None = None
) -> str | None:
    """Resolve which deliverables to render, returning a ``--only`` string.

    Precedence:
        1. An explicit ``--only`` already on ``args`` wins untouched — automation
           (CI / the web) sets it deliberately and the checkbox must never
           override an explicit selection.
        2. Interactive TTY contexts render a checkbox with every deliverable
           pre-selected, so the default gesture (Enter) ships the full kit and
           the operator can deselect down to e.g. only the Security Assessment
           Report. Routed through the centralized prompt helper so it auto-resolves
           to ALL deliverables non-interactively (CI/web) and is telemetry-mirrored.

    Args:
        args: argparse namespace; reads ``only``, writes nothing.
        shell: Optional shell, threaded into the prompt helper so its
            non-interactive predicate (``shell.auto`` / posture) is honoured.

    Returns:
        A comma-separated slug string for ``--only`` (a strict subset, or the
        full set), or ``None`` when nothing should be narrowed (the caller then
        treats ``None`` as "all" via :func:`_parse_only`). An explicit
        ``args.only`` is returned verbatim.
    """
    explicit = getattr(args, "only", None)
    if explicit and str(explicit).strip():
        return str(explicit)

    from adscan_core.rich_output import questionary_checkbox_values

    labels = [DELIVERABLE_LABELS[slug] for slug in DELIVERABLE_SLUGS]
    selected_labels = questionary_checkbox_values(
        title="Select the deliverables to generate (all selected by default):",
        options=labels,
        default_values=None,  # None → ALL pre-selected / auto-all non-interactively.
        shell=shell,
    )

    # ``None`` = cancelled / prompt unavailable → fall back to the full kit.
    if not selected_labels:
        return None

    label_to_slug = {title: slug for slug, title in DELIVERABLE_LABELS.items()}
    chosen = [
        label_to_slug[label] for label in selected_labels if label in label_to_slug
    ]
    if not chosen or len(chosen) == len(DELIVERABLE_SLUGS):
        # Nothing resolved, or the full set chosen → let _parse_only default to all.
        return None
    return ",".join(chosen)


def _drop_unsupportable_items(
    items: tuple[_KitItem, ...],
    workspace_dir: Path,
) -> tuple[_KitItem, ...]:
    """Remove kit artefacts this workspace has no data to fill.

    A paid deliverable that arrives empty is worse than one that is absent: it
    costs the reader the time to open it, and the only thing it can say is that
    there is nothing to say. Two artefacts are legitimately conditional, and the
    entry list VARIES between runs by design because of them:

    * the AD Control Coverage Report renders positive assurance from
      ``control_evidence``, and a scan that probed nothing clear has none;
    * the AD Password Hygiene Report renders what credential recovery proved,
      and a scan that attempted no recovery has no block to render — the
      structural absence rule, read through the shared hygiene gate.

    Each is dropped rather than shipped empty, so a kit missing one of them
    reads as "this run produced nothing for it", never as a broken kit.

    The check is deliberately narrow. Every other artefact derives from findings
    and attack paths, which any real scan produces; a missing one there is a bug
    to fix, not a document to suppress.

    Args:
        items: The selected kit artefacts, in canonical order.
        workspace_dir: Source workspace carrying ``technical_report.json``.

    Returns:
        ``items`` minus anything unsupportable. Best-effort: on any single
        check's failure that one check leaves its artefact in place.
    """
    kept = items

    # Coverage Report — dropped when the scan mapped no control AREA at all
    # (``has_coverage_data`` is "verified or needs-attention", not "verified").
    if any(item.slug == "coverage-matrix" for item in kept):
        try:
            from adscan_internal.pro.reporting.coverage_report_databinding import (
                build_coverage_report_databinding,
            )

            context = build_coverage_report_databinding(workspace_dir)
            if not context.get("has_coverage_data"):
                print_info(
                    "Skipping the AD Control Coverage Report: this scan mapped "
                    "no control area to report on."
                )
                kept = tuple(it for it in kept if it.slug != "coverage-matrix")
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    # Password Hygiene Report — dropped when credential recovery never ran, so
    # the kit never ships a document whose own figures would read as "your
    # passwords are strong" off a scan that tested none (the absence rule).
    if any(item.slug == "password-hygiene" for item in kept):
        try:
            from adscan_internal.pro.reporting.password_hygiene_databinding import (
                workspace_has_password_hygiene,
            )

            if not workspace_has_password_hygiene(workspace_dir):
                print_info(
                    "Skipping the AD Password Hygiene Report: this engagement "
                    "attempted no credential recovery, so there is nothing to "
                    "report on password strength or reuse."
                )
                kept = tuple(it for it in kept if it.slug != "password-hygiene")
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    return kept


# ---------------------------------------------------------------------------
# Generators — async wrappers around the existing PRO renderers
# ---------------------------------------------------------------------------


async def _render_bonus_async(
    bonus_key: str,
    output_path: Path,
    workspace_dir: Path | None = None,
    theme: str = "",
    frameworks: list[str] | None = None,
    branding: str = "cobrand",
    client_cover_html: str = "",
    client_back_html: str = "",
    client_logo_data_uri: str = "",
    composition_seams_enabled: bool = False,
    cover_title: str = "",
    cover_subtitle: str = "",
    is_sample: bool = False,
) -> int:
    """Render a single bonus PDF in a worker thread.

    When ``workspace_dir`` is supplied it is threaded into the bonus
    renderer so the playbook / checklist / coverage matrix can re-rank
    their content against the techniques actually observed in the scan.
    ``theme`` overrides the per-bonus default when non-empty.

    ``frameworks`` carries the operator-selected compliance regimes so the
    playbook/checklist render ONLY those frameworks' controls — the same
    selection the Security Assessment Report honours. Without this the bonuses
    fell back to ALL five frameworks and leaked DORA/ENS into an ISO 27001 kit.

    ``branding`` carries the resolved ``BrandingPosture`` so the playbook and
    the AD Control Coverage Report debrand the shared ``ADscan Priority``
    scoring-model name (and the ADscan cover wordmark) exactly as the
    Security Assessment Report does under ``"whitelabel"``.

    The ``client_*``/``composition_seams_enabled``/``cover_*`` parameters carry
    the composition seams (client cover/back/logo + this deliverable's own
    title/subtitle) so the bonus is branded as the consultancy's own document,
    exactly like the Security Assessment Report. All default to the no-op, so a
    non-entitled / no-client-cover run is byte-identical to today.

    ``is_sample`` stamps the public-sample watermark band; it is set only by
    :file:`scripts/regenerate_samples.py` so the published example kit renders
    through this same function rather than a second, drifting copy of it. The
    cheatsheet is product documentation and ``render_bonus`` refuses to
    watermark it even when the flag is set.
    """
    from adscan_internal.cli.bonuses import render_bonus

    return await asyncio.to_thread(
        render_bonus,
        bonus_key,
        output_path,
        is_sample=is_sample,
        workspace_dir=workspace_dir,
        theme=theme or None,
        frameworks=frameworks,
        branding=branding,
        client_cover_html=client_cover_html,
        client_back_html=client_back_html,
        client_logo_data_uri=client_logo_data_uri,
        composition_seams_enabled=composition_seams_enabled,
        cover_title=cover_title,
        cover_subtitle=cover_subtitle,
    )


_VALID_REPORT_THEMES: tuple[str, ...] = ("corporate_light", "premium_dark", "editorial")
# Audit-grade light by default. The Security Assessment Report is the client's
# status instrument toward their board and DORA auditors — it must read as a
# serious, print-clean compliance document, not a dark terminal artefact. The
# report template is built on the ``--bg-0``/``--text`` variable scheme, which
# only ``corporate_light`` re-skins (``premium_dark`` is built on
# ``--paper``/``--ink`` for the editorial bonuses and would leave the report on
# its own DARK ``:root``). So ``corporate_light`` is both the strategy-correct
# AND the technically-correct default for the report. Bonuses keep their own
# editorial catalog theme (see ``bonus_theme`` in ``_render_kit``).
_DEFAULT_REPORT_THEME: str = "corporate_light"

# Short aliases for --theme: operators can pass "dark" or "light" instead of
# the full canonical names. Empty string means "not set — use env var or default".
_THEME_ALIASES: dict[str, str] = {
    "dark": "premium_dark",
    "light": "corporate_light",
    "warm": "editorial",
    "": "",
}

# Labels shown in the questionary picker. Order is intentional: dark first
# (default for screen demos), light second (auditor / board print). Keep
# this map in lockstep with :data:`_VALID_REPORT_THEMES`.
_THEME_PICKER_MAP: dict[str, str] = {
    "Editorial — warm bone, ember accent (premium, McKinsey-grade)": "editorial",
    "Corporate — white/navy, print-safe (Big-4 / auditor)": "corporate_light",
}


def _resolve_theme(args: argparse.Namespace) -> str:
    """Resolve the report theme using the canonical precedence chain.

    Order of precedence:
        1. ``--theme`` flag (with short aliases ``dark``/``light``).
        2. Legacy ``--report-theme`` flag.
        3. ``ADSCAN_PDF_THEME`` environment variable.
        4. Interactive questionary select in TTY contexts — mirrors the
           ``generate_report`` REPL command for cross-command parity.
        5. :data:`_DEFAULT_REPORT_THEME` (``premium_dark``).

    Returns:
        A theme value guaranteed to be in :data:`_VALID_REPORT_THEMES`.
        Invalid explicit inputs (typo'd env var, garbage flag) silently
        fall back to the default — the kit must always render.
    """
    raw_theme = getattr(args, "theme", "") or ""
    resolved_alias = _THEME_ALIASES.get(raw_theme, raw_theme)
    report_theme_flag = getattr(args, "report_theme", "") or ""
    env_theme = os.environ.get("ADSCAN_PDF_THEME", "").strip()

    # External bring-your-own-CSS: a --theme value that is a .css path, or the
    # ADSCAN_EXTERNAL_THEME_CSS env var, bypasses the built-in membership
    # clamp entirely — the theme loader (themes/__init__.py::load_theme_css)
    # resolves a filesystem path directly.
    external_theme_css = os.environ.get("ADSCAN_EXTERNAL_THEME_CSS", "").strip()
    if external_theme_css:
        return external_theme_css

    chosen = resolved_alias or report_theme_flag or env_theme
    if chosen:
        if chosen.endswith(".css"):
            return chosen
        return chosen if chosen in _VALID_REPORT_THEMES else _DEFAULT_REPORT_THEME

    from adscan_internal.interaction import is_non_interactive as _is_non_interactive

    if _is_non_interactive() or getattr(args, "_prompts_prefilled", False):
        return _DEFAULT_REPORT_THEME

    try:
        from questionary import select  # type: ignore[import-untyped]

        label = select(
            "Report theme:",
            choices=list(_THEME_PICKER_MAP.keys()),
        ).ask()
    except Exception:  # noqa: BLE001 — questionary missing or non-TTY edge cases
        return _DEFAULT_REPORT_THEME

    if not label:
        return _DEFAULT_REPORT_THEME
    return _THEME_PICKER_MAP.get(label, _DEFAULT_REPORT_THEME)


def _is_lite_runtime() -> bool:
    return False  # deliver is PRO-only; no runtime LITE path


def _resolve_branding_posture(args: argparse.Namespace):
    """Resolve the deliverable's branding posture (mirrors ``_resolve_theme``)."""
    from adscan_internal.services.report_branding import (
        resolve_branding_posture,
        whitelabel_entitled_from_config,
    )

    requested = (getattr(args, "branding", None) or "").strip() or None
    return resolve_branding_posture(
        requested=requested,
        env=os.environ,
        is_lite=_is_lite_runtime(),
        whitelabel_entitled=whitelabel_entitled_from_config(),
    )


def _resolve_client_composition_seam_html(path: str | None, *, flag_name: str) -> str:
    """Read a ``--client-cover``/``--client-back`` fragment file's text.

    Best-effort: a missing or unreadable file is a warning, never a fatal
    error — the kit still renders with the default cover/back page. The
    ``composition_seams`` entitlement is checked separately, inside
    ``_build_context``, so this helper only resolves WHAT the operator
    supplied, not whether the install is entitled to use it (a non-entitled
    install still gets an early, informative warning here when a flag was
    passed, in addition to the silent no-op deeper in the render).

    Args:
        path: The raw ``--client-cover``/``--client-back`` value, or ``None``.
        flag_name: The flag's display name, for the warning message.

    Returns:
        The file's text content, or ``""`` when no path was given or the
        file could not be read.
    """
    raw = (path or "").strip()
    if not raw:
        return ""
    fragment_path = Path(raw).expanduser()
    try:
        if not fragment_path.is_file():
            print_warning(
                f"{flag_name} file not found: {fragment_path}. "
                "Rendering the default page instead."
            )
            return ""
        return fragment_path.read_text(encoding="utf-8")
    except Exception as exc:  # noqa: BLE001 — a bad fragment must not abort delivery
        print_warning(
            f"Could not read {flag_name} file {fragment_path}: {exc}. "
            "Rendering the default page instead."
        )
        return ""


def resolve_seam_fragment_for_slug(raw: str | None, slug: str, *, kind: str) -> str:
    """Resolve the composition-seam fragment HTML for one deliverable.

    ``--client-cover``/``--client-back`` accept EITHER a single file (one
    fragment branding every deliverable, the DFY default) OR a directory, so a
    consultancy can give each kit PDF its own cover/back page.

    Resolution rules:

    * ``raw`` empty/``None`` → ``""`` (no seam for this deliverable).
    * ``raw`` is a directory → the per-slug file ``<dir>/<kind>-<slug>.html`` if
      present, else the shared fallback ``<dir>/<kind>.html`` if present, else
      ``""`` (a warning; that deliverable renders the default page).
    * ``raw`` is a file → its text (the same fragment for every deliverable —
      today's behaviour, unchanged).
    * ``raw`` is neither a file nor a directory → a warning and ``""``.

    Best-effort: a missing/unreadable fragment is a warning, never fatal — the
    kit still renders with the default page for that deliverable. The
    ``composition_seams`` entitlement is checked separately in the render
    pipeline; this helper only resolves WHAT the operator supplied per slug.

    Args:
        raw: The raw ``--client-cover``/``--client-back`` value, or ``None``.
        slug: The ``_KitItem.slug`` of the deliverable being resolved
            (``executive`` / ``playbook`` / ``coverage-matrix``).
        kind: ``"cover"`` or ``"back"`` — selects the per-slug/shared filename
            and labels the warning.

    Returns:
        The resolved fragment text, or ``""`` when no fragment applies.
    """
    flag_name = "--client-cover" if kind == "cover" else "--client-back"
    value = (raw or "").strip()
    if not value:
        return ""
    base = Path(value).expanduser()
    try:
        if base.is_dir():
            per_slug = base / f"{kind}-{slug}.html"
            shared = base / f"{kind}.html"
            target = per_slug if per_slug.is_file() else shared
            if not target.is_file():
                print_warning(
                    f"{flag_name} directory {base} has no {per_slug.name} or "
                    f"{shared.name}. Rendering the default {kind} page for the "
                    f"{slug} deliverable."
                )
                return ""
            return target.read_text(encoding="utf-8")
        if base.is_file():
            return base.read_text(encoding="utf-8")
        print_warning(
            f"{flag_name} path not found: {base}. Rendering the default "
            f"{kind} page instead."
        )
        return ""
    except Exception as exc:  # noqa: BLE001 — a bad fragment must not abort delivery
        print_warning(
            f"Could not read {flag_name} {kind} fragment from {base}: {exc}. "
            "Rendering the default page instead."
        )
        return ""


async def _render_assessment_async(
    output_path: Path,
    workspace_dir: Path,
    metadata: dict[str, str],
    report_theme: str = _DEFAULT_REPORT_THEME,
    frameworks: list[str] | None = None,
    branding: str = "cobrand",
    emit: tuple[str, ...] = _DEFAULT_EMIT,
    client_cover_html: str = "",
    client_back_html: str = "",
    client_logo_data_uri: str = "",
    composition_seams_enabled: bool = False,
    cover_title: str = "",
    cover_subtitle: str = "",
    is_sample: bool = False,
) -> int:
    """Render the Security Assessment Report PDF in a worker thread.

    Reads ``technical_report.json`` from the workspace and feeds it
    through the canonical PRO orchestrator with the **full** profile —
    executive section + technical section + attack paths. The earlier
    ``executive`` profile shipped a stripped variant (zero attack
    paths) that operators routinely supplemented by copying the
    standalone ``report.pdf`` into their delivery directory; the kit
    now ships the full report directly so the headline artefact is the
    one the customer actually wants to open.

    Args:
        output_path: Where to write the rendered PDF.
        workspace_dir: Workspace containing ``technical_report.json``.
        metadata: Report metadata (workspace_name, report_date, client, ...).
        report_theme: Visual theme — one of :data:`_VALID_REPORT_THEMES`.
            Defaults to ``premium_dark`` for backwards compatibility with
            existing callers that did not pass a theme. Invalid values fall
            back to the default rather than raising — the kit should always
            render even with a typo'd flag.
        emit: Which output formats to produce for this report, from
            :data:`_VALID_EMIT_VALUES`. ``pdf`` and ``html`` are unconditional
            (the behaviour every caller already depends on); ``data`` emits
            ``report_model.json`` beside them, and ONLY when the install also
            carries the ``data_export`` entitlement
            (``report_branding.entitlement_enabled``) — an un-entitled install
            that asks for ``data`` silently gets no JSON file, never an error.
            Defaults to :data:`_DEFAULT_EMIT` (``pdf,html``), i.e. omitting
            the argument reproduces the exact pre-``--emit`` behaviour.
        client_cover_html: Optional consultancy-supplied HTML fragment that
            replaces ADscan's own cover page (``--client-cover``). Gated on
            the ``composition_seams`` entitlement inside the orchestrator;
            empty by default, which renders the unchanged default cover.
        client_back_html: Optional consultancy-supplied HTML fragment
            rendered as a closing back page (``--client-back``). Same gate;
            empty by default renders no extra page.
        client_logo_data_uri: The client logo already resolved to a
            ``data:`` URI (``client_logo.resolve_client_logo_data_uri``).
            When non-empty AND ``composition_seams_enabled``, every page of
            the PDF carries the logo as a running header/footer mark (the
            final composition seam — a consultancy's own mark on every
            page, the way a Big-4 firm's own report repeats its mark).
            Empty by default, which leaves the PDF engine options unchanged.
        composition_seams_enabled: Whether the install carries the
            ``composition_seams`` entitlement. Same gate as
            ``client_cover_html``/``client_back_html``. ``False`` by
            default.
        cover_title: Per-deliverable title filled into the client cover/back
            ``{{DOCUMENT_TITLE}}`` token (e.g. "Security Assessment"), so one
            authored client cover brands this PDF with its own name.
        cover_subtitle: Per-deliverable subtitle filled into the client
            cover/back ``{{DOCUMENT_SUBTITLE}}`` token.
        is_sample: Stamp the public-sample watermark band on every page. Set
            only by :file:`scripts/regenerate_samples.py`, which renders the
            published example kit through THIS function so the sample is the
            same artefact a paying engagement receives, marked as a sample.
            ``False`` for every delivery, which is byte-identical to before.
    """
    # An external bring-your-own-CSS skin (a .css path or an existing file) is
    # NOT a built-in theme name — let it through to the orchestrator, which
    # resolves a filesystem path via load_theme_css. Only genuine invalid names
    # (typos) fall back to the default.
    _is_external_theme = report_theme.endswith(".css") or Path(report_theme).is_file()
    if not _is_external_theme and report_theme not in _VALID_REPORT_THEMES:
        report_theme = _DEFAULT_REPORT_THEME

    # Resolve the selected frameworks. An empty/None selection stays empty
    # (default none): the kit omits the compliance sections rather than forcing
    # a regime the client did not request.
    fw: list[str] = list(frameworks) if frameworks else list(_DEFAULT_FRAMEWORKS)

    def _run() -> int:
        import json as _json

        from adscan_internal.pro.reporting.orchestrator import (
            generate_report_html,
            generate_report_pdf,
        )
        from adscan_internal.pro.reporting.report_builder import (
            build_report_data_from_raw,
        )
        from adscan_internal.pro.services.report_service import (
            ensure_report_attack_paths,
        )

        report_json = workspace_dir / "technical_report.json"
        if not report_json.is_file():
            raise FileNotFoundError(
                f"technical_report.json not found in {workspace_dir}. "
                f"Run 'start_auth' or 'report' first to populate the workspace."
            )
        raw = _json.loads(report_json.read_text(encoding="utf-8"))
        # Normalize the raw technical report into the renderer mapping via
        # the single source of truth shared with ``generate_report``. The
        # raw JSON stores ``domains[*].vulnerabilities`` empty (the vuln
        # map is derived on demand from ``findings``); feeding it raw made
        # the compliance engine see zero findings per requirement and
        # falsely report ~100% conformant for every framework.
        report_data = (
            build_report_data_from_raw(raw, workspace_dir=workspace_dir)
            if isinstance(raw, dict)
            else {}
        )
        # Compute + inject attack paths the same way ``generate_report`` does.
        # The renderer expects them already present; the workspace JSON stores
        # them empty (computed on demand), so without this the kit report
        # shipped with ZERO attack paths -- the "deliver is suspiciously fast"
        # symptom. Single source of truth shared with report_service.
        # Also emits the per-framework compliance block into
        # technical_report.json for the selected frameworks (verbatim ingest by
        # the web) — same SSOT engine as the PDF compliance sections.
        ensure_report_attack_paths(report_data, workspace_dir, frameworks=fw)
        pdf_bytes = generate_report_pdf(
            report_data,
            metadata=metadata,
            report_profile="full",
            frameworks=fw,
            # White-label slot only (the customer's own firm mark). ADscan's
            # own cover mark comes from the shared brand SSOT inside the
            # renderer, keyed on the theme — see report_service._generate_html_pdf.
            logo_path=None,
            engine="chromium",
            renderer="cytoscape",
            template="premium",
            theme=report_theme,
            # The workspace ROOT (holds technical_report.json) so the compliance
            # snapshot reconciles the verified-clear (positive-evidence) controls
            # with the AD Control Coverage Report. Without it the deliver-kit SAR
            # renders "0 conformant" and drops the observed-good assurance the
            # standalone `report` output already shows.
            workspace_dir=workspace_dir,
            branding=branding,
            client_cover_html=client_cover_html,
            client_back_html=client_back_html,
            client_logo_data_uri=client_logo_data_uri,
            composition_seams_enabled=composition_seams_enabled,
            cover_title=cover_title,
            cover_subtitle=cover_subtitle,
            is_sample=is_sample,
        )
        output_path.write_bytes(pdf_bytes)
        # Emit the report HTML as a first-class output alongside the PDF —
        # same report_data/metadata/theme/branding/workspace_dir, built via
        # the shared orchestrator helper so there is no second render path.
        html_str = generate_report_html(
            report_data,
            metadata=metadata,
            report_profile="full",
            frameworks=fw,
            logo_path=None,
            renderer="cytoscape",
            template="premium",
            theme=report_theme,
            workspace_dir=workspace_dir,
            branding=branding,
            client_cover_html=client_cover_html,
            client_back_html=client_back_html,
        )
        output_path.with_suffix(".html").write_text(html_str, encoding="utf-8")
        # Emit the branding-invariant derived-data export (report_model.json)
        # beside the PDF/HTML — opt-in via ``--emit data`` AND gated on the
        # ``data_export`` entitlement, so an un-entitled install that passes
        # ``--emit data`` gets no JSON file rather than an error (mirrors the
        # whitelabel-entitlement posture: silently withhold, never fail the
        # kit). Reuses the SAME ``report_data``/``metadata``/``workspace_dir``/
        # ``fw`` already in scope from the PDF/HTML render above — one
        # derivation, three output formats.
        if "data" in emit:
            from adscan_internal.services.report_branding import (
                entitlement_enabled,
            )

            if entitlement_enabled("data_export"):
                from adscan_internal.pro.reporting.report_model_export import (
                    build_report_model_export,
                )

                model = build_report_model_export(
                    report_data,
                    metadata,
                    workspace_dir=workspace_dir,
                    frameworks=fw,
                )
                (output_path.parent / "report_model.json").write_text(
                    _json.dumps(model, indent=2), encoding="utf-8"
                )
        return len(pdf_bytes)

    return await asyncio.to_thread(_run)


async def _render_kit(
    *,
    staging_dir: Path,
    workspace_dir: Path,
    metadata: dict[str, str],
    items: tuple[_KitItem, ...],
    report_theme: str = _DEFAULT_REPORT_THEME,
    bonus_theme: str = "",
    frameworks: list[str] | None = None,
    branding: str = "cobrand",
    emit: tuple[str, ...] = _DEFAULT_EMIT,
    client_cover_raw: str | None = None,
    client_back_raw: str | None = None,
    client_logo_data_uri: str = "",
    composition_seams_enabled: bool = False,
    is_sample: bool = False,
) -> dict[str, int]:
    """Render the selected kit artefacts in parallel.

    Args:
        staging_dir: Directory where individual PDFs are written.
        workspace_dir: Source workspace (for ``technical_report.json``).
        metadata: Report metadata threaded into the executive PDF.
        items: Subset of ``_KIT`` to render (canonical order preserved).
        report_theme: Visual theme for the Security Assessment Report.
        bonus_theme: Visual theme for the bonus PDFs. Empty string means each
            bonus renders with its OWN catalog theme (the warm-bone editorial
            for playbook/checklist, white for coverage) — the decoupled
            default. A non-empty value (set only when the operator passes an
            explicit ``--theme``/``--report-theme``) overrides every bonus so
            the whole kit shares one skin.
        emit: Output formats for the Security Assessment Report (see
            :func:`_parse_emit`). Only consumed by the assessment item — the
            bonus artefacts are unaffected.
        client_cover_raw: The raw ``--client-cover`` value (a file OR a
            directory of ``cover-<slug>.html`` per-deliverable fragments), or
            ``None``. Resolved PER deliverable via
            :func:`resolve_seam_fragment_for_slug`, so each kit PDF can carry
            its own cover. Composition-seams entitlement-gated downstream.
        client_back_raw: The raw ``--client-back`` value (a file OR a directory
            of ``back-<slug>.html`` fragments), or ``None``. Resolved per
            deliverable the same way. Same gate.
        client_logo_data_uri: The client logo already resolved to a
            ``data:`` URI. The running per-page logo header/footer is a
            PDF-engine concern applied to every deliverable.
        composition_seams_enabled: Whether the install carries the
            ``composition_seams`` entitlement. Same gate as the cover/back
            seams. Only consumed by the assessment item.
        is_sample: Stamp the public-sample watermark on every artefact. Set
            only by :file:`scripts/regenerate_samples.py`, so the published
            example kit is rendered by this function rather than by a second
            copy of it that can drift from what delivery ships. ``False`` for
            every delivery.

    Returns:
        Mapping ``{filename: byte_size}`` for the rendered artefacts.
    """
    staging_dir.mkdir(parents=True, exist_ok=True)
    tasks: list[Any] = []
    for item in items:
        out_path = staging_dir / item.filename
        # Resolve the cover/back fragment PER deliverable: a single-file
        # ``--client-cover`` yields the same fragment for every item (the DFY
        # default), a directory yields this item's own ``cover-<slug>.html``
        # (or the shared ``cover.html`` fallback).
        item_cover_html = resolve_seam_fragment_for_slug(
            client_cover_raw, item.slug, kind="cover"
        )
        item_back_html = resolve_seam_fragment_for_slug(
            client_back_raw, item.slug, kind="back"
        )
        if item.bonus_key is None:
            tasks.append(
                _render_assessment_async(
                    out_path,
                    workspace_dir,
                    metadata,
                    report_theme=report_theme,
                    frameworks=frameworks,
                    branding=branding,
                    emit=emit,
                    client_cover_html=item_cover_html,
                    client_back_html=item_back_html,
                    client_logo_data_uri=client_logo_data_uri,
                    composition_seams_enabled=composition_seams_enabled,
                    cover_title=item.cover_title,
                    cover_subtitle=item.cover_subtitle,
                    is_sample=is_sample,
                )
            )
        else:
            tasks.append(
                _render_bonus_async(
                    item.bonus_key,
                    out_path,
                    workspace_dir,
                    theme=bonus_theme,
                    frameworks=frameworks,
                    branding=branding,
                    client_cover_html=item_cover_html,
                    client_back_html=item_back_html,
                    client_logo_data_uri=client_logo_data_uri,
                    composition_seams_enabled=composition_seams_enabled,
                    cover_title=item.cover_title,
                    cover_subtitle=item.cover_subtitle,
                    is_sample=is_sample,
                )
            )
    # ``return_exceptions=True`` so one broken renderer cannot mask the others:
    # the operator gets every deliverable that failed in a single message
    # instead of re-running to discover the next one. A failure here aborts the
    # kit — a requested deliverable is never quietly dropped, and with a staging
    # directory per run there is no earlier copy to fall back on anyway.
    outcomes = await asyncio.gather(*tasks, return_exceptions=True)
    failures = [
        (item.filename, outcome)
        for item, outcome in zip(items, outcomes)
        if isinstance(outcome, BaseException)
    ]
    if failures:
        for filename, exc in failures:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_error(f"{filename} failed to render: {exc}")
        raise KitArtifactError(
            "The kit was not packaged: "
            + ", ".join(filename for filename, _ in failures)
            + " failed to render. Fix the cause and re-run; shipping the kit "
            "without a requested deliverable is not an option."
        )
    return {
        item.filename: outcome if isinstance(outcome, int) else 0
        for item, outcome in zip(items, outcomes)
    }


def _generate_affected_assets_appendix(
    *,
    staging_dir: Path,
    workspace_dir: Path,
) -> tuple[str, ...]:
    """Write the consolidated affected-assets appendix into ``staging_dir``.

    Emits ``affected_assets_appendix.csv`` and ``affected_assets_appendix.json``
    carrying the COMPLETE, untruncated affected-asset set for every finding —
    the full machine-readable record the capped inline PDF lists point at. The
    data is sourced from the SAME affected-assets SSOT the PDFs use (loaded the
    same way as the assessment report), so the appendix and the PDF inline lists
    cannot diverge. Best-effort: a failure here never aborts the kit.

    Returns the bundled filenames (added flat to the kit ZIP), or ``()`` when
    the appendix could not be produced.
    """
    try:
        from adscan_internal.pro.reporting.affected_assets_exports import (
            write_affected_assets_appendix,
        )
        from adscan_internal.pro.reporting.report_builder import (
            build_report_data_from_raw,
        )
        from adscan_internal.pro.services.report_service import (
            ensure_report_attack_paths,
        )

        report_json = workspace_dir / "technical_report.json"
        if not report_json.is_file():
            print_warning(
                "Affected-assets appendix skipped: technical_report.json not found."
            )
            return ()
        raw = json.loads(report_json.read_text(encoding="utf-8"))
        report_data = (
            build_report_data_from_raw(raw, workspace_dir=workspace_dir)
            if isinstance(raw, dict)
            else {}
        )
        # Compute + inject attack paths the same way the assessment report does,
        # so the appendix's correlated assets match the PDF exactly.
        ensure_report_attack_paths(report_data, workspace_dir)
        result = write_affected_assets_appendix(report_data, output_dir=staging_dir)
        print_info_debug(
            f"Affected-assets appendix: {int(result['row_count'])} rows "
            f"→ {result['csv_filename']}, {result['json_filename']}"
        )
        return (str(result["csv_filename"]), str(result["json_filename"]))
    except Exception as exc:  # noqa: BLE001 — appendix is best-effort but logged
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_warning(f"Affected-assets appendix skipped: {exc}")
        return ()


def _generate_endpoint_defense_appendix(
    *,
    staging_dir: Path,
    workspace_dir: Path,
) -> tuple[str, ...]:
    """Write the per-host endpoint-defense appendix into ``staging_dir``.

    Emits ``endpoint_defense_appendix.csv``: one row per examined host with the
    state ADscan observed, the products seen, and the credential-extraction
    techniques run against it. The report tables only the hosts needing
    attention (the examined population scales with how far the engagement's
    credentials reach, so it can run to thousands), and this is the complete
    record those bounded lists point at. Sourced from the SAME recorded block
    and the SAME shared view the report renders, so the two cannot diverge.

    Best-effort: a failure here never aborts the kit. Returns ``()`` when no
    domain recorded a block, so a scan that examined nothing ships no file
    rather than an empty one.
    """
    try:
        from adscan_internal.pro.reporting.endpoint_defense_appendix import (
            write_endpoint_defense_appendix,
        )
        from adscan_internal.pro.reporting.report_builder import (
            build_report_data_from_raw,
        )

        report_json = workspace_dir / "technical_report.json"
        if not report_json.is_file():
            return ()
        raw = json.loads(report_json.read_text(encoding="utf-8"))
        report_data = (
            build_report_data_from_raw(raw, workspace_dir=workspace_dir)
            if isinstance(raw, dict)
            else {}
        )
        result = write_endpoint_defense_appendix(report_data, output_dir=staging_dir)
        if result is None:
            return ()
        print_info_debug(
            f"Endpoint-defense appendix: {int(result['row_count'])} rows "
            f"\u2192 {result['csv_filename']}"
        )
        return (str(result["csv_filename"]),)
    except Exception as exc:  # noqa: BLE001 — appendix is best-effort but logged
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_warning(f"Endpoint-defense appendix skipped: {exc}")
        return ()


# ---------------------------------------------------------------------------
# Staging — one run owns one directory, exclusively
# ---------------------------------------------------------------------------
#
# The kit used to render into a single shared ``<deliverables>/staging`` that
# was never pruned, and packaging bundled whatever sat at each expected
# filename. Any artefact a run did not produce — because its render was
# skipped, because the operator narrowed the selection, or because the format
# is opt-in — was therefore served from whatever an EARLIER run had left
# behind. That shipped a kit whose Hardening Playbook quoted a different
# number of reachable routes than the Security Assessment Report beside it,
# and, in steady state, a ``report_model.json`` describing a different scan
# and a different compliance framework than the PDFs it travelled with.
#
# The fix is topological rather than procedural: a run renders into its OWN
# freshly-created directory under ``staging/``, so "this file is from this
# run" is a property of WHERE it lives and nothing has to remember to
# invalidate anything. A freshness heuristic on a shared directory was
# rejected: the only signals available are mtimes, and ADscan deliberately
# STEPS the host wall clock mid-engagement to sync with the DC (see
# CLAUDE.md § Clock and time constraints), so an mtime comparison against a
# run-start timestamp is not sound here. A per-run directory also keeps every
# earlier kit's files intact, which matters because the web Enterprise
# product serves individual kit files by the path recorded in that kit's
# manifest — overwriting in place made a download from kit A stream kit B's
# bytes.


#: Directory-name prefix for a per-run staging directory under ``staging/``.
_KIT_RUN_DIR_PREFIX: str = "run-"

#: Machine contract on STDOUT. ``deliver`` announces the manifest of the kit it
#: just produced as ``ADSCAN_KIT_MANIFEST=<absolute path>`` on its own line, so
#: a caller that captures stdout reads ITS OWN output instead of the shared
#: ``deliverables/manifest.json`` pointer. That matters for the Enterprise web,
#: which can run two kit-producing flows against one workspace (reporting
#: requested at scan launch, and requested again after the scan finishes): the
#: worker reads the pointer AFTER its own deliver returns, so a deliver that
#: lands in between would otherwise be filed against the wrong kit row.
#:
#: Mirrored by ``appliance/celery/adscan_celery/tasks.py`` (lockstep per
#: CLAUDE.md § adscan_web) and locked by a contract test. No square brackets:
#: Rich parses those as markup. Grep-stable; append-only.
KIT_MANIFEST_ANNOUNCE_PREFIX: str = "ADSCAN_KIT_MANIFEST="

#: Filename suffixes a kit's ZIP and its own manifest carry after the stamp.
#: The ZIP keeps the ``-adscan-kit.zip`` tail it has always had, so an operator
#: (and a mail filter, and a customer's archive) still recognises it.
_KIT_ZIP_SUFFIX: str = "-adscan-kit.zip"
_KIT_MANIFEST_SUFFIX: str = "-manifest.json"

#: The run stamp: UTC, ISO-ordered, second-resolution. Readable as a date at a
#: glance (it keeps the ``YYYY-MM-DD`` prefix the ZIP name has always shown)
#: and lexicographically chronological, so sorting names sorts by time.
_KIT_RUN_STAMP_FORMAT: str = "%Y-%m-%dT%H%M%SZ"

#: Stamp formats a run directory may carry, newest convention first. The second
#: is the pre-upgrade format, still on disk in workspaces that delivered before
#: the per-kit naming landed; it is parsed so pruning can order a mixed set
#: chronologically instead of alphabetically (which would prune the NEWEST).
_KIT_RUN_STAMP_FORMATS: tuple[str, ...] = (_KIT_RUN_STAMP_FORMAT, "%Y%m%dT%H%M%SZ")

#: How many per-run staging directories to keep under ``<deliverables>/staging``.
#: Older ones are pruned when a new run opens, so an appliance that delivers
#: daily does not grow without bound. Override with
#: ``ADSCAN_DELIVER_KEEP_RUNS`` (``0`` disables pruning entirely).
_DEFAULT_KIT_RUN_RETENTION: int = 5


@dataclass(frozen=True)
class _KitStage:
    """One ``deliver`` run's identity: its staging dir, its ZIP, its manifest.

    The staging directory is created empty, so membership is provenance: a
    file inside it was written by THIS run. Every packaging decision reads the
    stage rather than probing a shared path, which is what makes a stale
    artefact unrepresentable instead of merely unlikely.

    The same ``stamp`` names all three artefacts, so a kit is a coherent
    triple on disk (``staging/run-<stamp>/``, ``<stamp>-adscan-kit.zip``,
    ``<stamp>-manifest.json``) and two runs can never land on each other.
    """

    root: Path
    stamp: str
    deliverables_dir: Path

    @property
    def zip_path(self) -> Path:
        """Where this kit's ZIP goes."""
        return self.deliverables_dir / f"{self.stamp}{_KIT_ZIP_SUFFIX}"

    @property
    def manifest_path(self) -> Path:
        """Where this kit's own manifest goes (beside its ZIP).

        Distinct from the root ``deliverables/manifest.json`` pointer, which
        always describes the LATEST kit and is the contract the web/Celery
        side reads. This one stays with its kit forever, so an earlier kit
        remains resolvable after a newer one is built.
        """
        return self.deliverables_dir / f"{self.stamp}{_KIT_MANIFEST_SUFFIX}"

    def path_for(self, filename: str) -> Path:
        """Return the in-stage path a renderer should write ``filename`` to."""
        return self.root / filename

    def produced(self, filename: str) -> bool:
        """Return whether this run produced ``filename``."""
        return (self.root / filename).is_file()

    def require(self, filename: str) -> Path:
        """Return the path to ``filename``, or raise if this run lacks it.

        Raises:
            KitArtifactError: When the run produced no such file.
        """
        path = self.root / filename
        if not path.is_file():
            raise KitArtifactError(
                f"{filename} was not produced by this run "
                f"(expected it in {self.root}). The kit was not packaged: "
                f"shipping an earlier run's copy would put contradictory "
                f"figures in the same deliverable."
            )
        return path

    def size_of(self, filename: str) -> int:
        """Return the byte size of a produced artefact (0 when absent)."""
        path = self.root / filename
        return path.stat().st_size if path.is_file() else 0

    def filter_produced(
        self, names: tuple[str, ...], *, channel: str
    ) -> tuple[str, ...]:
        """Keep only the names this run produced, naming any that it did not.

        For the BEST-EFFORT channels only — the MITRE Navigator bundle and the
        affected-assets appendix, which are documented as never blocking a
        delivery. Dropping one here cannot ship a stale file (an earlier run's
        copy lives in that run's directory, not this one's); it only keeps the
        ZIP and the manifest agreeing on what is actually there. The paid
        deliverables stay strict and go through :meth:`require`.
        """
        kept = tuple(name for name in names if self.produced(name))
        missing = [name for name in names if name not in kept]
        if missing:
            print_warning(
                f"{channel}: {', '.join(missing)} was reported but not written "
                "to this run's staging directory, so it is not in the kit."
            )
        return kept


def _kit_run_retention() -> int:
    """Resolve how many per-run staging directories to keep."""
    raw = (os.environ.get("ADSCAN_DELIVER_KEEP_RUNS") or "").strip()
    if not raw:
        return _DEFAULT_KIT_RUN_RETENTION
    try:
        value = int(raw)
    except ValueError:
        print_warning(
            "ADSCAN_DELIVER_KEEP_RUNS is not an integer; keeping the default "
            f"of {_DEFAULT_KIT_RUN_RETENTION} staging runs."
        )
        return _DEFAULT_KIT_RUN_RETENTION
    return max(value, 0)


def _open_kit_stage(
    staging_root: Path,
    *,
    deliverables_dir: Path | None = None,
    retention: int | None = None,
) -> _KitStage:
    """Open this run's kit identity: its staging dir, its ZIP and manifest names.

    Args:
        staging_root: The stable ``<deliverables>/staging`` directory that
            holds one subdirectory per run. Kept as the parent so the
            documented layout and the workspace-root walk-up in
            ``report_service._resolve_workspace_root_for_output`` still
            resolve.
        deliverables_dir: Where this kit's ZIP and manifest go. Defaults to
            ``staging_root.parent``, which is the layout ``run_deliver``
            builds (``<deliverables>/staging``), not a guess.
        retention: How many run directories to keep (including the new one).
            ``None`` reads :func:`_kit_run_retention`; ``0`` keeps everything.

    Returns:
        A :class:`_KitStage` whose ``root`` is a newly created, empty directory
        and whose stamp is free across the whole deliverables directory.
    """
    deliverables = deliverables_dir or staging_root.parent
    staging_root.mkdir(parents=True, exist_ok=True)
    base = datetime.now(timezone.utc).strftime(_KIT_RUN_STAMP_FORMAT)

    # The stamp must be free for ALL THREE artefacts, not just the staging
    # directory: pruning can free a run directory whose ZIP is still on disk
    # (ZIPs are never pruned), and reusing that stamp would overwrite a kit
    # already delivered to a client.
    suffix = 0
    while True:
        stamp = base if suffix == 0 else f"{base}-{suffix}"
        candidate = staging_root / f"{_KIT_RUN_DIR_PREFIX}{stamp}"
        taken = (
            (deliverables / f"{stamp}{_KIT_ZIP_SUFFIX}").exists()
            or (deliverables / f"{stamp}{_KIT_MANIFEST_SUFFIX}").exists()
        )
        if not taken:
            try:
                candidate.mkdir()
                break
            except FileExistsError:
                pass
        suffix += 1

    stage = _KitStage(root=candidate, stamp=stamp, deliverables_dir=deliverables)
    keep = _kit_run_retention() if retention is None else max(retention, 0)
    _prune_kit_runs(staging_root, keep=keep, active=candidate)
    _warn_about_pre_per_run_artifacts(staging_root)
    return stage


def _kit_run_sort_key(path: Path) -> tuple[datetime, str]:
    """Return a chronological sort key for a per-run staging directory.

    Parses the stamp out of the directory name rather than comparing names as
    strings, because a workspace mid-upgrade holds both stamp conventions and
    they do not sort against each other (``2026-06-01T…`` sorts BEFORE
    ``20260101T…``, which would prune the newest runs and keep the stale ones).
    An unparseable name sorts oldest so it is pruned first, never kept ahead of
    a real run.
    """
    stamp = path.name[len(_KIT_RUN_DIR_PREFIX) :]
    for fmt in _KIT_RUN_STAMP_FORMATS:
        for candidate in (stamp, stamp.rsplit("-", 1)[0]):
            try:
                return (datetime.strptime(candidate, fmt), path.name)
            except ValueError:
                continue
    return (datetime.min, path.name)


def _warn_about_pre_per_run_artifacts(staging_root: Path) -> None:
    """Name any artefacts a pre-per-run build left loose in ``staging_root``.

    Builds before the per-run staging directory rendered straight into
    ``staging/``. Those files can no longer reach a kit, but an operator who
    picks a PDF out of ``staging/`` by hand would still be handing a client an
    old document — which is the failure this whole section exists to prevent.
    So the condition is named once, out loud. The files are never deleted: they
    are the operator's, and some are the only copy of a kit already delivered.
    """
    suffixes = {".pdf", ".html", ".json", ".csv"}
    try:
        loose = sorted(
            path.name
            for path in staging_root.iterdir()
            if path.is_file() and path.suffix.lower() in suffixes
        )
    except OSError:
        return
    if not loose:
        return
    print_warning(
        f"{staging_root} still holds {len(loose)} file(s) from an older build "
        "that rendered directly into it: "
        f"{', '.join(loose[:4])}{' …' if len(loose) > 4 else ''}. "
        "They are NOT part of this kit — each run now stages into its own "
        "subdirectory. Deliver the ZIP, or the files under this run's "
        "subdirectory; delete the loose ones once you no longer need them."
    )


def _prune_kit_runs(staging_root: Path, *, keep: int, active: Path) -> None:
    """Delete the oldest per-run STAGING directories beyond ``keep``.

    Staging is the intermediate; the kit ZIP is the deliverable, and ZIPs are
    NEVER pruned here or anywhere else. A kit already handed to a client must
    stay on disk, so this only reclaims the loose rendered files.

    Ordering is by the UTC stamp parsed out of the directory name
    (:func:`_kit_run_sort_key`) — never by mtime, because ADscan steps the host
    clock mid-engagement. The active run is always retained regardless of
    ``keep``. Best-effort: a failure to prune never blocks a delivery.
    """
    if keep <= 0:
        return
    import shutil

    try:
        runs = sorted(
            (
                path
                for path in staging_root.iterdir()
                if path.is_dir() and path.name.startswith(_KIT_RUN_DIR_PREFIX)
            ),
            key=_kit_run_sort_key,
        )
    except OSError:
        return
    doomed = [path for path in runs[: max(len(runs) - keep, 0)] if path != active]
    for path in doomed:
        try:
            shutil.rmtree(path)
            print_info_debug(f"Pruned old deliverable staging run {path.name}")
        except OSError as exc:
            print_info_debug(f"Could not prune staging run {path.name}: {exc}")


# ---------------------------------------------------------------------------
# Packaging + presentation
# ---------------------------------------------------------------------------


def collect_kit_bundle(
    *,
    stage: _KitStage,
    workspace_dir: Path,
    client: str | None = None,
    engagement: str | None = None,
    include_navigator: bool = True,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Produce the kit's non-PDF companions and confirm what the run wrote.

    Everything a kit carries beside its PDFs is assembled here: the MITRE
    ATT&CK Navigator bundle, the consolidated affected-assets appendix, the
    per-host endpoint-defense appendix, and the report's own HTML twin and
    derived-data export. Each is best-effort by design and each is then
    confirmed against the stage, so the ZIP and the manifest are built from one
    list rather than from two independently-probed ones.

    It is a named function rather than a stretch of ``main`` because the
    published example kit is built from the same sequence. The example kit used
    to be assembled by a separate script that listed its members by hand, and
    it went on shipping three document names the product had renamed or retired
    months earlier. Deriving it from here makes that drift unrepresentable.

    Args:
        stage: This run's staging identity. Membership is provenance, so only
            files this run wrote can reach the kit.
        workspace_dir: Source workspace holding ``technical_report.json``.
        client: Client name stamped into the Navigator layer, when set.
        engagement: Engagement name stamped into the Navigator layer.
        include_navigator: ``False`` skips the Navigator bundle (``deliver
            --no-navigator``).

    Returns:
        ``(extras, flat_bundle)`` — the Navigator filenames, which go into the
        ZIP under ``mitre/``, and the filenames bundled flat beside the PDFs.
    """
    extras: tuple[str, ...] = ()
    if include_navigator:
        extras = _generate_navigator_extras(
            staging_dir=stage.root,
            workspace_dir=workspace_dir,
            client=client,
            engagement=engagement,
        )

    # Consolidated affected-assets appendix (CSV + JSON) — the complete,
    # untruncated record of every finding's affected assets, bundled flat next
    # to the PDFs. Always generated; the PDFs' overflow lines name the CSV.
    appendix = _generate_affected_assets_appendix(
        staging_dir=stage.root,
        workspace_dir=workspace_dir,
    )

    # Per-host endpoint-defense appendix. The report tables only the hosts
    # carrying an action, because the examined population scales with how far
    # the engagement's credentials reach; this carries every examined host, so
    # bounding the PDF costs the client no information. Absent when no domain
    # recorded a block, rather than an empty file that reads as a failed
    # export.
    appendix += _generate_endpoint_defense_appendix(
        staging_dir=stage.root,
        workspace_dir=workspace_dir,
    )

    # The main report's first-class HTML and the optional derived-data export
    # (report_model.json) are written beside the report PDF inside the stage.
    # Bundle them FLAT (top-level, like the appendix) so the kit ZIP carries
    # them and the downstream kit-download consumer surfaces them. Both are
    # conditional — the HTML follows ``--emit html``, the JSON follows
    # ``--emit data`` plus the ``data_export`` entitlement — so the kit asks
    # the stage whether THIS run produced them. The same question used to be
    # asked of a shared directory, which is how a five-day-old export
    # describing another scan ended up in every kit.
    report_outputs = tuple(
        name
        for name in ("Security_Assessment_Report.html", "report_model.json")
        if stage.produced(name)
    )
    # Verify the best-effort channels ONCE, here, so the ZIP and the manifest
    # are built from the same confirmed list. The paid deliverables are not
    # filtered: a missing one fails the run inside ``_package_zip``.
    extras = stage.filter_produced(extras, channel="MITRE ATT&CK Navigator")
    flat_bundle = stage.filter_produced(
        appendix + report_outputs, channel="Kit appendix"
    )
    return extras, flat_bundle


def _package_zip(
    stage: _KitStage,
    zip_path: Path,
    items: tuple[_KitItem, ...],
    extras: tuple[str, ...] = (),
    appendix: tuple[str, ...] = (),
) -> None:
    """Bundle this run's artefacts into ``zip_path``.

    Every name is resolved through :meth:`_KitStage.require`, so the ZIP can
    only ever contain files the current run produced. A name that is missing
    raises :class:`KitArtifactError` BEFORE the archive is opened — a kit is
    either complete or absent, never quietly short by one deliverable and
    never padded with an earlier run's copy.

    ``extras`` is a tuple of filenames the run produced that are not part of
    the canonical PDFs but ship alongside them — the MITRE ATT&CK Navigator
    JSON layer and the interactive HTML bundle. Extras are written into the
    ZIP under a top-level ``mitre/`` folder so the kit stays tidy when the
    client unzips it.

    ``appendix`` is a tuple of filenames (the consolidated affected-assets
    appendix CSV/JSON, the report's HTML twin, the derived-data export)
    bundled FLAT at the top level next to the PDFs — the PDFs reference the
    CSV by its bare name, so it must not be nested.

    Raises:
        KitArtifactError: When any requested artefact is missing from the
            stage.
    """
    members: list[tuple[Path, str]] = [
        (stage.require(item.filename), item.filename) for item in items
    ]
    members += [(stage.require(name), name) for name in appendix]
    members += [(stage.require(extra), f"mitre/{extra}") for extra in extras]

    zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for src, arcname in members:
            zf.write(src, arcname=arcname)


def _write_manifest(
    *,
    manifest_path: Path,
    zip_path: Path,
    stage: _KitStage,
    items: tuple[_KitItem, ...],
    workspace_dir: Path,
    extras: tuple[str, ...] = (),
    appendix: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Write ``manifest.json`` next to the ZIP describing the deliverable.

    The manifest is the contract consumed by the web/Celery task in the
    next batch — keep its shape stable. Returns the dict that was written
    so callers (and tests) can assert against it without re-reading.

    The affected-assets appendix files are listed under the existing
    ``extras`` key with a flat (top-level) ``arcname``, so the web ingestion —
    which already enumerates ``extras`` — picks them up with no schema change.

    Paths point into THIS run's staging directory, which is what lets the web
    keep serving an older kit's files correctly after a newer kit is built.
    """
    selection = {slug: (slug in {it.slug for it in items}) for slug in _VALID_SLUGS}

    files: list[dict[str, Any]] = []
    for item in items:
        path = stage.path_for(item.filename)
        files.append(
            {
                "slug": item.slug,
                "name": item.filename,
                "title": item.title,
                "size": stage.size_of(item.filename),
                "path": str(path),
            }
        )

    extra_files: list[dict[str, Any]] = []
    for name in appendix:
        extra_files.append(
            {
                "name": name,
                "size": stage.size_of(name),
                "path": str(stage.path_for(name)),
                "arcname": name,
            }
        )
    for extra in extras:
        extra_files.append(
            {
                "name": extra,
                "size": stage.size_of(extra),
                "path": str(stage.path_for(extra)),
                "arcname": f"mitre/{extra}",
            }
        )

    manifest: dict[str, Any] = {
        "manifest_version": 2,
        # Per RUN, not per day: two kits built the same day are two different
        # kits, and a day-granular id made two manifests claim to describe the
        # same one. The DB keys kit rows on their own UUID, so nothing breaks;
        # what this buys is that a manifest and a row can be correlated.
        "kit_id": f"{workspace_dir.name}-{stage.stamp}",
        "workspace": workspace_dir.name,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "selection": selection,
        "zip": str(zip_path),
        "files": files,
        "extras": extra_files,
    }
    payload = json.dumps(manifest, indent=2)

    # Written twice from ONE dict, so the two copies cannot disagree:
    #   * beside its own ZIP, where it stays for good, so an earlier kit is
    #     still resolvable after a newer one is built;
    #   * at the root ``deliverables/manifest.json``, the documented contract
    #     the Celery worker reads immediately after ``adscan deliver`` and
    #     persists, which therefore always describes the LATEST kit.
    for destination in (stage.manifest_path, manifest_path):
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(payload, encoding="utf-8")
    return manifest


def _announce_kit_manifest(stage: _KitStage) -> None:
    """Print the ``ADSCAN_KIT_MANIFEST=`` line for the kit just produced.

    See :data:`KIT_MANIFEST_ANNOUNCE_PREFIX`. Emitted on stdout through the
    shared console (so it also lands in the session recording) with markup
    parsing and highlighting OFF and soft wrapping ON: a long absolute path
    must arrive on ONE line, because a wrapped path is an unparseable path,
    and markup parsing on a filesystem path is the documented crash in
    CLAUDE.md § "Square brackets in log/print messages".
    """
    from adscan_core.output._state import get_console

    get_console().print(
        f"{KIT_MANIFEST_ANNOUNCE_PREFIX}{stage.manifest_path}",
        soft_wrap=True,
        markup=False,
        highlight=False,
    )


def _format_size(num_bytes: int) -> str:
    """Return a human-readable size string (KB / MB)."""
    if num_bytes >= 1_000_000:
        return f"{num_bytes / 1_000_000:.1f} MB"
    return f"{num_bytes / 1024:.0f} KB"


# ---------------------------------------------------------------------------
# MITRE ATT&CK Navigator extras — bundled into every PRO kit by default.
# Hormozi rationale: the interactive HTML is the SOC-facing artefact and
# the JSON layer opens in MITRE's own free Navigator UI. Bundling both in
# the same ZIP collapses two operator gestures into one and makes the
# kit a single shareable unit (PDF for the board + HTML for the SOC +
# JSON for the detection engineer). Generated in the staging dir and
# packaged under ``mitre/`` inside the ZIP.
# ---------------------------------------------------------------------------


_NAVIGATOR_LAYER_FILE: str = "navigator-layer.json"
_NAVIGATOR_HTML_FILE: str = "navigator.html"
_NAVIGATOR_DIFF_FILE: str = "navigator-diff-layer.json"


def _generate_navigator_extras(
    *,
    staging_dir: Path,
    workspace_dir: Path,
    client: str | None,
    engagement: str | None,
) -> tuple[str, ...]:
    """Render the Navigator layer + interactive HTML + (optional) diff.

    Reads ``technical_report.json`` from ``workspace_dir``, builds the
    PRO-watermarked Navigator layer, snapshots it into the workspace
    history, and renders the interactive HTML bundle. When a previous
    history snapshot exists, also emits a diff layer.

    Errors are swallowed: the kit must still ship if the navigator
    extras fail. Failures are logged via telemetry and surfaced as
    warnings to the operator.

    Returns:
        Tuple of filenames written into ``staging_dir`` (later passed to
        ``_package_zip`` as ``extras``). Empty tuple on failure.
    """
    # Lazy imports — keeps the deliver module's import surface small and
    # isolates failures in the navigator stack from the four PDFs.
    from adscan_internal.cli.mitre_navigator import (
        _previous_snapshot,
        _save_history_snapshot,
    )
    from adscan_internal.pro.reporting.mitre_navigator_html import (
        build_interactive_html,
    )
    from adscan_internal.pro.reporting.report_builder import (
        build_report_data_from_raw,
    )
    from adscan_internal.services.mitre_navigator import (
        WATERMARK_PRO,
        build_diff_layer,
        build_navigator_layer,
    )

    report_path = workspace_dir / "technical_report.json"
    if not report_path.is_file():
        print_warning(
            "MITRE navigator artefacts skipped: "
            "technical_report.json not found in workspace."
        )
        return ()

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_warning(f"MITRE navigator artefacts skipped: {exc}")
        return ()

    # Normalize the raw report so the navigator sees synthesized
    # ``vulnerabilities`` maps (the raw JSON stores them empty -- the same
    # root cause that made the compliance section render ~100% conformant).
    # Without this the navigator layer was always empty of techniques.
    report_data = (
        build_report_data_from_raw(report, workspace_dir=workspace_dir)
        if isinstance(report, dict)
        else {}
    )

    # Pick the domain with the MOST findings rather than the first non-empty
    # one, so a multi-domain kit targets the domain that actually carries the
    # exposure (e.g. essos.local over a near-clean child domain).
    def _vuln_count(value: object) -> int:
        if not isinstance(value, dict):
            return 0
        vulns = value.get("vulnerabilities")
        return len(vulns) if isinstance(vulns, dict) else 0

    domain: str | None = (
        max(report_data, key=lambda k: _vuln_count(report_data[k]), default=None)
        if report_data
        else None
    )
    if domain is not None and _vuln_count(report_data.get(domain)) == 0:
        domain = None

    extra_meta: dict[str, str] = {
        "assessment_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
    }
    if engagement:
        extra_meta["engagement"] = engagement
    if client:
        extra_meta["client"] = client

    try:
        layer = build_navigator_layer(
            report_data,
            domain=domain,
            watermark=WATERMARK_PRO,
            extra_metadata=extra_meta,
        )
    except Exception as exc:  # noqa: BLE001 — best-effort, kit must still ship
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_warning(f"MITRE navigator layer build failed: {exc}")
        return ()

    written: list[str] = []
    staging_dir.mkdir(parents=True, exist_ok=True)

    layer_path = staging_dir / _NAVIGATOR_LAYER_FILE
    layer_path.write_text(json.dumps(layer, indent=2, sort_keys=True), encoding="utf-8")
    written.append(_NAVIGATOR_LAYER_FILE)

    # Diff vs previous workspace snapshot (if any).
    history_dir = workspace_dir / "mitre" / "history"
    previous_snapshot_path = _previous_snapshot(history_dir)
    previous_layer: dict[str, Any] | None = None
    diff_layer: dict[str, Any] | None = None
    if previous_snapshot_path is not None:
        try:
            previous_layer = json.loads(
                previous_snapshot_path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_warning(
                f"Could not read previous Navigator snapshot {previous_snapshot_path}: {exc}"
            )
            previous_layer = None
    if previous_layer is not None:
        try:
            diff_layer = build_diff_layer(layer, previous_layer, domain=domain)
            diff_path = staging_dir / _NAVIGATOR_DIFF_FILE
            diff_path.write_text(
                json.dumps(diff_layer, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            written.append(_NAVIGATOR_DIFF_FILE)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_warning(f"Navigator diff layer build failed: {exc}")

    # Interactive HTML bundle.
    try:
        html = build_interactive_html(
            layer,
            domain=domain,
            engagement=engagement,
            client=client,
            diff_layer=diff_layer,
            previous_layer=previous_layer,
        )
        html_path = staging_dir / _NAVIGATOR_HTML_FILE
        html_path.write_text(html, encoding="utf-8")
        written.append(_NAVIGATOR_HTML_FILE)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_warning(f"Navigator interactive HTML failed: {exc}")

    # Snapshot the layer into history so the *next* deliver run can diff.
    try:
        _save_history_snapshot(history_dir, layer)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_warning(f"Could not snapshot Navigator history: {exc}")

    # Lightweight telemetry — Hormozi: instrument what matters before
    # iterating. Tracks bundle adoption without leaking customer data.
    try:
        telemetry.capture(
            "deliver.navigator_bundled",
            {
                "techniques": len(layer.get("techniques", [])),
                "has_diff": diff_layer is not None,
                "has_html": _NAVIGATOR_HTML_FILE in written,
                "watermark": "pro",
            },
        )
    except Exception:  # noqa: BLE001 — telemetry must never break the kit
        pass

    return tuple(written)


def _render_closing_panel(
    *,
    sizes: dict[str, int],
    zip_path: Path,
    items: tuple[_KitItem, ...],
    extras: tuple[str, ...] = (),
    stage: _KitStage | None = None,
) -> None:
    """Render the premium kit-ready panel — eyebrow caps, mono paths.

    The four canonical PDFs are listed first; MITRE Navigator extras
    (when bundled) appear under a separate "BONUS · MITRE ATT&CK" eyebrow
    so the operator sees at a glance what the client will unzip.
    """
    from rich.console import Group
    from rich.table import Table
    from rich.text import Text

    eyebrow = Text(
        "CLIENT DELIVERABLE KIT · READY TO SHIP",
        style="bold bright_cyan",
    )

    table = Table.grid(padding=(0, 2))
    table.add_column(justify="left")
    table.add_column(justify="right")
    for item in items:
        size = sizes.get(item.filename, 0)
        table.add_row(
            Text(item.filename, style="bright_cyan on grey11"),
            Text(_format_size(size) if size else "—", style="dim"),
        )

    blocks: list[Any] = [eyebrow, Text(""), table]

    if extras and stage is not None:
        extras_eyebrow = Text(
            "BONUS · MITRE ATT&CK NAVIGATOR (mitre/)",
            style="bold bright_magenta",
        )
        extras_table = Table.grid(padding=(0, 2))
        extras_table.add_column(justify="left")
        extras_table.add_column(justify="right")
        for extra in extras:
            size = stage.size_of(extra)
            extras_table.add_row(
                Text(f"mitre/{extra}", style="bright_magenta on grey11"),
                Text(_format_size(size) if size else "—", style="dim"),
            )
        blocks.extend([Text(""), extras_eyebrow, Text(""), extras_table])

    zip_line = Text()
    zip_line.append("ZIP:  ", style="bold")
    zip_line.append(str(zip_path), style="bright_cyan on grey11")

    final = Text("Kit ready. Hand it to your client.", style="bold")

    blocks.extend([Text(""), zip_line, Text(""), final])
    print_panel(Group(*blocks), border_style="bright_cyan", padding=(1, 2))


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


async def run_deliver(args: argparse.Namespace) -> int:
    """Orchestrate playbook + checklist + coverage_matrix + executive assessment.

    Args:
        args: argparse namespace; honours ``--workspace``, ``--client``,
            ``--engagement``, ``--output``, ``--only``.

    Returns:
        Process exit code: ``0`` on success, ``1`` on failure, ``2`` on
        usage error (LITE invocation, no workspace, invalid ``--only``).
    """
    if not tier.is_pro():
        # Use the canonical helper so we don't double-wrap the panel
        # (``print_panel`` adds its own border around the already-bordered
        # panel returned by the renderer). Single source of truth lives
        # in ``adscan_core.pro_upsell.print_pro_upsell``. This is a
        # peak-value commercial gate (a LITE operator reached for a PRO
        # deliverable), so it routes by operator lane exactly like the
        # launcher's PRO gate — a buyer role sees the Enterprise body, not
        # the pentester /pro CTA.
        from adscan_core.operator_role import resolve_cta_lane
        from adscan_core.pro_upsell import print_pro_upsell

        print_pro_upsell("deliver", "direct_invocation", lane=resolve_cta_lane())
        return 2

    try:
        items = _parse_only(getattr(args, "only", None))
    except ValueError as exc:
        print_error(str(exc))
        return 2

    try:
        emit = _parse_emit(getattr(args, "emit", None))
    except ValueError as exc:
        print_error(str(exc))
        return 2

    # Resolve interactive inputs in the order an operator naturally thinks
    # about a delivery: which scan → who is the client → what compliance
    # → how it looks. Each helper is idempotent and silently picks defaults
    # in non-interactive contexts, so this order also degrades cleanly in
    # ``adscan ci`` and other CI gates.
    workspace_dir = _resolve_workspace(args)
    if workspace_dir is None or not workspace_dir.is_dir():
        print_error(
            "No workspace available. Run 'adscan start' first, or pass --workspace WS."
        )
        return 2

    # Reconcile the workspace's findings against its attack graph ONCE, before
    # anything reads ``technical_report.json`` — the supportability filter below,
    # the assessment report, the bonuses and the affected-assets appendix all
    # render in parallel off the same file. The per-save sync during a scan
    # normally leaves the two artifacts in agreement; this is the backstop for a
    # workspace produced by an earlier build, so the kit can never ship a
    # finding count that contradicts the attack paths in the same document.
    from adscan_internal.services.attack_graph_findings import (
        reconcile_workspace_attack_graph_findings,
    )

    reconcile_workspace_attack_graph_findings(str(workspace_dir))

    client, engagement = _resolve_client_meta(args)

    # Persist the client logo (flag or picked in the sync prefill) so the report
    # cover co-brands and later runs reuse it. Best-effort; never blocks delivery.
    _resolve_and_persist_client_logo(args)

    items = _drop_unsupportable_items(items, workspace_dir)
    if not items:
        print_error(
            "This workspace carries no data for the selected deliverables. "
            "Widen the selection with --only, or run a scan against the domain first."
        )
        return 2

    try:
        frameworks = _resolve_frameworks(args)
    except ValueError as exc:
        print_error(str(exc))
        return 2
    # Use the client name as the workspace display name when provided so the
    # cover title reads "Acme Corp Security Report" rather than the internal
    # workspace directory name (e.g. "Goad-example").
    display_name = client or workspace_dir.name
    metadata: dict[str, str] = {
        "workspace_name": display_name,
        "report_date": time.strftime("%B %d, %Y"),
        "report_type": "Active Directory Security Assessment",
        "report_version": get_version(),
        "client_name": client or "",
        "engagement_id": engagement or "",
    }
    # Tell the Security Assessment Report whether the AD Password Hygiene Report
    # is shipping alongside it IN THIS KIT, so the SAR cross-references it ONLY
    # when it was actually produced (a pointer to a document that does not exist
    # is the same defect class as a placeholder leak). The standalone
    # ``adscan report`` path never sets this, so it renders no pointer.
    if any(item.slug == "password-hygiene" for item in items):
        metadata["password_hygiene_companion"] = "1"

    deliverables_dir = workspace_dir / "deliverables"
    output_override = getattr(args, "output", None)
    if output_override:
        deliverables_dir = Path(output_override).expanduser().resolve()
    staging_root = deliverables_dir / "staging"
    # The ZIP name comes from the run's own stamp (resolved with the stage,
    # below) so two delivers on one day are two kits. ``manifest.json`` at the
    # root stays exactly where it is: the Celery worker reads that path to find
    # its own output, so it is a contract, not a convenience.
    manifest_path = deliverables_dir / "manifest.json"

    # Resolve the report theme via the canonical precedence chain — flags
    # → env var → questionary picker (TTY only) → default. Keeping this in
    # ``_resolve_theme`` mirrors ``_resolve_frameworks`` and gives the
    # operator one place to look when the kit ships with the wrong skin.
    report_theme = _resolve_theme(args)

    # Decouple the bonus skin from the report skin. By default the bonuses
    # render with their OWN editorial catalog theme (warm-bone playbook /
    # checklist, white coverage) — passing an empty ``bonus_theme`` tells
    # ``render_bonus`` to fall back to ``BONUSES[key]["theme"]``. Only when the
    # operator explicitly chose a theme (``--theme`` / ``--report-theme`` /
    # ``ADSCAN_PDF_THEME``) do we force that one skin across the whole kit.
    # ``_prefill_interactive_inputs`` stashes this before folding the resolved
    # theme back into ``args.theme`` (which would otherwise make the inline
    # check always true). Fall back to the inline computation when prefill did
    # not run (defensive — every real path goes through ``run_deliver_sync``).
    explicit_theme_set = getattr(args, "_explicit_theme_set", None)
    if explicit_theme_set is None:
        explicit_theme_set = bool(
            (getattr(args, "theme", "") or "").strip()
            or (getattr(args, "report_theme", "") or "").strip()
            or os.environ.get("ADSCAN_PDF_THEME", "").strip()
        )
    bonus_theme = report_theme if explicit_theme_set else ""

    # Composition seams (--client-cover / --client-back): read the operator's
    # fragment files up front, best-effort (a missing/unreadable file warns
    # and degrades to the default page — see the helper). The entitlement
    # itself is checked again, authoritatively, inside the render pipeline
    # (html_pdf_generator._build_context); this early check only gives the
    # operator a clearer signal when they asked for a seam their install
    # cannot use, instead of a silently-unchanged PDF.
    # Keep the RAW arg values — each may be a single fragment FILE (the DFY
    # default: one cover brands every deliverable) OR a DIRECTORY of per-slug
    # fragments (``cover-<slug>.html`` / ``back-<slug>.html``). The actual
    # per-deliverable resolution happens inside ``_render_kit`` so each kit PDF
    # can carry its own cover/back.
    client_cover_raw = (getattr(args, "client_cover", None) or "").strip()
    client_back_raw = (getattr(args, "client_back", None) or "").strip()
    from adscan_internal.services.report_branding import entitlement_enabled

    composition_seams_enabled = entitlement_enabled("composition_seams")
    if (client_cover_raw or client_back_raw) and not composition_seams_enabled:
        print_warning(
            "--client-cover/--client-back supplied, but this install does "
            "not carry the composition_seams entitlement. Rendering the "
            "default cover/back page."
        )

    # Running per-page client-logo header/footer: the SAME entitlement and
    # the SAME already-resolved logo the cover page co-brands with (single
    # resolver, no second logo lookup) — the orchestrator itself degrades to
    # the unchanged default engine options when not entitled or no logo set.
    from adscan_internal.services.client_logo import resolve_client_logo_data_uri

    client_logo_data_uri = resolve_client_logo_data_uri(
        getattr(args, "client_logo", None)
    )

    print_info(f"Rendering Client Deliverable Kit for {workspace_dir.name}…")
    # State the compliance scope out loud, including when it is empty. A kit
    # that quietly omits its paid-tier compliance mapping is how one ships
    # without it and nobody notices.
    announce_compliance_scope(
        resolve_compliance_scope(
            explicit=frameworks, workspace_dir=workspace_dir
        )
    )
    # Open this run's own staging directory. Everything below writes into it
    # and reads back out of it, so the kit can only contain artefacts this run
    # produced — see the § Staging block above for why this is a directory per
    # run rather than a freshness check on a shared one.
    try:
        stage = _open_kit_stage(staging_root, deliverables_dir=deliverables_dir)
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(f"Could not prepare the deliverables staging directory: {exc}")
        return 1
    zip_path = stage.zip_path

    try:
        sizes = await _render_kit(
            staging_dir=stage.root,
            workspace_dir=workspace_dir,
            metadata=metadata,
            items=items,
            report_theme=report_theme,
            bonus_theme=bonus_theme,
            frameworks=frameworks,
            branding=_resolve_branding_posture(args).value,
            emit=emit,
            client_cover_raw=client_cover_raw,
            client_back_raw=client_back_raw,
            client_logo_data_uri=client_logo_data_uri,
            composition_seams_enabled=composition_seams_enabled,
        )
    except KitArtifactError as exc:
        # Each failing deliverable was already reported individually inside
        # ``_render_kit``; this is the summary line and the non-zero exit.
        print_error(str(exc))
        return 1
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(f"Kit generation failed: {exc}")
        return 1

    extras, flat_bundle = collect_kit_bundle(
        stage=stage,
        workspace_dir=workspace_dir,
        client=client,
        engagement=engagement,
        include_navigator=not getattr(args, "no_navigator", False),
    )

    try:
        _package_zip(stage, zip_path, items, extras, flat_bundle)
    except KitArtifactError as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(str(exc))
        return 1
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(f"Could not package ZIP: {exc}")
        return 1

    try:
        _write_manifest(
            manifest_path=manifest_path,
            zip_path=zip_path,
            stage=stage,
            items=items,
            workspace_dir=workspace_dir,
            extras=extras,
            appendix=flat_bundle,
        )
        _announce_kit_manifest(stage)
    except Exception as exc:  # noqa: BLE001 — manifest is best-effort but logged
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_warning(f"Manifest could not be written: {exc}")

    _render_closing_panel(
        sizes=sizes,
        zip_path=zip_path,
        items=items,
        extras=extras,
        stage=stage,
    )
    print_success(f"Kit packaged at {zip_path}")

    # Stash the headline artefact (the Security Assessment Report — full
    # profile). The "open it now?" prompt is fired by ``run_deliver_sync``
    # AFTER the event loop exits: ``prompt_and_open`` spins a
    # prompt_toolkit Application that leaks a coroutine if run inside
    # ``asyncio.run``'s running loop.
    # ``adscan ci`` reads this back off the namespace for its single-PDF
    # artifact plumbing, so it never has to reconstruct a staging path (the
    # path is per-run now). On-disk consumers resolve the same artefact
    # through ``manifest.json``, which is the published contract.
    headline_name = "Security_Assessment_Report.pdf"
    if stage.produced(headline_name):
        setattr(args, "_headline_pdf", str(stage.path_for(headline_name)))

    return 0


def add_deliver_subparser(
    subparsers: argparse._SubParsersAction,
) -> argparse.ArgumentParser:
    """Register the ``deliver`` subparser on the main argparse tree."""
    parser = subparsers.add_parser(
        "deliver",
        help="Generate the full Client Deliverable Kit (4 PDFs + ZIP).",
        description=(
            "Render the four PRO PDFs in parallel and package them into a "
            "single ZIP under <workspace>/deliverables/. PRO only."
        ),
    )
    parser.add_argument(
        "--workspace",
        dest="workspace",
        default=None,
        help="Workspace name or path (default: prompt or active workspace).",
    )
    parser.add_argument(
        "--client",
        dest="client",
        default=None,
        help="Client name (optional, embedded in metadata).",
    )
    parser.add_argument(
        "--engagement",
        dest="engagement",
        default=None,
        help="Engagement code (optional, embedded in metadata).",
    )
    parser.add_argument(
        "--output",
        dest="output",
        default=None,
        help="Override the deliverables output directory.",
    )
    parser.add_argument(
        "--client-logo",
        dest="client_logo",
        default=None,
        metavar="PATH",
        help=(
            "Client logo (PNG/SVG/JPG) placed beside the ADscan mark on the "
            "report cover. Persisted and reused on later runs. The ADscan mark "
            "is kept; suppressing it (full white-label) is a separate paid tier."
        ),
    )
    parser.add_argument(
        "--client-cover",
        dest="client_cover",
        default=None,
        metavar="PATH",
        help=(
            "HTML fragment file that REPLACES ADscan's own cover page verbatim "
            "on EVERY kit deliverable (each filled with that PDF's own title). "
            "PATH may instead be a DIRECTORY of per-deliverable fragments "
            "(cover-<slug>.html, else a shared cover.html fallback). Requires "
            "the composition_seams entitlement; an un-entitled install ignores "
            "this flag and renders the default cover."
        ),
    )
    parser.add_argument(
        "--client-back",
        dest="client_back",
        default=None,
        metavar="PATH",
        help=(
            "HTML fragment file rendered as a closing back page on EVERY kit "
            "deliverable. PATH may instead be a DIRECTORY of per-deliverable "
            "fragments (back-<slug>.html, else a shared back.html fallback). "
            "Requires the composition_seams entitlement; an un-entitled install "
            "ignores this flag."
        ),
    )
    parser.add_argument(
        "--only",
        dest="only",
        type=str,
        default=None,
        help=(
            "Comma-separated list of deliverables to generate. "
            f"Choices: report, {', '.join(s for s in _VALID_SLUGS if s != 'executive')}. "
            "Default: all four. ('executive' kept as a deprecated alias for 'report'.)"
        ),
    )
    parser.add_argument(
        "--frameworks",
        dest="frameworks",
        type=str,
        default=None,
        help=(
            "Comma-separated compliance frameworks to render in the kit. "
            f"Choices: {', '.join(_VALID_FRAMEWORK_KEYS)}. "
            "When omitted, an interactive checkbox prompts in TTY contexts; "
            "non-interactive runs include no compliance section unless one is "
            "selected explicitly."
        ),
    )
    parser.add_argument(
        "--no-navigator",
        dest="no_navigator",
        action="store_true",
        help=(
            "Skip the MITRE ATT&CK Navigator extras (JSON layer + "
            "interactive HTML + diff). Default: included in every kit."
        ),
    )
    # NOTE on theme validation: we deliberately do NOT use argparse
    # ``choices=`` here. Only the two SUPPORTED, homogeneous kit themes
    # (``editorial`` / ``corporate_light``) are advertised via ``metavar`` and
    # the help text. ``premium_dark`` (and its ``dark`` alias) remain ACCEPTED
    # for internal preview/testing — they render a mixed kit (dark report +
    # light bonuses), so we don't surface them to customers, but a developer
    # can still pass ``--theme dark``. Unknown/typo'd values degrade to the
    # default inside :func:`_resolve_theme` (it never raises).
    parser.add_argument(
        "--report-theme",
        dest="report_theme",
        metavar="{editorial,corporate_light}",
        default="",
        help=(
            "Visual theme for the whole kit. 'editorial' = premium warm-bone "
            "(McKinsey-grade); 'corporate_light' = white Big-4/auditor. "
            f"Default: {_DEFAULT_REPORT_THEME}."
        ),
    )
    parser.add_argument(
        "--theme",
        dest="theme",
        default="",
        metavar="{editorial,corporate_light}",
        help=(
            "Kit theme. 'editorial' = premium warm-bone editorial "
            "(McKinsey-grade). 'corporate_light' = white Big-4/auditor. "
            f"Default: env var ADSCAN_PDF_THEME or '{_DEFAULT_REPORT_THEME}'."
        ),
    )
    parser.add_argument(
        "--branding",
        choices=("adscan", "cobrand", "whitelabel"),
        default=None,
        help="Branding posture for the deliverable: adscan | cobrand (default) | whitelabel.",
    )
    parser.add_argument(
        "--emit",
        dest="emit",
        type=str,
        default=None,
        help=(
            "Comma-separated Security Assessment Report outputs. The PDF and "
            "HTML are always produced; the only opt-in is 'data', which adds "
            "report_model.json (the branding-invariant derived-data export) "
            "alongside them. "
            f"Choices: {', '.join(_VALID_EMIT_VALUES)}. "
            f"Default: {','.join(_DEFAULT_EMIT)}. "
            "'data' requires the data_export entitlement; an un-entitled "
            "install silently omits it."
        ),
    )
    # Mirrors the per-subcommand --debug on start/ci/install/check. The host
    # launcher forwards --debug to the container subcommand, so deliver must
    # accept it (argparse rejects unknown flags). Activation into DEBUG_MODE
    # happens in the top-level dispatcher's debug block (adscan.py), which
    # lists "deliver" alongside the other debug-aware commands.
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable debug mode.",
    )
    return parser


def _prefill_interactive_inputs(args: argparse.Namespace) -> None:
    """Resolve every interactive input in the SYNC context, before the loop.

    ``questionary.ask()`` spins its own prompt_toolkit ``Application``
    synchronously; invoked inside ``asyncio.run``'s running loop it leaks the
    coroutine ("Application.run_async was never awaited") and the prompt never
    displays — so the kit silently fell back to defaults (e.g. it never asked
    which compliance frameworks to include). Resolving here, where no event
    loop runs, lets the prompts actually work. Results are written back to
    ``args`` and the ``_prompts_prefilled`` sentinel makes the async resolvers
    trust them instead of re-prompting (and re-leaking).
    """
    # Capture "did the operator explicitly choose a theme?" BEFORE we fold the
    # resolved value into ``args.theme`` — the report/bonus theme decouple
    # depends on distinguishing an explicit choice from the resolved default.
    setattr(
        args,
        "_explicit_theme_set",
        bool(
            (getattr(args, "theme", "") or "").strip()
            or (getattr(args, "report_theme", "") or "").strip()
            or os.environ.get("ADSCAN_PDF_THEME", "").strip()
        ),
    )

    workspace = _resolve_workspace(args)
    if workspace is not None:
        args.workspace = str(workspace)
    client, engagement = _resolve_client_meta(args)
    args.client = client
    args.engagement = engagement
    # Client logo picker (host GUI + manual fallback) — must run here, outside the
    # event loop, like every other prompt. Sets args.client_logo when picked.
    _prefill_client_logo(args)
    # Deliverable selection FIRST: a checkbox (everything pre-selected) so the
    # operator can deselect down to e.g. only the Security Assessment Report. An
    # explicit ``--only`` is returned verbatim and never overridden; CI/web run
    # non-interactively and auto-resolve to ALL (or their explicit ``--only``).
    args.only = _resolve_deliverables(args, shell=getattr(args, "_shell", None))
    try:
        args.frameworks = ",".join(_resolve_frameworks(args))
    except ValueError:
        # Either an invalid --frameworks value or an audit engagement with no
        # framework scoped. Leave both for run_deliver to re-resolve and
        # surface as a clean error (exit 2) instead of swallowing it here.
        pass
    args.theme = _resolve_theme(args)
    args.report_theme = ""  # folded into args.theme above; avoid double-resolution

    setattr(args, "_prompts_prefilled", True)


def _maybe_open_headline(args: argparse.Namespace) -> None:
    """Offer to open the Security Assessment Report once the kit is built.

    Runs in the SYNC wrapper, after the event loop has exited — the
    ``prompt_and_open`` confirm prompt is yet another prompt_toolkit
    Application that must not run inside ``asyncio.run``'s loop. Auto-skips
    in non-interactive contexts (handled inside ``prompt_and_open``).
    """
    headline = getattr(args, "_headline_pdf", "") or ""
    if not headline:
        return
    path = Path(headline)
    if not path.is_file():
        return
    from adscan_internal.services.host_open import prompt_and_open

    prompt_and_open(path, prompt="Open the security assessment report now?")


def run_deliver_sync(args: argparse.Namespace) -> int:
    """Synchronous wrapper for the top-level CLI dispatcher."""
    try:
        # All interactive prompts run HERE, outside the event loop. See
        # _prefill_interactive_inputs for why (questionary + asyncio.run).
        _prefill_interactive_inputs(args)
        rc = asyncio.run(run_deliver(args))
    except KeyboardInterrupt:
        print_warning("Deliver cancelled.")
        return 130
    if rc == 0:
        _maybe_open_headline(args)
    return rc


__all__ = (
    "DEFAULT_DELIVERABLE_SLUGS",
    "DELIVERABLE_LABELS",
    "DELIVERABLE_SLUGS",
    "add_deliver_subparser",
    "run_deliver",
    "run_deliver_sync",
)
