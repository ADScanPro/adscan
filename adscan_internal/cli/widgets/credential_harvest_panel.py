"""Shared credential-harvest panel — the one rendering every harvesting
surface (poisoning, spraying, kerberoasting, AS-REP roasting) uses.

Renders the two orthogonal nomenclature axes (CLAUDE.md § Nomenclature
Standard) side by side per principal:

* Privilege Tier (axis 1, what the principal IS GRANTED) — a badge sourced
  ONLY from :func:`compromise_class.privilege_tier_label`.
* Compromise Reach (axis 2, what a validated attack path PROVES it can
  reach) — sourced ONLY from :func:`compromise_class.compromise_reach_label_short`.

Ordering surfaces the headline finding first: a Tier-2 principal with a
validated path to Tier 0 is the product's core value, so tier is the primary
sort key (directness-first, matching the rest of the product) and reach is
the tie-breaker within a tier.

This module is a pure renderable builder — no I/O, no side effects, L1
testable — exactly like
``adscan_internal/services/background_jobs/jobs_view.py::format_jobs_table``.
It renders the tier/reach values already present on the record; it does not
classify them (see ``credential_harvest_classification.py``).
"""
from __future__ import annotations

import os

from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from adscan_core.theme import COLOR_AMBER, COLOR_CRIMSON, COLOR_MUTED, COLOR_SAGE, COLOR_STEEL
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.compromise_class import (
    CompromiseClass,
    PrivilegeTier,
    compromise_reach_label_short,
    privilege_tier_label,
)
from adscan_internal.services.credential_harvest_record import HarvestedPrincipal

_TIER_RANK: dict[str, int] = {
    PrivilegeTier.TIER0_DIRECT.value: 3,
    PrivilegeTier.TIER0_ESCALATION_CAPABLE.value: 2,
    PrivilegeTier.TIER1.value: 1,
    PrivilegeTier.TIER2.value: 0,
}

# The documented 4-level Compromise Reach ladder (CLAUDE.md § Nomenclature
# Standard), highest-impact first — the tie-breaker within a tier.
_REACH_RANK: dict[str, int] = {
    CompromiseClass.DOMAIN_BREAKER.value: 5,
    CompromiseClass.TIER0_FOOTHOLD.value: 4,
    CompromiseClass.PRIVILEGED_ESCALATOR.value: 3,
    CompromiseClass.COMPROMISE_ENABLER.value: 2,
    CompromiseClass.UNAUTHENTICATED_PRINCIPAL.value: 1,
    CompromiseClass.NONE.value: 0,
}

_TIER_BADGE_STYLE: dict[str, str] = {
    PrivilegeTier.TIER0_DIRECT.value: f"bold {COLOR_CRIMSON}",
    PrivilegeTier.TIER0_ESCALATION_CAPABLE.value: f"bold {COLOR_CRIMSON}",
    PrivilegeTier.TIER1.value: f"bold {COLOR_AMBER}",
    PrivilegeTier.TIER2.value: COLOR_STEEL,
}

_TIER_BADGE_GLYPH: dict[str, str] = {
    PrivilegeTier.TIER0_DIRECT.value: "▲",
    PrivilegeTier.TIER0_ESCALATION_CAPABLE.value: "▲",
    PrivilegeTier.TIER1.value: "◆",
    PrivilegeTier.TIER2.value: "·",
}

_CRACK_STATUS_STYLE: dict[str, str] = {
    "cracked": COLOR_SAGE,
    "captured": COLOR_STEEL,
    "cracking": COLOR_AMBER,
    # A crack waiting its turn behind another crack — quieter than the active
    # "cracking" (amber): dim + muted so the eye reads it as "not working yet".
    "queued": f"dim {COLOR_MUTED}",
    "rainbow_pending": COLOR_AMBER,
    "uncrackable_machine": COLOR_MUTED,
    "uncracked": COLOR_MUTED,
}

# Human-readable hash family per hashcat mode, for the Status cell (mirrors
# cracking_job._mode_label without importing the background-job module here).
_MODE_HASH_FAMILY: dict[str, str] = {
    "5500": "NetNTLMv1",
    "5600": "NetNTLMv2",
    "13100": "Kerberoast",
    "19600": "Kerberoast",
    "19700": "Kerberoast",
    "18200": "AS-REP",
    "19800": "AS-REP",
    "19900": "AS-REP",
}

# The effort ladder, so escalation offers only tiers strictly above the max
# already attempted (mirrors cracking_wordlist_policy.EFFORT_LEVELS; kept local
# to avoid importing the services layer into this pure renderable module).
_EFFORT_LEVELS: tuple[str, ...] = ("fast", "balanced", "thorough")

# Statuses that carry (or already hold) a usable credential, so the activation
# selector can offer them: a background crack recovered the plaintext
# ("cracked"), or spraying validated it and it is already in the store
# ("captured"). Everything else (uncracked / uncrackable_machine /
# rainbow_pending / cracking) has no credential to add yet.
_ACTIVATABLE_STATUSES: frozenset[str] = frozenset({"cracked", "captured"})

_SOURCE_LABEL: dict[str, str] = {
    "poisoning": "broadcast poisoning",
    "spraying": "password spray",
    "kerberoasting": "kerberoast",
    "asreproasting": "AS-REP roast",
}


def order_harvested_principals(
    records: list[HarvestedPrincipal],
) -> list[HarvestedPrincipal]:
    """Return ``records`` ordered by priority: tier first, reach second.

    Directness-first, matching the rest of the product's attack-path
    ordering: a Tier-0-direct principal always outranks a Tier-2 principal,
    even one with a validated Tier-0 reach — within the SAME tier, the
    highest Compromise Reach class sorts first (the "headline" case: a
    Tier-2 principal with a validated path to Tier 0 sorts above a Tier-2
    principal with no path).
    """
    return sorted(
        records,
        key=lambda r: (
            -_TIER_RANK.get(r.privilege_tier, 0),
            -_REACH_RANK.get(r.compromise_reach, 0),
            r.username.lower(),
        ),
    )


def _tier_badge(privilege_tier: str | None) -> Text:
    # UNDETERMINED (no membership/graph data) → honest "Unknown", never a false
    # "Tier 2: Standard". A None (or unrecognized) tier value lands here.
    if not privilege_tier or privilege_tier not in _TIER_BADGE_GLYPH:
        return Text("· Unknown", style=COLOR_MUTED)
    glyph = _TIER_BADGE_GLYPH.get(privilege_tier, "·")
    style = _TIER_BADGE_STYLE.get(privilege_tier, COLOR_STEEL)
    label = privilege_tier_label(
        next((t for t in PrivilegeTier if t.value == privilege_tier), PrivilegeTier.TIER2)
    )
    return Text(f"{glyph} {label}", style=style)


def _reach_cell(compromise_reach: str | None) -> Text:
    # UNDETERMINED (no attack-graph/path data) → "Not assessed", never a false
    # "Standard reach" (which would imply "assessed, no path found").
    if not compromise_reach or compromise_reach not in _REACH_RANK:
        return Text("Not assessed", style=COLOR_MUTED)
    cls = next(
        (c for c in CompromiseClass if c.value == compromise_reach), CompromiseClass.NONE
    )
    label = compromise_reach_label_short(cls)
    if cls in (CompromiseClass.DOMAIN_BREAKER, CompromiseClass.TIER0_FOOTHOLD):
        return Text(f"→ {label}", style=f"bold {COLOR_CRIMSON}")
    if cls is CompromiseClass.NONE:
        return Text(label, style=COLOR_MUTED)
    return Text(f"→ {label}", style=COLOR_AMBER)


def _status_label(record: HarvestedPrincipal) -> str:
    """The human status phrase for a record, encoding effort exhaustion."""
    if record.crack_status == "uncrackable_machine":
        return "not crackable (machine)"
    if (
        record.crack_status == "uncracked"
        and record.max_effort == _EFFORT_LEVELS[-1]
    ):
        return "exhausted (all tiers)"
    return record.crack_status.replace("_", " ")


def _compact_method(method: str) -> str:
    """Shorten a method for the status cell: drop the wordlist extension.

    Keeps a ``" + rule"`` suffix intact (``combined_audit_base.txt + best64`` ->
    ``combined_audit_base + best64``) so the running-crack cell stays compact.
    """
    text = str(method or "").strip()
    if not text:
        return ""
    if " + " in text:
        base, rule = text.split(" + ", 1)
        return f"{os.path.splitext(base)[0]} + {rule}"
    return os.path.splitext(text)[0]


def _cracking_status_text(record: HarvestedPrincipal) -> str:
    """The running-crack status phrase: ``cracking · <method> · <eta> · <pct>``.

    Each segment is included only when present, so a crack with no ETA estimate
    degrades cleanly to a plain ``cracking`` (or ``cracking · <method>``).
    """
    parts = ["cracking"]
    method = _compact_method(record.method)
    if method:
        parts.append(method)
    if record.eta:
        parts.append(record.eta)
    if record.progress:
        parts.append(record.progress)
    return " · ".join(parts)


def _queued_status_text() -> str:
    """The waiting-crack status phrase: ``queued · waiting for the running crack``.

    A background crack that is alive but has not yet started work — only one
    crack runs at a time, so it is serialized behind the crack currently using
    the compute. Honest + quiet (the operator sees it is enqueued, not stalled),
    and vendor-neutral (no tool names) so it is safe on any client-facing
    surface.
    """
    return "queued · waiting for the running crack"


def _status_cell(record: HarvestedPrincipal) -> Text:
    style = _CRACK_STATUS_STYLE.get(record.crack_status, COLOR_MUTED)
    if record.crack_status == "cracking":
        return Text(_cracking_status_text(record), style=style)
    if record.crack_status == "queued":
        return Text(_queued_status_text(), style=style)
    parts = [_status_label(record)]
    family = _MODE_HASH_FAMILY.get(str(record.mode).strip())
    if family:
        parts.append(family)
    elif record.ntlm_version:
        parts.append(f"NTLM{record.ntlm_version}")
    parts.append(record.account_type)
    return Text(" · ".join(parts), style=style)


def build_credential_harvest_panel(records: list[HarvestedPrincipal]):
    """Return the shared Rich Panel every harvest surface renders.

    Never raises: an empty ``records`` list renders a single "no principals
    harvested yet" row rather than an empty table.
    """
    table = Table(show_header=True, header_style=f"bold {COLOR_STEEL}", box=None, padding=(0, 1))
    table.add_column("#", style=COLOR_MUTED, justify="right", width=4)
    table.add_column("Principal")
    table.add_column("Privilege Tier")
    table.add_column("Compromise Reach")
    table.add_column("Source")
    table.add_column(
        "Method", style=COLOR_MUTED, overflow="ellipsis", max_width=22, no_wrap=True
    )
    table.add_column("Status")

    ordered = order_harvested_principals(records)
    for idx, record in enumerate(ordered, start=1):
        table.add_row(
            str(idx),
            mark_sensitive(record.username, "user"),
            _tier_badge(record.privilege_tier),
            _reach_cell(record.compromise_reach),
            _SOURCE_LABEL.get(record.source, record.source or "-"),
            record.method or "-",
            _status_cell(record),
        )
    if not ordered:
        table.add_row("-", "No principals harvested yet", "", "", "", "", "")

    title = Text(f" Credential Harvest · {len(ordered)} principal{'s' if len(ordered) != 1 else ''} ")
    return Panel(
        Group(table),
        title=title,
        title_align="left",
        border_style=COLOR_STEEL,
    )


# --- Foreground actions ----------------------------------------------------
# Appended per Task 6 of the credential-harvest UX plan. These imports live
# here (not at module top) to keep the append surgical. All are module-level
# (not lazy-in-function) so they resolve once and stay patchable at this
# module's namespace — `attack_path_execution` does not import this panel, so
# there is no import cycle, and in the live runtime it is always already
# loaded by the time a harvest surface renders.

from typing import Any  # noqa: E402

from adscan_core import telemetry  # noqa: E402
from adscan_core.rich_output import (  # noqa: E402
    confirm_ask,
    print_info,
    print_info_debug,
    print_instruction,
    print_panel,
    questionary_checkbox_values,
)
from adscan_internal.cli.attack_path_execution import (  # noqa: E402
    offer_attack_paths_for_execution_for_principals,
)
from adscan_internal.interaction import is_non_interactive  # noqa: E402
from adscan_internal.services.background_jobs import enqueue_cracking_job  # noqa: E402


def offer_credential_harvest_actions(
    shell: Any,
    domain: str,
    records: list[HarvestedPrincipal],
    *,
    auto_retry_uncracked: bool = False,
) -> None:
    """Offer the standard credential-harvest actions at a foreground safe point.

    Runs on the foreground REPL thread (never a background worker) at a safe
    point after a harvest surface has classified its records. Three actions:

    * Select principals -> ``add_credential`` + launch the authenticated scan
      via :func:`offer_attack_paths_for_execution_for_principals` (reused
      unchanged — the same prioritization spraying already uses).
    * Retry-crack any ``uncracked`` principal that carries a ``hash_file``,
      via :func:`enqueue_cracking_job` (sub-project A) at a stronger effort
      tier — offered interactively, or auto-launched when
      ``auto_retry_uncracked`` is set (used by the scan-end reconciliation
      seam so a still-uncracked hash gets one more pass unattended).
    * Copy a ``rainbow_pending`` machine hash's on-disk path for the
      operator's own rig — printed cleartext via :func:`mark_sensitive`
      (never redacted — the operator needs the value).

    Non-interactive-safe: every prompt routes through the centralized
    ``questionary_checkbox_values`` / ``confirm_ask`` helpers, which
    auto-resolve to their safe default when the runtime is non-interactive
    (CLAUDE.md § Interactive prompts MUST auto-resolve) — never a raw
    questionary/Rich prompt, so ``adscan ci`` never hangs. Never raises: every
    branch is best-effort, matching the other foreground offer helpers in this
    codebase (``handle_validated_domain_hits_followup``,
    ``maybe_launch_poisoning_job``) — a harvest-action failure must not break
    the scan.

    Args:
        shell: The active ``PentestShell`` (threaded into every prompt helper
            so the non-interactive predicate can auto-resolve).
        domain: The target AD domain the harvested principals belong to.
        records: The classified :class:`HarvestedPrincipal` records to act on.
        auto_retry_uncracked: When True, re-queue every still-uncracked hash
            without prompting (the scan-end reconciliation path).
    """
    if not records:
        return
    try:
        _offer_add_credential_and_scan(shell, domain, records)
        _offer_retry_uncracked(shell, domain, records, auto_retry=auto_retry_uncracked)
        _show_rainbow_pending_hashes(records)
    except Exception as exc:  # noqa: BLE001 — foreground actions are best-effort
        telemetry.capture_exception(exc)


_TIER0_VALUES: frozenset[str] = frozenset(
    {
        PrivilegeTier.TIER0_DIRECT.value,
        PrivilegeTier.TIER0_ESCALATION_CAPABLE.value,
    }
)


def _resolve_stored_domain_secret(
    shell: Any, domain: str, username: str
) -> str | None:
    """Return the real stored password / NT hash for a domain principal, or None.

    Case-insensitive lookup of ``domains_data[<domain>]["credentials"]`` only.
    Deliberately does NOT fall back to a Kerberos ccache path
    (``kerberos_tickets``): a spray hit stores a password/hash, and
    ``add_credential`` must re-verify a real secret — never treat a ticket path
    as a password. Both the domain key and the username are matched
    case-insensitively so a spray record activates against the value the spray
    flow persisted regardless of casing.
    """
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return None
    domain_data = domains_data.get(domain)
    if not isinstance(domain_data, dict):
        normalized = str(domain or "").strip().rstrip(".").lower()
        for candidate_key, candidate_value in domains_data.items():
            if (
                str(candidate_key or "").strip().rstrip(".").lower() == normalized
                and isinstance(candidate_value, dict)
            ):
                domain_data = candidate_value
                break
    if not isinstance(domain_data, dict):
        return None
    credentials = domain_data.get("credentials")
    if not isinstance(credentials, dict):
        return None
    target = str(username or "").strip().lower()
    if not target:
        return None
    for stored_user, stored_credential in credentials.items():
        if str(stored_user or "").strip().lower() != target:
            continue
        if isinstance(stored_credential, str) and stored_credential.strip():
            return stored_credential.strip()
        break
    return None


def _activate_record(shell: Any, domain: str, record: HarvestedPrincipal) -> None:
    """``add_credential`` a single harvested principal.

    A BACKGROUND crack carries the recovered plaintext on ``record.secret`` (it
    deliberately did NOT auto-add) — use it so the credential verifies for real.

    A spraying record has no secret on the record itself: the spray flow already
    persisted the real password to the store and minted a TGT. Feeding an empty
    string into ``add_credential``'s live re-verification would fail with a logon
    failure and PURGE the just-captured credential, stranding downstream
    attack-path execution. So resolve the REAL stored secret and re-add THAT,
    keeping the credential validated. Only when no stored secret exists (a
    genuine blank-password hit, or nothing persisted yet) do we fall back to the
    explicit-blank path via ``allow_empty_credential``.
    """
    add_credential = getattr(shell, "add_credential", None)
    if not callable(add_credential):
        return
    secret = str(record.secret or "")
    if not secret:
        resolved = _resolve_stored_domain_secret(shell, domain, record.username)
        if resolved:
            secret = resolved
    try:
        add_credential(
            domain,
            record.username,
            secret,
            ui_silent=True,
            prompt_for_user_privs_after=False,
            skip_user_privs_enumeration=True,
            allow_empty_credential=(secret == ""),
            credential_origin=record.source,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)


def _render_tier0_captured_panel(records: list[HarvestedPrincipal]) -> None:
    """Premium panel flagging Tier-0 principals auto-activated from the harvest.

    Mirrors spraying's headline treatment: a captured Tier-0 credential is the
    product's core value, so it is auto-added and surfaced loudly rather than
    left for the operator to notice in a checkbox list.
    """
    if not records:
        return
    lines = [
        f"{mark_sensitive(r.username, 'user')}  ·  {_status_label(r)}"
        for r in records
    ]
    try:
        print_panel(
            "\n".join(lines),
            title="🛡  Tier 0 Captured",
            border_style=COLOR_CRIMSON,
            expand=False,
        )
    except Exception as exc:  # noqa: BLE001 — a panel must never block activation
        telemetry.capture_exception(exc)


def _offer_add_credential_and_scan(
    shell: Any, domain: str, records: list[HarvestedPrincipal]
) -> None:
    ordered = order_harvested_principals(records)
    # A cracked/validated Tier-0 principal is the headline finding: auto-add it
    # (mirroring spraying) + flag it loudly, rather than burying it in a
    # checkbox. Everything else is operator-selected (default all).
    tier0 = [
        r
        for r in ordered
        if r.privilege_tier in _TIER0_VALUES and r.crack_status in _ACTIVATABLE_STATUSES
    ]
    for record in tier0:
        _activate_record(shell, domain, record)
    _render_tier0_captured_panel(tier0)

    remaining = [
        r
        for r in ordered
        if r not in tier0 and r.crack_status in _ACTIVATABLE_STATUSES
    ]
    options = [r.username for r in remaining]
    selected: list[str] = []
    if options:
        selected = list(
            questionary_checkbox_values(
                title="Select harvested principals to add as credentials and pivot from:",
                options=options,
                default_values=options,
                shell=shell,
            )
            or []
        )
        by_user = {r.username: r for r in remaining}
        for username in selected:
            record = by_user.get(username)
            if record is not None:
                _activate_record(shell, domain, record)

    principals = [r.username for r in tier0] + selected
    if not principals:
        return
    offer_attack_paths_for_execution_for_principals(
        shell,
        domain,
        principals=principals,
        max_depth=10,
        target="all" if len(principals) <= 15 else "highvalue",
        target_mode="object",
    )


def _escalation_target(max_effort: str) -> str:
    """The effort tier to re-crack at — strictly above ``max_effort``.

    Returns ``""`` when the ``thorough`` ladder has already been walked (no
    higher tier exists — the hash is exhausted) or when the account is not
    escalatable. Otherwise returns the strongest tier above what was tried;
    ``resolve_effort`` climbs from there so a single escalate covers every
    intermediate rung.
    """
    m = str(max_effort or "").strip().lower()
    if m == _EFFORT_LEVELS[-1]:
        return ""
    return _EFFORT_LEVELS[-1]


def _is_escalatable(record: HarvestedPrincipal) -> bool:
    """Only a USER hash still uncracked with effort headroom can escalate.

    A machine account is never wordlist-crackable (relay-only), and a hash
    already walked to ``thorough`` is exhausted — neither is offered.
    """
    return bool(
        record.crack_status == "uncracked"
        and record.hash_file
        and str(record.account_type).strip().lower() != "machine"
        and _escalation_target(record.max_effort)
    )


def _offer_retry_uncracked(
    shell: Any,
    domain: str,
    records: list[HarvestedPrincipal],
    *,
    auto_retry: bool,
) -> None:
    escalatable = [r for r in records if _is_escalatable(r)]
    if not escalatable:
        return
    if not auto_retry:
        if is_non_interactive(shell):
            return
        proceed = confirm_ask(
            f"{len(escalatable)} harvested hash(es) remain uncracked. "
            "Retry with a stronger effort tier in the background?",
            default=True,
        )
        if not proceed:
            return
    for record in escalatable:
        target = _escalation_target(record.max_effort)
        try:
            enqueue_cracking_job(
                shell,
                domain=domain,
                user=record.username,
                # Thread the ORIGINAL hashcat mode so a roast record re-cracks
                # under 13100/18200 (not the NetNTLM default) — the Phase-1 gap.
                mode=record.mode or None,
                ntlm_version=record.ntlm_version,
                hash_file=record.hash_file,
                effort=target,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
    print_info(
        f"Queued {len(escalatable)} retry-crack job(s) at the "
        f"'{_EFFORT_LEVELS[-1]}' effort tier — check status with 'jobs'."
    )


def _show_rainbow_pending_hashes(records: list[HarvestedPrincipal]) -> None:
    pending = [r for r in records if r.crack_status == "rainbow_pending" and r.hash_file]
    if not pending:
        return
    lines = [
        f"{mark_sensitive(r.username, 'user')} · {mark_sensitive(r.hash_file, 'path')}"
        for r in pending
    ]
    print_panel(
        "\n".join(lines),
        title="Rainbow-Pending Machine Hashes",
        border_style=COLOR_AMBER,
        expand=False,
    )


# --- Non-interactive (CI) value-prioritized activation + escalation ---------
# The interactive review above lets the operator decide. In a non-interactive
# run (`adscan ci`, the web/PoV worker) there is no operator, so the scan-end
# seam calls the function below instead. The client engaged for a PROVEN path
# to domain compromise harvested unattended, so we prioritize the expensive
# THOROUGH crack + the auto-activation by COMPROMISE VALUE read off the
# now-complete attack graph: Tier 0 principals and principals with a validated
# attack-path to Tier 0 first; everything else stays harvested-only (it already
# got the cheap FAST net). This module owns both the interactive and the CI
# paths so they share the activation/escalation primitives above.

from adscan_internal.services.credential_harvest_classification import (  # noqa: E402
    classify_harvested_principal_tier,
    classify_harvested_principals_reach,
)

# Compromise Reach classes whose validated path LANDS on a Tier 0 asset or
# escalation group — a proven path TO Tier 0. `compromise_enabler` is only a
# waypoint that does NOT land on Tier 0, so it is deliberately excluded (the
# same distinction the client glossary draws).
_PATH_TO_TIER0_REACH: frozenset[str] = frozenset(
    {
        CompromiseClass.DOMAIN_BREAKER.value,
        CompromiseClass.TIER0_FOOTHOLD.value,
        CompromiseClass.PRIVILEGED_ESCALATOR.value,
    }
)


def _tier_from_value(value: str) -> PrivilegeTier:
    return next((t for t in PrivilegeTier if t.value == value), PrivilegeTier.TIER2)


def _reach_from_value(value: str) -> CompromiseClass:
    return next((c for c in CompromiseClass if c.value == value), CompromiseClass.NONE)


def _ci_value_priority(
    tier: PrivilegeTier | None, reach: CompromiseClass | None
) -> int:
    """Compromise-value priority for the CI default (higher = crack/activate first).

    Order: Tier 0 — direct (3) > Tier 0 — escalation-capable (2) >
    validated-path-to-Tier-0 (1) > everything else (0, skipped for THOROUGH and
    for auto-activation). This is the directness-first ordering the rest of the
    product uses, applied to the harvest.

    An UNDETERMINED tier / reach (``None``) is NOT Tier 0 and is NOT a validated
    path to Tier 0 — it resolves to priority 0, so an unclassified principal is
    never auto-activated or mid-scan-interrupted as if it were high-value.
    """
    if tier is PrivilegeTier.TIER0_DIRECT:
        return 3
    if tier is PrivilegeTier.TIER0_ESCALATION_CAPABLE:
        return 2
    if reach is not None and reach.value in _PATH_TO_TIER0_REACH:
        return 1
    return 0


def _ci_classify_against_graph(
    shell: Any, domain: str, records: list[HarvestedPrincipal]
) -> "dict[str, tuple[PrivilegeTier | None, CompromiseClass]]":
    """Re-read tier + reach for each record off the now-complete scan-end graph.

    Uses the classification SSOT (the same functions the harvest producers use),
    so a principal captured EARLY (e.g. a poisoning hit before the auth graph
    existed) is re-graded against the complete graph at scan end. The tier may be
    ``None`` (UNDETERMINED) — which the value gate treats as not-Tier-0. Reach is
    normalized to a concrete class (UNDETERMINED / no-path collapses to NONE for
    the gate). Best-effort: a per-record tier failure or a whole-batch reach
    failure falls back to the value already stamped on the record. Keyed by
    lowercased username.
    """
    usernames = [r.username for r in records if r.username]
    try:
        reach_by_user = classify_harvested_principals_reach(
            shell, domain=domain, usernames=usernames
        )
    except Exception as exc:  # noqa: BLE001 — graph read is best-effort
        telemetry.capture_exception(exc)
        reach_by_user = {}
    out: dict[str, tuple[PrivilegeTier | None, CompromiseClass]] = {}
    for record in records:
        key = record.username.strip().lower()
        if not key:
            continue
        try:
            tier = classify_harvested_principal_tier(
                shell, domain=domain, username=record.username,
                account_type=record.account_type,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            tier = _tier_from_value(record.privilege_tier)
        reach = reach_by_user.get(key)
        if reach is None:
            reach = _reach_from_value(record.compromise_reach)
        out[key] = (tier, reach)
    return out


def _credential_already_stored(shell: Any, domain: str, username: str) -> bool:
    """True when this principal already has a domain credential in the store.

    The dedupe guard against spraying's own CI activation (and any earlier
    step): a principal already activated must not be double-added. Case- and
    whitespace-insensitive on the username. Best-effort — a shape surprise in
    ``domains_data`` reads as "not stored" so activation still proceeds.
    """
    try:
        domains_data = getattr(shell, "domains_data", None) or {}
        creds = (domains_data.get(domain, {}) or {}).get("credentials", {}) or {}
        target = username.strip().lower()
        return any(str(stored).strip().lower() == target for stored in creds)
    except Exception:  # noqa: BLE001
        return False


def activate_and_escalate_harvest_ci(
    shell: Any, domain: str, records: list[HarvestedPrincipal]
) -> None:
    """Non-interactive scan-end default: value-prioritize by the attack graph.

    Two effects, both keyed on compromise value read off the now-complete
    scan-end graph (Tier 0 or a validated path to Tier 0):

    * **Auto-activate** every BACKGROUND-cracked credential that is Tier 0 or
      completes a validated path to Tier 0 (``add_credential`` + the normal
      chained authenticated enumeration), deduped against credentials already
      in the store (e.g. spraying's own CI activation). Non-path cracked creds
      stay harvested-only (report evidence) — the CI run does not chase them.
    * **Escalate THOROUGH cracking** for still-uncracked Tier 0 /
      path-to-Tier-0 principals first, in that order; principals that are
      neither are NOT given expensive GPU time (they already got the FAST net).

    Interactive runs never reach here — they keep the operator-driven review
    selector. Best-effort: never raises (the caller also wraps it).
    """
    if not records:
        return
    try:
        classification = _ci_classify_against_graph(shell, domain, records)
        _ci_auto_activate_path_completing(shell, domain, records, classification)
        _ci_escalate_thorough_by_value(shell, domain, records, classification)
    except Exception as exc:  # noqa: BLE001 — the whole CI path is best-effort
        telemetry.capture_exception(exc)


def _ci_default_class(
    classification: "dict[str, tuple[PrivilegeTier | None, CompromiseClass]]", username: str
) -> "tuple[PrivilegeTier | None, CompromiseClass]":
    return classification.get(
        username.strip().lower(), (PrivilegeTier.TIER2, CompromiseClass.NONE)
    )


def _ci_auto_activate_path_completing(
    shell: Any,
    domain: str,
    records: list[HarvestedPrincipal],
    classification: "dict[str, tuple[PrivilegeTier, CompromiseClass]]",
) -> None:
    """Add + pivot every path-completing background-cracked credential (CI)."""
    ranked = sorted(
        records,
        key=lambda r: -_ci_value_priority(*_ci_default_class(classification, r.username)),
    )
    activated: list[str] = []
    for record in ranked:
        # Only a BACKGROUND crack carries the recovered plaintext to add; a
        # spraying "captured" record is already in the store (spraying activated
        # it), so it is left to the dedupe guard rather than re-added here.
        if record.crack_status != "cracked":
            continue
        tier, reach = _ci_default_class(classification, record.username)
        if _ci_value_priority(tier, reach) <= 0:
            continue  # not Tier 0, no validated path to Tier 0 → harvested-only
        if _credential_already_stored(shell, domain, record.username):
            continue  # dedupe: spraying (or an earlier step) already activated it
        _activate_record(shell, domain, record)
        activated.append(record.username)
    if not activated:
        return
    print_info(
        f"Auto-activated {len(activated)} path-completing credential(s) "
        "(Tier 0 / validated path to Tier 0) and pivoting."
    )
    offer_attack_paths_for_execution_for_principals(
        shell,
        domain,
        principals=activated,
        max_depth=10,
        target="all" if len(activated) <= 15 else "highvalue",
        target_mode="object",
    )


def _ci_escalate_thorough_by_value(
    shell: Any,
    domain: str,
    records: list[HarvestedPrincipal],
    classification: "dict[str, tuple[PrivilegeTier, CompromiseClass]]",
) -> None:
    """Escalate THOROUGH cracking only for Tier 0 / path-to-Tier-0 uncracked hashes."""
    prioritized: list[tuple[int, HarvestedPrincipal]] = []
    for record in records:
        if not _is_escalatable(record):
            continue
        tier, reach = _ci_default_class(classification, record.username)
        priority = _ci_value_priority(tier, reach)
        if priority <= 0:
            # Neither Tier 0 nor a validated path to Tier 0 — do NOT spend
            # THOROUGH GPU on it; the FAST tier already ran.
            continue
        prioritized.append((priority, record))
    if not prioritized:
        return
    # tier0-direct → tier0-escalation-capable → path-to-tier0 (stable within a
    # priority band, so the graph-order tie-break is preserved).
    prioritized.sort(key=lambda item: -item[0])
    for _priority, record in prioritized:
        target = _escalation_target(record.max_effort)
        try:
            enqueue_cracking_job(
                shell,
                domain=domain,
                user=record.username,
                mode=record.mode or None,
                ntlm_version=record.ntlm_version,
                hash_file=record.hash_file,
                effort=target,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
    print_info(
        f"Queued {len(prioritized)} value-prioritized retry-crack job(s) at the "
        f"'{_EFFORT_LEVELS[-1]}' effort tier (Tier 0 / attack-path-to-Tier-0 first) "
        "— check status with 'jobs'."
    )


# --- Foreground-safe drain review + on-demand `harvest` viewer -------------
# A background crack usually FINISHES after the fast scan has already ended, so
# tying the review to scan-end alone means real cracks never get reviewed. These
# two entry points surface the review at ANY foreground-safe point instead: the
# between-commands drain (`check_background_tasks`) when a crack completes, and
# the on-demand `harvest` command. Both render the SAME shared table + reuse the
# SAME activation/escalation selector as the scan-end seam — no duplicated UX.


def render_harvest_review_at_drain(
    shell: Any,
    domain: str,
    *,
    newly_cracked_usernames: list[str],
    between_phase_value_gate: bool = False,
) -> None:
    """Render the harvest review at the between-commands foreground drain.

    Called from ``check_background_tasks`` right after a completed background
    crack has been persisted — a point where no scan or command is executing,
    so rendering here never collides with the live sequential output (the hard
    background-job invariant). Shows the consolidated table (finished captures +
    any still-running cracks) via the shared panel, then a follow-up keyed on
    whether anything JUST cracked:

    * Any newly-cracked credential (regardless of Privilege Tier) — offer the
      batch activation/escalation selector so the operator can pivot. A cracked
      user is worth activating whatever its tier, and in an unauthenticated scan
      the first cracked user is the whole progression (``add_credential`` ->
      authenticated enumeration). The selector auto-selects Tier 0 and defaults
      the rest to all, so it stays one batch prompt, not a per-hash nag.
    * Nothing actionable newly cracked (only in-progress / only uncracked rows)
      — show the table and point at the ``harvest`` command.

    Non-interactive runs (``adscan ci`` / the web-PoV worker) render the table
    for the log but take no action — the scan-end CI path
    (``activate_and_escalate_harvest_ci``) owns value-prioritized auto-activation
    there. Never raises: every branch is best-effort.

    ``between_phase_value_gate`` switches this into the Phase-2d MID-SCAN
    break-point policy (:func:`maybe_surface_high_value_cracks_between_phases`
    sets it before routing through the same central drain): instead of the
    between-commands "any new crack -> offer activation", only a NEW Tier 0 /
    validated-path-to-Tier-0 crack interrupts the scan with the review + a brief
    activation prompt; a NEW lower-value crack is notify-only (one line, no
    prompt); already-surfaced principals never re-appear. This keeps ONE review
    UX and reuses the value classification — the delta + value-gate are the only
    additions.
    """
    try:
        from adscan_internal.services.credential_harvest_view import (  # noqa: PLC0415
            load_effective_harvest_records,
        )

        records = load_effective_harvest_records(shell, domain)
        if not records:
            return
        if between_phase_value_gate:
            _surface_between_phase_delta(
                shell, domain, records, newly_cracked_usernames
            )
            return
        console = getattr(shell, "console", None)
        panel = build_credential_harvest_panel(records)
        if console is not None:
            console.print(panel)
        if is_non_interactive(shell):
            # CI: the scan-end seam owns auto-activation; here we only log the table.
            return
        wanted = {str(u).strip().lower() for u in (newly_cracked_usernames or [])}
        newly_cracked = [
            r
            for r in records
            if r.username.strip().lower() in wanted and r.crack_status == "cracked"
        ]
        if newly_cracked:
            offer_credential_harvest_actions(shell, domain, records)
        else:
            print_instruction(
                "Harvested credential(s) recorded. Review and activate them "
                "anytime with the 'harvest' command."
            )
    except Exception as exc:  # noqa: BLE001 — the drain review is best-effort
        telemetry.capture_exception(exc)


def render_harvest_command(shell: Any, domain: str) -> None:
    """Render the on-demand ``harvest`` review: the table + the actions selector.

    The first-class viewer AND action entry point for every background-crack
    source (poisoning NetNTLMv1/v2, Kerberoast, AS-REP). Loads the consolidated
    state (persisted captures + in-flight cracks), renders the shared table,
    then — interactively — offers the activation/escalation selector. In a
    non-interactive run it prints the table and returns (no selector, no hang).
    Never raises.
    """
    try:
        from adscan_internal.services.credential_harvest_view import (  # noqa: PLC0415
            load_effective_harvest_records,
        )

        records = load_effective_harvest_records(shell, domain)
        if not records:
            print_info(
                "No harvested credentials yet. Captures from broadcast poisoning, "
                "kerberoasting and AS-REP roasting appear here as they land."
            )
            return
        console = getattr(shell, "console", None)
        panel = build_credential_harvest_panel(records)
        if console is not None:
            console.print(panel)
        if is_non_interactive(shell):
            return
        offer_credential_harvest_actions(shell, domain, records)
    except Exception as exc:  # noqa: BLE001 — the harvest command is best-effort
        telemetry.capture_exception(exc)


# --- Phase 2d: mid-scan between-phase break points -------------------------
# For a LONG authenticated scan the review was only surfaced AFTER the whole
# scan ended (the pre-prompt drain runs BETWEEN commands, never mid-scan). A
# cracked Tier 0 / DA credential is THE finding and could change the rest of the
# scan, so it must surface DURING the scan — at a phase boundary — not only at
# the end. These break points fire at each phase transition FROM Attack Paths
# Discovery onward (before that there is no attack graph, so tier / path
# classification is impossible) and are VALUE-GATED so only a DA/Tier 0 can
# "pause" the scan; a lower-value crack is notify-only and the scan continues.
#
# Loop-safety (the owner's explicit concern): the call site is the SYNCHRONOUS
# scan flow (``run_enumeration``) at a boundary where the previous phase's
# ``asyncio.run()`` has already returned — so the activation action's async
# stack runs with no loop active. Belt-and-suspenders on top of that, the entry
# point re-checks ``running_event_loop_present()`` AND routes the drain + render
# through the ONE central loop-guarded path
# (``_drain_and_render_background_notifications``), which DEFERS (never crashes)
# if a running loop is ever present.

# The per-scan marker attribute name (a plain shell attribute — NEVER
# ``domains_data``, so it never reaches ``save_workspace_data``). Holds the
# lowercased sAMAccountNames already surfaced at an earlier break point, so the
# delta at the next boundary re-surfaces only genuinely-new cracks.
_BETWEEN_PHASE_SURFACED_ATTR = "_between_phase_surfaced_users"

# The shell flag the entry point sets so the shared drain render
# (``render_harvest_review_at_drain``) applies the value-gate + delta-dedup
# policy instead of the between-commands "any new crack -> offer" policy.
_BETWEEN_PHASE_ACTIVE_ATTR = "_harvest_between_phase_active"


def _between_phase_surfaced_set(shell: Any) -> set:
    """Return (lazily creating) the per-scan already-surfaced username set.

    Stored as a plain shell attribute so the transient ``set`` never lands in
    ``domains_data`` / ``save_workspace_data`` (CLAUDE.md § CI Validation). A
    shape surprise (a non-set left by something else) is replaced defensively.
    """
    current = getattr(shell, _BETWEEN_PHASE_SURFACED_ATTR, None)
    if not isinstance(current, set):
        current = set()
        try:
            setattr(shell, _BETWEEN_PHASE_SURFACED_ATTR, current)
        except Exception:  # noqa: BLE001 — a read-only mock shell degrades to no dedup
            pass
    return current


def _surface_between_phase_delta(
    shell: Any,
    domain: str,
    records: list[HarvestedPrincipal],
    newly_cracked_usernames: list[str],
) -> None:
    """Value-gated, delta-deduped mid-scan surfacing of newly-cracked creds.

    Delegated to by :func:`render_harvest_review_at_drain` when the between-phase
    flag is set. Only a NEW Tier 0 / validated-path-to-Tier-0 crack interrupts
    the scan with the review table + the activation selector; a NEW lower-value
    crack is notify-only (a single line, no prompt); a principal already surfaced
    at an earlier boundary never re-appears. Non-interactive runs render the
    table for the log and take no action (the scan-end Phase-2b CI path owns
    value-prioritized auto-activation). Never raises.
    """
    wanted = {str(u).strip().lower() for u in (newly_cracked_usernames or [])}
    surfaced = _between_phase_surfaced_set(shell)
    newly_cracked = [
        r
        for r in records
        if r.username.strip().lower() in wanted
        and r.crack_status == "cracked"
        and r.username.strip().lower() not in surfaced
    ]
    if not newly_cracked:
        return

    # Mark the whole new-cracked delta as surfaced NOW so the next boundary never
    # re-surfaces the same principal, whatever branch is taken below.
    for record in newly_cracked:
        surfaced.add(record.username.strip().lower())

    # Value classification off the (post-collection, now-populated) graph — the
    # SAME SSOT the CI scan-end path uses, so tier / path-to-Tier-0 are computed
    # once, consistently.
    classification = _ci_classify_against_graph(shell, domain, newly_cracked)
    high_value = [
        record
        for record in newly_cracked
        if _ci_value_priority(*_ci_default_class(classification, record.username)) > 0
    ]

    console = getattr(shell, "console", None)
    if is_non_interactive(shell):
        # CI: render the consolidated table for the log; do NOT prompt. The
        # scan-end Phase-2b path (``activate_and_escalate_harvest_ci``) owns the
        # value-prioritized auto-activation there — never double-handle it here.
        if console is not None:
            console.print(build_credential_harvest_panel(records))
        return

    if high_value:
        # THE finding mid-scan: show the full table for context, then offer the
        # activation/escalation selector scoped to the NEW cracked delta (so an
        # already-activated earlier capture is never re-added). This is the ONLY
        # case that pauses the scan for an operator decision.
        if console is not None:
            console.print(build_credential_harvest_panel(records))
        offer_credential_harvest_actions(shell, domain, newly_cracked)
    else:
        # Lower-value: notify-only, the scan continues. Act on demand via
        # 'harvest'. No table, no prompt — keep the mid-scan interruption minimal.
        count = len(newly_cracked)
        print_instruction(
            f"{count} credential{'s' if count != 1 else ''} cracked in the "
            "background — review and activate anytime with the 'harvest' command."
        )


def maybe_surface_high_value_cracks_between_phases(shell: Any, domain: str) -> None:
    """Phase-2d break point: surface a NEW high-value background crack mid-scan.

    Called by the synchronous scan-phase runner (``run_enumeration``) at each
    phase boundary from Attack Paths Discovery onward. It routes the drain +
    review through the ONE central loop-guarded path
    (``_drain_and_render_background_notifications``), setting a flag so that
    path's harvest render applies the value-gate + delta-dedup
    (:func:`_surface_between_phase_delta`) instead of the between-commands
    policy. The central drain both PERSISTS the completed-but-undrained cracks
    (so ``load_effective_harvest_records`` sees them mid-scan) and renders them.

    Gating:

    * Only the long AUTHENTICATED scan (``shell.scan_mode == "auth"`` — set by
      ``start_auth`` and the ``adscan ci`` auth path) gets between-phase breaks;
      a short ``start_unauth`` scan keeps scan-end-only surfacing. This is the
      small predicate, not a forked flow — ``run_enumeration`` is the auth flow,
      and ``start_unauth`` never reaches it.
    * Loop guard (belt-and-suspenders): the seam is loop-free by construction,
      but if a running event loop is ever present this DEFERS (the completed
      cracks stay queued on the registry bus for the next loop-free drain /
      scan-end) rather than risking the nested-``asyncio.run`` crash.

    Best-effort and idempotent: never raises, never breaks the scan.
    """
    try:
        if str(getattr(shell, "scan_mode", "") or "") != "auth":
            return
        from adscan_internal.cli.repl_background_surfacing import (  # noqa: PLC0415
            running_event_loop_present,
        )

        if running_event_loop_present():
            print_info_debug(
                "between-phase crack break point reached under a running event "
                "loop; deferring to the next loop-free drain"
            )
            return
        drain = getattr(shell, "_drain_and_render_background_notifications", None)
        if not callable(drain):
            return
        try:
            setattr(shell, _BETWEEN_PHASE_ACTIVE_ATTR, True)
        except Exception:  # noqa: BLE001 — a read-only mock shell still drains
            pass
        try:
            drain()
        finally:
            try:
                setattr(shell, _BETWEEN_PHASE_ACTIVE_ATTR, False)
            except Exception:  # noqa: BLE001
                pass
    except Exception as exc:  # noqa: BLE001 — the break point must never break the scan
        telemetry.capture_exception(exc)
