"""Password hygiene: the shared RENDER projection both paid surfaces consume.

:mod:`adscan_core.reporting.password_hygiene` owns the DATA — the recovery rate,
the per-tier coverage, the reuse grouping, and the absence rule. This module
owns the one step after it: turning that data into the shape a client-facing
surface draws, which is the display order of the reuse groups and the humanized
account names inside them.

WHY THIS IS NOT IN ``pro/``
---------------------------
It used to be, inside the kit document's databinding, and the web platform can
never import ``pro/`` (private, obfuscated, and the appliance backend ships only
``cli_stubs`` + ``adscan_core``). So a CTEM surface built against the same
persisted block would have re-implemented the projection, and the two surfaces
would have diverged not on the figures (those were already a shared SSOT and
cannot drift) but on the PRESENTATION: whether an account reads ``svc_sql`` or
the shouted ``SVC_SQL@CORP.EXAMPLE``, and whether the reuse group covering an
administrative account leads the table or sits third. That is the same class of
defect the edge-detail panel already paid for with relation humanization.

Craft is not IP: the engine that turns HTML into PDF and the design system that
styles it both left ``pro/`` on exactly these grounds, and the sibling
projections the two surfaces share (``user_exposure_ranking``,
``cracking_coverage``, ``chokepoint_copy``) all live here for the same reason. A
projection of figures the client already reads in the PDF carries nothing worth
obfuscating. What stays in ``pro/`` is DOCUMENT COMPOSITION: the cover, the
masthead, the section order, the page geometry, the branding.

WHAT PASSES THROUGH AND WHAT DOES NOT
-------------------------------------
Every figure is copied VERBATIM out of the view. This module never computes a
rate, a population or a denominator, because crossing two denominators is a
documented trap in this codebase. It adds display projections only.

It also never carries a password. A reuse group names the ACCOUNTS that share
one; the secret belongs on the operator's terminal and in the credential
appendix, never in an aggregate a web platform stores in a database.

Dependency-light (``__future__`` + ``typing`` + the display humanizer, itself
dependency-light), so the web backend and the appliance can both import it.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from adscan_core.reporting.password_hygiene import (
    iter_present_password_hygiene,
    read_password_hygiene,
    tier0_rollup_segment,
)
from adscan_core.reporting.privilege_tier_labels import (
    PRIVILEGE_TIER_TOKEN_ORDER,
    TIER_TOKEN_TIER0_DIRECT,
    highest_privilege_tier_token,
    privilege_tier_label_for_token,
    token_is_tier0,
)
from adscan_core.reporting.principal_display import humanize_principal_for_prose

#: Every key a hygiene render section carries. The contract test that locks the
#: PDF and the CTEM to one projection asserts against this tuple, so a field
#: added for one surface cannot be silently absent from the other.
SECTION_FIELDS: tuple[str, ...] = (
    "name",
    "extracted_total",
    "recovered_total",
    "recovery_rate_pct",
    "krbtgt_recovered",
    "high_value_extracted",
    "high_value_recovered",
    "tier_labels",
    "headline",
    "segments",
    "tier0",
    "reuse_recovered",
    "reuse_unrecovered",
)

#: Every key a reuse-group row carries. ``accounts`` is humanized display names,
#: never the shared password. ``top_tier`` names the most privileged tier the
#: group touches, so a shared password covering a domain-controlling account
#: does not read like one covering an escalation-capable account.
REUSE_ROW_FIELDS: tuple[str, ...] = (
    "accounts",
    "size",
    "has_tier0",
    "has_tier0_direct",
    "top_tier",
    "top_tier_label",
)


def humanize_reuse_accounts(accounts: Any, *, report_domain: str) -> list[str]:
    """Return the client-prose display names for a reuse group's accounts.

    Routes every account through the humanization SSOT so a shouted UPN, a raw
    SID or a ``@WELLKNOWN`` label never reaches the client: a user account types
    lower case (``svc_sql``) and the ``@domain`` suffix is stripped intra-domain.
    A localized directory name is de-shouted, never translated.

    The account's object class is not carried on the stored row, so each is
    humanized as the account it is (user default), which is correct for the
    service and user accounts a credential dump recovers.
    """
    out: list[str] = []
    for account in accounts or ():
        name = str(account or "").strip()
        if not name:
            continue
        out.append(
            humanize_principal_for_prose(label=name, report_domain=report_domain)
        )
    return out


def _tier_label(tier: str, tier_labels: Mapping[str, str] | None) -> str:
    """A tier token's label, preferring the wording the block itself carries.

    The block was worded where the label owner is importable, so reading it back
    is what keeps the PDF and the CTEM on identical words. The provider seam is
    the fallback for a block written before the wording was persisted; an
    unresolvable token renders empty rather than inventing a tier.
    """
    token = str(tier or "").strip().lower()
    if not token:
        return ""
    if isinstance(tier_labels, Mapping):
        label = str(tier_labels.get(token) or "").strip()
        if label:
            return label
    return privilege_tier_label_for_token(token)


def build_reuse_group_rows(
    groups: Any, *, report_domain: str, tier_labels: Mapping[str, str] | None = None
) -> list[dict[str, Any]]:
    """Project reuse groups onto render rows, groups covering Tier-0 first.

    The data SSOT already orders groups largest-first; this re-orders so a group
    covering a Tier-0 account leads (an administrative account sharing its
    password with a standard user is the sentence that decides the engagement)
    WITHOUT changing the set. Each row carries the humanized account names and
    the most privileged tier the group touches, never the shared password.

    The tier split matters on this row, not just the boundary: a shared password
    on an account with direct control of the domain is a different finding from
    one on an escalation-capable account, and the client cannot act on "includes
    a privileged account".

    Args:
        groups: The persisted reuse groups, each carrying ``segment_counts``
            keyed by tier token.
        report_domain: Humanization context for the account names.
        tier_labels: The block's own ``tier token -> label`` wording, so the row
            reads the same words as the segment table without reaching the tier
            classifier (the web backend cannot).
    """
    rows: list[dict[str, Any]] = []
    for group in groups or ():
        if not isinstance(group, Mapping):
            continue
        counts: dict[str, int] = {}
        segment_counts = group.get("segment_counts")
        if isinstance(segment_counts, Mapping):
            for tier, count in segment_counts.items():
                try:
                    counts[str(tier or "").strip().lower()] = int(count or 0)
                except (TypeError, ValueError):
                    continue
        present = [tier for tier, count in counts.items() if count > 0]
        top_tier = highest_privilege_tier_token(present)
        accounts = humanize_reuse_accounts(
            group.get("accounts"), report_domain=report_domain
        )
        try:
            size = int(group.get("size") or len(accounts))
        except (TypeError, ValueError):
            size = len(accounts)
        rows.append(
            {
                "accounts": accounts,
                "size": size,
                "has_tier0": any(token_is_tier0(tier) for tier in present),
                "has_tier0_direct": counts.get(TIER_TOKEN_TIER0_DIRECT, 0) > 0,
                "top_tier": top_tier,
                "top_tier_label": _tier_label(top_tier, tier_labels),
            }
        )
    # Tier-0-bearing groups first (direct control ahead of escalation-capable),
    # then largest, then alphabetically by the first account so the order is
    # deterministic. Display re-order only; same set.
    rows.sort(
        key=lambda r: (
            not r["has_tier0_direct"],
            not r["has_tier0"],
            -r["size"],
            r["accounts"][0] if r["accounts"] else "",
        )
    )
    return rows


def build_password_hygiene_section(
    name: str, view: Mapping[str, Any]
) -> dict[str, Any]:
    """Build one domain's render section from its verbatim hygiene view.

    Args:
        name: The domain the view belongs to. Used as the humanization context,
            so an account in this domain drops its ``@domain`` suffix and one in
            a trusted domain keeps it.
        view: The shape :func:`password_hygiene.read_password_hygiene` returns.

    Returns:
        A section carrying exactly :data:`SECTION_FIELDS`. Figures are passed
        through unchanged; the only additions are display projections (the
        humanized reuse rows and the Tier-0 segment lifted out for the lead).
    """
    stored = [
        dict(segment)
        for segment in view.get("segments") or ()
        if isinstance(segment, Mapping)
    ]
    tier_labels = (
        dict(view.get("tier_labels"))
        if isinstance(view.get("tier_labels"), Mapping)
        else {}
    )
    # Tier order, worst first, and only the tiers that HAVE accounts. The record
    # carries every tier so its figures reconcile against the extracted total;
    # a row reading "0 of 0" on a surface a client reads buys nothing, which is
    # what the removed High-Value bucket did on a real engagement. A segment the
    # order does not know (an older block) keeps its place at the end rather
    # than being dropped, because dropping a figure is worse than an odd row.
    rank = {tier: index for index, tier in enumerate(PRIVILEGE_TIER_TOKEN_ORDER)}
    segments = [
        segment
        for segment in sorted(
            stored,
            key=lambda s: rank.get(
                str(s.get("tier") or "").strip().lower(), len(rank)
            ),
        )
        if int(segment.get("extracted") or 0) > 0
    ]
    rollup = tier0_rollup_segment(stored)
    tier0 = rollup.as_dict() if rollup is not None and rollup.extracted > 0 else None
    return {
        "name": name,
        "extracted_total": view.get("extracted_total"),
        "recovered_total": view.get("recovered_total"),
        "recovery_rate_pct": view.get("recovery_rate_pct"),
        "krbtgt_recovered": bool(view.get("krbtgt_recovered")),
        # Orthogonal to the tiers, passed through verbatim: an account counted
        # here is also counted in its tier's row, so they are never summed.
        "high_value_extracted": view.get("high_value_extracted"),
        "high_value_recovered": view.get("high_value_recovered"),
        "tier_labels": tier_labels,
        "headline": str(view.get("headline") or ""),
        "segments": segments,
        "tier0": tier0,
        "reuse_recovered": build_reuse_group_rows(
            view.get("reuse_groups_recovered"),
            report_domain=name,
            tier_labels=tier_labels,
        ),
        "reuse_unrecovered": build_reuse_group_rows(
            view.get("reuse_groups_unrecovered"),
            report_domain=name,
            tier_labels=tier_labels,
        ),
    }


def build_password_hygiene_sections(
    named_views: Iterable[tuple[str, Mapping[str, Any]]],
) -> list[dict[str, Any]]:
    """Project ``(domain, view)`` pairs onto render sections, in input order."""
    return [
        build_password_hygiene_section(name, view)
        for name, view in named_views or ()
        if isinstance(view, Mapping)
    ]


def password_hygiene_sections_for_domains(
    domain_blocks: Iterable[tuple[str, Any]],
) -> list[dict[str, Any]]:
    """Read, gate and project in one call: the whole chain for a multi-domain run.

    Composes the presence gate
    (:func:`password_hygiene.iter_present_password_hygiene`, which carries the
    absence rule) with the projection, so a domain that attempted no recovery is
    simply absent from the result and no surface has to remember the gate.

    Args:
        domain_blocks: ``(domain_name, domain_block)`` pairs, each block a
            ``technical_report.json`` domain entry or a renderer's
            ``report_data`` entry for that domain.
    """
    return build_password_hygiene_sections(iter_present_password_hygiene(domain_blocks))


def password_hygiene_section_for_domain(
    domain: str, domain_block: Any
) -> dict[str, Any] | None:
    """Read, gate and project ONE domain: the shape a per-domain surface serves.

    The web CTEM is per-domain where the kit document is per-run, so this is the
    single-domain entry point onto the same projection. ``None`` when the domain
    carries no recovery block, which is the absence rule: the caller renders
    nothing rather than a 0% that reads as "your passwords are strong".
    """
    view = read_password_hygiene(domain_block)
    if not view.get("present"):
        return None
    return build_password_hygiene_section(str(domain), view)


__all__ = [
    "REUSE_ROW_FIELDS",
    "SECTION_FIELDS",
    "build_password_hygiene_section",
    "build_password_hygiene_sections",
    "build_reuse_group_rows",
    "humanize_reuse_accounts",
    "password_hygiene_section_for_domain",
    "password_hygiene_sections_for_domains",
]
