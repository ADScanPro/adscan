"""Attack-path renderers and narrative formatters."""

from __future__ import annotations

from typing import List, Dict, Callable

from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text
from rich.table import Table

import adscan_core.output._state as _state
from adscan_core.theme import ADSCAN_PRIMARY
from adscan_core.output._state import mark_sensitive
from adscan_core.output._log import (
    BRAND_COLORS,
    print_info,
    print_info_debug,
    print_warning,
)
from adscan_core.output._panels import print_panel
from adscan_core.output._tables import print_table
from adscan_core.smb_exclusion_policy import (
    is_globally_excluded_smb_share,
)


_SHARE_ACCESS_RELATION_KEYS = {
    "readshare": "Read",
    "writeshare": "Write",
    "fullcontrolshare": "Full Control",
}


__all__ = [
    "print_attack_paths_summary",
    "print_attack_path_detail",
    "print_attack_steps_summary",
    "print_attack_path_detail_debug",
    "print_attack_paths_summary_debug",
    "order_attack_paths_for_display",
    "_fallback_format_attack_path_node_label",
    "_fallback_format_attack_path_relation_label",
    "_fallback_format_attack_path_relation_display",
    "_fallback_format_attack_path_source_context",
    "_get_attack_path_narrative_formatters",
    "_format_attack_step_details",
    "_build_attack_steps_table",
    "_format_effective_target_basis_compact",
    "render_smb_exposed_resources_panel",
]


def _format_effective_target_basis_compact(
    path: dict[str, object] | None,
) -> tuple[str, str]:
    """Return compact primary/extras strings for effective target basis rendering."""
    if not isinstance(path, dict):
        return "", ""
    primary = path.get("effective_target_basis_primary")
    if not isinstance(primary, dict):
        return "", ""
    basis_kind = str(primary.get("basis_kind") or "").strip().lower()
    basis_kind_display = "MemberOf" if basis_kind == "member_of" else "Contains"
    target_label = str(primary.get("target_label") or "").strip()
    if not target_label:
        return "", ""
    primary_text = f"Reason: {basis_kind_display} -> {target_label}"

    extras = path.get("effective_target_basis_extras")
    if not isinstance(extras, list) or not extras:
        return primary_text, ""
    extra_labels = [
        str(extra.get("target_label") or "").strip()
        for extra in extras
        if isinstance(extra, dict) and str(extra.get("target_label") or "").strip()
    ]
    if not extra_labels:
        return primary_text, ""
    extras_summary = f"(+{len(extra_labels)} more)"
    detail_text = f"Also: {', '.join(extra_labels)}"
    return f"{primary_text} {extras_summary}", detail_text


def _share_name_from_details(details: dict[str, object] | None) -> str:
    """Return the graph-provided SMB share name for one share edge."""
    if not isinstance(details, dict):
        return ""
    for key in ("share_name", "share", "shareName"):
        value = str(details.get(key) or "").strip()
        if value:
            return value
    collector_method = str(details.get("collector_method") or "").strip()
    if collector_method.lower().startswith("share_acl:"):
        return collector_method.split(":", 1)[1].strip()
    return ""


def _is_share_access_relation(relation: object) -> bool:
    """Return True when *relation* is a native share-access capability edge."""
    return str(relation or "").strip().lower() in _SHARE_ACCESS_RELATION_KEYS


def _format_share_access_relation_display(
    relation: object,
    *,
    details: dict[str, object] | None = None,
) -> str:
    """Return a compact share-access label with share provenance inline."""
    relation_key = str(relation or "").strip().lower()
    access = _SHARE_ACCESS_RELATION_KEYS.get(relation_key)
    if not access:
        return ""
    share_name = _share_name_from_details(details)
    return (
        f"Share Access [{share_name}: {access}]"
        if share_name
        else f"Share Access [{access}]"
    )


def _share_access_rank(access_values: set[str]) -> int:
    """Return a sortable severity rank for a set of share access labels."""
    if "Full Control" in access_values:
        return 3
    if "Write" in access_values:
        return 2
    if "Read" in access_values:
        return 1
    return 0


def _format_share_access_set(access_values: set[str]) -> str:
    """Return a premium compact label for share permissions."""
    if "Full Control" in access_values:
        return "Full Control"
    if {"Read", "Write"}.issubset(access_values):
        return "Read+Write"
    if "Write" in access_values:
        return "Write"
    if "Read" in access_values:
        return "Read"
    return "Unknown"


def _path_reaches_domain_object(nodes: list, domain: str) -> bool:
    """Return True when the path's terminal node IS the domain object.

    The domain object is labelled with the domain FQDN (e.g. ``ESSOS.LOCAL``),
    optionally suffixed with ``@<realm>``. Used to decide whether a
    Domain-Compromised path already terminates at the domain object or needs
    the ``⇒ Domain Compromised`` closure marker because the depth budget
    truncated the structural DCSync closure.
    """
    if not nodes:
        return False
    terminal = str(nodes[-1]).split("@", 1)[0].strip().lower()
    return bool(terminal) and terminal == str(domain or "").strip().lower()


def _path_has_excluded_share_access_step(path: Dict[str, object]) -> bool:
    """Return True when a display path includes a globally excluded share edge."""
    steps = path.get("steps")
    if not isinstance(steps, list):
        return False
    for step in steps:
        if not isinstance(step, dict):
            continue
        relation = step.get("action") or step.get("relation")
        if not _is_share_access_relation(relation):
            continue
        details = step.get("details")
        share_name = _share_name_from_details(
            details if isinstance(details, dict) else None
        )
        if share_name and is_globally_excluded_smb_share(share_name):
            return True
    return False


def _collect_share_exposure_rows(
    paths: list[Dict[str, object]],
    *,
    limit: int = 8,
) -> list[dict[str, object]]:
    """Aggregate share-capability paths into operator-friendly exposure rows."""
    exposures: dict[tuple[str, str, str], dict[str, object]] = {}
    for path in paths:
        steps = path.get("steps")
        if not isinstance(steps, list):
            continue
        nodes = path.get("nodes")
        source = str(
            path.get("source")
            or (nodes[0] if isinstance(nodes, list) and nodes else "")
        ).strip()
        for step in steps:
            if not isinstance(step, dict):
                continue
            relation = step.get("action") or step.get("relation")
            relation_key = str(relation or "").strip().lower()
            access = _SHARE_ACCESS_RELATION_KEYS.get(relation_key)
            if not access:
                continue
            details = step.get("details")
            details = details if isinstance(details, dict) else {}
            share_name = _share_name_from_details(details)
            if share_name and is_globally_excluded_smb_share(share_name):
                continue
            host = str(details.get("to") or path.get("target") or "").strip()
            if not host:
                continue
            share_key = share_name or "unknown"
            source_label = str(
                details.get("source_label") or details.get("from") or source
            ).strip()
            key = (host.lower(), share_key.lower())
            row = exposures.setdefault(
                key,
                {
                    "host": host,
                    "share": share_key,
                    "access": set(),
                    "principals": set(),
                    "via": set(),
                    "impact_rank": 0,
                    "admin_share": is_globally_excluded_smb_share(share_key),
                    "choke": False,
                },
            )
            row_access = row.get("access")
            if isinstance(row_access, set):
                row_access.add(access)
            if source_label:
                principals = row.get("principals")
                if isinstance(principals, set):
                    principals.add(source_label)
            source_kind = str(details.get("source_kind") or "").strip().lower()
            if source_kind:
                via = row.get("via")
                if isinstance(via, set):
                    via.add(source_kind)
            if bool(details.get("is_choke_point")):
                row["choke"] = True
            if (
                str(details.get("to_control_level") or "").strip().lower()
                == "direct_domain_control"
            ):
                row["impact_rank"] = max(int(row.get("impact_rank") or 0), 3)
            elif bool(details.get("is_choke_point")):
                row["impact_rank"] = max(int(row.get("impact_rank") or 0), 2)
            else:
                row["impact_rank"] = max(int(row.get("impact_rank") or 0), 1)

    ranked = sorted(
        exposures.values(),
        key=lambda row: (
            int(row.get("impact_rank") or 0),
            _share_access_rank(
                row.get("access") if isinstance(row.get("access"), set) else set()
            ),
            0 if bool(row.get("admin_share")) else 1,
            str(row.get("host") or "").lower(),
            str(row.get("share") or "").lower(),
        ),
        reverse=True,
    )
    return ranked[: max(0, limit)]


def _path_contains_share_access_step(path: Dict[str, object]) -> bool:
    """Return True when the path includes any share-access edge (ReadShare/WriteShare/FullControlShare)."""
    steps = path.get("steps")
    if not isinstance(steps, list):
        return False
    return any(
        _is_share_access_relation(step.get("action") or step.get("relation"))
        for step in steps
        if isinstance(step, dict)
    )


def _render_share_resources_panel(rows: list[dict[str, object]]) -> None:
    """Render a premium SMB resource exposure panel with risk tiers and attack opportunities."""
    if not rows:
        return

    console = _state._get_console()

    # ── Summary header ────────────────────────────────────────────────────────
    hosts: set[str] = {str(r.get("host") or "") for r in rows if r.get("host")}
    write_rows = [
        r
        for r in rows
        if any(a in {"Write", "Full Control"} for a in (r.get("access") or set()))
    ]
    tier0_rows = [r for r in rows if int(r.get("impact_rank") or 0) >= 3]

    summary = Text()
    summary.append(f"{len(hosts)} host(s)", style=f"bold {BRAND_COLORS['info']}")
    summary.append("  ·  ", style="dim")
    summary.append(f"{len(rows)} share(s) exposed", style="bold white")
    if write_rows:
        summary.append("  ·  ", style="dim")
        summary.append(
            f"{len(write_rows)} writable", style=f"bold {BRAND_COLORS['warning']}"
        )
    if tier0_rows:
        summary.append("  ·  ", style="dim")
        summary.append(
            f"{len(tier0_rows)} on Tier 0 host", style=f"bold {BRAND_COLORS['error']}"
        )

    print_panel(
        summary,
        title="Exposed SMB Resources",
        border_style=BRAND_COLORS["info"],
        spacing="before",
    )

    # ── Risk classification ───────────────────────────────────────────────────
    def _row_risk(row: dict[str, object]) -> int:
        rank = int(row.get("impact_rank") or 0)
        has_write = any(
            a in {"Write", "Full Control"} for a in (row.get("access") or set())
        )
        if rank >= 3:
            return 2
        if bool(row.get("choke")) or has_write:
            return 1
        return 0

    high = [r for r in rows if _row_risk(r) == 2]
    medium = [r for r in rows if _row_risk(r) == 1]
    low = [r for r in rows if _row_risk(r) == 0]

    def _render_tier(
        tier_rows: list[dict[str, object]], label: str, label_style: str
    ) -> None:
        if not tier_rows:
            return
        console.print(Rule(style=label_style))
        for row in tier_rows:
            host = str(row.get("host") or "?")
            share = str(row.get("share") or "?")
            access_values: set[str] = (
                row.get("access") if isinstance(row.get("access"), set) else set()
            )
            access_str = _format_share_access_set(access_values)
            principals = sorted(
                str(p) for p in (row.get("principals") or set()) if str(p).strip()
            )

            line = Text()
            line.append("  ▸ ", style=f"bold {label_style}")
            line.append(label, style=f"bold {label_style}")
            line.append("  ", style="")
            line.append(mark_sensitive(host, "hostname"), style=f"bold {ADSCAN_PRIMARY}")
            line.append("  /  ", style="dim")
            line.append(share, style="bold white")
            line.append("\n")

            access_color = (
                "bold red"
                if "Full Control" in access_values
                else f"bold {BRAND_COLORS['warning']}"
                if "Write" in access_values
                else "white"
            )
            line.append("     Access   ", style="dim")
            line.append(access_str, style=access_color)
            line.append("\n")

            if principals:
                line.append("     Via      ", style="dim")
                principal_display = ", ".join(
                    mark_sensitive(p, "user") for p in principals[:3]
                )
                line.append(principal_display, style="white")
                if len(principals) > 3:
                    line.append(f"  +{len(principals) - 3} more", style="dim")
                line.append("\n")

            signals: list[tuple[str, str]] = []
            if int(row.get("impact_rank") or 0) >= 3:
                signals.append(("Tier 0 host", f"bold {BRAND_COLORS['error']}"))
            if bool(row.get("choke")):
                signals.append(("choke point", f"bold {BRAND_COLORS['warning']}"))
            if bool(row.get("admin_share")):
                signals.append(("admin share — confirm live access", "dim"))
            if signals:
                line.append("     Signals  ", style="dim")
                for i, (sig, sig_style) in enumerate(signals):
                    if i:
                        line.append("  ·  ", style="dim")
                    line.append(sig, style=sig_style)
                line.append("\n")

            console.print(line)

    _render_tier(high, "HIGH", BRAND_COLORS["error"])
    _render_tier(medium, "MED", BRAND_COLORS["warning"])
    _render_tier(low, "LOW", "dim")

    # ── Attack Opportunities: writable non-admin shares ───────────────────────
    write_candidates = [
        r
        for r in rows
        if any(a in {"Write", "Full Control"} for a in (r.get("access") or set()))
        and not bool(r.get("admin_share"))
    ]
    if not write_candidates:
        console.print()
        return

    console.print()
    console.print(
        Rule(
            f"Attack Opportunities  ({len(write_candidates)} writable share(s))",
            style=f"bold {BRAND_COLORS['warning']}",
        )
    )

    opp = Text()
    for row in write_candidates[:4]:
        host = str(row.get("host") or "")
        share = str(row.get("share") or "")
        principals = sorted(
            str(p) for p in (row.get("principals") or set()) if str(p).strip()
        )
        access_values_w: set[str] = (
            row.get("access") if isinstance(row.get("access"), set) else set()
        )
        access_str_w = _format_share_access_set(access_values_w)

        opp.append("\n  ⚡ ", style=f"bold {BRAND_COLORS['warning']}")
        opp.append(f"\\\\{host}\\{share}", style="bold white")
        opp.append(f"  [{access_str_w}]", style=f"{BRAND_COLORS['warning']}")
        if principals:
            opp.append(f"  ←  {', '.join(principals[:2])}", style="dim")
            if len(principals) > 2:
                opp.append(f" +{len(principals) - 2}", style="dim")
        opp.append("\n     Technique  ", style="dim")
        opp.append(
            "Drop SCF/LNK → capture NTLM hash via Responder / ntlm-coerce",
            style="white",
        )
        opp.append("\n     Condition  ", style="dim")
        opp.append("Privileged user must browse this share", style="dim")
        opp.append("\n")

    console.print(opp)
    console.print()


def render_smb_exposed_resources_panel(
    rows: list[dict[str, object]],
    domain: str = "",
    *,
    via_column_header: str = "Granted via",
    effective_note: bool = False,
) -> None:
    """Render the SMB exposed-resources surface for Phase 7: SMB Share Exposure.

    Premium-aligned with the rest of the product's phase UX:

    * **Operation header** — same ``print_operation_header`` panel used by
      every other workflow (DCSync, ESC1/ESC8, password spraying review,
      etc.), so the operator's eye-rhythm is unchanged when transitioning
      between phases.
    * **One unified table** — single Rich ``Table`` with a ``Host`` column
      that groups shares; no nested per-host tables (the previous design
      mixed ``SIMPLE_HEAVY`` inner tables inside a ``ROUNDED`` outer
      panel, which broke the visual rhythm and made it look like two
      different widgets stacked together).
    * **No redundant "Attack Opportunities" section** — the same writable
      shares were already in the table above. We surface technique +
      condition hints once, as a footer line under the table.
    * **Strict semantic colour** — Access cell colour encodes severity
      (Full Control = green, Read+Write = yellow, Read Only = cyan); the
      panel still reads correctly with ``NO_COLOR``.

    Args:
        rows: Share exposure rows from ``collect_share_exposures_from_graph``.
            Each dict must carry at least ``host``, ``share``,
            ``access`` (set[str]), and ``principals`` (set[str]).
            Optional: ``impact_rank`` (int), ``admin_share`` (bool).
        domain: Target domain name — shown in the operation-header context.
        via_column_header: Header for the 3rd column. Defaults to
            ``"Granted via"`` (the Phase-7 graph caller). The live per-user
            caller passes ``"Effective for"`` so the column reads as the
            credential whose effective access is shown.
        effective_note: When ``True``, render a single dim footer line under
            the table clarifying that access is this credential's effective
            access (share ACL intersected with NTFS, via SMB2 MaximalAccess).
    """
    from collections import defaultdict
    from rich.box import ROUNDED
    from rich.table import Table

    from adscan_core.output._panels import print_operation_header

    if not rows:
        return

    console = _state._get_console()

    # Filter out system shares already excluded by the shared policy
    # (IPC$, ADMIN$, drive letter $, print$, fax$, certenroll, ...).
    visible_rows = [
        r for r in rows if not is_globally_excluded_smb_share(str(r.get("share") or ""))
    ]
    if not visible_rows:
        return

    # ── Group by host so the table can render one section per host ────────────
    by_host: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in visible_rows:
        host = str(row.get("host") or "?").strip()
        by_host[host].append(row)

    # Sort hosts: Tier 0 first (highest blast radius), then share count desc.
    def _host_sort_key(
        host_item: tuple[str, list[dict[str, object]]],
    ) -> tuple[int, int]:
        h_rows = host_item[1]
        tier0 = any(int(r.get("impact_rank") or 0) >= 3 for r in h_rows)
        return (0 if tier0 else 1, -len(h_rows))

    sorted_hosts = sorted(by_host.items(), key=_host_sort_key)

    # Set when any rendered row's access is share-level only (NTFS unverified),
    # so the footer can explain the "(share-level only)" marker once.
    any_unverified = False

    # ── Access semantics — severity-coded label per access set ────────────────
    def _access_label(access_set: set[str]) -> tuple[str, str]:
        if "Full Control" in access_set:
            return "Full Control", "bold green"
        if "Write" in access_set and "Read" in access_set:
            return "Read+Write", "bold yellow"
        if "Write" in access_set:
            return "Write", "bold yellow"
        return "Read Only", "cyan"

    def _principals_display(principals: object) -> str:
        if not isinstance(principals, set):
            return ""
        sorted_p = sorted(str(p) for p in principals if str(p).strip())
        return ", ".join(sorted_p[:3]) + (
            f"  +{len(sorted_p) - 3}" if len(sorted_p) > 3 else ""
        )

    # ── Summary counters used by the operation header ─────────────────────────
    total_hosts = len(by_host)
    total_shares = len(visible_rows)
    tier0_hosts = sum(
        1 for _, h_rows in by_host.items()
        if any(int(r.get("impact_rank") or 0) >= 3 for r in h_rows)
    )
    writable_count = sum(
        1
        for r in visible_rows
        if any(a in {"Write", "Full Control"} for a in (r.get("access") or set()))
    )
    full_control_count = sum(
        1 for r in visible_rows if "Full Control" in (r.get("access") or set())
    )

    # ── Premium operation header (canonical phase chrome) ─────────────────────
    header_details: dict[str, str] = {}
    if domain:
        header_details["Domain"] = mark_sensitive(domain, "domain")
    host_summary = f"{total_hosts}"
    if tier0_hosts:
        host_summary += f"  ·  {tier0_hosts} Tier-0 DC"
    header_details["Hosts"] = host_summary
    share_summary = f"{total_shares}"
    if writable_count:
        share_summary += f"  ·  {writable_count} writable"
    if full_control_count:
        share_summary += f"  ·  {full_control_count} full-control"
    header_details["Shares"] = share_summary
    if writable_count:
        header_details["Technique"] = (
            "Drop SCF/LNK in a writable share → capture NTLM hash via "
            "Responder / ntlm-coerce when a privileged user browses"
        )

    print_operation_header(
        "SMB Share Exposure",
        header_details,
        icon="📂",
    )

    # ── Single unified table — host grouped via per-host section rows ────────
    table = Table(
        box=ROUNDED,
        show_header=True,
        header_style=f"bold {BRAND_COLORS['info']}",
        padding=(0, 1),
        expand=False,
        title_justify="left",
    )
    table.add_column("Host / Share", style="white", no_wrap=True)
    table.add_column("Access", no_wrap=True)
    table.add_column(via_column_header, style="dim", no_wrap=False, overflow="fold")

    for host_idx, (host, host_rows) in enumerate(sorted_hosts):
        is_tier0 = any(int(r.get("impact_rank") or 0) >= 3 for r in host_rows)

        # Host section row — one cell spanning visually via emphasis only,
        # so the operator scans by host without losing the table structure.
        host_label = Text()
        host_label.append("▸ ", style="dim")
        host_label.append(mark_sensitive(host, "hostname"), style="bold white")
        if is_tier0:
            host_label.append("  ·  Tier-0 DC", style=f"bold {BRAND_COLORS['error']}")
        host_label.append(
            f"  ·  {len(host_rows)} share(s)", style="dim"
        )
        # Use a section separator between hosts (skip before the first).
        if host_idx > 0:
            table.add_section()
        table.add_row(host_label, Text(""), Text(""))

        for row in sorted(host_rows, key=lambda r: str(r.get("share") or "")):
            share_name = str(row.get("share") or "?")
            access_set: set[str] = (
                row.get("access") if isinstance(row.get("access"), set) else set()
            )
            acc_label, acc_style = _access_label(access_set)
            # A row whose access came only from the raw share-level ACL (NTFS
            # never verified) may overstate write/full-control — flag it so the
            # access reads as a lead to confirm, not a confirmed grant.
            ntfs_unverified = row.get("ntfs_verified") is False
            access_text = Text(acc_label, style=acc_style)
            if ntfs_unverified:
                access_text.append("  (share-level only)", style="dim")
                any_unverified = True
            via_str = _principals_display(row.get("principals"))
            share_cell = Text()
            share_cell.append("    ", style="dim")  # indent under host
            share_cell.append(share_name, style="white")
            table.add_row(
                share_cell,
                access_text,
                via_str or "-",
            )

    console.print(table)

    if effective_note:
        console.print(
            "Access shown is this credential's effective access "
            "(share ACL ∩ NTFS, SMB2 MaximalAccess).",
            style="dim",
        )
    if any_unverified:
        console.print(
            "Rows marked (share-level only) report the share ACL alone — NTFS "
            "permissions were not verified, so the access may be lower in "
            "practice. Review before relying on write/full-control.",
            style="dim",
        )


def _collect_path_choke_points(
    steps: list[object],
) -> list[dict[str, object]]:
    """Return the choke-point step detail dicts present on a path."""
    found: list[dict[str, object]] = []
    for step in steps:
        if not isinstance(step, dict):
            continue
        details = step.get("details")
        if not isinstance(details, dict):
            continue
        if not bool(details.get("is_choke_point")):
            continue
        found.append(details)
    return found


def _choke_point_rank(details: dict[str, object]) -> tuple[int, int, int]:
    """Return (severity, directness, blast) ranks for one choke-point detail."""
    directness = str(details.get("choke_point_directness") or "").strip().lower()
    severity = str(details.get("severity") or "").strip().lower()
    blast_radius = details.get("blast_radius")
    severity_rank = (
        3
        if severity == "critical"
        else 2
        if severity == "high"
        else 1
        if severity == "medium"
        else 0
    )
    directness_rank = (
        2 if directness == "direct" else 1 if directness == "indirect" else 0
    )
    blast_rank = (
        blast_radius if isinstance(blast_radius, int) and blast_radius > 0 else 0
    )
    return severity_rank, directness_rank, blast_rank


def _path_choke_summary(path: Dict[str, object]) -> dict[str, object] | None:
    """Return the top-ranked choke-point summary across all steps in a path."""
    steps = path.get("steps", [])
    if not isinstance(steps, list):
        return None
    choke_points = _collect_path_choke_points(steps)
    if not choke_points:
        return None
    ranked = sorted(choke_points, key=_choke_point_rank, reverse=True)
    top = ranked[0]
    blast_radius = top.get("blast_radius")
    return {
        "count": len(choke_points),
        "top": top,
        "severity_rank": _choke_point_rank(top)[0],
        "directness_rank": _choke_point_rank(top)[1],
        "blast_radius": blast_radius
        if isinstance(blast_radius, int) and blast_radius > 0
        else 0,
    }


def _canonical_attack_path_sort_key(
    path: Dict[str, object],
) -> tuple[int, ...]:
    """Return the canonical sort key for one attack path.

    Single source of truth for UX path ordering. Any change to the criterion
    (promoting/demoting a factor, swapping ranks) belongs in this function;
    it propagates automatically to every consumer that uses
    ``order_attack_paths_for_display`` — table, selector prompt, snapshot,
    future exporters.
    """
    # Lazy import: adscan_core ships in LITE builds which load this module
    # before adscan_internal is imported, so the dependency stays per-call.
    from adscan_internal.services.attack_step_support_registry import (
        build_path_execution_priority_key,
    )

    choke_summary = _path_choke_summary(path)
    if choke_summary is None:
        choke_presence = 0
        severity_rank = 0
        blast_radius = 0
    else:
        choke_presence = 1
        severity_rank = int(choke_summary.get("severity_rank") or 0)
        blast_radius = int(choke_summary.get("blast_radius") or 0)
    path_length = path.get("length")
    path_length_rank = (
        path_length if isinstance(path_length, int) and path_length >= 0 else 0
    )
    base = build_path_execution_priority_key(path)
    # The viability_rank field was inserted at base[4]; downstream indices
    # shifted +1.  The outer ``*base[:5]`` slice still groups paths by
    # (priority_class, terminal_class, followup, priority_rank), and the
    # newly-added viability_rank (now at base[4]) becomes the 5th outer
    # factor so reachable targets always surface before unreachable ones
    # within the same Tier-0/high-value/pivot bucket.
    return (
        *base[:5],
        -choke_presence,
        -severity_rank,
        -blast_radius,
        base[5],   # status_order (was base[4])
        base[6],   # agg_effort_score (was base[5])
        base[7],   # terminal_semantics (was base[6])
        base[8],   # terminal_effort (was base[7])
        path_length_rank,
        base[10],  # source (was base[9])
        base[11],  # target (was base[10])
    )


def order_attack_paths_for_display(
    paths: list[Dict[str, object]] | None,
) -> list[Dict[str, object]]:
    """Return attack paths in canonical UX display order.

    **Single source of truth** for what the operator sees and in what order.
    The table renderer (`print_attack_paths_summary`) and any selector
    prompt that lets the operator pick a path MUST consume the output of
    this function so they cannot diverge by construction.

    Filtering: drops paths the table omits — admin-share access steps
    (C$, ADMIN$, ...) and share-access edges (these surface in the
    resource-exposure panel, not the attack-path table).

    Ordering: choke-point severity → ADscan execution priority → path length.
    Stable; idempotent on already-ordered input.

    To change sort criteria for the entire product (CLI, selector,
    snapshot, future exporters) edit ``_canonical_attack_path_sort_key``.
    """
    if not paths:
        return []
    after_global_exclusion = [
        path for path in paths if not _path_has_excluded_share_access_step(path)
    ]
    displayable = [
        path
        for path in after_global_exclusion
        if not _path_contains_share_access_step(path)
    ]
    return sorted(displayable, key=_canonical_attack_path_sort_key)


def print_attack_paths_summary(
    domain: str,
    paths: List[Dict[str, object]],
    max_display: int = 5,
    *,
    max_path_steps: int | None = None,
    search_mode_label: str | None = None,
    actionable_count: int | None = None,
    show_sections: bool = False,
    share_rows: list[dict[str, object]] | None = None,
) -> list[Dict[str, object]]:
    """Render attack paths in a clear, compact summary.

    When ``show_sections=True`` the table is split into ADscan outcome
    sections such as direct domain control, compromise enablers,
    high-impact privileges, and pivots.

    Args:
        share_rows: Pre-computed share exposure inventory from
            ``collect_share_exposures_from_graph``.  When supplied, this
            replaces the legacy path-derived share collection so the
            SMB exposure panel is independent of DFS parameters (max_depth,
            target_mode, max_paths cap).  When ``None``, falls back to
            extracting share data from ``paths`` (legacy behaviour).
    """
    from rich.table import Table
    from adscan_internal.services.adcs_path_display import resolve_adcs_display_target
    from adscan_internal.services.attack_step_support_registry import (
        DISPLAY_TIER_COMPROMISE_ENABLER,
        DISPLAY_TIER_DOMAIN_COMPROMISE,
        DISPLAY_TIER_LATERAL_PIVOT,
        DISPLAY_TIER_ORDER,
        DISPLAY_TIER_STYLES,
        DISPLAY_TIER_TIER0_FOOTHOLD,
        describe_path_target_outcome,
        get_path_display_tier,
    )

    if not paths and not share_rows:
        return

    # Filtering+ordering is delegated to the canonical UX helper so the
    # selector prompt that consumes the same `summaries` list cannot
    # diverge from this table. See ``order_attack_paths_for_display``.
    ordered_paths = order_attack_paths_for_display(paths)

    # Share exposure inventory — prefer the caller-supplied graph-derived rows
    # (independent of DFS parameters) over the legacy path-derived fallback.
    # The fallback consumes the post-global-exclusion list (admin shares
    # already stripped) so the exposure panel matches the table semantics.
    after_global_exclusion = (
        [path for path in paths if not _path_has_excluded_share_access_step(path)]
        if share_rows is None
        else []
    )
    effective_share_rows: list[dict[str, object]] = (
        share_rows
        if share_rows is not None
        else _collect_share_exposure_rows(after_global_exclusion, limit=12)
    )

    if not ordered_paths and not effective_share_rows:
        return []

    if not ordered_paths:
        return []

    total = len(ordered_paths)
    show_count = min(max_display, total)
    visible = ordered_paths[:show_count]

    total_by_class = (
        {
            tier: sum(1 for p in ordered_paths if get_path_display_tier(p) == tier)
            for tier in DISPLAY_TIER_ORDER
        }
        if show_sections
        else {tier: 0 for tier in DISPLAY_TIER_ORDER}
    )
    visible_by_class = (
        {
            tier: sum(1 for p in visible if get_path_display_tier(p) == tier)
            for tier in DISPLAY_TIER_ORDER
        }
        if show_sections
        else {tier: 0 for tier in DISPLAY_TIER_ORDER}
    )
    visible_classes = [
        tier for tier in DISPLAY_TIER_ORDER if visible_by_class[tier] > 0
    ]

    summary_text = Text()
    if show_sections:
        for idx, tier in enumerate(DISPLAY_TIER_ORDER):
            label, icon, style_key = DISPLAY_TIER_STYLES[tier]
            if idx > 0:
                summary_text.append("   ", style="dim")
            summary_text.append(f"{icon} {label}: ", style="bold white")
            visible_count = visible_by_class[tier]
            total_count = total_by_class[tier]
            count_label = (
                f"{visible_count}/{total_count}"
                if 0 < visible_count < total_count
                else str(total_count)
            )
            count_style = BRAND_COLORS[style_key] if total_count > 0 else "dim"
            summary_text.append(count_label, style=f"bold {count_style}")
        summary_text.append("   Showing: ", style="bold white")
        summary_text.append(str(show_count), style=f"bold {BRAND_COLORS['success']}")
        if show_count < total:
            summary_text.append(f"/{total}", style="dim")
    else:
        summary_text.append("Attack Paths Found: ", style="bold white")
        summary_text.append(str(total), style=f"bold {BRAND_COLORS['warning']}")
        summary_text.append("  ")
        summary_text.append("Showing: ", style="bold white")
        summary_text.append(str(show_count), style=f"bold {BRAND_COLORS['info']}")
    if str(search_mode_label or "").strip():
        summary_text.append("  ")
        summary_text.append("Mode: ", style="bold white")
        summary_text.append(
            str(search_mode_label).strip(), style=f"bold {BRAND_COLORS['success']}"
        )
    if isinstance(actionable_count, int) and actionable_count >= 0:
        summary_text.append("  ")
        summary_text.append("Actionable: ", style="bold white")
        summary_text.append(
            f"{actionable_count}/{total}", style=f"bold {BRAND_COLORS['warning']}"
        )

    print_panel(
        summary_text,
        title=f"🧭 Domain: {domain}",
        border_style=BRAND_COLORS["info"],
        padding=(0, 2),
        expand=True,
        spacing="both",
    )

    def _mark_path_node(name: str) -> str:
        if not name:
            return "N/A"
        if "." in name or name.endswith("$"):
            return mark_sensitive(name, "hostname")
        return mark_sensitive(name, "user")

    def _format_choke_point_badge(details: dict[str, object]) -> Text:
        directness = str(details.get("choke_point_directness") or "").strip().lower()
        blast_radius = details.get("blast_radius")
        badge = Text()
        label = (
            "CHOKE: Direct"
            if directness == "direct"
            else "CHOKE: Indirect"
            if directness == "indirect"
            else "CHOKE"
        )
        style = (
            BRAND_COLORS["error"]
            if directness == "direct"
            else BRAND_COLORS["warning"]
            if directness == "indirect"
            else BRAND_COLORS["info"]
        )
        badge.append(label, style=f"bold {style}")
        if isinstance(blast_radius, int) and blast_radius > 1:
            badge.append(f" x{blast_radius}", style=f"bold {style}")
        return badge

    def _render_top_choke_points_panel(
        paths_to_render: list[Dict[str, object]],
    ) -> None:
        aggregate: dict[tuple[str, str, str], dict[str, object]] = {}
        for path in paths_to_render:
            steps = path.get("steps", [])
            if not isinstance(steps, list):
                continue
            for details in _collect_path_choke_points(steps):
                source = str(details.get("from") or "").strip()
                target = str(details.get("to") or "").strip()
                choke_type = (
                    str(details.get("choke_point_type") or "").strip().lower()
                    or "transition"
                )
                if not source or not target:
                    continue
                key = (source, target, choke_type)
                blast_radius = details.get("blast_radius")
                blast_value = (
                    blast_radius
                    if isinstance(blast_radius, int) and blast_radius > 0
                    else 0
                )
                ranked = _choke_point_rank(details)
                current = aggregate.get(key)
                if current is None:
                    aggregate[key] = {
                        "source": source,
                        "target": target,
                        "choke_type": choke_type,
                        "details": details,
                        "occurrences": 1,
                        "max_blast_radius": blast_value,
                        "rank": ranked,
                    }
                    continue
                current["occurrences"] = int(current.get("occurrences") or 0) + 1
                current["max_blast_radius"] = max(
                    int(current.get("max_blast_radius") or 0), blast_value
                )
                if ranked > tuple(current.get("rank") or (0, 0, 0)):
                    current["details"] = details
                    current["rank"] = ranked
        if not aggregate:
            return

        ranked_items = sorted(
            aggregate.values(),
            key=lambda item: (
                tuple(item.get("rank") or (0, 0, 0)),
                int(item.get("max_blast_radius") or 0),
                int(item.get("occurrences") or 0),
            ),
            reverse=True,
        )
        summary = Text()
        summary.append("Top choke points: ", style="bold white")
        for idx, item in enumerate(ranked_items[:3], start=1):
            if idx > 1:
                summary.append("   ", style="dim")
            details = item["details"]
            summary.append(f"{idx}. ", style="dim")
            summary.append_text(_format_choke_point_badge(details))
            summary.append("  ", style="dim")
            summary.append(
                _mark_path_node(str(item.get("source") or "")),
                style=BRAND_COLORS["info"],
            )
            summary.append(" → ", style="dim")
            summary.append(
                _mark_path_node(str(item.get("target") or "")),
                style=BRAND_COLORS["warning"],
            )
            blast_radius = int(item.get("max_blast_radius") or 0)
            occurrences = int(item.get("occurrences") or 0)
            if blast_radius > 0:
                summary.append(
                    f"  blast {blast_radius}", style=f"bold {BRAND_COLORS['warning']}"
                )
            if occurrences > 1:
                summary.append(f"  seen in {occurrences} path(s)", style="dim")
        print_panel(
            summary,
            title="⚠ Choke Point Priorities",
            border_style=BRAND_COLORS["warning"],
            padding=(0, 2),
            expand=True,
            spacing="after",
        )

    _render_top_choke_points_panel(visible)

    table = Table(
        title=f"Attack Paths ({show_count})",
        title_style=f"bold {BRAND_COLORS['success']}",
        border_style=BRAND_COLORS["success"],
        show_header=True,
        header_style=f"bold {BRAND_COLORS['success']}",
        padding=(0, 1),
    )
    table.add_column("#", justify="right", width=3)
    table.add_column("Path", style="cyan", no_wrap=False)
    table.add_column("Affected", style="white", no_wrap=False, width=10)
    table.add_column("Target", style="white", no_wrap=False, width=10)
    table.add_column("Type", style="white", no_wrap=False, width=18)
    table.add_column("State", style="white", no_wrap=False, width=10)
    table.add_column("Exec", style="white", no_wrap=False, width=10)
    table.add_column("Status", style="magenta", no_wrap=False, width=10)
    table.add_column("Len", justify="right", width=4)
    format_node_label, _, format_relation_display, _ = (
        _get_attack_path_narrative_formatters()
    )

    def _format_inline_chain(
        nodes: list[object],
        rels: list[object],
        steps: list[object] | None = None,
    ) -> Text:
        if not nodes:
            return Text("N/A")
        chain = Text()
        truncated = False
        rels_to_render = rels
        nodes_to_render = nodes
        step_details_to_render: list[dict[str, object] | None] = []
        if isinstance(steps, list):
            for step in steps:
                if isinstance(step, dict):
                    details = step.get("details")
                    step_details_to_render.append(
                        details if isinstance(details, dict) else None
                    )
        if (
            isinstance(max_path_steps, int)
            and max_path_steps > 0
            and len(rels) > max_path_steps
        ):
            truncated = True
            rels_to_render = rels[:max_path_steps]
            nodes_to_render = nodes[: max_path_steps + 1]
            step_details_to_render = step_details_to_render[:max_path_steps]

        chain.append(
            _mark_path_node(format_node_label(str(nodes_to_render[0]), domain))
        )
        for idx, rel in enumerate(rels_to_render):
            if idx + 1 >= len(nodes_to_render):
                break
            step_details = (
                step_details_to_render[idx]
                if idx < len(step_details_to_render)
                else None
            )
            rel_label = format_relation_display(
                rel,
                details=step_details,
            )
            share_rel_label = _format_share_access_relation_display(
                rel,
                details=step_details,
            )
            if share_rel_label:
                rel_label = share_rel_label
            next_label = str(nodes_to_render[idx + 1])
            if isinstance(step_details, dict):
                next_label = str(
                    step_details.get("display_to")
                    or resolve_adcs_display_target(
                        rel,
                        step_details,
                        fallback_target=next_label,
                    )
                    or next_label
                )
            chain.append(" → ", style="dim")
            chain.append(rel_label, style=BRAND_COLORS["warning"])
            chain.append(" → ", style="dim")
            chain.append(_mark_path_node(format_node_label(next_label, domain)))
        if not truncated and len(nodes) > len(rels) + 1:
            for node in nodes[len(rels) + 1 :]:
                chain.append(" → ", style="dim")
                chain.append(_mark_path_node(format_node_label(str(node), domain)))
        if truncated:
            remaining = max(0, len(rels) - len(rels_to_render))
            chain.append(" → ", style="dim")
            chain.append(f"...(+{remaining} more)", style="dim")
        return chain

    def _format_exec_cell(meta: dict[str, object] | None) -> Text:
        if not isinstance(meta, dict):
            return Text("", style="dim")
        execution_support_status = str(
            meta.get("execution_support_status") or ""
        ).strip()
        if execution_support_status.lower() == "unsupported":
            return Text("Unsupported", style=BRAND_COLORS["error"])
        execution_ready_count = meta.get("execution_ready_count")
        execution_candidate_count = meta.get("execution_candidate_count")
        execution_context_required = bool(meta.get("execution_context_required"))
        if not execution_context_required:
            return Text("Direct", style=BRAND_COLORS["info"])
        if not (
            isinstance(execution_ready_count, int)
            and execution_ready_count >= 0
            and isinstance(execution_candidate_count, int)
            and execution_candidate_count >= 0
        ):
            return Text("?", style="dim")
        if execution_ready_count <= 0:
            return Text("NeedsCred", style=BRAND_COLORS["error"])
        if execution_candidate_count > execution_ready_count:
            return Text(
                f"{execution_ready_count}/{execution_candidate_count}",
                style=BRAND_COLORS["success"],
            )
        return Text("Ready", style=BRAND_COLORS["success"])

    def _format_target_state_cell(meta: dict[str, object] | None) -> Text:
        if not isinstance(meta, dict):
            return Text("", style="dim")
        target_enabled = meta.get("execution_target_enabled")
        if target_enabled is True:
            return Text("Enabled", style=BRAND_COLORS["success"])
        if target_enabled is False:
            return Text("Disabled", style=BRAND_COLORS["error"])
        return Text("", style="dim")

    for idx, path in enumerate(visible, start=1):
        nodes = path.get("nodes", [])
        rels = path.get("relations", [])
        steps = path.get("steps", [])
        if not isinstance(nodes, list):
            nodes = []
        if not isinstance(rels, list):
            rels = []
        if not isinstance(steps, list):
            steps = []

        display_tier = get_path_display_tier(path)
        path_str = _format_inline_chain(nodes, rels, steps)
        # Domain-compromise closure marker. A path classified as Domain
        # Compromised whose visible chain stops at a Tier-0 principal (e.g.
        # DOMAIN ADMINS) or asset rather than the Domain object — typically
        # because the depth budget truncated the structural DCSync closure —
        # would otherwise dead-end ambiguously and violate the nomenclature
        # rule "attack paths terminate at Domain Compromised, never at Domain
        # Admins". We append the canonical closure marker so the terminus is
        # unambiguous without fabricating graph edges in the cached record.
        if (
            display_tier == DISPLAY_TIER_DOMAIN_COMPROMISE
            and nodes
            and not _path_reaches_domain_object(nodes, domain)
        ):
            path_str.append("  ⇒ ", style="dim")
            path_str.append("Domain Compromised", style=f"bold {BRAND_COLORS['error']}")
        # Diagnostic provenance; the detail view surfaces it labelled, so keep
        # it out of the default compact table.
        if _state.is_debug_mode():
            basis_primary, _ = _format_effective_target_basis_compact(path)
            if basis_primary:
                path_str.append("\n", style="dim")
                path_str.append(basis_primary, style="dim")
        choke_points = _collect_path_choke_points(steps)
        if choke_points:
            path_str.append("\n", style="dim")
            for cp_idx, details in enumerate(choke_points[:2], start=1):
                if cp_idx > 1:
                    path_str.append("  ", style="dim")
                path_str.append_text(_format_choke_point_badge(details))
        length = path.get("length", len(rels))
        status = str(path.get("status") or "theoretical")
        # Drift diagnostic: recompute the path-level status from the live
        # step statuses and log a warning when it diverges from what the
        # summary record carries. This nails down whether the bug is the
        # summary holding a stale ``status`` (computed once, never refreshed
        # after individual step statuses changed) or a renderer-side issue.
        try:
            from adscan_internal.services.attack_paths_core import (
                _derive_display_status_from_steps,
            )
            steps_for_check = path.get("steps") or []
            if steps_for_check:
                fresh_status = _derive_display_status_from_steps(steps_for_check)
                if fresh_status != status:
                    try:
                        from adscan_core.rich_output import print_info_debug
                    except Exception:  # pragma: no cover - defensive
                        print_info_debug = None  # type: ignore[assignment]
                    if print_info_debug is not None:
                        step_view = ", ".join(
                            f"{(s.get('action') or '?')}={s.get('status') or '?'}"
                            for s in steps_for_check
                            if isinstance(s, dict)
                        )
                        print_info_debug(
                            "[attack_paths_render] STATUS DRIFT: "
                            f"summary.status={status!r} fresh_from_steps={fresh_status!r} "
                            f"steps=[{step_view}]"
                        )
        except Exception:  # pragma: no cover - diagnostic only
            pass

        affected_cell = ""
        target_cell = ""
        try:
            from adscan_internal.services.path_renderer import (
                TechnicalRenderer as _TechRenderer,
            )
            from adscan_internal.services.path_renderer import (
                _path_compromise_class as _path_cls,
            )

            _renderer = _TechRenderer()
            _badge = _renderer.render_class_label(_path_cls(path))
            path_type_cell = f"{_badge} {describe_path_target_outcome(path)}"
        except Exception:
            path_type_cell = describe_path_target_outcome(path)
        state_cell = Text("", style="dim")
        meta = path.get("meta") if isinstance(path, dict) else None
        if isinstance(meta, dict):
            # Prefer combined principal count (users + computers); fall back to
            # legacy user-only count for older cached records.
            affected_count = meta.get("affected_principal_count")
            if not isinstance(affected_count, int):
                affected_count = meta.get("affected_user_count")
            if isinstance(affected_count, int):
                affected_cell = str(affected_count)
            target_kind = str(meta.get("execution_support_target_kind") or "").strip()
            if target_kind:
                target_cell = target_kind
            state_cell = _format_target_state_cell(meta)
        exec_cell = _format_exec_cell(meta if isinstance(meta, dict) else None)

        row_style = "dim" if display_tier == DISPLAY_TIER_LATERAL_PIVOT else ""
        idx_style = (
            BRAND_COLORS["error"]
            if display_tier == DISPLAY_TIER_DOMAIN_COMPROMISE
            else BRAND_COLORS["warning"]
            if display_tier
            in (DISPLAY_TIER_TIER0_FOOTHOLD, DISPLAY_TIER_COMPROMISE_ENABLER)
            else None
        )
        idx_cell: str | Text = (
            Text(str(idx), style=f"bold {idx_style}") if idx_style else str(idx)
        )
        row = [
            idx_cell,
            path_str,
            affected_cell,
            target_cell,
            path_type_cell,
            state_cell,
            exec_cell,
            status,
            str(length),
        ]
        end_section = (
            show_sections
            and idx < show_count
            and display_tier != get_path_display_tier(visible[idx])
            and display_tier in visible_classes
        )
        table.add_row(*row, style=row_style, end_section=end_section)

    print_table(table, spacing="both")
    return list(ordered_paths)


_ATTACK_PATH_NARRATIVE_FALLBACK_LOGGED = False


def _fallback_format_attack_path_node_label(label: str, domain: str) -> str:
    """Best-effort node label formatter when reporting narratives are unavailable."""
    value = str(label or "").strip()
    if not value:
        return "N/A"
    domain_value = str(domain or "").strip().lower()

    if "\\" in value:
        value = value.split("\\", 1)[1].strip()

    if "@" in value:
        left, _, right = value.partition("@")
        if right and right.strip().lower() == domain_value:
            return left.strip() or value
    if domain_value and value.lower().endswith(f".{domain_value}"):
        host = value[: -(len(domain_value) + 1)].split(".", 1)[0].strip()
        return host or value

    return value


def _fallback_format_attack_path_relation_label(relation: str) -> str:
    """Best-effort relation formatter when reporting narratives are unavailable."""
    import re

    value = str(relation or "").strip()
    if not value:
        return "N/A"
    value = value.replace("_", " ")
    value = re.sub(r"([a-z])([A-Z])", r"\1 \2", value)
    return value


def _fallback_format_attack_path_relation_display(
    relation: object,
    *,
    details: dict[str, object] | None = None,
    formatter: Callable[[str], str] | None = None,
) -> str:
    """Fallback compact relation label when reporting narratives are unavailable."""
    relation_text = str(relation or "").strip()
    relation_label = (
        formatter(relation_text)
        if callable(formatter) and relation_text
        else _fallback_format_attack_path_relation_label(relation_text)
    )
    if not isinstance(details, dict):
        return relation_label
    relation_key = relation_text.lower()
    if relation_key == "userdescription":
        source_username = str(details.get("source_username") or "").strip()
        if source_username:
            return f"{relation_label} (from {source_username})"
        return relation_label
    if _is_share_access_relation(relation_text):
        return _format_share_access_relation_display(relation_text, details=details)
    if relation_key in {"passwordinshare", "passwordinfile", "gpppassword"}:
        host_hint = ""
        share_hint = ""
        artifact_hint = ""
        for value in details.get("hosts_list"), details.get("hosts"):
            if isinstance(value, list) and value:
                host_hint = str(value[0] or "").strip()
                if host_hint:
                    break
            elif isinstance(value, str) and value.strip():
                host_hint = value.strip()
                break
        for value in details.get("shares_list"), details.get("shares"):
            if isinstance(value, list) and value:
                share_hint = str(value[0] or "").strip()
                if share_hint:
                    break
            elif isinstance(value, str) and value.strip():
                share_hint = value.strip()
                break
        artifact_text = str(details.get("artifact") or "").strip().replace("\\", "/")
        if artifact_text:
            artifact_hint = artifact_text.rsplit("/", 1)[-1]
        context_hint = ""
        if share_hint and artifact_hint:
            context_hint = f"{share_hint}/{artifact_hint}"
        elif host_hint and share_hint:
            context_hint = f"{host_hint}:{share_hint}"
        elif artifact_hint:
            context_hint = artifact_hint
        elif share_hint:
            context_hint = share_hint
        elif host_hint:
            context_hint = host_hint
        return f"{relation_label} [{context_hint}]" if context_hint else relation_label
    if relation_key in {"dumplsa", "dumpdpapi", "dumplsass"}:
        context_hint = (
            str(details.get("target_host") or "").strip()
            or str(details.get("credential_username") or "").strip()
        )
        return f"{relation_label} [{context_hint}]" if context_hint else relation_label
    return relation_label


def _fallback_format_attack_path_source_context(
    relation: object,
    *,
    details: dict[str, object] | None = None,
) -> str:
    """Fallback source-context formatter when reporting narratives are unavailable."""
    if not isinstance(details, dict):
        return ""

    relation_key = str(relation or "").strip().lower()
    if relation_key == "userdescription":
        source_username = str(details.get("source_username") or "").strip()
        auth_mechanism = str(details.get("auth_mechanism") or "").strip().lower()
        secret = str(details.get("secret") or "").strip()
        context_parts: list[str] = []
        if source_username:
            context_parts.append(f"description of {source_username}")
        if auth_mechanism == "ldap_anonymous_bind":
            context_parts.append("via anonymous LDAP bind")
        elif auth_mechanism == "ldap_authenticated_bind":
            context_parts.append("via authenticated LDAP query")
        if secret:
            context_parts.append(f"secret {mark_sensitive(secret, 'password')}")
        return " ".join(context_parts).strip()

    if relation_key in {"passwordinshare", "passwordinfile", "gpppassword"}:
        host_hint = ""
        share_hint = ""
        artifact_hint = str(details.get("artifact") or "").strip().replace("\\", "/")
        artifact_kind = str(details.get("artifact_kind") or "").strip().lower()
        secret = str(details.get("secret") or details.get("password") or "").strip()
        for value in details.get("hosts_list"), details.get("hosts"):
            if isinstance(value, list) and value:
                host_hint = str(value[0] or "").strip()
                if host_hint:
                    break
            elif isinstance(value, str) and value.strip():
                host_hint = value.strip()
                break
        for value in details.get("shares_list"), details.get("shares"):
            if isinstance(value, list) and value:
                share_hint = str(value[0] or "").strip()
                if share_hint:
                    break
            elif isinstance(value, str) and value.strip():
                share_hint = value.strip()
                break
        context_parts: list[str] = []
        if share_hint:
            context_parts.append(f"share {share_hint}")
        if host_hint:
            context_parts.append(f"host {host_hint}")
        if artifact_hint:
            if artifact_kind:
                context_parts.append(f"{artifact_kind} artifact {artifact_hint}")
            else:
                context_parts.append(f"artifact {artifact_hint}")
        if secret:
            context_parts.append(f"secret {mark_sensitive(secret, 'password')}")
        return " | ".join(context_parts)

    if relation_key in {"dumplsa", "dumpdpapi", "dumplsass"}:
        target_host = str(details.get("target_host") or "").strip()
        credential_username = str(details.get("credential_username") or "").strip()
        secret = str(details.get("secret") or "").strip()
        context_parts: list[str] = []
        if target_host:
            context_parts.append(f"host {target_host}")
        if credential_username:
            context_parts.append(f"credential {credential_username}")
        if secret:
            context_parts.append(f"secret {mark_sensitive(secret, 'password')}")
        return " | ".join(context_parts)

    if relation_key == "passwordspray":
        spray_type = str(details.get("spray_type") or "").strip()
        password = str(details.get("password") or "").strip()
        context_parts: list[str] = []
        if spray_type:
            context_parts.append(f"mode {spray_type}")
        if password:
            context_parts.append(f"password {mark_sensitive(password, 'password')}")
        return " | ".join(context_parts)

    if relation_key in {"domainpassreuse", "domainpassreusesource"}:
        credential_type = str(details.get("credential_type") or "").strip().lower()
        credential = str(details.get("credential") or "").strip()
        evidence_source = str(details.get("evidence_source") or "").strip()
        context_parts: list[str] = []
        if credential:
            secret_label = (
                credential_type if credential_type in {"password", "hash"} else "secret"
            )
            context_parts.append(
                f"{secret_label} {mark_sensitive(credential, 'password')}"
            )
        if evidence_source:
            context_parts.append(f"evidence {evidence_source}")
        return " | ".join(context_parts)

    if relation_key in {
        "localadminpassreuse",
        "localcredreusesource",
        "localcredtodomainreuse",
    }:
        credential_type = str(details.get("credential_type") or "").strip().lower()
        credential = str(details.get("credential") or "").strip()
        source = str(details.get("source") or "").strip()
        context_parts: list[str] = []
        if credential:
            secret_label = (
                credential_type if credential_type in {"password", "hash"} else "secret"
            )
            context_parts.append(
                f"{secret_label} {mark_sensitive(credential, 'password')}"
            )
        if source:
            context_parts.append(f"evidence {source}")
        return " | ".join(context_parts)

    return ""


def _get_attack_path_narrative_formatters() -> tuple[
    Callable[[str, str], str],
    Callable[[str], str],
    Callable[..., str],
    Callable[..., str],
]:
    """Resolve attack-path label formatters with a LITE-safe fallback."""
    global _ATTACK_PATH_NARRATIVE_FALLBACK_LOGGED
    try:
        import importlib

        module = importlib.import_module(
            "adscan_internal.reporting.attack_path_narratives"
        )
        format_node_label = getattr(module, "format_node_label", None)
        format_relation_label = getattr(module, "format_relation_label", None)
        format_relation_display = getattr(module, "format_relation_display", None)
        format_relation_source_context = getattr(
            module, "format_relation_source_context", None
        )
        if (
            callable(format_node_label)
            and callable(format_relation_label)
            and callable(format_relation_display)
            and callable(format_relation_source_context)
        ):
            return (
                format_node_label,
                format_relation_label,
                format_relation_display,
                format_relation_source_context,
            )
        raise AttributeError(
            "attack_path_narratives module missing required formatter callables"
        )
    except Exception as exc:  # pragma: no cover - depends on runtime packaging
        if not _ATTACK_PATH_NARRATIVE_FALLBACK_LOGGED:
            _ATTACK_PATH_NARRATIVE_FALLBACK_LOGGED = True
            print_info_debug(
                "Attack-path narrative formatter unavailable; using built-in fallback "
                f"(reason: {exc})"
            )
        return (
            _fallback_format_attack_path_node_label,
            _fallback_format_attack_path_relation_label,
            lambda relation, details=None: (
                _fallback_format_attack_path_relation_display(
                    relation,
                    details=details,
                    formatter=_fallback_format_attack_path_relation_label,
                )
            ),
            lambda relation, details=None: _fallback_format_attack_path_source_context(
                relation,
                details=details,
            ),
        )


def print_attack_path_detail(
    domain: str,
    path: Dict[str, object],
    *,
    index: int | None = None,
    search_mode_label: str | None = None,
) -> None:
    """Render a detailed single attack path breakdown."""
    from rich.table import Table
    from adscan_internal.services.adcs_path_display import resolve_adcs_display_target
    from adscan_internal.services.attack_step_support_registry import (
        classify_path_compromise_semantics,
        describe_path_compromise_effort,
        describe_path_compromise_semantics,
    )

    nodes = path.get("nodes", [])
    rels = path.get("relations", [])
    if not isinstance(nodes, list):
        nodes = []
    if not isinstance(rels, list):
        rels = []

    def _mark_node(name: str) -> str:
        if not name:
            return "N/A"
        if "." in name or name.endswith("$"):
            return mark_sensitive(name, "hostname")
        return mark_sensitive(name, "user")

    def _format_status(value: object) -> Text:
        status = str(value or "discovered").strip().lower()
        if status in {"exploited", "success", "succeeded"}:
            return Text(status, style=f"bold {BRAND_COLORS['success']}")
        if status in {"attempted"}:
            return Text(status, style=f"bold {BRAND_COLORS['warning']}")
        if status in {"failed", "error"}:
            return Text(status, style=f"bold {BRAND_COLORS['error']}")
        return Text(status, style="dim")

    def _render_choke_point_summary(step_details: dict[str, object]) -> None:
        if not bool(step_details.get("is_choke_point")):
            return
        summary = Text()
        summary.append("Choke Point: ", style="bold white")
        directness = (
            str(step_details.get("choke_point_directness") or "").strip().lower()
        )
        if directness == "direct":
            summary.append("Direct transition", style=BRAND_COLORS["error"])
        elif directness == "indirect":
            summary.append("Indirect transition", style=BRAND_COLORS["warning"])
        else:
            summary.append("Privilege transition", style=BRAND_COLORS["info"])
        blast_radius = step_details.get("blast_radius")
        if isinstance(blast_radius, int) and blast_radius > 0:
            summary.append("  ", style="dim")
            summary.append(
                f"blast radius {blast_radius}",
                style=BRAND_COLORS["warning"],
            )
        reason = str(step_details.get("choke_point_reason") or "").strip()
        if reason:
            summary.append("  ", style="dim")
            summary.append(reason, style="dim")
        _state._get_console().print(summary)

    header = Text()
    header.append("Attack Path", style="bold white")
    if index is not None:
        header.append(f" #{index}", style=f"bold {BRAND_COLORS['info']}")
    header.append("  ")
    header.append(f"Domain: {domain}", style="dim")

    print_panel(
        header,
        title="🧭 Path Details",
        border_style=BRAND_COLORS["info"],
        padding=(0, 2),
        expand=True,
        spacing="both",
    )

    if str(search_mode_label or "").strip():
        mode_summary = Text()
        mode_summary.append("Search Mode: ", style="bold white")
        mode_summary.append(
            str(search_mode_label).strip(), style=BRAND_COLORS["success"]
        )
        _state._get_console().print(mode_summary)

    path_compromise_semantics = ""
    if rels:
        path_compromise_semantics = classify_path_compromise_semantics(
            [str(rel) for rel in rels if str(rel or "").strip()]
        )
        path_type_summary = Text()
        path_type_summary.append("Path Type: ", style="bold white")
        path_type_summary.append(
            describe_path_compromise_semantics(
                [str(rel) for rel in rels if str(rel or "").strip()]
            ),
            style=BRAND_COLORS["warning"],
        )
        _state._get_console().print(path_type_summary)
        effort_summary = Text()
        effort_summary.append("Compromise Effort: ", style="bold white")
        effort_summary.append(
            describe_path_compromise_effort(
                [str(rel) for rel in rels if str(rel or "").strip()]
            ),
            style=BRAND_COLORS["info"],
        )
        _state._get_console().print(effort_summary)

    choke_step_details = [
        step.get("details")
        for step in path.get("steps", [])
        if isinstance(step, dict)
        and isinstance(step.get("details"), dict)
        and bool(step.get("details", {}).get("is_choke_point"))
    ]
    for details in choke_step_details[:3]:
        if isinstance(details, dict):
            _render_choke_point_summary(details)

    meta = path.get("meta") if isinstance(path.get("meta"), dict) else {}
    if isinstance(meta, dict):
        execution_scope = str(meta.get("execution_scope") or "").strip()
        if execution_scope:
            execution_summary = Text()
            execution_summary.append("Execution Scope: ", style="bold white")
            execution_summary.append(execution_scope, style=BRAND_COLORS["info"])
            _state._get_console().print(execution_summary)

        affected_source = str(meta.get("affected_users_source") or "").strip()
        affected_count = meta.get("affected_principal_count")
        if not isinstance(affected_count, int):
            affected_count = meta.get("affected_user_count")
        if affected_source:
            affected_summary = Text()
            affected_summary.append("Affected Scope: ", style="bold white")
            if isinstance(affected_count, int) and affected_count >= 0:
                affected_summary.append(
                    f"{affected_count} principal(s)", style=BRAND_COLORS["warning"]
                )
            else:
                affected_summary.append("unknown", style="dim")
            affected_summary.append(" via ", style="dim")
            affected_summary.append(affected_source, style=BRAND_COLORS["info"])
            _state._get_console().print(affected_summary)

        execution_ready_count = meta.get("execution_ready_count")
        execution_candidate_count = meta.get("execution_candidate_count")
        execution_candidate_source = str(
            meta.get("execution_candidate_source") or ""
        ).strip()
        execution_readiness_reason = str(
            meta.get("execution_readiness_reason") or ""
        ).strip()
        execution_support_status = str(
            meta.get("execution_support_status") or ""
        ).strip()
        execution_support_reason = str(
            meta.get("execution_support_reason") or ""
        ).strip()
        execution_support_target_kind = str(
            meta.get("execution_support_target_kind") or ""
        ).strip()
        execution_context_action = str(
            meta.get("execution_context_action") or ""
        ).strip()
        execution_target_enabled = meta.get("execution_target_enabled")
        execution_target_enabled_source = str(
            meta.get("execution_target_enabled_source") or ""
        ).strip()
        execution_target_viability_status = str(
            meta.get("execution_target_viability_status") or ""
        ).strip()
        execution_target_viability_summary = str(
            meta.get("execution_target_viability_summary") or ""
        ).strip()
        execution_target_reachable = meta.get("execution_target_reachable")
        execution_target_reachable_source = str(
            meta.get("execution_target_reachable_source") or ""
        ).strip()
        execution_target_matched_ips = meta.get("execution_target_matched_ips")
        execution_target_vantage_mode = str(
            meta.get("execution_target_vantage_mode") or ""
        ).strip()
        execution_target_execution_advisory = str(
            meta.get("execution_target_execution_advisory") or ""
        ).strip()
        if execution_support_status.lower() == "unsupported":
            support_summary = Text()
            support_summary.append("Execution Support: ", style="bold white")
            support_summary.append("Unsupported", style=BRAND_COLORS["error"])
            if execution_support_target_kind:
                support_summary.append("  ", style="dim")
                support_summary.append(
                    f"target={execution_support_target_kind}",
                    style=BRAND_COLORS["warning"],
                )
            if execution_support_reason:
                support_summary.append("  ", style="dim")
                support_summary.append(
                    execution_support_reason, style=BRAND_COLORS["warning"]
                )
            _state._get_console().print(support_summary)
        if isinstance(execution_target_enabled, bool):
            target_state_summary = Text()
            target_state_summary.append("Target State: ", style="bold white")
            if execution_target_enabled:
                target_state_summary.append("Enabled", style=BRAND_COLORS["success"])
            else:
                target_state_summary.append("Disabled", style=BRAND_COLORS["error"])
            if execution_target_enabled_source:
                target_state_summary.append(" via ", style="dim")
                target_state_summary.append(
                    execution_target_enabled_source, style=BRAND_COLORS["info"]
                )
            _state._get_console().print(target_state_summary)
            if (
                execution_target_enabled is False
                and execution_context_action.lower() in {"genericall", "genericwrite"}
            ):
                advisory_summary = Text()
                advisory_summary.append("Execution Advisory: ", style="bold white")
                target_kind_lower = execution_support_target_kind.lower()
                if target_kind_lower == "user":
                    advisory_summary.append(
                        "ADscan will offer to enable the user before exploitation.",
                        style=BRAND_COLORS["warning"],
                    )
                elif target_kind_lower == "computer":
                    advisory_summary.append(
                        "ADscan will offer to enable the computer account before exploitation.",
                        style=BRAND_COLORS["warning"],
                    )
                else:
                    advisory_summary.append(
                        "Write access may still be useful even though the target is disabled.",
                        style=BRAND_COLORS["warning"],
                    )
                _state._get_console().print(advisory_summary)
        if execution_support_target_kind.lower() == "computer" and (
            execution_target_viability_status
            or isinstance(execution_target_reachable, bool)
        ):
            viability_summary = Text()
            viability_summary.append("Target Viability: ", style="bold white")
            if execution_target_viability_status == "reachable_from_current_vantage":
                viability_summary.append(
                    "Reachable from current vantage",
                    style=BRAND_COLORS["success"],
                )
            elif execution_target_viability_status == "resolved_but_unreachable":
                viability_summary.append(
                    "Resolved but unreachable from current vantage",
                    style=BRAND_COLORS["error"],
                )
            elif execution_target_viability_status == "enabled_but_unresolved":
                viability_summary.append(
                    "Enabled inventory entry without IP resolution",
                    style=BRAND_COLORS["warning"],
                )
            elif execution_target_viability_status == "not_in_enabled_inventory":
                viability_summary.append(
                    "Missing from enabled computer inventory",
                    style=BRAND_COLORS["error"],
                )
            elif execution_target_viability_status == "enabled_inventory_only":
                viability_summary.append(
                    "Enabled inventory only",
                    style=BRAND_COLORS["info"],
                )
            elif execution_target_viability_summary:
                viability_summary.append(
                    execution_target_viability_summary,
                    style=BRAND_COLORS["info"],
                )
            else:
                viability_summary.append("Unknown", style="dim")

            if execution_target_vantage_mode:
                viability_summary.append(" via ", style="dim")
                viability_summary.append(
                    execution_target_vantage_mode,
                    style=BRAND_COLORS["info"],
                )
            elif execution_target_reachable_source:
                viability_summary.append(" via ", style="dim")
                viability_summary.append(
                    execution_target_reachable_source,
                    style=BRAND_COLORS["info"],
                )
            _state._get_console().print(viability_summary)

            detail_fragments: list[str] = []
            if execution_target_viability_summary:
                detail_fragments.append(execution_target_viability_summary)
            if (
                isinstance(execution_target_matched_ips, (list, tuple))
                and execution_target_matched_ips
            ):
                detail_fragments.append(
                    "matched IPs: "
                    + ", ".join(str(item) for item in execution_target_matched_ips[:3])
                )
            if detail_fragments:
                viability_detail = Text()
                viability_detail.append("Viability Details: ", style="bold white")
                viability_detail.append("  ".join(detail_fragments), style="dim")
                _state._get_console().print(viability_detail)
            if execution_target_execution_advisory:
                viability_advisory = Text()
                viability_advisory.append("Execution Advisory: ", style="bold white")
                viability_advisory.append(
                    execution_target_execution_advisory,
                    style=BRAND_COLORS["warning"],
                )
                _state._get_console().print(viability_advisory)
        if path_compromise_semantics == "access_capability_only":
            advisory_summary = Text()
            advisory_summary.append("Execution Advisory: ", style="bold white")
            action_key = execution_context_action.lower()
            if action_key == "canpsremote":
                advisory_summary.append(
                    "This path grants privileged WinRM/PowerShell access to the target host. "
                    "Treat it as high-value host access rather than an immediate credential compromise.",
                    style=BRAND_COLORS["warning"],
                )
            elif action_key == "canrdp":
                advisory_summary.append(
                    "This path grants privileged RDP access to the target host. "
                    "Interactive access may unlock further post-exploitation, but it is not a direct credential compromise by itself.",
                    style=BRAND_COLORS["warning"],
                )
            elif action_key == "sqladmin":
                advisory_summary.append(
                    "This path grants privileged SQL administrative access. "
                    "Use SQL post-exploitation and impersonation checks to turn it into code execution or credential access.",
                    style=BRAND_COLORS["warning"],
                )
            elif action_key == "adminto":
                advisory_summary.append(
                    "This path grants local administrator-style host access. "
                    "Host credential dumping and local secret extraction usually provide the next highest-value move.",
                    style=BRAND_COLORS["warning"],
                )
            else:
                advisory_summary.append(
                    "This path grants privileged host access rather than direct identity compromise. "
                    "Expect host-centric post-exploitation follow-ups after execution.",
                    style=BRAND_COLORS["warning"],
                )
            _state._get_console().print(advisory_summary)
        if (
            isinstance(execution_ready_count, int)
            and execution_ready_count >= 0
            and isinstance(execution_candidate_count, int)
            and execution_candidate_count >= 0
        ):
            readiness_summary = Text()
            readiness_summary.append("Execution Readiness: ", style="bold white")
            if execution_ready_count <= 0:
                readiness_summary.append(
                    "Needs stored credential",
                    style=BRAND_COLORS["error"],
                )
            elif execution_candidate_count > execution_ready_count:
                readiness_summary.append(
                    f"{execution_ready_count}/{execution_candidate_count} ready",
                    style=(
                        BRAND_COLORS["success"]
                        if execution_ready_count > 0
                        else BRAND_COLORS["error"]
                    ),
                )
            else:
                readiness_summary.append(
                    f"{execution_ready_count} ready",
                    style=(
                        BRAND_COLORS["success"]
                        if execution_ready_count > 0
                        else BRAND_COLORS["error"]
                    ),
                )
            if execution_candidate_source:
                readiness_summary.append(" via ", style="dim")
                readiness_summary.append(
                    execution_candidate_source, style=BRAND_COLORS["info"]
                )
            if execution_ready_count <= 0 and execution_readiness_reason:
                readiness_summary.append("  ", style="dim")
                readiness_summary.append(
                    execution_readiness_reason, style=BRAND_COLORS["warning"]
                )
            _state._get_console().print(readiness_summary)

    basis_primary, basis_detail = _format_effective_target_basis_compact(path)
    if basis_primary:
        basis_summary = Text()
        basis_summary.append("Effective Target Basis: ", style="bold white")
        basis_summary.append(
            basis_primary.removeprefix("Reason: "), style=BRAND_COLORS["warning"]
        )
        _state._get_console().print(basis_summary)
        if basis_detail:
            basis_extra_summary = Text()
            basis_extra_summary.append("Also: ", style="bold white")
            basis_extra_summary.append(
                basis_detail.removeprefix("Also: "), style=BRAND_COLORS["info"]
            )
            _state._get_console().print(basis_extra_summary)

    steps = path.get("steps", [])
    if not isinstance(steps, list):
        steps = []
    _, _, format_relation_display, format_relation_source_context = (
        _get_attack_path_narrative_formatters()
    )

    step_status_map: dict[tuple[str, str, str], object] = {}
    for step in steps:
        if not isinstance(step, dict):
            continue
        details = step.get("details")
        if not isinstance(details, dict):
            continue
        from_label = str(details.get("from") or "")
        to_label = str(details.get("to") or "")
        action = str(step.get("action") or "")
        if not (from_label and to_label and action):
            continue
        step_status_map[(from_label, to_label, action)] = step.get("status")

    table = Table(
        show_header=True,
        header_style=f"bold {BRAND_COLORS['success']}",
        border_style=BRAND_COLORS["success"],
        padding=(0, 1),
    )
    table.add_column("#", justify="right", width=3)
    table.add_column("From", style="cyan", no_wrap=False)
    table.add_column("Relation", style="yellow", no_wrap=False)
    table.add_column("To", style="cyan", no_wrap=False)
    has_source_context = any(
        format_relation_source_context(
            str(step.get("action") or step.get("relation") or ""),
            details=step.get("details")
            if isinstance(step.get("details"), dict)
            else None,
        )
        for step in steps
        if isinstance(step, dict)
    )
    if has_source_context:
        table.add_column("Source Context", style="dim", no_wrap=False)
    table.add_column("Status", style="white", no_wrap=True)

    if nodes and rels:
        for idx, rel in enumerate(rels, start=1):
            if idx > len(nodes) - 1:
                break
            from_node = str(nodes[idx - 1])
            to_node = str(nodes[idx])
            rel_name = str(rel)
            status = step_status_map.get((from_node, to_node, rel_name), "discovered")
            details = next(
                (
                    step.get("details")
                    for step in steps
                    if isinstance(step, dict)
                    and str(step.get("action") or "") == rel_name
                    and isinstance(step.get("details"), dict)
                    and str(step["details"].get("from") or "") == from_node
                    and str(step["details"].get("to") or "") == to_node
                ),
                None,
            )
            table.add_row(
                str(idx),
                _mark_node(from_node),
                format_relation_display(rel_name, details=details),
                _mark_node(
                    str(
                        (details.get("display_to") if isinstance(details, dict) else "")
                        or resolve_adcs_display_target(
                            rel_name,
                            details if isinstance(details, dict) else None,
                            fallback_target=to_node,
                        )
                        or to_node
                    )
                ),
                *(
                    [format_relation_source_context(rel_name, details=details)]
                    if has_source_context
                    else []
                ),
                _format_status(status),
            )
        print_table(table, spacing="after")
        return

    if steps:
        for idx, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                continue
            details = step.get("details")
            if not isinstance(details, dict):
                continue
            from_label = str(details.get("from") or "")
            to_label = str(details.get("to") or "")
            action = str(step.get("action") or "")
            if not (from_label and to_label and action):
                continue
            table.add_row(
                str(idx),
                _mark_node(from_label),
                format_relation_display(action, details=details),
                _mark_node(
                    str(
                        details.get("display_to")
                        or resolve_adcs_display_target(
                            action,
                            details,
                            fallback_target=to_label,
                        )
                        or to_label
                    )
                ),
                *(
                    [format_relation_source_context(action, details=details)]
                    if has_source_context
                    else []
                ),
                _format_status(step.get("status")),
            )
        print_table(table, spacing="after")
        return

    print_info("No graph nodes/relations or steps recorded for this path.", icon="")


def print_attack_steps_summary(
    domain: str,
    steps: List[Dict[str, object]],
    *,
    max_display: int = 10,
    start_user: str | None = None,
) -> None:
    """Render a compact listing of raw attack graph steps (edges).

    This is intended for transparency and debugging. It uses the same step
    table rendering as `print_attack_path_detail` for consistency.
    """
    from rich.text import Text

    if not steps:
        return

    console = _state._get_console()
    total = len(steps)
    show_count = min(max_display, total)

    header = Text()
    header.append("Attack Steps", style="bold white")
    if start_user:
        header.append("  ", style="dim")
        header.append("User: ", style="dim")
        header.append(mark_sensitive(start_user, "user"), style="dim")

    summary = Text()
    summary.append("Attack Steps Found: ", style="bold white")
    summary.append(str(total), style=f"bold {BRAND_COLORS['warning']}")
    summary.append("  ")
    summary.append("Showing: ", style="bold white")
    summary.append(str(show_count), style=f"bold {BRAND_COLORS['info']}")

    console.print()
    console.print(
        Panel(
            summary,
            title=f"🧩 Domain: {domain}",
            border_style=BRAND_COLORS["info"],
            padding=(0, 2),
        )
    )
    if start_user:
        console.print(header)

    table, truncated = _build_attack_steps_table(steps, max_steps=max_display)
    console.print()
    console.print(table)
    if truncated:
        print_warning(f"Showing first {max_display} steps only ({total} total).")


def _format_attack_step_details(step_details: object) -> str:
    if not isinstance(step_details, dict):
        return ""
    fields: list[str] = []
    if bool(step_details.get("is_choke_point")):
        directness = (
            str(step_details.get("choke_point_directness") or "").strip().lower()
        )
        blast_radius = step_details.get("blast_radius")
        choke_label = (
            "choke=direct"
            if directness == "direct"
            else "choke=indirect"
            if directness == "indirect"
            else "choke=yes"
        )
        if isinstance(blast_radius, int) and blast_radius > 0:
            choke_label += f" blast={blast_radius}"
        fields.append(choke_label)
    from_node = step_details.get("from")
    if isinstance(from_node, str) and from_node:
        from_display = (
            mark_sensitive(from_node, "hostname")
            if "." in from_node or from_node.endswith("$")
            else mark_sensitive(from_node, "user")
        )
        fields.append(f"from={from_display}")
    to_node = step_details.get("to")
    if isinstance(to_node, str) and to_node:
        to_display = (
            mark_sensitive(to_node, "hostname")
            if "." in to_node or to_node.endswith("$")
            else mark_sensitive(to_node, "user")
        )
        fields.append(f"to={to_display}")
    username = step_details.get("username")
    if isinstance(username, str) and username:
        fields.append(f"user={mark_sensitive(username, 'user')}")
    target = step_details.get("target")
    if isinstance(target, str) and target:
        target_display = (
            mark_sensitive(target, "hostname")
            if "." in target or target.endswith("$")
            else mark_sensitive(target, "user")
        )
        fields.append(f"target={target_display}")
    roast_type = step_details.get("roast_type")
    if isinstance(roast_type, str) and roast_type:
        fields.append(f"type={roast_type}")
    delegation_type = step_details.get("delegation_type")
    if isinstance(delegation_type, str) and delegation_type:
        fields.append(f"delegation={delegation_type}")
    delegation_to = step_details.get("delegation_to")
    if isinstance(delegation_to, str) and delegation_to:
        fields.append(f"spn={mark_sensitive(delegation_to, 'service')}")
    edge_type = step_details.get("edge_type")
    if isinstance(edge_type, str) and edge_type:
        fields.append(f"edge={edge_type}")
    # The cracked wordlist is recorded per-attempt under ``details.attempts``
    # (``[{"wordlist": ..., "status": ..., "at": ...}, ...]``), NOT as a flat
    # ``details.wordlist`` key. Prefer the last successful attempt's wordlist;
    # fall back to the last attempt that named a wordlist.
    wordlist = step_details.get("wordlist")
    if not (isinstance(wordlist, str) and wordlist):
        attempts = step_details.get("attempts")
        if isinstance(attempts, list):
            cracked = ""
            last_named = ""
            for attempt in attempts:
                if not isinstance(attempt, dict):
                    continue
                attempt_wordlist = attempt.get("wordlist")
                if isinstance(attempt_wordlist, str) and attempt_wordlist:
                    last_named = attempt_wordlist
                    status = str(attempt.get("status") or "").strip().lower()
                    if status in {"success", "cracked", "ok", "found"}:
                        cracked = attempt_wordlist
            wordlist = cracked or last_named
    if isinstance(wordlist, str) and wordlist:
        fields.append(f"wordlist={wordlist}")
    notes = step_details.get("notes")
    if isinstance(notes, str) and notes:
        fields.append(f"notes={notes}")
    elif isinstance(notes, dict) and notes:
        # Best-effort: show at most a few primitive entries.
        parts: list[str] = []
        for key, value in notes.items():
            if value is None:
                continue
            if isinstance(value, (str, int, float, bool)) and str(value).strip():
                parts.append(f"{key}={value}")
        if parts:
            fields.append("notes=" + " ".join(parts[:4]))
    return ", ".join(fields)


def _build_attack_steps_table(
    steps: List[Dict[str, object]], *, max_steps: int
) -> tuple["Table", bool]:
    from rich.table import Table

    status_styles = {
        "pending": BRAND_COLORS["warning"],
        "attempted": BRAND_COLORS["info"],
        "discovered": BRAND_COLORS["info"],
        "success": BRAND_COLORS["success"],
        "failed": BRAND_COLORS["error"],
        "error": BRAND_COLORS["error"],
    }

    steps_table = Table(
        title="Steps",
        title_style=f"bold {BRAND_COLORS['info']}",
        border_style=BRAND_COLORS["info"],
        show_header=True,
        header_style=f"bold {BRAND_COLORS['info']}",
        padding=(0, 1),
    )
    steps_table.add_column("#", justify="right", width=3)
    steps_table.add_column("Action", style="cyan", no_wrap=False)
    steps_table.add_column("Status", style="white", no_wrap=False)
    _, _, format_relation_display, format_relation_source_context = (
        _get_attack_path_narrative_formatters()
    )
    has_source_context = any(
        format_relation_source_context(
            str(step.get("action") or step.get("type") or ""),
            details=step.get("details")
            if isinstance(step.get("details"), dict)
            else None,
        )
        for step in steps
        if isinstance(step, dict)
    )
    if has_source_context:
        steps_table.add_column("Source Context", style="dim", no_wrap=False)
    steps_table.add_column("Details", style="dim", no_wrap=False)

    truncated = len(steps) > max_steps
    for idx, step in enumerate(steps[:max_steps], start=1):
        if not isinstance(step, dict):
            continue
        action = step.get("action") or step.get("type") or "N/A"
        status = str(step.get("status") or "pending").lower()
        status_style = status_styles.get(status, BRAND_COLORS["warning"])
        details = step.get("details") if isinstance(step.get("details"), dict) else None
        details_text = _format_attack_step_details(details)
        steps_table.add_row(
            str(step.get("step") or idx),
            format_relation_display(str(action), details=details),
            Text(status, style=f"bold {status_style}"),
            *(
                [format_relation_source_context(str(action), details=details)]
                if has_source_context
                else []
            ),
            details_text or "—",
        )

    return steps_table, truncated


def print_attack_path_detail_debug(
    domain: str,
    path: Dict[str, object],
    *,
    index: int | None = None,
) -> None:
    """Print a detailed attack path only when debug mode is enabled."""
    if not _state._debug_mode:
        return
    print_info_debug("DEBUG attack path detail (debug-only output).")
    print_attack_path_detail(domain, path, index=index)
    _state._get_console().print()


def print_attack_paths_summary_debug(
    domain: str,
    paths: List[Dict[str, object]],
    *,
    stage_label: str = "",
    max_display: int = 30,
) -> None:
    """Print an attack-path summary table only when debug mode is enabled.

    Used to instrument the post-processing pipeline — shows the current set of
    display records after each filter/rule is applied so the pipeline can be
    inspected step-by-step without affecting normal (non-debug) output.

    Follows the same pattern as print_attack_path_detail_debug: the stage label
    is emitted via print_info_debug (logger → RichHandler with DEBUG indicator)
    for consistency with the rest of the debug UX.

    Args:
        domain: Domain name shown in the table header.
        paths: Display records at this pipeline stage.
        stage_label: Human-readable name for the stage (e.g. "after cyclic filter").
        max_display: Maximum rows to show in the table (default 30).
    """
    if not _state._debug_mode:
        return
    label = str(stage_label or "pipeline stage").strip()
    print_info_debug(f"[attack-paths] {label} — {len(paths)} path(s)")
    if not paths:
        return
    print_attack_paths_summary(domain, paths, max_display=max_display)
    _state._get_console().print()
