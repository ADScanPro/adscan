"""Kit-facts SSOT — one canonical value per datum the PRO kit shows twice.

The PRO Client Deliverable Kit renders four documents from ONE scan — the
Security Assessment Report (SAR), the AD Hardening Playbook, the AD Control
Coverage Report and the lab writeup — plus the web CTEM as a fifth (lockstep)
surface. A client reads the SAME datum (a count, a label, a nomination) in more
than one of them, and when each document RE-DERIVES that datum instead of reading
ONE persisted source they can DISAGREE. Three real Cicada round-3 findings were
exactly this class (the "fix this first" item named by technique in the SAR and
by finding in the Playbook; a verified-clear count present in one compliance
surface and dropped from another; the Guest credential shown as a password in one
table and as "nothing to rotate" in another).

This module is the intra-kit analogue of ``CLAUDE.md`` § "Dual-tier reporting"
(the PRO↔LITE parity contract) applied WITHIN the PRO kit, and it operationalises
§ "Fix the CLASS, not the surface": a shared datum is registered ONCE here, every
consumer reads it through :func:`read_kit_fact`, and a parity harness
(``tests/unit/pro/reporting/test_kit_deliverable_parity.py``) fails CI the moment
any surface drifts from the registered value.

Design — three pieces:

* :data:`KIT_FACTS` — the registry. One :class:`KitFact` row per datum a client
  reads across ≥2 kit surfaces, naming WHERE its canonical value lives and WHICH
  surfaces must agree. Adding a shared datum is one row here.
* :func:`read_kit_fact` — the ONE accessor every consumer calls. It resolves a
  registry row's ``location`` (a persisted-block dotted path, the derived
  ``kit_facts`` block, or a shared formatter function) to the canonical value, so
  a renderer that calls it can never re-derive.
* :func:`build_kit_facts` — stamps the small set of derived scalars that have no
  persisted home today into ``domains[<d>]["kit_facts"]``, mirroring how
  ``exposure_kpis`` / ``compliance`` / ``chokepoint_cardinality`` are stamped, so
  the block is on disk before any deliverable renders. Idempotent + best-effort:
  a failure leaves the block absent and each surface keeps its current behaviour.

LITE-safe by construction: module-level imports are only ``__future__`` +
stdlib. Anything that reaches into ``adscan_internal.services`` (never
``adscan_internal.pro``) is a LAZY in-function import inside :func:`build_kit_facts`,
so importing this module from the host launcher, the appliance backend, or the
LITE runtime costs nothing and pulls in no engine or native stack.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# ── Kit surfaces a datum can be rendered on ──────────────────────────────────
SAR = "sar"  # Security Assessment Report
PB = "playbook"  # AD Hardening Playbook
COV = "coverage"  # AD Control Coverage Report
WU = "writeup"  # Lab writeup
WEB = "web"  # Web CTEM (lockstep; locked by tests/unit/web/*_parity.py, not here)


# ── Classification of each shared datum (from the spec §2 audit) ─────────────
#: A datum whose surfaces already read ONE shared SSOT / persisted block today.
SAFE = "safe"
#: A datum that is re-derived per surface but currently AGREES — a latent drift.
LATENT = "latent"
#: A datum that actively diverged (a judge finding) — migrated / being migrated.
ACTIVE = "active"
#: A DELIBERATE difference (kept, with a stated reconciling note).
INTENTIONAL = "intentional"


@dataclass(frozen=True)
class KitFact:
    """One client-facing datum that appears across ≥2 kit surfaces.

    Attributes:
        key: Stable identifier, e.g. ``"fix_first_nomination"``.
        surfaces: Every deliverable that renders this datum (a tuple of the
            ``SAR``/``PB``/``COV``/``WU``/``WEB`` constants).
        location: WHERE the canonical value lives, read by :func:`read_kit_fact`.
            One of three shapes:

            * ``("block", "<dotted.path>")`` — a persisted ``technical_report``
              domain block. ``{fw}`` / ``{d}`` in the path are substituted from
              the ``read_kit_fact`` arguments; a ``.<n>`` segment indexes a list.
            * ``("kit_facts", "<key>")`` — the derived ``kit_facts`` block this
              module stamps (:func:`build_kit_facts`).
            * ``("fn", "<name>")`` — a shared formatter/derivation function that
              is the SSOT; :func:`read_kit_fact` returns :data:`FN_FACT` for these
              (the parity harness locks them with a bespoke assertion, not a
              persisted-value read).
        classification: One of :data:`SAFE` / :data:`LATENT` / :data:`ACTIVE` /
            :data:`INTENTIONAL` — the spec §2 audit verdict, for reporting.
        reconcile_note: Non-empty ONLY for an intentional difference (the
            surfaces deliberately present the datum differently and this note is
            the reconciling footnote a reader crossing two documents sees).
    """

    key: str
    surfaces: tuple[str, ...]
    location: tuple[str, str]
    classification: str = LATENT
    reconcile_note: str = ""


#: Sentinel returned by :func:`read_kit_fact` for a ``("fn", ...)`` location — the
#: canonical value is a shared function's output, not a persisted scalar, so the
#: harness locks it by asserting the shared function is used, not by value read.
FN_FACT = object()

# ── Client-facing labels for the two "on a validated path" metrics (#16) ──────
#: The two kit metrics that count "something on a validated path to domain
#: compromise" are DIFFERENT numbers and must never share a label a CISO reads as
#: the other: the Playbook counts FINDINGS whose technique sits on a validated
#: path, while the Security Assessment Report headline counts ACCOUNTS with a
#: validated path. Declaring both labels here, once, keeps the collision from
#: returning (spec §2 #16 — a same-named KPI carrying two different numbers).
FINDINGS_ON_PATH_LABEL = "Findings on a validated path"
ACCOUNTS_ON_PATH_LABEL = "Accounts with a validated path"

#: Sentinel returned when a registered value is genuinely absent on the workspace
#: (an older artifact, or a derived scalar not yet stamped). Distinct from ``None``
#: so a caller can tell "no such datum here" from "the datum's value is None".
MISSING = object()


# ─────────────────────────────────────────────────────────────────────────────
# THE REGISTRY — one row per shared datum in the spec §2 inventory (25 total).
# Adding a datum a client reads in ≥2 kit documents is ONE row here; the parity
# harness then locks it. Numbers in comments map to the spec §2 table rows.
# ─────────────────────────────────────────────────────────────────────────────
KIT_FACTS: tuple[KitFact, ...] = (
    # 1 — the "fix this first" nomination (SAR Start-Here lead == Playbook top).
    KitFact(
        "fix_first_nomination",
        (SAR, PB),
        ("block", "chokepoint_cardinality.remediation_start_here.rows.0.label"),
        ACTIVE,
    ),
    # 2 — F-NNN finding identifiers (aligned by shared ordering key).
    KitFact("finding_id", (SAR, PB), ("fn", "finding_id_ordering"), LATENT),
    # 3 — finding titles (VULN_CATALOG).
    KitFact("finding_title", (SAR, PB, COV, WU), ("fn", "vuln_catalog_title"), SAFE),
    # 4 — finding severity / ADscan-Priority score.
    KitFact(
        "finding_severity",
        (SAR, PB, COV),
        ("fn", "finding_severity_for_record"),
        SAFE,
    ),
    # 5 — remediation ORDERING (deliberately different; reconciled by a note).
    KitFact(
        "remediation_ordering",
        (SAR, PB),
        ("fn", "remediation_ordering"),
        INTENTIONAL,
        reconcile_note=(
            "The Playbook roadmap is sequenced by severity; the SAR Start-Here is "
            "ordered by validated attack paths broken per fix. Both name the SAME "
            "#1 item (fix_first_nomination); only the body order differs."
        ),
    ),
    # 6 — affected assets / hosts per finding (affected-assets v2 SSOT).
    KitFact(
        "affected_assets",
        (SAR, PB, COV),
        ("fn", "build_affected_assets_display_entries"),
        SAFE,
    ),
    # 7 — remediation prose / runbook (catalog SSOT).
    KitFact("remediation_prose", (SAR, PB, WU), ("fn", "catalog_remediation"), SAFE),
    # 8 — compliance control codes per finding (mapping SSOT; COV dup in lockstep).
    KitFact(
        "compliance_control_codes",
        (SAR, PB, COV),
        ("fn", "compliance_controls_for"),
        SAFE,
    ),
    # 9 — compliance three-state scorecard (SAR re-derives; WEB reads persisted).
    KitFact(
        "compliance_three_state",
        (SAR, WEB),
        ("block", "compliance.frameworks.{fw}.scorecard"),
        LATENT,
    ),
    # 10 — verified-clear / positive-evidence count per framework.
    KitFact(
        "verified_clear_count",
        (SAR, COV, WEB),
        ("block", "compliance.frameworks.{fw}.scorecard.verified_clear_controls"),
        ACTIVE,
    ),
    # 11 — credential representation (secret-type label + rotatable?).
    KitFact("credential_representation", (SAR, WU), ("kit_facts", "credentials"), ACTIVE),
    # 12 — recovered-secrets count (deliberately framed differently; reconciled).
    KitFact(
        "recovered_secret_count",
        (SAR, WU),
        ("kit_facts", "recovered_secret_count"),
        ACTIVE,
        reconcile_note=(
            "The Security Assessment Report frames the recovered secrets as "
            "accounts and the writeup frames them as secrets. Both count the same "
            "credential store, which holds the krbtgt account key alongside the "
            "user and service accounts, so both surfaces footnote the krbtgt "
            "inclusion from the ONE canonical recovered_secret_count."
        ),
    ),
    # 13 — attack-chain step / hop count (deliberately different; reconciled).
    KitFact(
        "chain_step_count",
        (SAR, WU),
        ("kit_facts", "chain_step_count"),
        ACTIVE,
        reconcile_note=(
            "The writeup counts technique steps; the SAR counts hops (structural "
            "group-membership edges included). The canonical count is the technique "
            "steps, footnoted 'N technique steps across an M-hop chain; K hops are "
            "structural group membership'."
        ),
    ),
    # 14 — attack-path route SET (shared compute_report_attack_paths).
    KitFact(
        "attack_path_route_set",
        (SAR, COV, WU),
        ("fn", "compute_report_attack_paths"),
        SAFE,
    ),
    # 15 — total / executed attack-path COUNT (SAR inline vs attack_path_counts).
    KitFact(
        "attack_path_totals",
        (SAR, COV),
        ("kit_facts", "attack_path_totals"),
        ACTIVE,
    ),
    # 16 — "accounts on path to DA" KPI (label collision: accounts vs findings).
    KitFact(
        "accounts_on_path_to_da",
        (SAR, PB),
        ("block", "exposure_kpis.user_axis"),
        LATENT,
    ),
    # 17 — compromise-reach label / compromise_class.
    KitFact(
        "compromise_reach_label",
        (SAR, WU),
        ("fn", "compromise_reach_label"),
        LATENT,
    ),
    # 18 — humanized principal / node labels (three humanizers today).
    KitFact("principal_label", (SAR, WU, WEB), ("fn", "node_label_formatter"), ACTIVE),
    # 19 — domain-compromise headline / "pwned" (the promote_to_pwned SSOT).
    KitFact(
        "domain_compromise_headline",
        (SAR, WU),
        ("kit_facts", "domain_compromised"),
        LATENT,
    ),
    # 20 — DCSync Tier-0 secrets (shared extractor).
    KitFact(
        "dcsync_tier0_secrets",
        (SAR, WU),
        ("fn", "extract_dcsync_tier0_secrets"),
        SAFE,
    ),
    # 21 — cleanup / environment-changes ledger (shared taxonomy).
    KitFact("cleanup_ledger", (SAR, WU), ("fn", "cleanup_taxonomy"), SAFE),
    # 22 — MITRE technique id / name (catalog).
    KitFact("mitre_technique", (SAR, PB, WU), ("fn", "catalog_mitre"), SAFE),
    # 23 — frameworks selected.
    KitFact("frameworks_selected", (SAR, PB, COV), ("block", "compliance.selected"), SAFE),
    # 24 — domain label / name (trivially agrees).
    KitFact("domain_label", (SAR, PB, COV, WU), ("fn", "domain_label"), LATENT),
    # 25 — per-step technique/relation narrative & manual command (catalog).
    KitFact("per_step_narrative", (SAR, WU, PB), ("fn", "catalog_step_narrative"), SAFE),
)

#: Keyed view of the registry.
KIT_FACTS_BY_KEY: dict[str, KitFact] = {fact.key: fact for fact in KIT_FACTS}


def _domains_map(report: Any) -> dict[str, Any]:
    """Return the domain-keyed map, accepting BOTH kit-fact report shapes.

    The kit facts are consumed off two different in-memory shapes of the same
    data, and both must resolve here or the SSOT is dead on one of them:

    * the persisted ``technical_report.json`` mapping, ``{"domains": {<d>: ...}}``
      — what the LITE flow and the parity harness load; and
    * the PRO render's ``report_data``, a FLAT ``{<domain>: {...}}`` map (plus a
      couple of non-domain top-level keys like ``environment_changes``) — the
      shape :func:`~adscan_internal.pro.services.report_service.ensure_report_attack_paths`
      builds and every SAR renderer iterates.

    A flat ``report_data`` never carries a ``"domains"`` key (its keys are domain
    FQDNs), so the wrapped shape is detected by a dict ``"domains"`` value and the
    flat shape falls through to ``report`` itself. Non-domain top-level entries in
    the flat map are naturally ignored by every caller (they guard on the domain's
    own blocks / an ``isinstance(dict)`` check).
    """
    if not isinstance(report, dict):
        return {}
    domains = report.get("domains")
    if isinstance(domains, dict):
        return domains
    return report


def _domain_entry(report: Any, domain: str) -> dict[str, Any]:
    """Return the domain's block from either report shape, or an empty dict."""
    entry = _domains_map(report).get(domain)
    return entry if isinstance(entry, dict) else {}


def _resolve_dotted(root: Any, dotted: str, *, fw: str | None, domain: str | None) -> Any:
    """Resolve a ``a.b.0.c`` path against nested dicts/lists. ``MISSING`` on any gap.

    ``{fw}`` / ``{d}`` segments are substituted from the arguments before the walk.
    A numeric segment indexes a list (or a dict with that string key).
    """
    node: Any = root
    for raw_seg in dotted.split("."):
        seg = raw_seg
        if seg == "{fw}":
            if not fw:
                return MISSING
            seg = fw
        elif seg == "{d}":
            if not domain:
                return MISSING
            seg = domain
        if isinstance(node, dict):
            if seg not in node:
                return MISSING
            node = node[seg]
        elif isinstance(node, (list, tuple)):
            try:
                node = node[int(seg)]
            except (ValueError, IndexError):
                return MISSING
        else:
            return MISSING
    return node


def read_kit_fact(
    report: dict[str, Any],
    domain: str,
    key: str,
    *,
    fw: str | None = None,
) -> Any:
    """Return the canonical value of a registered kit datum. Pure, best-effort.

    This is the ONE accessor every deliverable calls for a shared datum. It never
    re-derives — it resolves the registry row's ``location`` to the persisted /
    stamped value:

    * ``("block", path)`` — a dotted path under ``report["domains"][domain]``.
    * ``("kit_facts", name)`` — ``report["domains"][domain]["kit_facts"][name]``
      (stamped by :func:`build_kit_facts`).
    * ``("fn", name)`` — returns :data:`FN_FACT` (a shared function is the SSOT).

    Args:
        report: The loaded ``technical_report.json`` mapping.
        domain: The domain whose value to read.
        key: A :data:`KIT_FACTS` key.
        fw: The compliance framework key, required for ``{fw}`` locations.

    Returns:
        The canonical value, :data:`FN_FACT` for a function-sourced datum, or
        :data:`MISSING` when the value is absent on this workspace.
    """
    fact = KIT_FACTS_BY_KEY.get(key)
    if fact is None:
        return MISSING
    kind, path = fact.location
    if kind == "fn":
        return FN_FACT
    entry = _domain_entry(report, domain)
    if not entry:
        return MISSING
    if kind == "kit_facts":
        block = entry.get("kit_facts")
        if not isinstance(block, dict) or path not in block:
            return MISSING
        return block[path]
    if kind == "block":
        return _resolve_dotted(entry, path, fw=fw, domain=domain)
    return MISSING


def chain_reconcile_clause(
    *, technique_steps: Any, hop_count: Any, structural_hops: Any
) -> str:
    """Return the ONE reconciling footnote for the step-vs-hop count split (#13).

    The Security Assessment Report numbers a kill-chain by GRAPH HOPS (it lists
    the structural group-membership pivots as steps), while the lab writeup
    counts only the TECHNIQUE steps that were proved. The two figures are both
    honest but they disagree (a Cicada chain is "6 steps" in the SAR and "4
    steps" in the writeup) and a client reading both documents cannot reconcile
    them. Rather than force one convention, both surfaces render THIS clause,
    computed from the same three counts, so the difference is stated in one
    sentence instead of read as a contradiction.

    Args:
        technique_steps: N — the proved technique steps (the writeup's count).
        hop_count: M — the total graph hops in the chain (the SAR's count).
        structural_hops: K — how many hops are structural group membership.

    Returns:
        A single reconciling sentence, or ``""`` when there is nothing to
        reconcile (no structural hops, or the two counts already agree).
    """
    try:
        n = int(technique_steps)
        m = int(hop_count)
        k = int(structural_hops)
    except (TypeError, ValueError):
        return ""
    if k <= 0 or m <= n:
        return ""
    step_word = "technique step" if n == 1 else "technique steps"
    hop_word = "hop is" if k == 1 else "hops are"
    return (
        f"{n} {step_word} across a {m}-hop chain "
        f"({k} {hop_word} structural group membership)"
    )


def recovered_secret_reconcile_clause(
    *, total_secrets: Any, krbtgt_included: Any
) -> str:
    """Return the ONE reconciling footnote for the recovered-secret count (#12).

    The Security Assessment Report frames the recovered secrets as "accounts"
    (its §09 "Compromised Credentials" table) while the writeup credential
    ledger frames them as "secrets". Both count the SAME credential store, but
    that store holds the krbtgt account key alongside the user and service
    accounts, and a reader who reads "accounts" may not expect a machine key
    among them. Rather than let one surface silently exclude krbtgt and the
    other include it (the "8 vs 9" class), both surfaces render THIS clause,
    computed from the same canonical count, so the framing difference is stated
    in one sentence instead of read as two different totals.

    Args:
        total_secrets: The canonical recovered-secret count (krbtgt included).
        krbtgt_included: Whether the krbtgt account key is among them.

    Returns:
        A single reconciling sentence, or ``""`` when there is nothing to
        reconcile (no krbtgt in the recovered set, or an unusable count).
    """
    try:
        total = int(total_secrets)
    except (TypeError, ValueError):
        return ""
    if total < 1 or not krbtgt_included:
        return ""
    others = total - 1
    if others <= 0:
        return "This count includes the krbtgt account key."
    account_word = "account" if others == 1 else "accounts"
    return (
        f"This count includes the krbtgt account key alongside {others} user and "
        f"service {account_word}."
    )


def domain_compromise_proven(
    domain_data: Any, *, proven_domain_compromise: bool = False
) -> bool:
    """Return whether the domain is PROVEN compromised — the shared headline gate.

    The Security Assessment Report headline and the lab writeup headline both
    answer "did the domain fall?" and, before this SSOT, each derived the answer
    from a different signal (the SAR from the posture band and path counts, the
    writeup from ``compromise_class``), so they could disagree. Both now read
    THIS one fact, which prefers the persisted ``promote_to_pwned`` verdict
    (``auth == "pwned"`` — proven control of a Domain Admin) and falls back to a
    caller-supplied "a full-domain-compromise chain was proved end to end" flag.

    Args:
        domain_data: The domain's block (either report shape or the live
            ``domains_data`` entry); read for the ``auth == "pwned"`` SSOT.
        proven_domain_compromise: The caller's own "a chain reached full domain
            compromise" signal (the SAR's proven-domain-breaker count, the
            writeup's ``terminal_compromise_proven``), used only when the
            persisted ``pwned`` verdict is absent.

    Returns:
        ``True`` when the domain is proven compromised, else ``False``.
    """
    if (
        isinstance(domain_data, dict)
        and str(domain_data.get("auth") or "").strip().lower() == "pwned"
    ):
        return True
    return bool(proven_domain_compromise)


def _load_snapshot_paths(workspace_dir: str, domain: str) -> list[dict[str, Any]]:
    """Return the materialized attack paths from a domain's persisted snapshot.

    The representative-chain counts (:func:`build_kit_facts`, ``chain_step_count``)
    are computed off the persisted ``attack_paths_snapshot.json`` — the same
    materialized path set both the SAR and the writeup render — because the
    persisted ``technical_report.json`` carries an empty ``attack_paths`` list
    (it is derived on demand). Best-effort: any read/parse failure yields ``[]``.
    """
    import json  # noqa: PLC0415 - stdlib, kept lazy so the module stays import-light
    import os  # noqa: PLC0415

    snapshot = os.path.join(
        str(workspace_dir or ""),
        "domains",
        str(domain or ""),
        "attack_paths_snapshot.json",
    )
    try:
        with open(snapshot, encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception:  # noqa: BLE001 - a missing / malformed snapshot is normal
        return []
    paths = payload.get("paths") if isinstance(payload, dict) else None
    return [p for p in (paths or []) if isinstance(p, dict)]


def _read_domain_auth(
    entry: dict[str, Any], workspace_dir: str, domain: str
) -> str | None:
    """Return the domain's persisted ``auth`` verdict, or ``None`` when unknown.

    The ``promote_to_pwned`` SSOT writes ``auth = "pwned"`` onto the live
    ``domains_data``; the report render's domain entry carries it when present,
    otherwise the persisted ``variables.json`` (the at-rest ``domains_data``) is
    the authoritative source. Best-effort — a missing/unreadable file yields
    ``None`` and the compromise fact simply falls back to each surface's own
    proven signal.
    """
    auth = entry.get("auth") if isinstance(entry, dict) else None
    if auth:
        return str(auth).strip().lower()
    import json  # noqa: PLC0415
    import os  # noqa: PLC0415

    path = os.path.join(str(workspace_dir or ""), "variables.json")
    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception:  # noqa: BLE001 - no variables.json is a normal state
        return None
    domains_data = payload.get("domains_data") if isinstance(payload, dict) else None
    if not isinstance(domains_data, dict):
        domains_data = payload if isinstance(payload, dict) else {}
    block = domains_data.get(domain) if isinstance(domains_data, dict) else None
    value = block.get("auth") if isinstance(block, dict) else None
    return str(value).strip().lower() if value else None


def _read_domain_credential_principals(
    entry: dict[str, Any], workspace_dir: str, domain: str
) -> list[str]:
    """Return the principals of the domain's recovered-secret store, best-effort.

    The recovered-secret count (:func:`build_kit_facts`, ``recovered_secret_count``)
    must count ONE source so the SAR §09 credential table and the writeup ledger
    lead with the same figure. The credential store is that source; it is read
    with a layered fallback so the count is available on every report shape:

    * ``entry["compromised_credentials"]`` — the stamped provenance list the SAR
      renders one row per, present in the PRO render path (stamped before the
      kit-facts seam) and the persisted report;
    * ``entry["credentials"]`` — the merged domain credential store the writeup
      ledger counts, present on the flat PRO ``report_data``;
    * ``variables.json`` ``domains_data[<d>].credentials`` — the at-rest store,
      the authoritative source for the LITE flow and the parity fixture.

    krbtgt is INCLUDED (it is the most impactful recovered secret); the caller
    detects its presence to footnote the accounts-vs-secrets framing.
    """
    cc = entry.get("compromised_credentials") if isinstance(entry, dict) else None
    if isinstance(cc, list) and cc:
        principals = [
            str((row or {}).get("principal") or "").strip()
            for row in cc
            if isinstance(row, dict)
        ]
        principals = [p for p in principals if p]
        if principals:
            return principals
    creds = entry.get("credentials") if isinstance(entry, dict) else None
    if isinstance(creds, dict) and creds:
        return [str(p).strip() for p in creds if str(p).strip()]

    import json  # noqa: PLC0415
    import os  # noqa: PLC0415

    path = os.path.join(str(workspace_dir or ""), "variables.json")
    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception:  # noqa: BLE001 - no variables.json is a normal state
        return []
    domains_data = payload.get("domains_data") if isinstance(payload, dict) else None
    if not isinstance(domains_data, dict):
        domains_data = payload if isinstance(payload, dict) else {}
    block = domains_data.get(domain) if isinstance(domains_data, dict) else None
    store = block.get("credentials") if isinstance(block, dict) else None
    if not isinstance(store, dict):
        return []
    return [str(p).strip() for p in store if str(p).strip()]


def _representative_chain(paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return the steps of the representative (headline) attack path, or ``[]``.

    The representative chain is the one the SAR promotes as its hero and the
    writeup narrates: prefer a domain-breaker path (a full-domain-compromise
    route), and within that prefer the longest chain (the most complete story),
    deterministically. Mirrors the SAR hero selector's intent without importing
    ``pro/`` (this module is LITE-safe).
    """
    best: list[dict[str, Any]] | None = None
    best_key: tuple[int, int] | None = None
    for path in paths:
        steps = [s for s in (path.get("steps") or []) if isinstance(s, dict)]
        if not steps:
            continue
        cls = str(path.get("compromise_class") or "").strip().lower()
        # Rank: domain-breaker first (0), then everything else (1); within a
        # rank, the longest chain wins (negated length sorts descending).
        key = (0 if cls == "domain_breaker" else 1, -len(steps))
        if best_key is None or key < best_key:
            best, best_key = steps, key
    return best or []


def count_chain_reconciliation(steps: list[dict[str, Any]]) -> tuple[int, int, int]:
    """Return ``(technique_steps, hop_count, structural_hops)`` for a chain.

    A step is STRUCTURAL when it is a group-membership hop — its persisted
    ``status`` is ``"structural"`` OR its relation is a structural edge
    (``MemberOf`` …, per the ``edge_kind`` SSOT). Everything else is a technique
    step. ``hop_count`` is every step; ``technique_steps = hop_count -
    structural_hops``. Lazy ``edge_kind`` import keeps this module LITE-safe.
    """
    try:
        from adscan_internal.services.edge_kind import (  # noqa: PLC0415
            is_structural_relation,
        )
    except Exception:  # noqa: BLE001 - no engine → fall back to status-only

        def is_structural_relation(_relation: str | None) -> bool:  # type: ignore
            return False

    hop_count = 0
    structural_hops = 0
    for step in steps:
        if not isinstance(step, dict):
            continue
        hop_count += 1
        relation = str(step.get("action") or step.get("relation") or "")
        status = str(step.get("status") or "").strip().lower()
        if status == "structural" or is_structural_relation(relation):
            structural_hops += 1
    return hop_count - structural_hops, hop_count, structural_hops


def build_kit_facts(report: dict[str, Any], workspace_dir: str) -> dict[str, Any]:
    """Stamp the derived kit-fact scalars onto each domain. Best-effort, idempotent.

    Computes the canonical values for the derived scalars that have no persisted
    home today and writes them under ``report["domains"][<d>]["kit_facts"]``,
    exactly the way ``exposure_kpis`` / ``compliance`` are stamped, so every
    deliverable can consume them through :func:`read_kit_fact` instead of
    re-deriving. Mutates ``report`` in place and returns the per-domain
    ``{domain: kit_facts}`` map it stamped.

    Stamped this round:

    * ``attack_path_totals`` — ``{paths_total, paths_executed}`` from the
      ``attack_path_counts`` cardinality SSOT (never a raw inline path tally), so
      the SAR path count and the Coverage Report path count can be locked to ONE
      figure.
    * ``chain_step_count`` / ``chain_hop_count`` / ``chain_structural_hops`` —
      the representative kill-chain's technique-step count (N), total graph-hop
      count (M) and structural group-membership hops (K), computed once from the
      persisted attack-path snapshot so the SAR (hops) and the writeup (technique
      steps) reconcile to ONE footnote (spec §2 #13). Only stamped when the chain
      carries a structural hop worth reconciling.
    * ``recovered_secret_count`` / ``recovered_secret_krbtgt_included`` — the
      canonical count of recovered secrets in the domain credential store
      (krbtgt included) so the SAR §09 credential table and the writeup ledger
      lead with ONE figure and footnote the accounts-vs-secrets framing (spec §2
      #12), instead of each counting its own source dict.

    A failure on any domain leaves that domain's block absent (each surface then
    keeps its current behaviour — no regression). Never raises.
    """
    stamped: dict[str, Any] = {}
    domains = _domains_map(report)
    if not domains:
        return stamped

    # Lazy, in-function engine import keeps this module LITE-/host-safe: importing
    # kit_facts pulls in no engine or native stack.
    try:
        from adscan_internal.services.attack_path_counts import (  # noqa: PLC0415
            client_path_totals_from_kpis,
        )
    except Exception:  # noqa: BLE001 - no engine available → leave the block absent
        return stamped

    for domain_name, entry in domains.items():
        if not isinstance(entry, dict):
            continue
        facts: dict[str, Any] = {}
        try:
            totals = client_path_totals_from_kpis(entry.get("exposure_kpis"))
            if totals.paths_total > 0:
                facts["attack_path_totals"] = {
                    "paths_total": totals.paths_total,
                    "paths_executed": totals.paths_proven,
                    "paths_open_exposure": totals.paths_open_exposure,
                    "paths_full_domain_compromise": totals.paths_full_domain_compromise,
                }
        except Exception:  # noqa: BLE001 - one scalar failing must not drop the rest
            pass
        try:
            # The representative kill-chain's counts, for the step-vs-hop
            # reconciliation footnote both the SAR and the writeup render. Prefer
            # the in-memory attack_paths (the PRO flat report_data carries them),
            # else read the persisted snapshot.
            chain_paths = [
                p
                for p in (entry.get("attack_paths") or [])
                if isinstance(p, dict) and p.get("steps")
            ]
            if not chain_paths:
                chain_paths = _load_snapshot_paths(workspace_dir, str(domain_name))
            steps = _representative_chain(chain_paths)
            if steps:
                technique, hops, structural = count_chain_reconciliation(steps)
                if structural > 0 and hops > technique:
                    facts["chain_step_count"] = technique
                    facts["chain_hop_count"] = hops
                    facts["chain_structural_hops"] = structural
        except Exception:  # noqa: BLE001 - one scalar failing must not drop the rest
            pass
        try:
            # The domain-compromise headline fact both the SAR and the writeup
            # gate on — the persisted promote_to_pwned SSOT. Only a definitively
            # readable verdict is stamped; when auth is unknown the fact stays
            # absent and each surface falls back to its own proven signal.
            auth = _read_domain_auth(entry, workspace_dir, str(domain_name))
            if auth:
                facts["domain_compromised"] = auth == "pwned"
        except Exception:  # noqa: BLE001 - one scalar failing must not drop the rest
            pass
        try:
            # The recovered-secret count (spec §2 #12) — the ONE figure the SAR
            # §09 "Compromised Credentials" table and the writeup credential
            # ledger both lead with. Counted from ONE credential store so the two
            # surfaces cannot drift ("8 accounts" vs "9 secrets"); krbtgt is
            # INCLUDED, and the krbtgt-inclusion flag lets each surface footnote
            # the accounts-vs-secrets framing via recovered_secret_reconcile_clause.
            principals = _read_domain_credential_principals(
                entry, workspace_dir, str(domain_name)
            )
            if principals:
                facts["recovered_secret_count"] = len(principals)
                facts["recovered_secret_krbtgt_included"] = any(
                    p.strip().lower() == "krbtgt" for p in principals
                )
        except Exception:  # noqa: BLE001 - one scalar failing must not drop the rest
            pass
        if facts:
            existing = entry.get("kit_facts")
            if isinstance(existing, dict):
                existing.update(facts)
                entry["kit_facts"] = existing
            else:
                entry["kit_facts"] = facts
            stamped[str(domain_name)] = entry["kit_facts"]
    return stamped


__all__ = [
    "SAR",
    "PB",
    "COV",
    "WU",
    "WEB",
    "SAFE",
    "LATENT",
    "ACTIVE",
    "INTENTIONAL",
    "KitFact",
    "KIT_FACTS",
    "KIT_FACTS_BY_KEY",
    "FN_FACT",
    "MISSING",
    "FINDINGS_ON_PATH_LABEL",
    "ACCOUNTS_ON_PATH_LABEL",
    "read_kit_fact",
    "build_kit_facts",
    "chain_reconcile_clause",
    "recovered_secret_reconcile_clause",
    "domain_compromise_proven",
    "count_chain_reconciliation",
]
