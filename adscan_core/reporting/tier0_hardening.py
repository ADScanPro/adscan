"""Tier 0 asset-hardening render rows from persisted ``control_evidence``.

Import-safe SSOT (only stdlib + typing) so BOTH tiers consume ONE derivation:

* the PRO AD Control Coverage Report databinding
  (``adscan_internal/pro/reporting/coverage_report_databinding.py``), and
* the paid Enterprise web CTEM ingestion
  (``adscan_web/backend/app/services/ingestion_service.py``), which cannot
  import ``adscan_internal`` across the tier boundary.

The producer (``adscan_internal/services/positive_control_evidence.py``
``emit_control_plane_sync_account_items``) persists, per confirmed/ambiguous
Azure AD Connect sync account, a ``control_evidence`` entry under the
:data:`TIER0_HARDENING_CATEGORY` category carrying its own authored client
guidance and native remediation. This reads those entries VERBATIM (never
re-authoring the prose) into render rows, so the report and the web word the
same hardening item identically. See CLAUDE.md § "adscan_web — keep them in
lockstep".
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

#: ``control_evidence`` category the collector stamps on a control-plane sync
#: account hardening item. A CONFIRMED account is a Tier 0 asset to protect; an
#: AMBIGUOUS match needs a human confirmation.
TIER0_HARDENING_CATEGORY = "Tier 0 Asset Hardening"


#: The exact title the Security Assessment Report synthesizes for a foreign-tenant
#: directory-replication account
#: (``html_pdf_generator._build_foreign_tenant_replication_finding`` /
#: ``playbook_databinding._FOREIGN_FINDING_TITLE``). A FOREIGN row carries it so the
#: coverage card and the web CTEM can cross-reference that finding BY NAME — F-IDs
#: are render-order dependent, but the title resolves regardless of numbering.
FOREIGN_TENANT_SAR_FINDING = (
    "Possible Unauthorized Directory Replication to an External Tenant"
)


#: DNS labels too generic to identify a tenant as belonging to a client (TLDs and
#: common second-levels). A tenant token that is ONLY one of these can never
#: confirm ownership, so it is ignored when matching a tenant to the client.
_GENERIC_LABELS = frozenset(
    {
        "com", "net", "org", "local", "it", "es", "de", "fr", "uk", "eu", "io",
        "co", "gov", "edu", "mil", "int", "biz", "info", "onmicrosoft", "mail",
    }
)


def _format_date(iso_value: Any) -> str:
    """Render an ISO timestamp as a short human date; passthrough on failure."""
    text = str(iso_value or "").strip()
    if not text:
        return ""
    return text.split("T", 1)[0]


def _client_identity_tokens(domains: Iterable[str]) -> set[str]:
    """Return the identity tokens that mark a tenant as the client's own.

    The client's own DNS labels minus the generic TLD/second-level noise — e.g.
    ``corp.example.com`` -> ``{corp, example}``, ``fabrikam.local`` -> ``{fabrikam}``.
    A tenant that shares one of these tokens is the client's; a tenant that shares
    NONE is foreign-named and warrants an explicit authorization check.
    """
    tokens: set[str] = set()
    for domain in domains:
        for label in str(domain or "").lower().split("."):
            label = label.strip()
            if len(label) >= 3 and label not in _GENERIC_LABELS:
                tokens.add(label)
    return tokens


def _tenant_matches_client(tenant: str, client_tokens: set[str]) -> bool:
    """True when a sync-target tenant carries a client identity token.

    Matching is by SUBSTRING, not exact token equality, because a tenant name is
    usually a stylised variant of the client's own name, not an identical label:
    ``corpgroup.example`` and ``corp.onmicrosoft.example`` both belong to a client
    whose domain is ``corp.example`` (client token ``corp``), while ``fabrikam.example``
    shares no token and is the foreign target to elevate. A client token (>= 4 chars,
    to avoid trivial coincidences) that appears inside any tenant token — or a tenant
    token that appears inside a client token — is a match.

    Unknown tenant (empty) is treated as a match (no evidence of a foreign target),
    so an absent tenant never manufactures a false "rogue" elevation.
    """
    text = str(tenant or "").strip().lower()
    if not text or not client_tokens:
        return True
    tenant_tokens = [t for t in _split_tenant_tokens(text) if t]
    if not tenant_tokens:
        return True
    for client in client_tokens:
        if len(client) < 4:
            continue
        for tok in tenant_tokens:
            if client in tok or tok in client:
                return True
    return False


def _split_tenant_tokens(tenant: str) -> list[str]:
    """Split a tenant identifier into comparable tokens (on ``.`` and ``-``)."""
    out: list[str] = []
    for part in str(tenant or "").replace("-", ".").split("."):
        part = part.strip()
        if part and part not in _GENERIC_LABELS:
            out.append(part)
    return out


def build_tier0_hardening_items(
    domain_blocks: Iterable[tuple[str, Mapping[str, Any]]],
) -> list[dict[str, Any]]:
    """Fold the Tier 0 asset-hardening ``control_evidence`` into render rows.

    Args:
        domain_blocks: ``(domain, domain_block)`` pairs, each block carrying a
            ``control_evidence`` list. The report passes every domain; the web
            passes the one domain it is ingesting.

    Returns:
        One row per entry key (a workspace with several sync accounts keeps them
        distinct), sorted so the items that need a human decision surface first: a
        FOREIGN-TENANT account (its sync target bears no client identity token) or
        an UNCONFIRMED account leads, then confirmed same-tenant assurance items.
        Each row: ``title`` / ``account`` / ``guidance`` / ``remediation`` /
        ``confirmed`` (bool) / ``tenant`` / ``install_host`` / ``tenant_matches``
        (bool) / ``authorization_action`` (a prominent per-account action, or
        ``""``) / ``match_basis`` (for a FOREIGN row, the clause naming the
        organization's own domains and accepted sync tenants the match verdict
        ran against; ``""`` for a matching row) / ``sar_reference`` (for a FOREIGN
        row, the exact title of the Security Assessment Report finding it should
        cross-reference; ``""`` for a matching row, which raises no separate SAR
        finding) / ``domains`` (sorted) / ``checked_on``.

        ``tenant_matches`` is False only when a tenant is present AND shares no
        identity token with the client's own domains — the "sync to a foreign-named
        tenant" case a report must elevate rather than flatten into the same
        "expected, not a misconfiguration" reassurance every account carries.
    """
    domain_blocks = list(domain_blocks)
    client_tokens = _client_identity_tokens(domain for domain, _ in domain_blocks)
    org_domains = sorted(
        {str(domain).strip() for domain, _ in domain_blocks if str(domain).strip()}
    )
    items: dict[str, dict[str, Any]] = {}
    for domain, block in domain_blocks:
        if not isinstance(block, Mapping):
            continue
        entries = block.get("control_evidence")
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, Mapping):
                continue
            if str(entry.get("category") or "").strip() != TIER0_HARDENING_CATEGORY:
                continue
            key = str(entry.get("key") or "").strip()
            if not key:
                continue
            details = entry.get("details")
            details = details if isinstance(details, Mapping) else {}
            guidance = str(details.get("evidence") or "").strip()
            if not guidance:
                continue
            remediation = str(details.get("remediation") or "").strip()
            state = str(details.get("sync_account_state") or "").strip().lower()
            confirmed = state == "confirmed"
            tenant = str(details.get("tenant") or "").strip()
            install_host = str(details.get("install_host") or "").strip()
            last_seen = _format_date(entry.get("last_seen") or entry.get("discovered_at"))
            record = items.setdefault(
                key,
                {
                    "title": str(entry.get("title") or "").strip(),
                    "account": str(details.get("account") or "").strip(),
                    "guidance": guidance,
                    "remediation": remediation,
                    "confirmed": confirmed,
                    "tenant": tenant,
                    "install_host": install_host,
                    "domains": [],
                    "checked_on": "",
                },
            )
            if domain and domain not in record["domains"]:
                record["domains"].append(domain)
            if last_seen and last_seen > record["checked_on"]:
                record["checked_on"] = last_seen
    rows = list(items.values())
    for row in rows:
        row["domains"].sort()
        row["tenant_matches"] = _tenant_matches_client(row.get("tenant", ""), client_tokens)
        row["authorization_action"] = _authorization_action(row)
    # The tenants ADscan accepted as the client's own — named alongside the org
    # domains so a foreign-tenant verdict states what it matched against.
    matched_tenants = sorted(
        {
            str(row.get("tenant") or "").strip()
            for row in rows
            if row.get("tenant_matches", True) and str(row.get("tenant") or "").strip()
        }
    )
    for row in rows:
        if row.get("tenant_matches", True):
            row["match_basis"] = ""
            row["sar_reference"] = ""
        else:
            row["match_basis"] = _match_basis(
                str(row.get("tenant") or "").strip(), org_domains, matched_tenants
            )
            # A foreign-tenant account is promoted into the SAR as its own finding;
            # the coverage card cites it by name so the reader can jump to it.
            row["sar_reference"] = FOREIGN_TENANT_SAR_FINDING
    # A foreign-tenant account (its sync target shares no client identity token) is
    # the highest-priority item to verify, so it leads above the same-tenant rows.
    # WITHIN the matched group the original ordering is preserved — a CONFIRMED Tier-0
    # asset leads, the "confirm this is authorized" item follows — then by title.
    rows.sort(
        key=lambda r: (
            0 if not r["tenant_matches"] else 1,
            0 if r["confirmed"] else 1,
            r["title"].lower(),
        )
    )
    return rows


def _authorization_action(row: Mapping[str, Any]) -> str:
    """Return the prominent per-account authorization action, or ``""``.

    A sync account is only benign if the installation behind it is authorized. This
    lifts that check out of the guidance paragraph into a first-class action a
    reader cannot skim past, worded by the account's specific state:

    * FOREIGN TENANT — the sync target does not match the client's own domains, so
      this is the account to verify FIRST (a rogue replication account borrows this
      exact naming). Names the tenant and host so the reader can act.
    * UNCONFIRMED — provenance could not be read from the directory; a human must
      confirm the installation exists and is authorized.
    * CONFIRMED, same tenant — no separate action; the guidance's Tier-0 protection
      steps stand on their own.
    """
    tenant = str(row.get("tenant") or "").strip()
    host = str(row.get("install_host") or "").strip()
    where = ""
    if tenant and host:
        where = f" (target tenant {tenant}, running on {host})"
    elif tenant:
        where = f" (target tenant {tenant})"
    elif host:
        where = f" (running on {host})"
    if not row.get("tenant_matches", True):
        return (
            "Verify this account first: its synchronization target does not match "
            "this organization's domains" + where + ". Confirm the installation is "
            "authorized; if no such deployment exists, its directory-replication "
            "rights are unauthorized and must be removed."
        )
    if not row.get("confirmed", False):
        return (
            "Confirm this account belongs to an authorized Azure AD Connect "
            "installation" + where + " before treating it as benign."
        )
    return ""


def _match_basis(
    tenant: str, org_domains: list[str], matched_tenants: list[str]
) -> str:
    """Name the identity set the foreign-tenant verdict ran against.

    The "does not match this organization's domains" verdict is only auditable
    if the report also states WHAT it matched against. This names the
    organization's own domains (the identity basis the match derives from) and,
    when any exist, the sync-target tenants that WERE accepted as the client's,
    so a reader sees the boundary the foreign tenant fell outside of rather than
    taking the verdict on trust. Empty when no org domain is known (never assert
    a boundary that cannot be named).
    """
    if not org_domains:
        return ""
    tenants_clause = ""
    others = [t for t in matched_tenants if t and t != tenant]
    if others:
        word = "tenant" if len(others) == 1 else "tenants"
        tenants_clause = (
            f", and the sync {word} already accepted as this organization's "
            f"({', '.join(others)})"
        )
    tenant_name = tenant or "this sync target"
    return (
        "Matched against this organization's domains ("
        + ", ".join(org_domains)
        + ")"
        + tenants_clause
        + f"; {tenant_name} carries none of those identifiers."
    )


__all__ = [
    "FOREIGN_TENANT_SAR_FINDING",
    "TIER0_HARDENING_CATEGORY",
    "build_tier0_hardening_items",
]
