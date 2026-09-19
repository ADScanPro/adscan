"""Chained-DCSync narrative for a WriteDACL->domain money path (shared SSOT).

A money path that ends by GRANTING replication rights on the domain object
(WriteDACL / Owns / GenericAll / WriteOwner on the domain) terminates in the
attack graph at that grant — the DCSync replication it enables is NOT a graph
edge for the granted principal (post-exploitation reads are not edges; the only
DCSync edges in the graph are the structural ``discovered`` ones the inherent
replication holders carry). So the attack-path chain reads "... WriteDACL ->
Domain [confirmed]" and stops, with no visible account of the step that actually
replicated the Administrator and krbtgt secrets and took the domain.

HOMOGENIZATION DECISION (founder, 2026-09-18). Every attack path terminates at the
DOMAIN node — that is how ADscan demonstrates compromise. So for a WriteDACL whose
target IS the domain object, the DCSync is NOT rendered as a separate step, node or
derived edge (a second terminal at the same domain node would be a self-loop, would
break the "all paths end at the domain" convention, and would cause a step-count
mismatch between the writeup and the SAR). Instead, this module produces the text
that ENRICHES the terminal grant step's own NARRATIVE to explain that ADscan granted
replication rights on the domain and CHAINED a DCSync as a follow-up, naming the
replicated Tier-0 secrets. The proof lands on the money path itself (not buried in a
table) WITHOUT a second node/step. It is the SHARED SSOT for the decision, consumed
identically by the PRO PDF report and the CLI writeup, so the surfaces enrich the
SAME terminal step from the SAME proven record.

Exposure-Validation split by proof: this module renders the PROVEN enrichment ONLY.
The THEORETICAL case ("would grant replication rights and can chain a DCSync", no
proof claim, no secret names) is carried by the attack-step catalog's object-class
domain acl-abuse clause, which every surface already renders for a domain target —
so a not-walked path already reads correctly without this module firing.

The proof source (read by both surfaces) is the per-domain ``domain_compromise``
events in ``technical_report.json``: an event whose ``details.evidence_ref`` names
native replication (``native_dcsync``) is proof that ADscan replicated a Tier-0
secret. The enrichment names ONLY the secrets those events actually record (never an
invented one), so a workspace that did not prove the replication renders no proven
enrichment — the Exposure-Validation doctrine forbids a fabricated "domain
compromised" claim in a client deliverable.

Pure logic: no IO, no console, no network. Safe to import from ``adscan_core``,
the LITE/PRO runtime, and the web backend alike.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

__all__ = [
    "FULLY_EXECUTED_PATH_STATUSES",
    "extract_dcsync_tier0_secrets",
    "is_grant_relation",
    "terminal_target_is_domain",
    "build_dcsync_chain_enrichment",
]

#: Path display statuses meaning the chain was walked FULLY end to end. Mirrors
#: ``adscan_internal.services.attack_graph_core._FULLY_EXECUTED_PATH_STATUSES``
#: (kept here as the dependency-light copy so ``adscan_core`` need not import the
#: engine). A DCSync terminal is only ever appended to a fully-executed path.
FULLY_EXECUTED_PATH_STATUSES = frozenset({"exploited", "domain_compromised", "success"})

#: Grant relations onto the domain object that CONFER replication rights (and so
#: enable the terminal DCSync). Deliberately EXCLUDES ``dcsync``/``getchanges``
#: themselves: if the chain already ends in a replication edge, there is nothing
#: to append.
_GRANT_RELATIONS = frozenset(
    {"writedacl", "owns", "genericall", "writeowner", "allextendedrights"}
)

#: Evidence tokens (in a ``domain_compromise`` event's ``evidence_ref`` /
#: ``evidence``) that prove the compromise came from a native directory
#: replication, i.e. a real DCSync.
_DCSYNC_EVIDENCE_TOKENS = ("native_dcsync", "secretsdump", "dcsync", "drsuapi")

#: Canonical client-facing display labels for the Tier-0 secrets a DCSync
#: replicates. ``administrator`` is the RID-500 account; naming the RID makes the
#: finding auditor-legible.
_TIER0_SECRET_LABELS: dict[str, str] = {
    "administrator": "Administrator (RID 500)",
    "krbtgt": "krbtgt",
}

#: Stable display order (most significant first) so the terminal reads the same
#: regardless of event order.
_SECRET_ORDER: tuple[str, ...] = ("Administrator (RID 500)", "krbtgt")


def _relation_key(relation: Any) -> str:
    return str(relation or "").strip().lower()


#: The canonical Tier-0 secret principals (lowercased). ONLY these are named
#: from the recovered-credentials evidence, so a DCSync that also dumped ordinary
#: users (andy, mark, …) never lists them as Tier-0 secrets in the terminal.
_TIER0_SECRET_PRINCIPALS: frozenset[str] = frozenset(_TIER0_SECRET_LABELS)


def _order_secrets(secrets: set[str]) -> list[str]:
    ordered = [label for label in _SECRET_ORDER if label in secrets]
    ordered.extend(sorted(s for s in secrets if s not in _SECRET_ORDER))
    return ordered


def _credential_recovered_via_executed_dcsync(credential: Mapping[str, Any]) -> bool:
    """True when this recovered-credential record proves an EXECUTED DCSync.

    A DCSync method whose acquisition is ``executed`` is proof the secret was
    actually replicated. A theoretical / non-DCSync record is not.
    """

    methods = credential.get("methods")
    if isinstance(methods, (list, tuple)) and any(
        isinstance(method, Mapping) for method in methods
    ):
        # A per-method breakdown is authoritative: decide SOLELY from it so a
        # theoretical DCSync entry (acquisition != "executed") is not overridden
        # by a permissive top-level flag.
        return any(
            isinstance(method, Mapping)
            and str(method.get("method") or "").strip().lower() == "dcsync"
            and str(method.get("acquisition") or "").strip().lower() == "executed"
            for method in methods
        )
    # Fallback for a flat record that only carries the top-level method: accept it
    # only when it is a recorded DCSync (``method_recorded == "yes"``).
    return (
        str(credential.get("method") or "").strip().lower() == "dcsync"
        and str(credential.get("method_recorded") or "").strip().lower() == "yes"
    )


def _tier0_secrets_from_credentials(compromised_credentials: Any) -> set[str]:
    """Tier-0 secret labels proven replicated via an executed DCSync.

    Reads the report's recovered-credentials records (as attached to
    ``domain_data["compromised_credentials"]`` by the report pipeline) and names
    ONLY the canonical Tier-0 principals (krbtgt, Administrator RID 500) that were
    recovered via an executed DCSync. Ordinary DCSync'd users are never named.
    """

    if not isinstance(compromised_credentials, (list, tuple)):
        return set()
    labels: set[str] = set()
    for credential in compromised_credentials:
        if not isinstance(credential, Mapping):
            continue
        principal = str(credential.get("principal") or "").strip().lower()
        if principal not in _TIER0_SECRET_PRINCIPALS:
            continue
        if not _credential_recovered_via_executed_dcsync(credential):
            continue
        labels.add(_TIER0_SECRET_LABELS[principal])
    return labels


def extract_dcsync_tier0_secrets(
    events: Any,
    compromised_credentials: Any = None,
) -> list[str]:
    """Return the Tier-0 secrets a proven DCSync replicated, as display labels.

    Reads the per-domain ``domain_compromise`` events (as persisted in
    ``technical_report.json``) and collects the replicated principal names from
    those whose evidence proves a native directory replication. ``krbtgt`` and
    ``administrator`` map to their canonical client labels; any other proven
    Tier-0 principal recorded on such an event is named verbatim.

    A native-replication ``domain_compromise`` event is the GATE: without one no
    terminal is rendered, even if ``compromised_credentials`` lists DCSync'd
    Tier-0 accounts (the terminal is tied to a proven domain compromise, never
    fabricated). When the gate is open, the recovered-credentials record enriches
    the NAMED secrets: a Tier-0 account (krbtgt, Administrator RID 500) recovered
    via an EXECUTED DCSync is proven loot even when the ``domain_compromise``
    events only recorded one of the two (a scan-time incompleteness the report
    should not inherit). Both surfaces (report + writeup) read this SSOT, so they
    name the same secrets.

    Args:
        events: The per-domain event list (or any iterable of mappings). A
            non-iterable / non-mapping entry is skipped, never raised on.
        compromised_credentials: The domain's recovered-credentials records
            (``domain_data["compromised_credentials"]``), or ``None``. Used ONLY
            to enrich the named Tier-0 secrets once the event gate is open.

    Returns:
        The replicated Tier-0 secret display labels, ordered (Administrator,
        krbtgt, then any others), or ``[]`` when no proven replication event is
        present — the signal to render NO terminal.
    """

    if not isinstance(events, (list, tuple)):
        return []
    secrets: set[str] = set()
    proven_native_replication = False
    for event in events:
        if not isinstance(event, Mapping):
            continue
        if str(event.get("type")) != "domain_compromise":
            continue
        details = event.get("details")
        if not isinstance(details, Mapping):
            continue
        evidence = f"{details.get('evidence_ref') or ''} {details.get('evidence') or ''}".lower()
        if not any(token in evidence for token in _DCSYNC_EVIDENCE_TOKENS):
            continue
        proven_native_replication = True
        username = str(details.get("username") or "").strip()
        if not username:
            continue
        secrets.add(_TIER0_SECRET_LABELS.get(username.lower(), username))
    if not proven_native_replication:
        # GATE: no proven native replication ⇒ no terminal, whatever the
        # recovered-credentials say (never fabricate a compromise).
        return []
    secrets |= _tier0_secrets_from_credentials(compromised_credentials)
    return _order_secrets(secrets)


def is_grant_relation(relation: Any) -> bool:
    """True when ``relation`` is an ACL grant that CONFERS replication rights.

    These are the relations whose abuse onto the domain object grants the
    DS-Replication-Get-Changes rights that enable a DCSync (WriteDACL / Owns /
    GenericAll / WriteOwner / AllExtendedRights). A replication edge itself
    (``DCSync`` / ``GetChanges``) is NOT a grant — the chain already replicates —
    and a session / auth edge is a foothold, not a grant.
    """

    return _relation_key(relation) in _GRANT_RELATIONS


def terminal_target_is_domain(
    *,
    terminal_target_label: Any,
    domain_display: Any = None,
    target_object_class: Any = None,
) -> bool:
    """True when the terminal node is the DOMAIN object itself.

    The grant-then-DCSync case only exists when the write ACE is on the domain
    object (whose DACL confers the replication rights). A WriteDACL onto a group,
    user or computer is a different abuse and never chains a DCSync.

    Resolution is most-reliable first:

    1. ``target_object_class`` — the graph node's own object class when the caller
       has resolved it (the report stamps ``target_kind``). ``"domain"`` (also
       ``base`` / ``domaindns``) is authoritative; any other known class is a
       definite NO.
    2. The display-label heuristic — the domain OBJECT node's label is the bare
       domain name (no ``@`` principal suffix, no ``$`` machine suffix), so a
       label carrying either can never be the domain object. When ``domain_display``
       is given, the label must equal it (case-insensitively) to be the domain.
    """

    cls = str(target_object_class or "").strip().lower()
    if cls:
        return cls in {"domain", "base", "domaindns"}
    label = str(terminal_target_label or "").strip()
    if not label:
        return False
    # A principal in the domain carries an ``@domain`` suffix; a machine carries a
    # trailing ``$``. Either rules out the domain object.
    if "@" in label or label.rstrip().endswith("$"):
        return False
    dom = str(domain_display or "").strip()
    if dom:
        return label.lower() == dom.lower()
    # No domain to compare against: a bare, suffix-free label is the domain object
    # by construction of the graph's node labels.
    return True


def build_dcsync_chain_enrichment(
    *,
    path_status: Any,
    terminal_relation: Any,
    terminal_target_label: Any,
    domain_display: Any,
    secrets: list[str],
    target_object_class: Any = None,
) -> tuple[str, str] | None:
    """Return the PROVEN chained-DCSync narrative ``(long, short)``, or ``None``.

    The text is authored to be APPENDED to the terminal grant step's own
    narrative — it does NOT create a separate step. It renders nothing unless ALL
    hold:

    * the path was walked FULLY end to end (``path_status`` in
      :data:`FULLY_EXECUTED_PATH_STATUSES`);
    * its last real hop is a GRANT relation (WriteDACL / Owns / GenericAll /
      WriteOwner / AllExtendedRights) — NOT already a replication edge, so a chain
      that already ends in DCSync is not enriched twice;
    * that hop's target is the DOMAIN object (whose DACL confers the replication
      rights) — see :func:`terminal_target_is_domain`;
    * ``secrets`` is non-empty — i.e. the workspace actually PROVED the
      replication (see :func:`extract_dcsync_tier0_secrets`). A grant with no
      proven loot renders no enrichment (never fabricate a compromise); the
      catalog's theoretical domain clause already frames the not-walked case.

    Args:
        path_status: The path's display status.
        terminal_relation: The relation of the path's last real (non-structural)
            hop.
        terminal_target_label: The label of the node the path terminates at.
        domain_display: The domain name to render in the narrative.
        secrets: The proven replicated Tier-0 secret display labels.
        target_object_class: The terminal node's object class when resolved
            (``"domain"`` for the domain object); ``None`` falls back to the
            label heuristic in :func:`terminal_target_is_domain`.

    Returns:
        ``(long_narrative, short_narrative)`` naming the proven replicated Tier-0
        secrets, or ``None`` when the terminal step should not be enriched.
    """

    if str(path_status) not in FULLY_EXECUTED_PATH_STATUSES:
        return None
    if not is_grant_relation(terminal_relation):
        return None
    if not terminal_target_is_domain(
        terminal_target_label=terminal_target_label,
        domain_display=domain_display,
        target_object_class=target_object_class,
    ):
        return None
    clean_secrets = [str(s).strip() for s in (secrets or []) if str(s).strip()]
    if not clean_secrets:
        return None

    domain = str(domain_display or terminal_target_label or "the domain").strip() or "the domain"
    secrets_phrase = _join_secrets(clean_secrets)
    long_narrative = (
        f"Holding write access over {domain}'s access control list, ADscan granted "
        f"itself the directory-replication rights on the domain object and chained a "
        f"DCSync, replicating the directory's most privileged secrets from the domain "
        f"controller: {secrets_phrase}. Recovering the krbtgt key permits forging "
        f"arbitrary Kerberos tickets for any principal, so this is full domain "
        f"compromise, confirmed against the environment."
    )
    short_narrative = (
        f"ADscan granted itself replication rights on {domain} and chained a DCSync, "
        f"replicating {secrets_phrase}: full domain compromise, confirmed."
    )
    return long_narrative, short_narrative


def _join_secrets(secrets: list[str]) -> str:
    """Join secret labels into a natural English list (no Oxford em-dash)."""
    if len(secrets) == 1:
        return secrets[0]
    if len(secrets) == 2:
        return f"{secrets[0]} and {secrets[1]}"
    return ", ".join(secrets[:-1]) + f", and {secrets[-1]}"
