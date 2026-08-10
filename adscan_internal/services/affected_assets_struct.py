"""Structured, correlation-ready affected-asset entities.

The flat ``extract_affected_assets`` list in :mod:`affected_assets` answers
"what display strings does this finding affect". This module answers the
stronger question the platform needs: "what TYPED, IDENTIFIABLE entities does
this finding affect, with stable join keys", so the web can JOIN affected assets
to its asset tables (``UserAsset`` / ``ComputerAsset`` / ``Host``) and graph
nodes (``AttackGraphNode`` / ``AttackGraphEdge.finding_id``) instead of matching
strings.

The contract (one entity per affected asset)::

    {
      "type":       "user" | "computer" | "group" | "domain" | "template"
                    | "ca" | "share" | "artifact" | "credential",
      "identifier": <stable join key>,   # sAMAccountName / FQDN / template name…
      "display":    <human label>,       # "MEEREEN.ESSOS.LOCAL (192.168.180.12)"
      "role":       "source" | "target" | "affected",
      "sid":        <SID if known>,
      "ip":         <IP if a host and known>,
      "fqdn":       <FQDN if a host and known>,
      "upn":        <UPN if a user and known>,
      "node_id":    <attack-graph node id if resolvable>,
    }

Host entities ALWAYS carry both IP and FQDN when the inventory resolves them
(the owner's mandatory rule: ``MEEREEN.ESSOS.LOCAL (192.168.180.12)``).

The resolution from a bare sAMAccountName / SID to IP+FQDN+SID is done against an
:class:`AssetIndex` built once from the workspace attack graph. The composition
itself is pure: it takes the finding details, its rule, and an (optional) index,
and never performs I/O. Callers that have a workspace build the index once and
reuse it across every finding; callers without one still get correct entities,
just without the IP/FQDN enrichment a bare account name cannot supply on its own.

Tier-shared, like the flat resolution it builds on: the free exposure report and
the paid kit both stamp and read these entities, so the two artifacts can never
name different objects for the same finding.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
import ipaddress
import json
from pathlib import Path
from typing import Any

from adscan_internal.services.affected_asset_rules import (
    Extra,
    Scope,
    SourceMode,
    TargetMode,
    extract_adcs_ca_names,
    rule_for,
)
from adscan_internal.services.affected_assets import (
    PLACEHOLDER_ASSET_TOKENS,
    SERIALIZED_ENTITIES_KEY,
    _adcs_template_names,
    _details_view,
    _drop_direct_domain_breaker_assets,
    _extract_strings,
    _is_direct_domain_breaker_asset,
    _is_non_empty_string,
    extract_share_locations,
    format_account_display,
    is_precise_share_locator,
    iter_account_records,
)

# Entity type constants — the typed axis the platform correlates on.
TYPE_USER = "user"
TYPE_COMPUTER = "computer"
TYPE_GROUP = "group"
TYPE_DOMAIN = "domain"
TYPE_TEMPLATE = "template"
TYPE_CA = "ca"
TYPE_SHARE = "share"
TYPE_ARTIFACT = "artifact"
TYPE_CREDENTIAL = "credential"

ROLE_SOURCE = "source"
ROLE_TARGET = "target"
ROLE_AFFECTED = "affected"

# Reserved key under a finding's ``details`` that carries the serialized
# structured entities into ``technical_report.json``. The web ingestion reads
# this key directly off ``finding.details`` (see ingestion_service) — it is the
# single contract between the engine and the platform for affected assets.
SERIALIZED_KEY = SERIALIZED_ENTITIES_KEY


# --------------------------------------------------------------------------- #
# Structured entity                                                            #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class AffectedAssetEntity:
    """One typed, identifiable affected asset of a finding.

    ``identifier`` is the stable join key for the entity's type:

    * user → sAMAccountName
    * computer → FQDN (falls back to the short host / sAMAccountName)
    * group → sAMAccountName
    * domain → the domain name
    * template → the certificate-template name
    * ca → the Enterprise CA name
    * share / artifact / credential → the path / marker
    """

    type: str
    identifier: str
    display: str
    role: str = ROLE_AFFECTED
    sid: str | None = None
    ip: str | None = None
    fqdn: str | None = None
    upn: str | None = None
    node_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to the JSON contract (omitting empty optional fields)."""
        payload: dict[str, Any] = {
            "type": self.type,
            "identifier": self.identifier,
            "display": self.display,
            "role": self.role,
        }
        if self.sid:
            payload["sid"] = self.sid
        if self.ip:
            payload["ip"] = self.ip
        if self.fqdn:
            payload["fqdn"] = self.fqdn
        if self.upn:
            payload["upn"] = self.upn
        if self.node_id:
            payload["node_id"] = self.node_id
        return payload


# --------------------------------------------------------------------------- #
# Asset index — resolves bare account names / SIDs to full host/user records   #
# --------------------------------------------------------------------------- #


def _norm_key(value: Any) -> str:
    """Lowercase, trimmed token for index lookups."""
    return str(value or "").strip().lower()


def _strip_realm(value: str) -> str:
    """Return the bare principal, without an ``@REALM`` or ``DOMAIN\\`` wrapper.

    Detectors record a principal in whichever form the protocol handed them:
    ``MEEREEN$@ESSOS.LOCAL`` from an LDAP read, ``NORTH\\WINTERFELL$`` from an
    NTLM capture. Reducing both to ``MEEREEN$`` / ``WINTERFELL$`` is what lets
    the asset index resolve either to the same host record.
    """
    text = str(value or "").strip()
    if "\\" in text:
        text = text.rsplit("\\", 1)[-1].strip()
    if "@" in text:
        return text.split("@", 1)[0].strip()
    return text


@dataclass
class _ResolvedNode:
    """A directory object resolved from the attack graph."""

    kind: str
    samaccountname: str = ""
    name: str = ""
    fqdn: str = ""
    ip: str = ""
    sid: str = ""
    upn: str = ""
    node_id: str = ""


@dataclass
class AssetIndex:
    """Lookup from any principal token to a resolved directory object.

    Built once from the workspace attack graph (``attack_graph.json``) and reused
    across every finding so the bare ``samaccountname`` / ``object_id`` a posture
    finding persists can be enriched to IP + FQDN + SID. All lookups are
    alias-aware: a record is indexed under its sAMAccountName, SID, FQDN, short
    hostname, and ``HOST$`` form so any of those resolves it.
    """

    _by_token: dict[str, _ResolvedNode] = field(default_factory=dict)
    domain: str = ""
    dc_nodes: list[_ResolvedNode] = field(default_factory=list)

    def _register(self, node: _ResolvedNode, *, is_dc: bool = False) -> None:
        tokens: set[str] = set()
        for raw in (
            node.samaccountname,
            node.sid,
            node.fqdn,
            node.name,
            node.upn,
            node.node_id,
            # The IP too: a coercion / relay-surface finding records the hosts
            # that answered as bare addresses, and without this the entry could
            # never be resolved to its FQDN.
            node.ip,
        ):
            token = _norm_key(raw)
            if token:
                tokens.add(token)
                tokens.add(_strip_realm(token))
        # Short hostname for a computer (braavos.essos.local -> braavos and
        # braavos$), so a finding carrying any host form resolves.
        if node.fqdn:
            short = _norm_key(node.fqdn).split(".", 1)[0]
            if short:
                tokens.add(short)
                tokens.add(f"{short}$")
        if node.samaccountname:
            sam = _norm_key(node.samaccountname)
            tokens.add(sam)
            tokens.add(sam.rstrip("$"))
        for token in tokens:
            if token and token not in self._by_token:
                self._by_token[token] = node
        if is_dc:
            self.dc_nodes.append(node)

    def lookup(self, *candidates: Any) -> _ResolvedNode | None:
        """Return the resolved node for the first matching candidate token."""
        for candidate in candidates:
            token = _norm_key(candidate)
            if not token:
                continue
            node = self._by_token.get(token) or self._by_token.get(
                _strip_realm(token)
            )
            if node is not None:
                return node
        return None


def _node_props(node: Mapping[str, Any]) -> dict[str, Any]:
    props = node.get("properties")
    return props if isinstance(props, dict) else {}


def _is_dc_node(node: Mapping[str, Any], props: Mapping[str, Any]) -> bool:
    """Best-effort domain-controller classification for a computer node."""
    tags = node.get("system_tags") or []
    if isinstance(tags, list) and any(
        "domain_controller" in str(tag).lower() or str(tag).lower() == "dc"
        for tag in tags
    ):
        return True
    for value in (props.get("isdc"), props.get("is_dc"), node.get("is_dc")):
        if value is True:
            return True
    spns = props.get("serviceprincipalnames") or []
    if isinstance(spns, list) and any(
        str(spn).upper().startswith(("GC/", "LDAP/")) for spn in spns
    ):
        return True
    return False


def build_asset_index_from_graph(graph: Mapping[str, Any]) -> AssetIndex:
    """Build an :class:`AssetIndex` from a parsed ``attack_graph.json`` graph.

    Indexes every Computer, User and Group node so a finding's bare
    sAMAccountName / SID resolves to its FQDN + IP (+ SID / UPN). Never raises
    on a malformed graph — a missing field simply leaves that enrichment empty.

    Groups are indexed for the same reason hosts are: a name on its own does
    not say what kind of object it is. ``ACCOUNT OPERATORS`` and
    ``DOMAIN USERS`` are groups, and the only thing distinguishing them from an
    account with a space in its name is the directory itself. Without them in
    the index every ADCS enrolling group reached the client's asset inventory
    filed as a user.
    """
    index = AssetIndex(domain=str(graph.get("domain") or ""))
    nodes = graph.get("nodes")
    if isinstance(nodes, dict):
        node_iter: Iterable[Any] = nodes.values()
    elif isinstance(nodes, list):
        node_iter = nodes
    else:
        return index

    for node in node_iter:
        if not isinstance(node, dict):
            continue
        kind = str(node.get("kind") or "").strip().lower()
        if kind not in ("computer", "user", "group"):
            continue
        props = _node_props(node)
        sam = str(props.get("samaccountname") or "").strip()
        sid = str(
            props.get("objectid")
            or props.get("object_id")
            or node.get("objectId")
            or ""
        ).strip()
        node_id = str(node.get("id") or "").strip()
        if kind == "computer":
            resolved = _ResolvedNode(
                kind=TYPE_COMPUTER,
                samaccountname=sam,
                name=str(props.get("name") or node.get("label") or "").strip(),
                fqdn=str(props.get("dnshostname") or "").strip(),
                ip=str(props.get("ip_address") or "").strip(),
                sid=sid,
                node_id=node_id,
            )
            index._register(resolved, is_dc=_is_dc_node(node, props))
        else:
            resolved = _ResolvedNode(
                kind=TYPE_GROUP if kind == "group" else TYPE_USER,
                samaccountname=sam,
                name=str(props.get("name") or node.get("label") or "").strip(),
                sid=sid,
                upn=str(props.get("upn") or props.get("userprincipalname") or "").strip(),
                node_id=node_id,
            )
            index._register(resolved)
    return index


def load_asset_index(workspace_dir: str | Path, domain: str) -> AssetIndex:
    """Load and build an :class:`AssetIndex` from a workspace domain graph.

    Best-effort: returns an empty index when the graph is missing/unreadable so
    the structured composition degrades gracefully (entities without IP/FQDN
    enrichment rather than an exception).
    """
    try:
        graph_path = (
            Path(workspace_dir) / "domains" / str(domain) / "attack_graph.json"
        )
        if not graph_path.exists():
            return AssetIndex(domain=str(domain))
        with graph_path.open("r", encoding="utf-8") as handle:
            graph = json.load(handle)
        if not isinstance(graph, dict):
            return AssetIndex(domain=str(domain))
        index = build_asset_index_from_graph(graph)
        if not index.domain:
            index.domain = str(domain)
        return index
    except Exception:  # noqa: BLE001 - best-effort enrichment, never fatal
        return AssetIndex(domain=str(domain))


# --------------------------------------------------------------------------- #
# Display formatting                                                           #
# --------------------------------------------------------------------------- #


def format_host_display(*, fqdn: str = "", ip: str = "", fallback: str = "") -> str:
    """Return the canonical host label carrying BOTH FQDN and IP when known.

    Owner's mandatory rule: ``MEEREEN.ESSOS.LOCAL (192.168.180.12)``. Falls back
    gracefully when only one identifier is available, and to ``fallback`` (the
    bare account name) when neither resolves.
    """
    name = (fqdn or fallback or "").strip()
    ip = (ip or "").strip()
    if name and ip:
        return f"{name.upper()} ({ip})"
    if name:
        return name.upper()
    if ip:
        return ip
    return str(fallback or "").strip()


# --------------------------------------------------------------------------- #
# Per-principal / host resolution into typed entities                         #
# --------------------------------------------------------------------------- #

# A token that should never become an affected-asset entity on its own — these
# are container/realm placeholders, not concrete principals. Aliased to the flat
# extractor's set so the two sides cannot drift apart.
_PLACEHOLDER_TOKENS = PLACEHOLDER_ASSET_TOKENS


def _looks_like_ip(value: str) -> bool:
    """Return True when the token is a bare IP address.

    Deliberately narrow. A dotted token is NOT enough to call something a host —
    plenty of sAMAccountNames carry a dot (``david.orelious``) and typing those
    as computers would corrupt the platform's asset join.
    """
    text = str(value or "").strip()
    if not text:
        return False
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _looks_like_computer(
    value: str, node: _ResolvedNode | None, *, domain_hint: str = ""
) -> bool:
    """Classify a token as a computer without guessing from a dot.

    Three signals, in order of confidence: the asset index resolved it to a
    computer node; it is a bare IP; it carries the ``$`` machine-account suffix.
    Then, only when the finding's domain is known, a token that is an FQDN
    *inside that domain* (``srv01.corp.local`` under ``corp.local``). That last
    test is why the domain must be threaded in rather than inferred: plenty of
    sAMAccountNames contain a dot (``david.orelious``), and treating every
    dotted token as a host would file real users under the platform's computer
    assets.
    """
    if node is not None:
        return node.kind == TYPE_COMPUTER
    text = str(value or "").strip()
    if _looks_like_ip(text):
        return True
    if text.endswith("$") or _strip_realm(text).endswith("$"):
        return True
    domain = _norm_key(domain_hint)
    return bool(domain) and _norm_key(text).endswith(f".{domain}")


def _entity_for_principal(
    raw: str,
    *,
    role: str,
    index: AssetIndex | None,
    sid_hint: str = "",
    forced_type: str = "",
    qualifier: str = "",
    domain_hint: str = "",
) -> AffectedAssetEntity | None:
    """Resolve one principal token into a typed :class:`AffectedAssetEntity`.

    ``forced_type`` overrides the principal resolution for records that are not
    principals at all (a trust's partner domain). ``qualifier`` names the part of
    the record that is affected and is appended to the display. ``domain_hint``
    lets an unresolved FQDN be recognised as a host of that domain.
    """
    text = str(raw or "").strip()
    if not text or _norm_key(text) in _PLACEHOLDER_TOKENS:
        return None

    if forced_type == TYPE_DOMAIN:
        return _qualified_entity(_domain_entity(text), qualifier)

    node = index.lookup(text, sid_hint) if index is not None else None

    if _looks_like_computer(text, node, domain_hint=domain_hint):
        # A bare IP is not a name — leaving it out of ``fallback`` keeps the
        # display as ``10.0.0.5`` rather than ``10.0.0.5 (10.0.0.5)``.
        sam = (node.samaccountname if node else "") or (
            "" if _looks_like_ip(text) else _strip_realm(text)
        )
        # An unresolved FQDN IS the host name; carry it so the display and the
        # join key are the FQDN rather than a bare label. A principal form
        # (``HOST$@REALM``, ``DOMAIN\HOST$``) is NOT an FQDN even though it
        # contains a dot — treating it as one printed the realm as the hostname.
        fqdn = (node.fqdn if node else "") or (
            text
            if "." in text
            and not _looks_like_ip(text)
            and not any(ch in text for ch in "@\\$")
            else ""
        )
        ip = (node.ip if node else "") or (text if _looks_like_ip(text) else "")
        sid = (node.sid if node else "") or sid_hint
        identifier = fqdn or sam or _strip_realm(text)
        return _qualified_entity(
            AffectedAssetEntity(
                type=TYPE_COMPUTER,
                identifier=identifier,
                display=format_host_display(fqdn=fqdn, ip=ip, fallback=sam),
                role=role,
                sid=sid or None,
                ip=ip or None,
                fqdn=fqdn or None,
                node_id=(node.node_id if node else None) or None,
            ),
            qualifier,
        )

    # Account or group principal. Which of the two it is comes from the
    # directory (the asset index), never from the shape of the name: a group
    # called ``SPYS`` and an account called ``sql_svc`` are indistinguishable as
    # strings, and guessing puts groups in the client's user inventory.
    sam = (node.samaccountname if node else "") or _strip_realm(text)
    sid = (node.sid if node else "") or sid_hint
    upn = node.upn if node else ""
    display = sam
    if upn:
        display = f"{sam} ({upn})"
    return _qualified_entity(
        AffectedAssetEntity(
            type=TYPE_GROUP if node is not None and node.kind == TYPE_GROUP else TYPE_USER,
            identifier=sam,
            display=display,
            role=role,
            sid=sid or None,
            upn=upn or None,
            node_id=(node.node_id if node else None) or None,
        ),
        qualifier,
    )


def _domain_entity(domain: str) -> AffectedAssetEntity:
    name = str(domain or "").strip()
    return AffectedAssetEntity(
        type=TYPE_DOMAIN,
        identifier=name,
        display=name,
        role=ROLE_AFFECTED,
    )


def _qualified_entity(
    entity: AffectedAssetEntity, qualifier: str
) -> AffectedAssetEntity:
    """Return *entity* with the affected part of the principal in its display.

    The identifier stays the bare join key (sAMAccountName / FQDN) so the
    platform can still correlate the entity to its asset row, while the display
    names what actually has to be fixed — ``jdoe · description``.
    """
    detail = str(qualifier or "").strip()
    if not detail:
        return entity
    return replace(entity, display=format_account_display(entity.display, detail))


def _source_principals(details: Mapping[str, Any]) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for key in (
        "from",
        "source",
        "source_user",
        "source_username",
        "user",
        "username",
        "credential_username",
    ):
        for value in _extract_strings(details.get(key)):
            token = _norm_key(value)
            if token and token not in seen:
                seen.add(token)
                names.append(value)
    return names


def _target_principals(details: Mapping[str, Any], *, drop_breaker: bool) -> list[str]:
    raw: list[str] = []
    for key in ("to", "target", "target_user", "target_username", "target_host"):
        raw.extend(_extract_strings(details.get(key)))
    if drop_breaker:
        raw = _drop_direct_domain_breaker_assets(raw)
    out: list[str] = []
    seen: set[str] = set()
    for value in raw:
        token = _norm_key(value)
        if token and token not in seen:
            seen.add(token)
            out.append(value)
    return out


def _edge_principals(
    details: Mapping[str, Any],
    relation_aliases: set[str],
) -> tuple[list[str], list[str]]:
    """Return ``(sources, targets)`` from matching attack-graph edges.

    Targets that are direct domain breakers (Domain Admins / krbtgt / a DC) are
    dropped — they are where the escalation lands, not what the finding affects.
    """
    edges = details.get("attack_graph_edges")
    if not isinstance(edges, list):
        return [], []
    sources: list[str] = []
    targets: list[str] = []
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        relation = _norm_key(edge.get("relation")).replace(" ", "")
        if relation_aliases and relation and relation not in relation_aliases:
            continue
        for value in _extract_strings(edge.get("source")) + _extract_strings(
            edge.get("from")
        ):
            sources.append(value)
        for value in _extract_strings(edge.get("target")) + _extract_strings(
            edge.get("to")
        ):
            if not _is_direct_domain_breaker_asset(value):
                targets.append(value)
    return sources, targets


def _prefer_precise_share_entities(
    entities: Iterable[AffectedAssetEntity],
) -> list[AffectedAssetEntity]:
    """Drop bare-share entities once the exact secret-bearing files are known.

    Mirrors :func:`affected_assets.prefer_precise_share_locators` on the typed
    side, so the platform and the PDF list the same shares.
    """
    values = list(entities)
    shares = [entity for entity in values if entity.type == TYPE_SHARE]
    if not any(is_precise_share_locator(entity.identifier) for entity in shares):
        return values
    return [
        entity
        for entity in values
        if entity.type != TYPE_SHARE or is_precise_share_locator(entity.identifier)
    ]


def _dedupe(entities: Iterable[AffectedAssetEntity]) -> list[AffectedAssetEntity]:
    out: list[AffectedAssetEntity] = []
    seen: set[tuple[str, str, str]] = set()
    for entity in entities:
        key = (entity.type, _norm_key(entity.identifier), entity.role)
        if key in seen:
            continue
        seen.add(key)
        out.append(entity)
    return out


# --------------------------------------------------------------------------- #
# Public composition                                                           #
# --------------------------------------------------------------------------- #


def build_affected_asset_entities(
    finding_key: str,
    details: Any,
    *,
    domain_name: str | None = None,
    index: AssetIndex | None = None,
    relation_aliases: set[str] | None = None,
) -> list[AffectedAssetEntity]:
    """Return the typed, correlation-ready affected-asset entities for a finding.

    Driven by the finding-key :class:`AssetRule` (scope / source / target /
    extras). Pure: takes the finding details and an optional :class:`AssetIndex`
    (built once per workspace from the attack graph) and performs no I/O.

    The two finding types the owner distinguishes both flow through here:

    * ATTACK-STEP findings (ADCS, roasting, ACL, delegation, DCSync) → the FROM
      principal(s) as ``role="source"``, the TO principal(s)/resource(s) as
      ``role="target"``, plus the abused TEMPLATE(s) + CA for ADCS.
    * ISOLATED posture findings → the concrete affected hosts (IP + FQDN),
      affected accounts (sAMAccountName), or the domain object — by scope.
    """
    view = _details_view(details)
    rule = rule_for(finding_key)
    aliases = relation_aliases or set()
    entities: list[AffectedAssetEntity] = []
    domain_hint = str(domain_name or (index.domain if index is not None else "") or "")

    # ---- Scope-driven isolated-vulnerability entities -----------------------
    if rule.scope is Scope.DOMAIN_WIDE:
        if domain_name:
            entities.append(_domain_entity(domain_name))
    elif rule.scope is Scope.DC_SCOPED:
        # The DC answered for the control. Resolve the domain's DC host(s) to
        # IP + FQDN; fall back to the domain object when no DC resolves.
        dc_nodes = list(index.dc_nodes) if index is not None else []
        for node in dc_nodes:
            entities.append(
                AffectedAssetEntity(
                    type=TYPE_COMPUTER,
                    identifier=node.fqdn or node.samaccountname,
                    display=format_host_display(
                        fqdn=node.fqdn, ip=node.ip, fallback=node.samaccountname
                    ),
                    role=ROLE_AFFECTED,
                    sid=node.sid or None,
                    ip=node.ip or None,
                    fqdn=node.fqdn or None,
                    node_id=node.node_id or None,
                )
            )
        if not entities and domain_name:
            entities.append(_domain_entity(domain_name))
    elif rule.scope is Scope.HOST_SCOPED:
        for sam, sid, qualifier in iter_account_records(view, rule=rule):
            entity = _entity_for_principal(
                sam,
                role=ROLE_AFFECTED,
                index=index,
                sid_hint=sid,
                forced_type=rule.record_entity_type,
                qualifier=qualifier,
                domain_hint=domain_hint,
            )
            if entity is not None:
                entities.append(entity)
        if not entities and domain_name:
            # A host-scoped finding that persisted no concrete host still names
            # the domain so the platform shows something, never "no assets".
            entities.append(_domain_entity(domain_name))

    # ---- Attack-step source/target principals (per-principal scope) ---------
    if rule.scope is Scope.PER_PRINCIPAL:
        # A per-principal finding may ALSO carry its own record list — the
        # coercion probes record the hosts that answered while the same finding
        # can arrive from an attack-graph edge. The flat extractor reads those
        # records whatever the scope, so reading them here too is what keeps the
        # PDF and the platform showing the same assets.
        for name, sid, qualifier in iter_account_records(view, rule=rule):
            entity = _entity_for_principal(
                name,
                role=ROLE_AFFECTED,
                index=index,
                sid_hint=sid,
                forced_type=rule.record_entity_type,
                qualifier=qualifier,
                domain_hint=domain_hint,
            )
            if entity is not None:
                entities.append(entity)
        # For ADCS the edge/detail TARGET is the abused certificate template, not
        # a principal — those surface as typed TEMPLATE entities (via the
        # TEMPLATES extra + flat lift), so suppress target-principal extraction
        # here to avoid a template name leaking in as a bogus "user target".
        is_adcs = Extra.TEMPLATES in rule.extras
        sources: list[str] = []
        targets: list[str] = []
        if rule.source is SourceMode.PRINCIPALS:
            sources.extend(_source_principals(view))
        if not is_adcs:
            if rule.target is TargetMode.KEEP:
                targets.extend(_target_principals(view, drop_breaker=False))
            elif rule.target is TargetMode.DROP_BREAKER:
                targets.extend(_target_principals(view, drop_breaker=True))
        edge_sources, edge_targets = _edge_principals(view, aliases)
        if rule.source is SourceMode.PRINCIPALS:
            sources.extend(edge_sources)
        if not is_adcs:
            targets.extend(edge_targets)

        for name in sources:
            entity = _entity_for_principal(
                name, role=ROLE_SOURCE, index=index, domain_hint=domain_hint
            )
            if entity is not None:
                entities.append(entity)
        for name in targets:
            entity = _entity_for_principal(
                name, role=ROLE_TARGET, index=index, domain_hint=domain_hint
            )
            if entity is not None:
                entities.append(entity)

    # ---- Typed extras (ADCS templates + CA, shares, artifacts) --------------
    if Extra.TEMPLATES in rule.extras:
        template_names = list(_adcs_template_names(view))
        if not template_names:
            # The ADCS edge TARGET is the abused template object (e.g.
            # ``ESC13@ESSOS.LOCAL``); when the details carry no explicit template
            # field, recover it from the edge target so the template still
            # surfaces. CA targets are handled by the CA extra below.
            _, edge_targets = _edge_principals(view, aliases)
            ca_lower = {ca.strip().lower() for ca in extract_adcs_ca_names(view)}
            for target in edge_targets:
                name = _strip_realm(target).strip()
                if name and name.lower() not in ca_lower:
                    template_names.append(name)
        for template in template_names:
            entities.append(
                AffectedAssetEntity(
                    type=TYPE_TEMPLATE,
                    identifier=template,
                    display=template,
                    role=ROLE_AFFECTED,
                )
            )
    if Extra.CA in rule.extras:
        for ca in extract_adcs_ca_names(view):
            entities.append(
                AffectedAssetEntity(
                    type=TYPE_CA,
                    identifier=ca,
                    display=ca,
                    role=ROLE_AFFECTED,
                )
            )
    if Extra.SHARE_PATH in rule.extras:
        for location in extract_share_locations(view):
            entities.append(
                AffectedAssetEntity(
                    type=TYPE_SHARE,
                    identifier=location,
                    display=location,
                    role=ROLE_AFFECTED,
                )
            )
    if Extra.ARTIFACT in rule.extras:
        for key in ("artifact", "source_xml"):
            for value in _extract_strings(view.get(key)):
                entities.append(
                    AffectedAssetEntity(
                        type=TYPE_ARTIFACT,
                        identifier=value,
                        display=value,
                        role=ROLE_AFFECTED,
                    )
                )
    if Extra.PASSWORD_REDACTED in rule.extras:
        for key in ("password", "secret", "plaintext", "cleartext"):
            if _is_non_empty_string(view.get(key)):
                entities.append(
                    AffectedAssetEntity(
                        type=TYPE_CREDENTIAL,
                        identifier="recovered-credential",
                        display="Recovered credential (redacted)",
                        role=ROLE_AFFECTED,
                    )
                )
                break

    return _dedupe(entities)


def _typed_entities_from_flat_strings(
    flat_assets: Iterable[str],
) -> list[AffectedAssetEntity]:
    """Lift the flat extractor's typed ``Template:`` / ``CA:`` / ``Share:`` /
    ``Artifact:`` strings into structured entities.

    The flat :func:`extract_affected_assets` resolves the abused certificate
    template(s) + CA from the correlated attack paths (a richer resolution than
    the summarized finding edges, which often carry no template notes). Rather
    than duplicate that ADCS resolution, the serialization pass reuses it: the
    already-typed flat strings are mapped back to typed entities here so the
    structured contract carries the templates the report shows.
    """
    out: list[AffectedAssetEntity] = []
    for raw in flat_assets:
        text = str(raw or "").strip()
        lower = text.lower()
        if lower.startswith("template: "):
            name = text[len("template: ") :].strip()
            if name:
                out.append(
                    AffectedAssetEntity(
                        type=TYPE_TEMPLATE, identifier=name, display=name
                    )
                )
        elif lower.startswith("ca: "):
            name = text[len("ca: ") :].strip()
            if name:
                out.append(
                    AffectedAssetEntity(type=TYPE_CA, identifier=name, display=name)
                )
        elif lower.startswith("share: "):
            name = text[len("share: ") :].strip()
            if name:
                out.append(
                    AffectedAssetEntity(
                        type=TYPE_SHARE, identifier=name, display=name
                    )
                )
        elif lower.startswith("artifact: "):
            name = text[len("artifact: ") :].strip()
            if name:
                out.append(
                    AffectedAssetEntity(
                        type=TYPE_ARTIFACT, identifier=name, display=name
                    )
                )
    return out


def serialize_affected_asset_entities(
    finding_key: str,
    details: Any,
    *,
    domain_name: str | None = None,
    index: AssetIndex | None = None,
    relation_aliases: set[str] | None = None,
    flat_assets: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    """Return the JSON-serializable structured entities for a finding.

    The list written under ``details[SERIALIZED_KEY]`` in ``technical_report.json``
    and ingested verbatim by the web. Returns ``[]`` when the finding has no
    surfaceable entity (the caller then omits the key).

    ``flat_assets`` (optional) is the output of the flat
    :func:`affected_assets.extract_affected_assets` computed WITH the correlated
    attack paths in scope. When supplied, its typed ``Template:`` / ``CA:`` /
    ``Share:`` / ``Artifact:`` strings are lifted into structured entities so the
    ADCS templates the report resolves from the paths reach the structured
    contract too — reusing the single resolution path, never re-implementing it.
    """
    entities = build_affected_asset_entities(
        finding_key,
        details,
        domain_name=domain_name,
        index=index,
        relation_aliases=relation_aliases,
    )
    if flat_assets is not None:
        entities = _dedupe([*entities, *_typed_entities_from_flat_strings(flat_assets)])
    entities = _prefer_precise_share_entities(entities)
    return [entity.to_dict() for entity in entities]


# --------------------------------------------------------------------------- #
# Reading the serialized entities back                                         #
# --------------------------------------------------------------------------- #


def load_serialized_entities(details: Any) -> list[dict[str, Any]]:
    """Return the typed entities a finding carries under :data:`SERIALIZED_KEY`.

    The finalization pass writes these into ``technical_report.json``, so any
    renderer downstream of it can read the RESOLVED type and display of an
    asset instead of re-deriving them from a name. Returns ``[]`` for a finding
    that was never stamped, so callers keep their existing behaviour.
    """
    view = _details_view(details)
    raw = view.get(SERIALIZED_KEY)
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict)]


def _entity_alias_tokens(entity: Mapping[str, Any]) -> set[str]:
    """Return every token that should resolve to *entity*.

    A finding names the same object in whichever spelling its detector had: the
    bare sAMAccountName, ``HOST$@REALM`` from an LDAP read, an IP from a
    coercion probe, the FQDN from DNS. All of them have to reach the one
    resolved entity, or the lookup silently misses and the caller falls back to
    the raw string it was trying to improve on.
    """
    tokens: set[str] = set()
    for raw in (
        entity.get("identifier"),
        entity.get("display"),
        entity.get("fqdn"),
        entity.get("ip"),
        entity.get("sid"),
        entity.get("upn"),
        entity.get("node_id"),
    ):
        token = _norm_key(raw)
        if not token:
            continue
        tokens.add(token)
        tokens.add(_strip_realm(token))
    fqdn = _norm_key(entity.get("fqdn"))
    if fqdn:
        short = fqdn.split(".", 1)[0]
        if short:
            tokens.add(short)
            tokens.add(f"{short}$")
    identifier = _norm_key(entity.get("identifier"))
    if identifier:
        tokens.add(identifier.rstrip("$"))
    return {token for token in tokens if token}


def build_serialized_entity_index(details: Any) -> dict[str, dict[str, Any]]:
    """Return an alias-aware lookup over a finding's serialized entities.

    Maps every spelling of an object (sAMAccountName, ``HOST$``, short name,
    FQDN, IP, SID, node id) to the typed entity the engine resolved for it.
    Empty when the finding carries no entities.
    """
    index: dict[str, dict[str, Any]] = {}
    for entity in load_serialized_entities(details):
        for token in _entity_alias_tokens(entity):
            index.setdefault(token, entity)
    return index


def resolve_serialized_entity(
    index: Mapping[str, dict[str, Any]], token: Any
) -> dict[str, Any] | None:
    """Return the typed entity a raw principal token names, or ``None``."""
    text = _norm_key(token)
    if not text:
        return None
    return index.get(text) or index.get(_strip_realm(text))


def stamp_structured_affected_assets(
    findings: list[dict[str, Any]],
    *,
    domain_name: str,
    index: AssetIndex | None,
    attack_paths: list[dict[str, Any]] | None = None,
) -> bool:
    """Stamp every finding's ``details[SERIALIZED_KEY]`` with structured entities.

    The single serialization seam between the engine and the platform. Iterates
    the on-disk technical-report findings, computes the typed, correlation-ready
    affected-asset entities for each, and writes them into the finding's
    ``details`` so they ride into ``technical_report.json`` and the web ingests
    them verbatim (the web does NOT import the engine).

    The flat :func:`affected_assets.extract_affected_assets` is invoked WITH the
    correlated ``attack_paths`` so the ADCS templates / CA it resolves from the
    paths are lifted into the structured entities — one resolution path, no
    re-implementation.

    Returns ``True`` when any finding's serialized block changed (so the caller
    knows to persist). Never raises — a single bad finding is skipped.
    """
    from adscan_internal.services.affected_assets import (  # noqa: PLC0415
        _relation_aliases_for_vulnerability,
        extract_affected_assets,
    )

    changed = False
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        key = str(finding.get("key") or "").strip()
        if not key:
            continue
        details = finding.get("details")
        if not isinstance(details, dict):
            details = {}
            finding["details"] = details
        try:
            aliases = _relation_aliases_for_vulnerability(key)
            # Recompute from the finding's OWN data, never from a previously
            # stamped block: the flat extractor prefers the serialized entities
            # when they are present, so feeding them back would make a stale (or
            # wrong) entity self-perpetuating across every re-render.
            source_details = {
                key_name: value
                for key_name, value in details.items()
                if key_name != SERIALIZED_KEY
            }
            flat = extract_affected_assets(
                key,
                source_details,
                domain_name=domain_name,
                attack_paths=attack_paths,
            )
            serialized = serialize_affected_asset_entities(
                key,
                source_details,
                domain_name=domain_name,
                index=index,
                relation_aliases=aliases,
                flat_assets=flat,
            )
        except Exception:  # noqa: BLE001 - one bad finding never breaks the pass
            continue
        if details.get(SERIALIZED_KEY) != serialized:
            if serialized:
                details[SERIALIZED_KEY] = serialized
            elif SERIALIZED_KEY in details:
                del details[SERIALIZED_KEY]
            changed = True
    return changed


def stamp_report_vulnerabilities(
    vulnerabilities: Any,
    *,
    domain_name: str,
    index: AssetIndex | None,
    attack_paths: list[dict[str, Any]] | None = None,
) -> bool:
    """Stamp the typed entities onto an in-memory report's vulnerability map.

    :func:`stamp_workspace_affected_assets` writes the on-disk contract the
    platform ingests. This is its in-memory twin, for the render that is
    happening right now: the report builder loads ``technical_report.json``
    into ``{vuln_key: flattened_details}`` BEFORE the stamp runs, so without
    this the document being written would keep whatever entities the previous
    run left behind — a full render out of date by exactly one report. That is
    how a rebuilt kit could name a certificate template's enrolling groups
    correctly in the machine-readable appendix and by their previous, wrong
    resolution in the PDF prose beside it.

    Returns ``True`` when anything changed. Best-effort; never raises.
    """
    if not isinstance(vulnerabilities, dict) or not vulnerabilities:
        return False
    # The report's flattened detail dict IS the finding's details here, so the
    # adapter holds references and the stamp mutates the render's own data.
    findings = [
        {"key": key, "details": details}
        for key, details in vulnerabilities.items()
        if isinstance(details, dict)
    ]
    if not findings:
        return False
    for finding in findings:
        # The builder caches the FLAT asset list on the entry, and the flat
        # extractor returns that cache ahead of everything else. Its input has
        # just been recomputed, so the cache is stale by definition — leaving it
        # is what let the PDF's asset list and the appendix's disagree about the
        # same finding in the same kit.
        finding["details"].pop("_affected_assets", None)
    return stamp_structured_affected_assets(
        findings, domain_name=domain_name, index=index, attack_paths=attack_paths
    )


def stamp_workspace_affected_assets(
    workspace_dir: str | Path,
    domain_name: str,
    *,
    attack_paths: list[dict[str, Any]] | None = None,
    index: AssetIndex | None = None,
) -> bool:
    """Resolve and persist one domain's affected assets in ``technical_report.json``.

    The single workspace-level seam both report tiers call, so the free exposure
    report and the paid deliverable kit name the same objects for the same
    finding. It resolves the workspace's asset index once, stamps every finding
    of ``domain_name`` in place, and writes the report back only when something
    changed.

    Persisting rather than resolving per render is deliberate: the structured
    entities are the engine-to-platform contract the web ingests verbatim, so a
    scan whose report was rendered by either tier carries them on disk.

    Args:
        workspace_dir: Workspace root (container path).
        domain_name: The domain whose findings are stamped.
        attack_paths: That domain's computed attack paths, so ADCS templates and
            CAs resolved from a path reach the entities too. ``None`` when the
            caller has not computed them.
        index: A pre-built asset index, when the caller already has one (a
            report render stamps the file and its own in-memory copy from the
            same index rather than parsing the graph twice).

    Returns:
        ``True`` when at least one finding's entities changed and the report was
        rewritten. Best-effort: never raises.
    """
    try:
        from types import SimpleNamespace  # noqa: PLC0415

        from adscan_core.reporting.technical_report import (  # noqa: PLC0415
            _load_technical_report,
            _save_technical_report,
        )

        shell = SimpleNamespace(current_workspace_dir=str(workspace_dir))
        report = _load_technical_report(shell)
        domains = report.get("domains") if isinstance(report, dict) else {}
        entry = domains.get(domain_name) if isinstance(domains, dict) else None
        if not isinstance(entry, dict):
            return False
        findings = entry.get("findings")
        if not isinstance(findings, list) or not findings:
            return False
        if stamp_structured_affected_assets(
            findings,
            domain_name=domain_name,
            index=index if index is not None else load_asset_index(
                workspace_dir, domain_name
            ),
            attack_paths=attack_paths,
        ):
            _save_technical_report(shell, report)
            return True
        return False
    except Exception:  # noqa: BLE001 - a report must never break on enrichment
        return False
