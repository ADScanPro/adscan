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
      "display":    <human label>,       # "meereen.essos.local (192.168.180.12)"
      "role":       "source" | "target" | "affected",
      "sid":        <SID if known>,
      "ip":         <IP if a host and known>,
      "fqdn":       <FQDN if a host and known>,
      "upn":        <UPN if a user and known>,
      "node_id":    <attack-graph node id if resolvable>,
    }

Host entities ALWAYS carry both IP and FQDN when the inventory resolves them,
rendered in canonical lower case for the client deliverable (a DNS host name is
case-insensitive; the CLI keeps the technical casing): ``meereen.essos.local
(192.168.180.12)``.

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

from adscan_core.reporting.tier_basis import describe_tier_basis

from adscan_internal.services.affected_asset_rules import (
    Extra,
    Representation,
    Scope,
    TargetMode,
    extract_adcs_ca_names,
    rule_for,
)
from adscan_internal.services.attack_relation_labels import business_relation_phrase
from adscan_internal.services.compromise_class import (
    PrivilegeTier,
    node_stamped_privilege_tier,
    privilege_tier_label,
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
from adscan_internal.services.well_known_principals import (
    deshout_display_label,
    humanize_principal_for_prose,
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
# A pre-authentication ACCESS VECTOR (e.g. a null/guest session that reached the
# affected file with no credential). Not a directory principal — it is how the
# exposure was reached, surfaced as an affected asset so the client remediates
# the null-session gate, not a non-existent Anonymous ACE.
TYPE_ACCESS_VECTOR = "access_vector"

ROLE_SOURCE = "source"
ROLE_TARGET = "target"
ROLE_AFFECTED = "affected"

# --------------------------------------------------------------------------- #
# Per-account crack status (roasting findings)                                 #
# --------------------------------------------------------------------------- #

# The three HONEST per-account outcomes of a roasting finding (Exposure
# Validation): a roastable account ADscan actually CRACKED, one it ATTEMPTED but
# did not recover, and one merely EXPOSED (roastable, never attempted). Derived
# from the account's attack-graph edge STEP status, never guessed.
CRACK_STATUS_CRACKED = "cracked"
CRACK_STATUS_ATTEMPTED = "attempted"
CRACK_STATUS_EXPOSED = "exposed"

# STEP-status tokens that prove the account's secret was recovered / was tried.
# Mirrors the step-status vocabulary (success/succeeded == proven; failed/error
# == attempted) — never a bare literal at a call site.
_CRACKED_STEP_STATUSES = frozenset({"success", "succeeded"})
_ATTEMPTED_STEP_STATUSES = frozenset({"attempted", "failed", "error"})

# CRACKED leads, then attempted, then merely exposed — the proven recovery first.
_CRACK_STATUS_SORT_RANK: dict[str, int] = {
    CRACK_STATUS_CRACKED: 0,
    CRACK_STATUS_ATTEMPTED: 1,
    CRACK_STATUS_EXPOSED: 2,
}

# The roasting finding family. A roasting finding surfaces its roastable
# accounts (the CRACKED one included — it is the most valuable result, never
# dropped as a domain breaker) each with a per-account ``crack_status`` badge.
ROASTING_FINDING_KEYS = frozenset({"kerberoast", "asreproast", "timeroast"})

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
    # Axis 1 — the privilege TIER this object is GRANTED, read from the STAMPED
    # ``privilege_tier`` on its graph node (membership + ACL aware), never raw
    # ``isTierZero``. ``tier`` is the machine value (``tier0_direct`` …);
    # ``tier_label`` is the client-facing legend label. Both ``None`` when the
    # object carries no stamp (an older graph) or does not resolve to a node.
    tier: str | None = None
    tier_label: str | None = None
    # Axis-1 CONFIDENCE for the tier verdict and its client-safe reason, translated
    # once at the authoring boundary (``adscan_core.reporting.tier_basis``) from the
    # stamped machine ``privilege_tier_basis``. ``tier_confidence`` is
    # ``deterministic`` (read from the directory) or ``inferred`` (a server-role /
    # admin heuristic the client can correct); ``tier_basis`` is the ready-to-render
    # qualified phrase (``inferred: member server by operating-system role``). Both
    # ``None`` when the verdict carries no meaningful basis (a plain Tier 2). No
    # internal signal name ever reaches a client here.
    tier_confidence: str | None = None
    tier_basis: str | None = None
    # The finding-specific CLIENT role LABEL for this asset (``holder``,
    # ``roastable-target``, ``session-host``, ``delegating-account``, …), from
    # the finding's :class:`AssetRule.role_labels`. ``None`` when the generic
    # ``role`` axis is label enough.
    role_label: str | None = None
    # For a PAIRING finding (HasSession, ForceChangePassword, shadow-creds, LAPS,
    # gMSA, RBCD, NTLMv1-relay): the stable id of the per-edge pair this asset
    # belongs to, so the renderer can show who-can-do-what-to-whom
    # (``user @ host``) instead of two unrelated flat lists. ``None`` for a
    # non-paired asset.
    pairing_id: str | None = None
    # For a PAIRING finding whose edges carry DIFFERENT relations (the grouped
    # "Excessive Rights Across a Tier Boundary" finding), the client-safe business
    # phrase of THIS pair's right (``Full Control of the Target Object``,
    # ``Reset the Account Password``, …), so the renderer can show
    # ``holder -> <right> -> object`` instead of a bare arrow. ``None`` for a
    # single-relation PAIRING finding and every non-paired asset.
    pair_relation: str | None = None
    # The CONCRETE measured value for this asset in a staleness / age / obsolete
    # family finding, so the client sees the real figure (not a vague "older than
    # N days"): the ``pwdLastSet`` / ``lastLogonTimestamp`` date + age for the
    # staleness findings (``Last rotated 2017-05-23 (~3,409 days ago)``), or the
    # concrete operating-system string for an obsolete-OS finding (``Windows
    # Server 2003``). Derived from the asset's STAMPED graph-node property at
    # resolution time (``pwdlastset`` / ``lastlogon`` / ``os``); ``None`` for a
    # non-staleness finding or when the node carries no such property.
    metric: str | None = None
    # For a ROASTING finding (kerberoast / asreproast / timeroast): the honest
    # per-account outcome — ``cracked`` (the account's hash was recovered),
    # ``attempted`` (tried, not recovered) or ``exposed`` (roastable, never
    # attempted) — derived from the account's attack-graph edge STEP status.
    # ``None`` for every non-roasting asset.
    crack_status: str | None = None

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
        if self.tier:
            payload["tier"] = self.tier
        if self.tier_label:
            payload["tier_label"] = self.tier_label
        if self.tier_confidence:
            payload["tier_confidence"] = self.tier_confidence
        if self.tier_basis:
            payload["tier_basis"] = self.tier_basis
        if self.role_label:
            payload["role_label"] = self.role_label
        if self.pairing_id:
            payload["pairing_id"] = self.pairing_id
        if self.pair_relation:
            payload["pair_relation"] = self.pair_relation
        if self.metric:
            payload["metric"] = self.metric
        if self.crack_status:
            payload["crack_status"] = self.crack_status
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
    # The STAMPED ``privilege_tier`` value (``tier0_direct`` …) read off the node
    # at index-build time, never raw ``isTierZero``. Empty when the node carries
    # no stamp.
    tier: str = ""
    # The STAMPED ``privilege_tier_basis`` value (``app_spn`` / ``tier0_group`` …)
    # recording WHICH signal produced the tier verdict (axis-1 confidence). Empty
    # when the node carries no basis (an older graph, or a deterministic Tier-0
    # from the DC fast-path). Translated to a client-safe phrase at entity build.
    tier_basis: str = ""
    # Measured staleness/age/OS source properties, read off the node at
    # index-build time for the per-asset ``metric`` of a staleness-family finding.
    # ``pwdlastset`` / ``lastlogon`` are Windows FILETIME integers (``None`` when
    # absent); ``os`` is the operating-system string (empty when absent).
    pwdlastset: int | None = None
    lastlogon: int | None = None
    os: str = ""


@dataclass
class _ResolvedTemplate:
    """A certificate template resolved from a ``CertTemplate`` graph node.

    A template has TWO names that both reach a finding: the localized
    ``displayName`` (the node ``label`` / ``properties.name`` — what the admin
    sees, e.g. Italian ``CONTROLLER DI DOMINIO``) and the English ``cn`` (a real
    directory attribute used inside a remediation DN, e.g. ``DomainController``).
    Resolving either to the SAME node is what lets the builder collapse the
    "same template under two names" duplicate and always display the localized
    name (per the original-language rule), while keeping the CN for commands.
    """

    object_id: str = ""
    label: str = ""  # localized displayName, realm stripped (raw case)
    cn: str = ""


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
    _templates_by_token: dict[str, _ResolvedTemplate] = field(default_factory=dict)

    def _register_template(self, template: _ResolvedTemplate) -> None:
        """Index a certificate template under every spelling that names it."""
        tokens: set[str] = set()
        for raw in (template.object_id, template.label, template.cn):
            token = _norm_key(raw)
            if token:
                tokens.add(token)
                tokens.add(_strip_realm(token))
        for token in tokens:
            self._templates_by_token.setdefault(token, template)

    def lookup_template(self, *candidates: Any) -> _ResolvedTemplate | None:
        """Return the template a name/objectId/CN/displayName resolves to."""
        for candidate in candidates:
            token = _norm_key(candidate)
            if not token:
                continue
            template = self._templates_by_token.get(
                token
            ) or self._templates_by_token.get(_strip_realm(token))
            if template is not None:
                return template
        return None

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
            node = self._by_token.get(token) or self._by_token.get(_strip_realm(token))
            if node is not None:
                return node
        return None


def _coerce_filetime(value: Any) -> int | None:
    """Return a Windows FILETIME integer from a node property, else ``None``.

    The collector stamps ``pwdlastset`` / ``lastlogon`` as integers, but an older
    graph (or a JSON round-trip) can carry a numeric string. Anything that is not
    a positive integer-like value resolves to ``None`` so the metric degrades
    cleanly to absent rather than raising.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            parsed = int(text)
            return parsed if parsed > 0 else None
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
        # Certificate templates are indexed on a SEPARATE axis so an ADCS finding
        # that names a template by its localized displayName (edge target) and by
        # its English CN (flat extractor) resolves both to one template — the
        # dedup key for the "same template under two names" bug.
        if kind in ("certtemplate", "cert_template"):
            props = _node_props(node)
            index._register_template(
                _ResolvedTemplate(
                    object_id=str(node.get("objectId") or node.get("id") or "").strip(),
                    label=_strip_realm(
                        str(
                            node.get("label")
                            or props.get("name")
                            or props.get("displayname")
                            or ""
                        ).strip()
                    ),
                    cn=str(props.get("cn") or "").strip(),
                )
            )
            continue
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
        # The STAMPED, membership + ACL aware privilege tier — the SSOT reader,
        # never raw ``isTierZero`` (which diverges: it is the pre-graph collector
        # flag and reads False on a stamp-graded Tier-0). ``None`` -> "".
        stamped = node_stamped_privilege_tier(node)
        tier = stamped.value if stamped is not None else ""
        tier_basis = str(props.get("privilege_tier_basis") or "").strip()
        pwdlastset = _coerce_filetime(props.get("pwdlastset"))
        lastlogon = _coerce_filetime(props.get("lastlogon"))
        if kind == "computer":
            resolved = _ResolvedNode(
                kind=TYPE_COMPUTER,
                samaccountname=sam,
                name=str(props.get("name") or node.get("label") or "").strip(),
                fqdn=str(props.get("dnshostname") or "").strip(),
                ip=str(props.get("ip_address") or "").strip(),
                sid=sid,
                node_id=node_id,
                tier=tier,
                tier_basis=tier_basis,
                pwdlastset=pwdlastset,
                lastlogon=lastlogon,
                # The operating-system string lives under ``os`` on the graph node
                # (the collector stamps ``operatingSystem`` there); accept the raw
                # ``operatingsystem`` alias too for an older graph.
                os=str(props.get("os") or props.get("operatingsystem") or "").strip(),
            )
            index._register(resolved, is_dc=_is_dc_node(node, props))
        else:
            resolved = _ResolvedNode(
                kind=TYPE_GROUP if kind == "group" else TYPE_USER,
                samaccountname=sam,
                name=str(props.get("name") or node.get("label") or "").strip(),
                sid=sid,
                upn=str(
                    props.get("upn") or props.get("userprincipalname") or ""
                ).strip(),
                node_id=node_id,
                tier=tier,
                tier_basis=tier_basis,
                pwdlastset=pwdlastset,
                lastlogon=lastlogon,
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
        graph_path = Path(workspace_dir) / "domains" / str(domain) / "attack_graph.json"
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

    Format: ``meereen.essos.local (192.168.180.12)``. AD / DNS host names are
    case-INSENSITIVE, so a host renders in the canonical LOWER case — the same
    casing the attack-path diagram, the domain block and the rest of the report
    use — instead of the graph's SHOUTING label. This closes the cross-surface
    inconsistency where the findings / appendix shouted ``DC.ACTIVE.HTB`` while
    every other surface read ``dc.active.htb`` (reverses the earlier uppercase
    rule; client-facing display only, the CLI is untouched). Falls back gracefully
    when only one identifier is available, and to ``fallback`` (the bare account
    name) when neither resolves.
    """
    # Lower-case the FQDN only (a case-insensitive DNS name); a bare fallback
    # machine-account name (``CASTELBLACK$``) is a principal, not a domain/FQDN,
    # so its casing is out of scope here and left as stored.
    name = (fqdn or "").strip().lower() or (fallback or "").strip()
    ip = (ip or "").strip()
    if name and ip:
        return f"{name} ({ip})"
    if name:
        return name
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


def _tier_fields(tier_value: str) -> tuple[str | None, str | None]:
    """Return ``(tier, tier_label)`` for a stamped privilege-tier value.

    ``tier_value`` is the machine value stored on the resolved node
    (``tier0_direct`` …). Returns ``(None, None)`` for an empty / unrecognised
    value so an unstamped asset carries no tier badge rather than a wrong one.
    """
    value = str(tier_value or "").strip().lower()
    if not value:
        return None, None
    try:
        tier = PrivilegeTier(value)
    except ValueError:
        return None, None
    return tier.value, privilege_tier_label(tier)


def _tier_basis_fields(node: _ResolvedNode | None) -> tuple[str | None, str | None]:
    """Return ``(tier_confidence, tier_basis_phrase)`` for a resolved node.

    Translates the node's stamped ``privilege_tier_basis`` into the client-facing
    confidence (``deterministic`` / ``inferred``) and the ready-to-render qualified
    phrase (``inferred: member server by operating-system role``) via the one
    SSOT. ``(None, None)`` for an unstamped / plain-Tier-2 node so it carries no
    basis badge rather than a wrong one.
    """
    if node is None:
        return None, None
    display = describe_tier_basis(node.tier_basis or None, node.tier or None)
    return display.confidence if display.qualified else None, display.qualified


# --------------------------------------------------------------------------- #
# Per-asset measured value (metric) for the staleness / age / obsolete family  #
# --------------------------------------------------------------------------- #

# Metric SOURCE kinds — which stamped node property the metric is derived from.
_METRIC_PWD_DATE = "pwd_date"  # pwdlastset FILETIME -> date + age
_METRIC_LOGON_DATE = "logon_date"  # lastlogon FILETIME -> date + age
_METRIC_OS = "os"  # the concrete operating-system string

# Finding key -> (metric source kind, client-facing lead label). Covers the
# staleness / age / obsolete-OS family; every other finding resolves to no metric
# so its assets render exactly as before. Both the canonical report keys and the
# detector/category aliases are listed so the map hits whichever spelling the
# finding carries.
_STALENESS_METRIC: dict[str, tuple[str, str]] = {
    # krbtgt rotation — the single most consequential staleness value.
    "krbtgt_password_age": (_METRIC_PWD_DATE, "Last rotated"),
    "krbtgt_age": (_METRIC_PWD_DATE, "Last rotated"),
    # Per-account password age.
    "stale_passwords": (_METRIC_PWD_DATE, "Password set"),
    "pwd_predates_policy": (_METRIC_PWD_DATE, "Password set"),
    # Machine-account password rotation — the machine's own pwdLastSet.
    "machine_password_rotation_disabled": (_METRIC_PWD_DATE, "Machine password set"),
    "machine_password_rotation_relaxed": (_METRIC_PWD_DATE, "Machine password set"),
    # Stale accounts / computers — keyed off real authentication activity.
    "stale_enabled_users": (_METRIC_LOGON_DATE, "Last logon"),
    "stale_user": (_METRIC_LOGON_DATE, "Last logon"),
    "stale_enabled_computers": (_METRIC_LOGON_DATE, "Last logon"),
    "stale_computer": (_METRIC_LOGON_DATE, "Last logon"),
    # Obsolete operating system — the concrete OS string per host.
    "obsolete_computers": (_METRIC_OS, ""),
    "obsolete_os": (_METRIC_OS, ""),
}


def metric_kind_for_finding(finding_key: str) -> tuple[str, str]:
    """Return ``(metric_source_kind, lead_label)`` for a staleness-family key.

    ``("", "")`` for any finding that carries no per-asset measured value, so a
    non-staleness finding's assets never gain a metric.
    """
    return _STALENESS_METRIC.get(str(finding_key or "").strip().lower(), ("", ""))


# Windows FILETIME -> Unix epoch conversion (the same constants the collector
# duplicates in ``audit_analyzer`` / ``graph_queries.filters``). Inlined here so
# this reporting module keeps a minimal import closure (it is bundled into the
# appliance backend, which must NOT reach the collector / engine stack).
_FILETIME_EPOCH_OFFSET = 116_444_736_000_000_000
_100NS_PER_SECOND = 10_000_000
# The Windows "never set" / "never expires" sentinels seen on pwdLastSet /
# lastLogon so a sentinel never renders as a bogus date.
_FILETIME_NEVER_SENTINEL = 0x7FFFFFFFFFFFFFFF


def _filetime_to_datetime(filetime: int) -> "Any":
    """Return a UTC ``datetime`` for a Windows FILETIME, or ``None`` on a sentinel."""
    from datetime import datetime, timezone  # noqa: PLC0415

    if filetime <= 0 or filetime == _FILETIME_NEVER_SENTINEL:
        return None
    unix_seconds = (filetime - _FILETIME_EPOCH_OFFSET) / _100NS_PER_SECOND
    if unix_seconds <= 0:
        return None
    return datetime.fromtimestamp(unix_seconds, tz=timezone.utc)


def _format_age_metric(filetime: int | None, label: str) -> str | None:
    """Return ``"<label> YYYY-MM-DD (~N,NNN days ago)"`` for a FILETIME, or ``None``.

    The rendered date is an ABSOLUTE calendar value derived from the FILETIME, so
    ``datetime`` is the correct clock here (not ``monotonic``). Returns ``None``
    for a missing / sentinel FILETIME so the asset simply carries no metric.
    """
    if not filetime:
        return None
    try:
        from datetime import datetime, timezone  # noqa: PLC0415

        moment = _filetime_to_datetime(int(filetime))
        if moment is None:
            return None
        age_days = (datetime.now(tz=timezone.utc) - moment).days
        if age_days < 0:
            age_days = 0
        date_str = moment.strftime("%Y-%m-%d")
        lead = str(label or "").strip()
        day_word = "day" if age_days == 1 else "days"
        age_phrase = f"~{age_days:,} {day_word} ago"
        return f"{lead} {date_str} ({age_phrase})" if lead else f"{date_str} ({age_phrase})"
    except Exception:  # noqa: BLE001 - metric is best-effort, never fatal
        return None


def _metric_for_node(
    node: _ResolvedNode | None, metric_kind: str, metric_label: str
) -> str | None:
    """Return the per-asset measured value for a resolved node, or ``None``.

    The ONE place the staleness metric is derived from a node property, so every
    surface shows the same figure. ``None`` when the node is unresolved or carries
    no value for the requested kind (honest absence, never a fabricated date/OS).
    """
    if node is None or not metric_kind:
        return None
    if metric_kind == _METRIC_OS:
        text = str(node.os or "").strip()
        return deshout_display_label(text) if text else None
    if metric_kind == _METRIC_PWD_DATE:
        return _format_age_metric(node.pwdlastset, metric_label)
    if metric_kind == _METRIC_LOGON_DATE:
        return _format_age_metric(node.lastlogon, metric_label)
    return None


def _entity_for_principal(
    raw: str,
    *,
    role: str,
    index: AssetIndex | None,
    sid_hint: str = "",
    forced_type: str = "",
    qualifier: str = "",
    domain_hint: str = "",
    role_label: str = "",
    pairing_id: str = "",
    pair_relation: str = "",
    metric_kind: str = "",
    metric_label: str = "",
) -> AffectedAssetEntity | None:
    """Resolve one principal token into a typed :class:`AffectedAssetEntity`.

    ``forced_type`` overrides the principal resolution for records that are not
    principals at all (a trust's partner domain). ``qualifier`` names the part of
    the record that is affected and is appended to the display. ``domain_hint``
    lets an unresolved FQDN be recognised as a host of that domain. ``role_label``
    carries the finding-specific client role label; ``pairing_id`` links the
    asset to its per-edge pair for a PAIRING finding. The asset's privilege
    ``tier`` is read from the resolved node's STAMPED tier (never ``isTierZero``).
    """
    text = str(raw or "").strip()
    if not text or _norm_key(text) in _PLACEHOLDER_TOKENS:
        return None

    role_label = role_label or None
    pairing_id = pairing_id or None
    pair_relation = pair_relation or None

    if forced_type == TYPE_DOMAIN:
        return _qualified_entity(
            _domain_entity(text, role_label=role_label, pairing_id=pairing_id),
            qualifier,
        )

    node = index.lookup(text, sid_hint) if index is not None else None
    tier, tier_label = _tier_fields(node.tier if node else "")
    tier_confidence, tier_basis = _tier_basis_fields(node)
    # The per-asset measured value for a staleness/age/obsolete-OS finding, read
    # from the resolved node's stamped property (``pwdlastset`` / ``lastlogon`` /
    # ``os``). ``None`` for every other finding, so non-staleness assets are
    # byte-identical to before.
    metric = _metric_for_node(node, metric_kind, metric_label)

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
                tier=tier,
                tier_label=tier_label,
                tier_confidence=tier_confidence,
                tier_basis=tier_basis,
                role_label=role_label,
                pairing_id=pairing_id,
                pair_relation=pair_relation,
                metric=metric,
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
    is_group = node is not None and node.kind == TYPE_GROUP
    # The DISPLAY is client-facing (web CTEM + the flat report), so name the
    # principal the way the prose humanizer SSOT does — an all-caps user sam
    # de-shouts (``SVC_TGS`` -> ``svc_tgs``), a well-known identity renders
    # canonical (``Everyone`` / ``Users``). The IDENTIFIER stays the raw sam so
    # correlation/joins are unchanged.
    display = (
        humanize_principal_for_prose(
            label=sam, samaccountname=sam, kind=TYPE_GROUP if is_group else TYPE_USER
        )
        or sam
    )
    if upn:
        display = f"{display} ({upn})"
    return _qualified_entity(
        AffectedAssetEntity(
            type=TYPE_GROUP if is_group else TYPE_USER,
            identifier=sam,
            display=display,
            role=role,
            sid=sid or None,
            upn=upn or None,
            node_id=(node.node_id if node else None) or None,
            tier=tier,
            tier_label=tier_label,
            tier_confidence=tier_confidence,
            tier_basis=tier_basis,
            role_label=role_label,
            pairing_id=pairing_id,
            pair_relation=pair_relation,
            metric=metric,
        ),
        qualifier,
    )


def _domain_entity(
    domain: str, *, role_label: str | None = None, pairing_id: str | None = None
) -> AffectedAssetEntity:
    name = str(domain or "").strip()
    return AffectedAssetEntity(
        type=TYPE_DOMAIN,
        identifier=name,
        display=name,
        role=ROLE_AFFECTED,
        role_label=role_label or None,
        pairing_id=pairing_id or None,
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


def _edge_pairs(
    details: Mapping[str, Any],
    relation_aliases: set[str],
) -> list[tuple[list[str], list[str], str]]:
    """Return per-edge ``(sources, targets, relation)`` tuples from matching edges.

    PAIRING findings (HasSession, ForceChangePassword, shadow-creds, LAPS, gMSA,
    RBCD, NTLMv1-relay) must preserve WHO can do WHAT to WHOM — so the builder
    keeps each edge's source(s) and target(s) together (one pair per edge) rather
    than flattening them into two unrelated lists. Breaker targets are dropped on
    the same rule as :func:`_edge_principals`, so the two stay consistent.

    The RAW edge relation travels with each pair so a grouped multi-relation
    finding (``excessive_cross_tier_rights``) can surface the specific right per
    pair; single-relation PAIRING findings ignore it.
    """
    edges = details.get("attack_graph_edges")
    if not isinstance(edges, list):
        return []
    pairs: list[tuple[list[str], list[str], str]] = []
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        relation = _norm_key(edge.get("relation")).replace(" ", "")
        if relation_aliases and relation and relation not in relation_aliases:
            continue
        srcs = _extract_strings(edge.get("source")) + _extract_strings(edge.get("from"))
        tgts = [
            value
            for value in (
                _extract_strings(edge.get("target")) + _extract_strings(edge.get("to"))
            )
            if not _is_direct_domain_breaker_asset(value)
        ]
        if srcs or tgts:
            pairs.append((srcs, tgts, str(edge.get("relation") or "")))
    return pairs


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
    seen: set[tuple[str, str, str, str]] = set()
    for entity in entities:
        # ``pairing_id`` is part of the key so a host that holds TWO sessions
        # (one edge pair each) keeps a copy per pair — collapsing them would lose
        # the per-pair "user @ host" linkage. A non-paired asset has pairing_id
        # ``None`` and dedupes exactly as before.
        key = (
            entity.type,
            _norm_key(entity.identifier),
            entity.role,
            entity.pairing_id or "",
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(entity)
    return out


def _resolve_template_fields(
    name: str, index: AssetIndex | None
) -> tuple[str, str, str]:
    """Return ``(identifier, display, node_id)`` for a certificate template name.

    A template reaches a finding under either of two names: its localized
    ``displayName`` (the edge target / template node label) or its English ``cn``
    (what the flat extractor resolves from the path). Both are looked up against
    the template index so either resolves to the SAME template, which is what
    lets the two be collapsed into one entity. The DISPLAY is always the LOCALIZED
    displayName (de-shouted, never anglicized); the IDENTIFIER is the CN when
    known (the real attribute a remediation DN references), so two genuinely
    distinct templates keep distinct identifiers and never collapse.
    """
    bare = _strip_realm(str(name or "").strip())
    template = index.lookup_template(name, bare) if index is not None else None
    if template is not None:
        localized = template.label or bare
        return (
            template.cn or localized,
            deshout_display_label(localized),
            template.object_id,
        )
    return bare or str(name or "").strip(), deshout_display_label(bare), ""


# --------------------------------------------------------------------------- #
# Roasting crack-status                                                         #
# --------------------------------------------------------------------------- #


def crack_status_from_step_status(status: Any) -> str:
    """Map an attack-graph edge STEP status to a per-account crack status.

    Exposure-Validation honest, three states: a proven recovery
    (``success``/``succeeded``) → :data:`CRACK_STATUS_CRACKED`; a tried-but-failed
    pass (``attempted``/``failed``/``error``) → :data:`CRACK_STATUS_ATTEMPTED`;
    anything else (``discovered``/``theoretical``/empty) → :data:`CRACK_STATUS_EXPOSED`
    — roastable, never attempted. Never a bare literal: keyed on the step-status
    token SSOTs above.
    """
    token = str(status or "").strip().lower()
    if token in _CRACKED_STEP_STATUSES:
        return CRACK_STATUS_CRACKED
    if token in _ATTEMPTED_STEP_STATUSES:
        return CRACK_STATUS_ATTEMPTED
    return CRACK_STATUS_EXPOSED


def _max_crack_status(current: str, candidate: str) -> str:
    """Return the more-advanced of two crack statuses (CRACKED > attempted > exposed).

    One account can arrive on several edges (a ``discovered`` roastable edge AND a
    later ``success`` crack edge); the account's badge is the strongest proof seen.
    """
    rank_current = _CRACK_STATUS_SORT_RANK.get(current, 99)
    rank_candidate = _CRACK_STATUS_SORT_RANK.get(candidate, 99)
    return current if rank_current <= rank_candidate else candidate


def _roasting_affected_entities(
    view: Mapping[str, Any],
    *,
    aliases: set[str],
    index: AssetIndex | None,
    domain_hint: str,
    target_label: str | None,
    rule: Any,
) -> list[AffectedAssetEntity]:
    """Return the roastable-account entities of a roasting finding, CRACKED first.

    Unlike the generic target overlay, a roasting finding KEEPS a direct
    domain-breaker target (``administrator``, RID 500): the account whose ticket
    was CRACKED is the single most valuable result and must be surfaced, not
    dropped as "where the escalation lands". Each account carries a per-account
    :attr:`AffectedAssetEntity.crack_status` derived from its edge STEP status,
    and the accounts are ordered CRACKED → attempted → exposed so the proven
    recovery leads.

    Accounts are read from the finding's attack-graph edges (the per-account STEP
    status lives on the edge), then the flat ``to``/``target`` detail keys and any
    per-principal account records as EXPOSED fallbacks. The same account on two
    edges collapses to one entity carrying its strongest crack status.
    """
    best_status: dict[str, str] = {}
    first_name: dict[str, str] = {}
    order: list[str] = []

    def _consider(name: Any, status_token: Any) -> None:
        text = str(name or "").strip()
        if not text or _norm_key(text) in _PLACEHOLDER_TOKENS:
            return
        crack = crack_status_from_step_status(status_token)
        key = _norm_key(_strip_realm(text))
        if not key:
            return
        if key not in best_status:
            best_status[key] = crack
            first_name[key] = text
            order.append(key)
        else:
            best_status[key] = _max_crack_status(best_status[key], crack)

    edges = view.get("attack_graph_edges")
    if isinstance(edges, list):
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            relation = _norm_key(edge.get("relation")).replace(" ", "")
            if aliases and relation and relation not in aliases:
                continue
            status_token = edge.get("status")
            for value in _extract_strings(edge.get("target")) + _extract_strings(
                edge.get("to")
            ):
                _consider(value, status_token)

    # Flat detail keys + per-principal account records — roastable accounts a
    # detector recorded without an edge carry no per-account status, so they
    # default to EXPOSED unless an edge already proved a stronger outcome.
    for value in _target_principals(view, drop_breaker=False):
        _consider(value, "")
    for name, _sid, _qualifier in iter_account_records(view, rule=rule):
        _consider(name, "")

    entities: list[AffectedAssetEntity] = []
    for key in order:
        entity = _entity_for_principal(
            first_name[key],
            role=ROLE_TARGET,
            index=index,
            domain_hint=domain_hint,
            role_label=target_label,
        )
        if entity is not None:
            entities.append(replace(entity, crack_status=best_status[key]))
    entities.sort(
        key=lambda item: _CRACK_STATUS_SORT_RANK.get(item.crack_status or "", 99)
    )
    return entities


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
    rep = rule.representation
    aliases = relation_aliases or set()
    entities: list[AffectedAssetEntity] = []
    domain_hint = str(domain_name or (index.domain if index is not None else "") or "")

    # Finding-specific client role labels (``holder`` / ``roastable-target`` …).
    affected_label = rule.role_label_for(ROLE_AFFECTED)
    source_label = rule.role_label_for(ROLE_SOURCE)
    target_label = rule.role_label_for(ROLE_TARGET)

    # ---- Roasting: roastable accounts, breakers KEPT, per-account crack status
    # A roasting finding (kerberoast / asreproast / timeroast) owns its own entity
    # list: it must INCLUDE the cracked account (``administrator``, a direct domain
    # breaker the generic target overlay would drop) and stamp a per-account
    # ``crack_status`` from each account's edge STEP status. CRACKED first.
    if finding_key in ROASTING_FINDING_KEYS:
        return _dedupe(
            _roasting_affected_entities(
                view,
                aliases=aliases,
                index=index,
                domain_hint=domain_hint,
                target_label=target_label,
                rule=rule,
            )
        )

    # Per-asset measured value (staleness/age/obsolete-OS family). Resolved once
    # from the finding key; ``("", "")`` for every other finding, so its assets
    # carry no metric. Only the AFFECTED record loops below (the staleness
    # findings are record-based / HOST_SCOPED or PER_PRINCIPAL) pass it through.
    metric_kind, metric_label = metric_kind_for_finding(finding_key)

    # ---- Scope-driven isolated-vulnerability entities -----------------------
    if rule.scope is Scope.DOMAIN_WIDE:
        if domain_name:
            entities.append(_domain_entity(domain_name, role_label=affected_label))
    elif rule.scope is Scope.DC_SCOPED:
        # The DC answered for the control. Resolve the domain's DC host(s) to
        # IP + FQDN; fall back to the domain object when no DC resolves.
        dc_nodes = list(index.dc_nodes) if index is not None else []
        for node in dc_nodes:
            tier, tier_label = _tier_fields(node.tier)
            tier_confidence, tier_basis = _tier_basis_fields(node)
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
                    tier=tier,
                    tier_label=tier_label,
                    tier_confidence=tier_confidence,
                    tier_basis=tier_basis,
                    role_label=affected_label or None,
                )
            )
        if not entities and domain_name:
            entities.append(_domain_entity(domain_name, role_label=affected_label))
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
                role_label=affected_label,
                metric_kind=metric_kind,
                metric_label=metric_label,
            )
            if entity is not None:
                entities.append(entity)
        if not entities and domain_name:
            # A host-scoped finding that persisted no concrete host still names
            # the domain so the platform shows something, never "no assets".
            entities.append(_domain_entity(domain_name, role_label=affected_label))

    # ---- Per-principal record list (coercion host lists, etc.) --------------
    # A per-principal finding may carry its own record list — the coercion probes
    # record the hosts that answered while the same finding can arrive from an
    # attack-graph edge. The flat extractor reads those records whatever the
    # scope, so reading them here too keeps the PDF and the platform aligned.
    if rule.scope is Scope.PER_PRINCIPAL:
        for name, sid, qualifier in iter_account_records(view, rule=rule):
            entity = _entity_for_principal(
                name,
                role=ROLE_AFFECTED,
                index=index,
                sid_hint=sid,
                forced_type=rule.record_entity_type,
                qualifier=qualifier,
                domain_hint=domain_hint,
                role_label=affected_label,
                metric_kind=metric_kind,
                metric_label=metric_label,
            )
            if entity is not None:
                entities.append(entity)

    # ---- Representation-driven SOURCE / TARGET principals -------------------
    # The declarative :class:`Representation` decides whether this finding
    # surfaces its source principal(s), its target object(s), or both, and
    # whether per-edge pairs are preserved — decoupled from the legacy read-modes
    # (which still drive the flat extractor). For ADCS the edge/detail TARGET is
    # the abused template, surfaced as a typed TEMPLATE entity, so target-
    # principal extraction is suppressed to avoid a template leaking in as a user.
    is_adcs = Extra.TEMPLATES in rule.extras
    # Targets are represented by the scope base for an isolated finding (the
    # domain for DCSync, the host list for a posture finding), so the target
    # overlay reads to/target keys only for PER_PRINCIPAL findings.
    wants_target_overlay = (
        rep.wants_target and rule.scope is Scope.PER_PRINCIPAL and not is_adcs
    )
    drop_breaker = rule.target is TargetMode.DROP_BREAKER

    pairs_emitted = False
    if rep is Representation.PAIRING:
        # Preserve who-can-do-what-to-whom: each edge becomes one pair sharing a
        # ``pairing_id``, so the renderer can show ``user @ host`` instead of two
        # flat lists. The edges ARE the representation here, so the flat detail-key
        # reads below only fire as a fallback when no edge pair was found.
        for pair_index, (pair_sources, pair_targets, pair_rel) in enumerate(
            _edge_pairs(view, aliases)
        ):
            pairing_id = f"pair-{pair_index}"
            # For a grouped multi-relation finding, carry the specific right of
            # THIS pair (its client-safe business phrase) so the renderer shows
            # ``holder -> <right> -> object``. Single-relation PAIRING findings
            # leave it blank and keep the plain arrow.
            pair_relation = (
                business_relation_phrase(pair_rel)
                if rule.show_relation_in_pairing and pair_rel
                else ""
            )
            for name in pair_sources:
                entity = _entity_for_principal(
                    name,
                    role=ROLE_SOURCE,
                    index=index,
                    domain_hint=domain_hint,
                    role_label=source_label,
                    pairing_id=pairing_id,
                    pair_relation=pair_relation,
                )
                if entity is not None:
                    entities.append(entity)
                    pairs_emitted = True
            if not is_adcs:
                for name in pair_targets:
                    entity = _entity_for_principal(
                        name,
                        role=ROLE_TARGET,
                        index=index,
                        domain_hint=domain_hint,
                        role_label=target_label,
                        pairing_id=pairing_id,
                        pair_relation=pair_relation,
                    )
                    if entity is not None:
                        entities.append(entity)
                        pairs_emitted = True

    # Flat (unpaired) source/target reads — for BOTH / SOURCE_ONLY / TARGET_ONLY,
    # and the detail-key fallback for a PAIRING finding that carried no edges. For
    # PAIRING the attack-graph edges are consumed as pairs above, so they are NOT
    # re-read flat here (that would duplicate the paired entity without its pair).
    if rep is not Representation.PAIRING or not pairs_emitted:
        include_edges = rep is not Representation.PAIRING
        sources: list[str] = []
        targets: list[str] = []
        if rep.wants_source:
            sources.extend(_source_principals(view))
            if include_edges:
                edge_sources, _ = _edge_principals(view, aliases)
                sources.extend(edge_sources)
        if wants_target_overlay:
            targets.extend(_target_principals(view, drop_breaker=drop_breaker))
            if include_edges:
                _, edge_targets = _edge_principals(view, aliases)
                targets.extend(edge_targets)

        for name in sources:
            entity = _entity_for_principal(
                name,
                role=ROLE_SOURCE,
                index=index,
                domain_hint=domain_hint,
                role_label=source_label,
            )
            if entity is not None:
                entities.append(entity)
        for name in targets:
            entity = _entity_for_principal(
                name,
                role=ROLE_TARGET,
                index=index,
                domain_hint=domain_hint,
                role_label=target_label,
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
        template_label = rule.role_label_for("template") or None
        for template in template_names:
            # Resolve the template to ONE identity (objectId + CN + localized
            # displayName), so the same template referenced here by its localized
            # label and by the flat extractor's English CN collapses to one entity.
            # Display is the localized name (de-shouted, never anglicized); the
            # identifier is the CN for remediation commands.
            identifier, display, node_id = _resolve_template_fields(template, index)
            entities.append(
                AffectedAssetEntity(
                    type=TYPE_TEMPLATE,
                    identifier=identifier,
                    display=display,
                    role=ROLE_AFFECTED,
                    role_label=template_label,
                    node_id=node_id or None,
                )
            )
    if Extra.CA in rule.extras:
        ca_label = rule.role_label_for("ca") or None
        for ca in extract_adcs_ca_names(view):
            entities.append(
                AffectedAssetEntity(
                    type=TYPE_CA,
                    identifier=ca,
                    display=ca,
                    role=ROLE_AFFECTED,
                    role_label=ca_label,
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
        for key in ("artifact", "source_xml", "unc_path"):
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
    if Extra.READ_SET in rule.extras:
        # The measured objects with effective READ access to the affected file —
        # WHO the client must remove from the share/NTFS ACL. Sourced ONLY from
        # the finding's measured ``details.read_set`` (the mxac/read-set SSOT);
        # never guessed. Each entry is ``{"sid", "label"}``; resolve the principal
        # through the asset index so a well-known SID still reads honestly.
        for entry in _read_set_records(view):
            sid = str(entry.get("sid") or "").strip()
            label = str(entry.get("label") or "").strip() or sid
            if not sid and not label:
                continue
            entity = _entity_for_principal(
                label or sid,
                role=ROLE_AFFECTED,
                index=index,
                sid_hint=sid or None,
                domain_hint=domain_hint,
            )
            if entity is not None:
                entities.append(entity)
    if Extra.NULL_SESSION_VECTOR in rule.extras:
        # The null/guest-session access VECTOR — surfaced ONLY when the finding
        # carries a PROVEN no-credential read (``unauthenticated_reachable`` + a
        # known ``reached_via``), never from a broad SID alone. It states the
        # exposure needs NO credential at the vulnerability level, so the client
        # remediates the null-session gate. An authenticated-only finding (no
        # ``unauthenticated_reachable``) never reaches here.
        if _view_is_unauthenticated_reachable(view):
            from adscan_core.reporting.unauthenticated_reach import (  # noqa: PLC0415
                unauthenticated_vector_display,
            )

            reached_via = str(view.get("reached_via") or "").strip()
            entities.append(
                AffectedAssetEntity(
                    type=TYPE_ACCESS_VECTOR,
                    identifier="unauthenticated-session",
                    display=unauthenticated_vector_display(reached_via),
                    role=ROLE_AFFECTED,
                )
            )

    return _dedupe(entities)


def _read_set_records(details: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Return the measured read-set records on a finding's details.

    The measured objects with effective READ access to the affected file, from
    the mxac/read-set SSOT (``ShareCredentialProvenanceService``), carried as
    ``details.read_set`` — a list of ``{"sid", "label"}``. Never fabricated.
    """
    raw = details.get("read_set")
    if not isinstance(raw, list):
        return []
    return [entry for entry in raw if isinstance(entry, Mapping)]


def _view_is_unauthenticated_reachable(details: Mapping[str, Any]) -> bool:
    """Return whether a finding's details carry a PROVEN no-credential read.

    Honesty gate for the null/guest access-vector asset: the finding must carry
    ``unauthenticated_reachable == True`` AND a known ``reached_via`` token. A
    broad SID (Everyone/Users) in the read-set alone is NOT proof of an
    anonymous read (the Everyone != Anonymous guard), so it does not qualify.
    """
    from adscan_core.reporting.unauthenticated_reach import (  # noqa: PLC0415
        REACHED_VIA_GUEST_SESSION,
        REACHED_VIA_NULL_SESSION,
    )

    if details.get("unauthenticated_reachable") is not True:
        return False
    token = str(details.get("reached_via") or "").strip().lower()
    return token in {REACHED_VIA_NULL_SESSION, REACHED_VIA_GUEST_SESSION}


def _typed_entities_from_flat_strings(
    flat_assets: Iterable[str],
    index: AssetIndex | None = None,
) -> list[AffectedAssetEntity]:
    """Lift the flat extractor's typed ``Template:`` / ``CA:`` / ``Share:`` /
    ``Artifact:`` strings into structured entities.

    The flat :func:`extract_affected_assets` resolves the abused certificate
    template(s) + CA from the correlated attack paths (a richer resolution than
    the summarized finding edges, which often carry no template notes). Rather
    than duplicate that ADCS resolution, the serialization pass reuses it: the
    already-typed flat strings are mapped back to typed entities here so the
    structured contract carries the templates the report shows.

    ``index`` lets a template named here by its English CN resolve to the SAME
    template the builder already surfaced by its localized displayName, so the
    two collapse into one entity (localized display, CN identifier) instead of
    appearing as two templates.
    """
    out: list[AffectedAssetEntity] = []
    for raw in flat_assets:
        text = str(raw or "").strip()
        lower = text.lower()
        if lower.startswith("template: "):
            name = text[len("template: ") :].strip()
            if name:
                # Resolve to ONE template identity so a localized-name entry from
                # the builder and this CN entry from the flat extractor collapse.
                # Display is the localized name (de-shouted, never anglicized);
                # the identifier is the CN for remediation commands.
                identifier, display, node_id = _resolve_template_fields(name, index)
                out.append(
                    AffectedAssetEntity(
                        type=TYPE_TEMPLATE,
                        identifier=identifier,
                        display=display,
                        node_id=node_id or None,
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
                    AffectedAssetEntity(type=TYPE_SHARE, identifier=name, display=name)
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
        entities = _dedupe(
            [*entities, *_typed_entities_from_flat_strings(flat_assets, index)]
        )
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
        ``True`` when the report was rewritten, which is when a finding's
        entities changed or its ADscan rating did. A caller holding its own copy
        of the file re-reads it on ``True``. Best-effort: never raises.
    """
    try:
        from types import SimpleNamespace  # noqa: PLC0415

        from adscan_core.reporting.technical_report import (  # noqa: PLC0415
            _load_technical_report,
            _save_technical_report,
            stamp_adscan_severity_report,
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
        changed = stamp_structured_affected_assets(
            findings,
            domain_name=domain_name,
            index=index
            if index is not None
            else load_asset_index(workspace_dir, domain_name),
            attack_paths=attack_paths,
        )
        # The ADscan rating is derived from the entities above, so the two have
        # to be settled together. A workspace whose entities did NOT move can
        # still carry no rating at all, because it was scanned by a build that
        # predates the rating being persisted; without this the report would
        # never be rewritten, the rating would stay absent, and both tiers would
        # keep counting the baseline band underneath it. The save seam re-derives
        # the rating itself, so this only decides whether a write is owed.
        changed = stamp_adscan_severity_report(report) or changed
        if changed:
            _save_technical_report(shell, report)
            return True
        return False
    except Exception:  # noqa: BLE001 - a report must never break on enrichment
        return False
