"""The ROLE model of a finding's affected assets: who can exploit it, what it exposes.

A finding that IS an attack step (an ADCS ESC, Kerberoasting, an ACL abuse, a
delegation, DCSync) has assets on two different sides, and a reader must never
have to work out which side an object is on:

* **Who can exploit it**: the principals that can carry out the step today. The
  attack-graph edge SOURCE. A broad built-in identity (``Authenticated Users``,
  ``Domain Users``) is ONE object, never its thousand members, and carries a
  ``scope_note`` saying how broad it is.
* **What it exposes**: what the attacker controls or impersonates once the step
  succeeds. The edge TARGET (the ESC14 mapped account, the roastable service
  account, the object an ACE controls).
* **Where the weakness lives**: the misconfigured object the fix is applied to
  (the certificate template, the CA, the domain root ACL). Typed resources the
  engine stamps with role ``affected`` on an attack-step finding.

A finding that is NOT an attack step (SMB signing not required, a weak password
policy, stale accounts) has one side only and keeps a single "Affected assets"
block.

WHERE THE ROLES COME FROM
-------------------------
The engine (``adscan_internal.services.affected_assets_struct``) derives every
entity's ``role`` from the finding's attack-graph edges and stamps it into the
finding under :data:`AFFECTED_ASSETS_STRUCT_KEY`. This module never re-derives a
role from names or from the finding key: it groups what the engine stamped. That
is what keeps the PDF report, the Playbook, the LITE report, the web CTEM and the
command personaliser (``<TEMPLATE>`` / ``<ACCOUNT>`` / ``<TRUSTEE>``) on one
answer.

It lives in ``adscan_core`` because every one of those readers can import it,
including the web backend, which cannot import the engine.

The one repair it does make is for a finding stamped before the ADCS role fix: an
ESC edge whose impersonated principal (``vulnerable_resources[].kind == "User"``)
was mistaken for a certificate TEMPLATE. Such an entity is moved back to the
exposed side, using the edge's own ``kind`` as the evidence, so an older
persisted scan never fills ``<TEMPLATE>`` with an account name.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from adscan_core.reporting.affected_assets_contract import (
    AFFECTED_ASSETS_DISPLAY_ONLY_KEY,
    AFFECTED_ASSETS_STRUCT_KEY,
)

# --------------------------------------------------------------------------- #
# Vocabulary                                                                   #
# --------------------------------------------------------------------------- #

#: The entity roles the engine stamps (``affected_assets_struct.ROLE_*``).
ROLE_SOURCE = "source"
ROLE_TARGET = "target"
ROLE_AFFECTED = "affected"

#: The client-facing role GROUPS a finding's assets are presented in.
GROUP_EXPLOIT = "exploit"
GROUP_EXPOSED = "exposed"
GROUP_WEAK_POINT = "weak_point"
GROUP_AFFECTED = "affected"

#: Display order: who can do it, what it costs, where to fix it.
GROUP_ORDER: tuple[str, ...] = (GROUP_EXPLOIT, GROUP_EXPOSED, GROUP_WEAK_POINT)

#: Client-facing group headings. Client copy, gated by the writing rules.
GROUP_LABELS: dict[str, str] = {
    GROUP_EXPLOIT: "Who can exploit it",
    GROUP_EXPOSED: "What it exposes",
    GROUP_WEAK_POINT: "Where the weakness lives",
    GROUP_AFFECTED: "Affected assets",
}

#: One plain sentence under each heading, for surfaces with room for it.
GROUP_HINTS: dict[str, str] = {
    GROUP_EXPLOIT: "Accounts and groups that can carry out this attack step today.",
    GROUP_EXPOSED: "What an attacker controls or impersonates once the step succeeds.",
    GROUP_WEAK_POINT: "The misconfigured object the fix is applied to.",
    GROUP_AFFECTED: "",
}

_GROUP_BY_ROLE: dict[str, str] = {
    ROLE_SOURCE: GROUP_EXPLOIT,
    ROLE_TARGET: GROUP_EXPOSED,
    ROLE_AFFECTED: GROUP_WEAK_POINT,
}

#: Entity types that name a principal or a host (the "who" and the "what"),
#: as opposed to a typed resource (template, CA, share, artifact, credential).
PRINCIPAL_TYPES: frozenset[str] = frozenset({"user", "group", "computer"})

# --------------------------------------------------------------------------- #
# Broad built-in identities                                                    #
# --------------------------------------------------------------------------- #

_SID_AUTHENTICATED_USERS = "S-1-5-11"
_SID_EVERYONE = "S-1-1-0"
_SID_ANONYMOUS = "S-1-5-7"
_SID_BUILTIN_USERS = "S-1-5-32-545"
_RID_DOMAIN_USERS = "513"
_RID_DOMAIN_COMPUTERS = "515"

#: Client copy explaining how broad a built-in identity is. Keyed by a stable
#: identity key; resolved by :func:`broad_scope_note`.
BROAD_SCOPE_NOTES: dict[str, str] = {
    "authenticated_users": "Any account that can sign in to the domain",
    "everyone": "Every identity the domain recognises",
    "anonymous_logon": "No credential needed",
    "builtin_users": "Every account in the domain",
    "domain_users": "Every user account in the domain",
    "domain_computers": "Every computer account in the domain",
    "other": "A built-in identity that covers many accounts",
}

_BROAD_NAME_KEYS: dict[str, str] = {
    "authenticated users": "authenticated_users",
    "everyone": "everyone",
    "anonymous logon": "anonymous_logon",
    "anonymous": "anonymous_logon",
    "users": "builtin_users",
    "domain users": "domain_users",
    "domain computers": "domain_computers",
}


def _name_stem(label: str) -> str:
    raw = str(label or "").strip()
    if "\\" in raw:
        raw = raw.rsplit("\\", 1)[-1]
    return raw.split("@", 1)[0].strip().lower()


def broad_identity_key(*, sid: str = "", label: str = "") -> str:
    """Return the broad-identity key of a built-in principal, or ``""``.

    Prefers the invariant SID; falls back to the name for a graph that stamped
    none. A real group whose name merely contains one of these words is not a
    match: only the exact built-in name is.
    """
    sid_upper = str(sid or "").strip().upper()
    if sid_upper == _SID_AUTHENTICATED_USERS:
        return "authenticated_users"
    if sid_upper == _SID_EVERYONE:
        return "everyone"
    if sid_upper == _SID_ANONYMOUS:
        return "anonymous_logon"
    if sid_upper == _SID_BUILTIN_USERS:
        return "builtin_users"
    if sid_upper.startswith("S-1-5-21-"):
        rid = sid_upper.rsplit("-", 1)[-1]
        if rid == _RID_DOMAIN_USERS:
            return "domain_users"
        if rid == _RID_DOMAIN_COMPUTERS:
            return "domain_computers"
        return ""
    return _BROAD_NAME_KEYS.get(_name_stem(label), "")


def broad_scope_note(*, sid: str = "", label: str = "") -> str:
    """Return the client note for a broad built-in identity, or ``""``."""
    key = broad_identity_key(sid=sid, label=label)
    return BROAD_SCOPE_NOTES.get(key, "") if key else ""


# --------------------------------------------------------------------------- #
# Reading the stamped entities                                                 #
# --------------------------------------------------------------------------- #


def _details_scopes(details: Any) -> list[Mapping[str, Any]]:
    """The mapping(s) a finding's entities may sit in (bare details or a record)."""
    if not isinstance(details, Mapping):
        return []
    inner = details.get("details")
    return [details, inner] if isinstance(inner, Mapping) else [details]


def stamped_entities(
    details: Any, *, include_display_only: bool = False
) -> list[dict[str, Any]]:
    """Return the engine-stamped entities of a finding, role-repaired.

    Accepts the bare ``details`` mapping or a finding record wrapping it.

    ``include_display_only`` appends the escalation's landing point (the
    :data:`AFFECTED_ASSETS_DISPLAY_ONLY_KEY` entities, each marked
    ``display_only``) for a DISPLAY surface. Leave it off anywhere a figure,
    a score or a command is derived: those objects must never move one.
    """
    entities: list[dict[str, Any]] = []
    for scope in _details_scopes(details):
        raw = scope.get(AFFECTED_ASSETS_STRUCT_KEY)
        if isinstance(raw, list):
            entities = repair_legacy_adcs_principal_templates(
                [dict(item) for item in raw if isinstance(item, Mapping)], scope
            )
            break
    if include_display_only:
        entities = entities + display_only_entities(details)
    return entities


def display_only_entities(details: Any) -> list[dict[str, Any]]:
    """The display-only exposed objects of a finding, each marked ``display_only``."""
    for scope in _details_scopes(details):
        raw = scope.get(AFFECTED_ASSETS_DISPLAY_ONLY_KEY)
        if isinstance(raw, list):
            return [
                {**dict(item), "role": ROLE_TARGET, "display_only": True}
                for item in raw
                if isinstance(item, Mapping)
            ]
    return []


def _principal_resource_kinds(details: Mapping[str, Any]) -> dict[str, str]:
    """Map edge ``vulnerable_resources`` principal names to their entity type.

    An ADCS ESC edge lists the impersonated principals of ESC9/ESC10/ESC14 in
    ``notes.vulnerable_resources`` with ``kind`` ``User`` / ``Computer`` /
    ``Group``. Keyed by the lower-cased name, realm stripped.
    """
    kinds: dict[str, str] = {}
    edges = details.get("attack_graph_edges")
    if not isinstance(edges, list):
        return kinds
    for edge in edges:
        if not isinstance(edge, Mapping):
            continue
        notes = edge.get("notes")
        if not isinstance(notes, Mapping):
            continue
        resources = notes.get("vulnerable_resources")
        if not isinstance(resources, list):
            continue
        for entry in resources:
            if not isinstance(entry, Mapping):
                continue
            kind = str(entry.get("kind") or "").strip().lower()
            if kind not in PRINCIPAL_TYPES:
                continue
            name = _name_stem(str(entry.get("name") or ""))
            if name:
                kinds[name] = kind
    return kinds


def repair_legacy_adcs_principal_templates(
    entities: list[dict[str, Any]], details: Mapping[str, Any]
) -> list[dict[str, Any]]:
    """Re-type a principal an older stamp mistook for a certificate template.

    Only an entity typed ``template`` whose name the finding's own edges declare
    as a principal (``vulnerable_resources[].kind``) is touched. It becomes a
    TARGET principal of that kind, lower-cased the way the humanizer names an
    account, unless the same principal is already stamped as a target.
    """
    if not any(str(e.get("type") or "").lower() == "template" for e in entities):
        return entities
    principal_kinds = _principal_resource_kinds(details)
    if not principal_kinds:
        return entities
    existing_targets = {
        (_name_stem(str(e.get("identifier") or "")))
        for e in entities
        if str(e.get("role") or "").lower() == ROLE_TARGET
    }
    repaired: list[dict[str, Any]] = []
    for entity in entities:
        etype = str(entity.get("type") or "").lower()
        stem = _name_stem(str(entity.get("identifier") or entity.get("display") or ""))
        kind = principal_kinds.get(stem) if etype == "template" else None
        if not kind:
            repaired.append(entity)
            continue
        if stem in existing_targets:
            continue
        existing_targets.add(stem)
        name = stem if kind != "group" else str(entity.get("display") or stem)
        repaired.append(
            {
                "type": kind,
                "identifier": stem,
                "display": name,
                "role": ROLE_TARGET,
            }
        )
    return repaired


# --------------------------------------------------------------------------- #
# The role view                                                                #
# --------------------------------------------------------------------------- #


def entity_role(entity: Mapping[str, Any]) -> str:
    """Return an entity's role, defaulting to ``affected``."""
    role = str(entity.get("role") or ROLE_AFFECTED).strip().lower()
    return role if role in (ROLE_SOURCE, ROLE_TARGET, ROLE_AFFECTED) else ROLE_AFFECTED


def is_attack_step(entities: Iterable[Mapping[str, Any]]) -> bool:
    """Return whether the entities describe an attack step (a source or a target)."""
    return any(entity_role(e) in (ROLE_SOURCE, ROLE_TARGET) for e in entities)


def _entity_key(entity: Mapping[str, Any]) -> tuple[str, str]:
    ident = str(entity.get("identifier") or entity.get("display") or "")
    return (str(entity.get("type") or "").lower(), ident.strip().casefold())


@dataclass(frozen=True)
class RoleGroup:
    """One client-facing group of a finding's assets."""

    key: str
    label: str
    hint: str
    entities: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        """Serialize for an API / template context."""
        return {
            "key": self.key,
            "label": self.label,
            "hint": self.hint,
            "entities": [dict(e) for e in self.entities],
        }


def group_entities_by_role(
    entities: Iterable[Mapping[str, Any]],
) -> list[RoleGroup]:
    """Group entities into the client-facing role groups, in display order.

    An attack-step finding yields up to three groups (who can exploit it, what it
    exposes, where the weakness lives); empty groups are omitted. Any other
    finding yields one ``affected`` group. Within a group an object appears once.
    """
    items = [dict(e) for e in entities if isinstance(e, Mapping)]
    if not items:
        return []
    if not is_attack_step(items):
        return [
            RoleGroup(
                key=GROUP_AFFECTED,
                label=GROUP_LABELS[GROUP_AFFECTED],
                hint=GROUP_HINTS[GROUP_AFFECTED],
                entities=tuple(_dedupe(items)),
            )
        ]
    buckets: dict[str, list[dict[str, Any]]] = {key: [] for key in GROUP_ORDER}
    for entity in items:
        buckets[_GROUP_BY_ROLE[entity_role(entity)]].append(entity)
    return [
        RoleGroup(
            key=key,
            label=GROUP_LABELS[key],
            hint=GROUP_HINTS[key],
            entities=tuple(_dedupe(buckets[key])),
        )
        for key in GROUP_ORDER
        if buckets[key]
    ]


def annotate_role_groups(
    entities: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Return copies of the entities, each stamped with its ``role_group``.

    Adds ``role_group`` (``exploit`` / ``exposed`` / ``weak_point``, or
    ``affected`` when the finding is not an attack step) and its heading
    ``role_group_label``, decided over the WHOLE set so a typed resource of an
    attack-step finding lands under "Where the weakness lives". Order is kept;
    duplicates are kept too (a renderer that pairs entities needs every one).
    """
    items = [dict(e) for e in entities if isinstance(e, Mapping)]
    attack_step = is_attack_step(items)
    for entity in items:
        key = _GROUP_BY_ROLE[entity_role(entity)] if attack_step else GROUP_AFFECTED
        entity["role_group"] = key
        entity["role_group_label"] = GROUP_LABELS[key]
    return items


def role_group_headings(entities: Iterable[Mapping[str, Any]]) -> list[dict[str, str]]:
    """The headings of the groups present, in display order (``key`` / ``label`` / ``hint``)."""
    return [
        {"key": group.key, "label": group.label, "hint": group.hint}
        for group in group_entities_by_role(entities)
    ]


def _dedupe(entities: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []
    for entity in entities:
        key = _entity_key(entity)
        if key in seen:
            continue
        seen.add(key)
        out.append(entity)
    return out


def unique_objects(entities: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """The distinct objects of a finding, one per object whatever its roles.

    The same account can be on both sides (it can exploit the step against one
    account and be exposed through another). It is still one object. Two
    kinds of object are shown but never counted: a ``display_only`` landing
    point, and a broad built-in identity on the exploit side (Authenticated
    Users stands for every account, it is not an affected asset).
    """
    return _dedupe(
        dict(e) for e in entities if isinstance(e, Mapping) and is_counted_object(e)
    )


def is_counted_object(entity: Mapping[str, Any]) -> bool:
    """Whether an entity counts as an affected object (the one counting rule).

    A ``display_only`` landing point and a broad built-in identity on the
    exploit side (it carries a ``scope_note``) are shown, never counted. Every
    figure derived from a finding's objects (``unique_objects``, the per-asset
    exposure in ``asset_finding_exposure``) applies this predicate.
    """
    return not entity.get("display_only") and not (
        entity_role(entity) == ROLE_SOURCE and entity.get("scope_note")
    )


def summary_highlights(
    entities: Iterable[Mapping[str, Any]], *, limit: int = 8
) -> list[str]:
    """The headline object names of a finding, one per object, most telling first.

    Exposed objects lead (what is at stake), then where the weakness lives,
    then who can exploit it. Case-insensitive de-duplication on the display.
    """
    items = [dict(e) for e in entities if isinstance(e, Mapping)]
    order = {GROUP_EXPOSED: 0, GROUP_WEAK_POINT: 1, GROUP_EXPLOIT: 2}
    if is_attack_step(items):
        items.sort(key=lambda e: order[_GROUP_BY_ROLE[entity_role(e)]])
    seen: set[str] = set()
    out: list[str] = []
    for entity in items:
        display = str(entity.get("display") or entity.get("identifier") or "").strip()
        if not display or display.casefold() in seen:
            continue
        seen.add(display.casefold())
        out.append(display)
        if len(out) >= limit:
            break
    return out


# --------------------------------------------------------------------------- #
# Resolved lists for command personalisation                                   #
# --------------------------------------------------------------------------- #


def command_principal_name(entity: Mapping[str, Any]) -> str:
    """The name an account command matches for one affected principal.

    ``Get-ADObject -LDAPFilter '(sAMAccountName=...)'``, ``Set-ADAccountControl
    -Identity`` and ``dsacls /R DOMAIN\\...`` match a sAMAccountName. A user or
    group entity's identifier already is one. A COMPUTER entity is identified by
    its FQDN (right for ``Invoke-Command -ComputerName``), and an FQDN in a
    sAMAccountName filter matches nothing: the delegation fix filtered
    ``sAMAccountName=castelblack.north.sevenkingdoms.local``, read nothing, and
    the ``Set-ADObject`` pipeline changed nothing without an error. So a computer
    is named by its sAMAccountName, in order:

    1. an explicit ``samaccountname`` on the entity;
    2. the graph node id the entity carries (``name:castelblack$``), which is the
       collected sAMAccountName;
    3. the first label of the identifier plus ``$``, the form Windows gives a
       computer account.

    Returns ``""`` for an entity with no usable name.
    """
    identifier = str(entity.get("identifier") or entity.get("display") or "").strip()
    if str(entity.get("type") or "").strip().lower() != "computer":
        return identifier
    explicit = str(entity.get("samaccountname") or "").strip()
    if explicit:
        return explicit
    node_id = str(entity.get("node_id") or "").strip()
    if node_id.lower().startswith("name:") and node_id.endswith("$"):
        return node_id[len("name:") :]
    host = identifier.split("\\")[-1].split("@")[0].split(".")[0].split(" ")[0].strip()
    host = host.rstrip("$")
    return f"{host}$" if host else ""


def _names(entities: Iterable[Mapping[str, Any]], *types: str) -> tuple[str, ...]:
    wanted = {t.lower() for t in types}
    out: list[str] = []
    seen: set[str] = set()
    for entity in entities:
        if str(entity.get("type") or "").lower() not in wanted:
            continue
        name = str(entity.get("identifier") or entity.get("display") or "").strip()
        if name and name.casefold() not in seen:
            seen.add(name.casefold())
            out.append(name)
    return tuple(out)


@dataclass(frozen=True)
class FindingAssetRoles:
    """A finding's affected objects resolved by role, for commands and runbooks.

    Every list holds identifiers (sAMAccountName, FQDN, template CN, CA name),
    the values a command names, in the engine's priority order.

    Attributes:
        attack_step: Whether the finding is an attack step (has a source or a
            target side).
        exploiters: The entities that can exploit it (edge sources).
        exposed: The entities it exposes (edge targets).
        weak_points: The misconfigured objects (role ``affected`` on an attack
            step; every asset of a non-attack-step finding).
    """

    attack_step: bool
    exploiters: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    exposed: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    weak_points: tuple[dict[str, Any], ...] = field(default_factory=tuple)

    @property
    def templates(self) -> tuple[str, ...]:
        """Certificate-template CNs, from every side (a template is never a principal)."""
        return _names(self.exposed + self.weak_points + self.exploiters, "template")

    @property
    def certificate_authorities(self) -> tuple[str, ...]:
        """Certificate-authority names."""
        return _names(self.exposed + self.weak_points + self.exploiters, "ca")

    @property
    def trustees(self) -> tuple[str, ...]:
        """Principals holding the abused right (who can exploit it).

        Account commands consume these (``sAMAccountName=`` filters,
        ``-Identity``, ``dsacls /R``), so a computer is listed by its
        sAMAccountName, never its FQDN (:func:`command_principal_name`).
        """
        out: list[str] = []
        seen: set[str] = set()
        for entity in self.exploiters:
            if str(entity.get("type") or "").lower() not in {"user", "group", "computer"}:
                continue
            name = command_principal_name(entity)
            if name and name.casefold() not in seen:
                seen.add(name.casefold())
                out.append(name)
        return tuple(out)

    @property
    def exploiter_accounts(self) -> tuple[str, ...]:
        """User accounts that can exploit the step."""
        return _names(self.exploiters, "user")

    @property
    def exposed_accounts(self) -> tuple[str, ...]:
        """User accounts the step exposes."""
        return _names(self.exposed, "user")

    @property
    def exposed_hosts(self) -> tuple[str, ...]:
        """Computers the step exposes."""
        return _names(self.exposed, "computer")

    @property
    def affected_accounts(self) -> tuple[str, ...]:
        """User accounts the finding is about: the exposed side, else the affected one."""
        return self.exposed_accounts or _names(self.weak_points, "user")

    @property
    def affected_hosts(self) -> tuple[str, ...]:
        """Computers the finding is about: the exposed side, else the affected one."""
        return self.exposed_hosts or _names(self.weak_points, "computer")

    @property
    def exposed_spns(self) -> tuple[str, ...]:
        """Service principal names of the exposed accounts (Kerberoasting)."""
        return tuple(
            dict.fromkeys(
                str(e.get("spn") or "").strip() for e in self.exposed if e.get("spn")
            )
        )

    def distinguished_names(self, side: str) -> dict[str, str]:
        """``{identifier: DN}`` of one side (``exploiters`` / ``exposed`` / ``weak_points``)."""
        entities = getattr(self, side, ())
        return {
            str(e.get("identifier") or ""): str(e.get("dn") or "")
            for e in entities
            if e.get("dn") and e.get("identifier")
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize the resolved lists (identifiers only) for an API."""
        return {
            "exposed_spns": list(self.exposed_spns),
            "distinguished_names": {
                side: self.distinguished_names(side)
                for side in ("exploiters", "exposed", "weak_points")
            },
            "attack_step": self.attack_step,
            "templates": list(self.templates),
            "certificate_authorities": list(self.certificate_authorities),
            "trustees": list(self.trustees),
            "exploiter_accounts": list(self.exploiter_accounts),
            "exposed_accounts": list(self.exposed_accounts),
            "exposed_hosts": list(self.exposed_hosts),
            "affected_accounts": list(self.affected_accounts),
            "affected_hosts": list(self.affected_hosts),
        }


def resolve_finding_asset_roles(details: Any) -> FindingAssetRoles:
    """Resolve a finding's stamped entities into role lists.

    Accepts the bare ``details`` mapping or a finding record wrapping it.
    """
    entities = stamped_entities(details)
    attack_step = is_attack_step(entities)
    exploiters = tuple(e for e in entities if entity_role(e) == ROLE_SOURCE)
    exposed = tuple(e for e in entities if entity_role(e) == ROLE_TARGET)
    weak_points = tuple(e for e in entities if entity_role(e) == ROLE_AFFECTED)
    return FindingAssetRoles(
        attack_step=attack_step,
        exploiters=exploiters,
        exposed=exposed,
        weak_points=weak_points,
    )


__all__ = [
    "BROAD_SCOPE_NOTES",
    "FindingAssetRoles",
    "GROUP_AFFECTED",
    "GROUP_EXPLOIT",
    "GROUP_EXPOSED",
    "GROUP_HINTS",
    "GROUP_LABELS",
    "GROUP_ORDER",
    "GROUP_WEAK_POINT",
    "PRINCIPAL_TYPES",
    "ROLE_AFFECTED",
    "ROLE_SOURCE",
    "ROLE_TARGET",
    "RoleGroup",
    "annotate_role_groups",
    "broad_identity_key",
    "broad_scope_note",
    "command_principal_name",
    "display_only_entities",
    "entity_role",
    "group_entities_by_role",
    "is_attack_step",
    "is_counted_object",
    "repair_legacy_adcs_principal_templates",
    "resolve_finding_asset_roles",
    "role_group_headings",
    "stamped_entities",
    "summary_highlights",
    "unique_objects",
]
