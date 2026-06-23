from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

NodeKind = Literal[
    "User",
    "Computer",
    "Group",
    "Domain",
    "GPO",
    "OU",
    "Container",
    "ForeignSecurityPrincipal",
    "CertTemplate",
    "EnterpriseCA",
    "RootCA",
    "AIACA",
    "NTAuthStore",
]


@dataclass(frozen=True)
class CollectorNode:
    """A normalized AD object ready for graph persistence."""

    object_id: str
    kind: NodeKind
    name: str
    domain: str
    samaccountname: str = ""
    distinguished_name: str = ""
    enabled: bool | None = None
    highvalue: bool = False
    properties: dict[str, Any] = field(default_factory=dict)

    def to_graph_payload(self) -> dict[str, Any]:
        props: dict[str, Any] = {
            "name": self.name,
            "domain": self.domain.upper(),
            "objectid": self.object_id,
            "distinguishedname": self.distinguished_name,
            "highvalue": self.highvalue,
            "isTierZero": self.highvalue,
            **self.properties,
        }
        if self.samaccountname:
            props["samaccountname"] = self.samaccountname
        if self.enabled is not None:
            props["enabled"] = self.enabled
        if self.highvalue:
            props["system_tags"] = "admin_tier_0"
        return {
            "kind": self.kind,
            "label": self.name,
            "name": self.name,
            "objectId": self.object_id,
            "highvalue": self.highvalue,
            "isTierZero": self.highvalue,
            "properties": props,
        }


@dataclass(frozen=True)
class CollectorEdge:
    """A normalized relationship ready for graph persistence."""

    source_object_id: str
    target_object_id: str
    relation: str
    source: str
    method: str
    notes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DomainPolicy:
    """Password and account policy fetched from the domain root object."""

    min_pwd_length: int | None
    lockout_threshold: int | None  # 0 = lockout disabled
    lockout_window_minutes: int | None
    max_pwd_age_days: int | None  # None = passwords never expire at domain level
    pwd_history_length: int | None
    machine_account_quota: int | None  # 0 = only admins; >0 = any domain user
    # Default Domain Password Policy uses the legacy ``pwdProperties`` bitmask
    # on the domain root object (the per-PSO equivalent is the dedicated
    # ``msDS-PasswordComplexityEnabled`` boolean). Bit 0
    # (DOMAIN_PASSWORD_COMPLEX = 0x1) drives "must meet complexity
    # requirements". ``None`` when the attribute is unreadable / absent so
    # callers can distinguish "not collected" from "explicitly disabled".
    complexity_enabled: bool | None = None
    # Per-attribute replication metadata from msDS-ReplAttributeMetaData, filtered
    # to password-policy-relevant attributes only. Each entry is a 3-tuple:
    #   (ldap_attr_name, iso_timestamp, version)
    # where version==1 means the attribute was set at provisioning and never
    # explicitly modified. Sorted newest-first. Empty when the attribute is
    # unreadable (insufficient permissions or very old DC).
    pwd_attrs_when_changed: tuple[tuple[str, str, int], ...] = ()
    # ISO 8601 timestamp of the most recent change to any password-policy
    # attribute, derived from pwd_attrs_when_changed. None when unreadable.
    pwd_policy_last_changed: str | None = None


@dataclass(frozen=True)
class PasswordSettingsObject:
    """Fine-grained password policy (PSO) — overrides domain default for the
    principals listed in ``applies_to``. Higher precedence (lower numeric value)
    wins when a principal is covered by multiple PSOs.
    """

    name: str
    distinguished_name: str
    precedence: int | None
    min_pwd_length: int | None
    max_pwd_age_days: int | None
    min_pwd_age_days: int | None
    lockout_threshold: int | None
    lockout_observation_window_minutes: int | None
    lockout_duration_minutes: int | None
    pwd_history_length: int | None
    complexity_enabled: bool | None
    reversible_encryption_enabled: bool | None
    applies_to: tuple[str, ...] = ()  # DNs of users/groups this PSO targets
    # Same per-attribute replication metadata pattern as DomainPolicy,
    # but for PSO-specific attribute names (msDS-MinimumPasswordLength, etc.)
    pwd_attrs_when_changed: tuple[tuple[str, str, int], ...] = ()
    pwd_policy_last_changed: str | None = None


@dataclass(frozen=True)
class ShadowCredentialFinding:
    """An AD object that already has msDS-KeyCredentialLink entries set."""

    object_id: str
    samaccountname: str
    kind: str  # "User" | "Computer"
    distinguished_name: str
    key_count: int  # number of KeyCredentialLink entries present


@dataclass(frozen=True)
class AuditFinding:
    """A hygiene or misconfiguration finding for audit-mode workspaces."""

    # stale_user | pwd_never_expires | krbtgt_age | machine_quota_risk
    # obsolete_os | rc4_only | pwd_predates_policy | pwd_policy_never_modified
    category: str
    samaccountname: str
    object_id: str
    detail: str
    severity: str  # critical | high | medium | low
    highvalue: bool = False  # admincount set or node.highvalue
    # Structured observed values backing the finding (e.g. the concrete
    # password-policy knobs read off the domain root for
    # ``weak_password_policy``). Plain JSON-serializable scalars only — no
    # LDAP types. Empty for findings with no structured observation. Compared
    # against the catalog ``recommended`` block at report/web render time.
    observed: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class UserPasswordCompliance:
    """Per-user password compliance row produced by the offline analyser.

    Snapshot field for downstream consumers (report, web, password
    spraying selection logic). Plain values only — no LDAP types.
    """

    samaccountname: str
    object_id: str
    distinguished_name: str
    enabled: bool
    is_admin_like: bool
    pwd_last_set_filetime: int | None  # Raw FILETIME (100-ns since 1601)
    pwd_last_set_iso: str | None  # ISO 8601 UTC; None when 0/unset/never
    pwd_age_days: int | None
    applied_policy_name: str  # "DDP" or "PSO:<cn>"
    applied_policy_dn: str
    applied_policy_when_changed: str | None
    pwd_predates_policy: bool
    pwd_over_max_age: bool
    pwd_never_expires: bool
    risk_level: str  # "high" | "medium" | "low" | "info"
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class PasswordComplianceReport:
    """Full domain-level password compliance snapshot.

    Persisted as ``password_compliance.json`` and consumed by the report
    builder, the web UI and password-spraying candidate selection.
    """

    domain: str
    # ISO 8601 timestamp of the most recent change to a password-policy
    # attribute, derived from msDS-ReplAttributeMetaData. More precise than
    # whenChanged (which includes non-password attributes like creationTime).
    policy_pwd_last_changed: str | None
    # True when every password-policy attribute has dwVersion==1 — set at
    # domain provisioning and never explicitly modified since.
    policy_never_modified: bool
    # Per-attribute breakdown: list of (attr_name, iso_timestamp, version)
    # tuples for every password-relevant attribute, sorted newest-first.
    policy_pwd_attrs: tuple[tuple[str, str, int], ...]
    psos_count: int
    users_total: int
    users_with_predates_policy: int
    users_with_over_max_age: int
    users_with_never_expires: int
    entries: tuple[UserPasswordCompliance, ...] = ()


@dataclass
class CollectionResult:
    """All collected data for one domain."""

    domain: str
    nodes: dict[str, CollectorNode] = field(default_factory=dict)
    edges: list[CollectorEdge] = field(default_factory=list)
    fsp_placeholders: dict[str, str] = field(default_factory=dict)
    diagnostics: list[dict[str, Any]] = field(default_factory=list)
    domain_policy: DomainPolicy | None = None
    psos: list[PasswordSettingsObject] = field(default_factory=list)
    shadow_credential_findings: list[ShadowCredentialFinding] = field(
        default_factory=list
    )
    audit_findings: list[AuditFinding] = field(default_factory=list)
    password_compliance: "PasswordComplianceReport | None" = None
    collection_scope: str = "ctf"
    adcs_elapsed: float = 0.0
    # Machine-account password rotation policy recovered from GPO SYSVOL templates
    # (set by the orchestrator in audit scope). None = not inspected / unavailable.
    machine_password_policy: Any | None = None

    def add_node(self, node: CollectorNode) -> None:
        if node.object_id:
            self.nodes[node.object_id.upper()] = node

    def add_edge(self, edge: CollectorEdge) -> None:
        if edge.source_object_id and edge.target_object_id:
            self.edges.append(edge)

    def add_fsp_placeholder(self, sid: str, foreign_domain: str) -> None:
        self.fsp_placeholders[sid.upper()] = foreign_domain.lower()


def _node_enabled_flag(node: CollectorNode) -> bool | None:
    """Resolve a node's enabled state during collection (fail-open friendly).

    ``enabled`` lives on the dataclass field at collection time and is only
    copied into ``properties`` at persistence (``to_graph_payload``). Read the
    field first, then fall back to the property so the predicate works on both
    live ``CollectorNode`` objects and persisted graph payloads. ``None`` means
    the flag is unknown.
    """
    flag = node.enabled
    if flag is None:
        flag = node.properties.get("enabled")
    if flag is None:
        return None
    return bool(flag)


def is_disabled_computer_account(node: CollectorNode) -> bool:
    """Return True only when a Computer node is explicitly disabled.

    Fail-open: a missing/unknown ``enabled`` flag is NOT treated as disabled.
    Used by host-collection telemetry to count hosts skipped specifically for
    being disabled (vs gMSA / non-SMB reasons).
    """
    if node.kind != "Computer":
        return False
    return _node_enabled_flag(node) is False


def is_collectable_computer_host(node: CollectorNode) -> bool:
    """Return True when a Computer node represents a real, reachable host.

    Some AD principals are computer-like accounts but not SMB endpoints. gMSAs
    commonly carry a trailing ``$`` and computer-like schema ancestry, but they
    should not be resolved, probed, or used as targets for host-local edges.

    Disabled computer accounts cannot authenticate, so they are excluded from
    SMB collection / DNS resolution (Phase 2) while remaining present in the
    attack graph as LDAP principals. The enabled check is fail-open: an unknown
    ``enabled`` flag keeps the host collectable so we never silently drop hosts
    when the flag was not populated.
    """
    if node.kind != "Computer":
        return False
    if node.properties.get("is_smb_host") is False:
        return False
    if node.properties.get("is_gmsa") is True:
        return False
    if str(node.properties.get("account_type") or "").casefold() == "gmsa":
        return False
    return _node_enabled_flag(node) is not False
