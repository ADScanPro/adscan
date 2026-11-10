"""One decoding of an Active Directory trust into the facts a client reads.

An AD trust is a handful of bits on a ``trustedDomain`` object, and those bits
decide whether the trust is attack surface at all. Whether it is transitive,
whether SID filtering applies, whether principals arriving over it are treated
as authenticated users on this side, whether Kerberos tickets are forwarded
across the boundary: each is one flag, and each changes the answer.

Three surfaces have to agree about them: the CLI trust matrix the operator
reads during the scan, the PDF report finding the client receives, and the web
CTEM panel the client browses. So the decoding happens here, exactly once, and
all three consume it.

Why ``adscan_core``
-------------------
The web backend cannot import the engine's trust module
(``adscan_internal/services/enumeration/trust_query.py``): that one lazily
imports ``winacl`` and ``badldap``, so it is barred from the appliance backend
image by the scope guarantee in
``adscan_web/backend/appliance-backend-modules.manifest``. ``adscan_core`` is
importable from the host launcher, the container runtime and the web backend
alike, which makes it the one place all three can share. The module is stdlib
only on purpose.

Sources
-------
``trustAttributes`` bits and ``trustType`` / ``trustDirection`` values are
MS-ADTS 6.1.6.7.9 / 6.1.6.7.12, mirrored verbatim by the vendored
``vendor/badldap/badldap/ldap_objects/adtrust.py`` enums. Keep the bit table
byte-identical to that enum.

Standard documented in:
- ``adscan-private-tool/CLAUDE.md`` § Nomenclature Standard
- ``adscan-obsidian/business/12_nomenclature_standard.md``
"""

from __future__ import annotations

from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Raw directory values
# ---------------------------------------------------------------------------

#: ``trustAttributes`` bits, in ascending bit order. Byte-identical to the
#: vendored badldap ``TrustAttributes`` enum (MS-ADTS 6.1.6.7.9).
TRUST_ATTRIBUTE_BITS: tuple[tuple[int, str], ...] = (
    (0x00000001, "NON_TRANSITIVE"),
    (0x00000002, "UPLEVEL_ONLY"),
    (0x00000004, "QUARANTINED_DOMAIN"),
    (0x00000008, "FOREST_TRANSITIVE"),
    (0x00000010, "CROSS_ORGANIZATION"),
    (0x00000020, "WITHIN_FOREST"),
    (0x00000040, "TREAT_AS_EXTERNAL"),
    (0x00000080, "USES_RC4_ENCRYPTION"),
    (0x00000100, "TRUST_USES_AES_KEYS"),
    (0x00000200, "CROSS_ORGANIZATION_NO_TGT_DELEGATION"),
    (0x00000400, "PIM_TRUST"),
    (0x00000800, "CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION"),
    (0x00001000, "DISABLE_AUTH_TARGET_VALIDATION"),
)

#: ``trustAttributes`` bit for cross-organization TGT-delegation forwarding.
#: Set on a forest trust, Kerberos ticket-granting tickets are forwarded across
#: the forest boundary, which is what turns a cross-forest trust into a
#: cross-forest unconstrained-delegation path.
TRUST_ATTR_CROSS_ORG_TGT_DELEGATION: int = 0x00000800

#: ``trustAttributes`` bit for domain quarantine, i.e. SID filtering.
TRUST_ATTR_QUARANTINED_DOMAIN: int = 0x00000004


# --- direction -------------------------------------------------------------

DIRECTION_DISABLED = "disabled"
DIRECTION_INBOUND = "inbound"
DIRECTION_OUTBOUND = "outbound"
DIRECTION_BIDIRECTIONAL = "bidirectional"
DIRECTION_UNKNOWN = "unknown"

#: Every direction value, in the order a reader should meet them.
TRUST_DIRECTIONS: tuple[str, ...] = (
    DIRECTION_BIDIRECTIONAL,
    DIRECTION_OUTBOUND,
    DIRECTION_INBOUND,
    DIRECTION_DISABLED,
    DIRECTION_UNKNOWN,
)

_DIRECTION_BY_RAW: dict[int, str] = {
    0: DIRECTION_DISABLED,
    1: DIRECTION_INBOUND,
    2: DIRECTION_OUTBOUND,
    3: DIRECTION_BIDIRECTIONAL,
}

_RAW_BY_DIRECTION: dict[str, int] = {
    value: key for key, value in _DIRECTION_BY_RAW.items()
}

#: The human labels the engine has always emitted, mapped back to the canonical
#: value. The collector persists the LABEL (not the integer) into the inventory
#: notes, so every consumer has to accept both forms.
_DIRECTION_BY_LABEL: dict[str, str] = {
    "disabled": DIRECTION_DISABLED,
    "inbound": DIRECTION_INBOUND,
    "outbound": DIRECTION_OUTBOUND,
    "bidirectional": DIRECTION_BIDIRECTIONAL,
    "unknown": DIRECTION_UNKNOWN,
}

#: Label shown to the operator in the CLI, unchanged from the engine's own
#: historical vocabulary.
TRUST_DIRECTION_OPERATOR_LABELS: dict[str, str] = {
    DIRECTION_DISABLED: "Disabled",
    DIRECTION_INBOUND: "Inbound",
    DIRECTION_OUTBOUND: "Outbound",
    DIRECTION_BIDIRECTIONAL: "Bidirectional",
    DIRECTION_UNKNOWN: "Unknown",
}


# --- kind ------------------------------------------------------------------

KIND_PARENT_CHILD = "parent_child"
KIND_TREE_ROOT = "tree_root"
KIND_FOREST = "forest"
KIND_EXTERNAL = "external"
KIND_REALM = "realm"
KIND_DCE = "dce"
KIND_AZURE_AD = "azure_ad"
KIND_DOWNLEVEL = "downlevel"
KIND_UNKNOWN = "unknown"

TRUST_KINDS: tuple[str, ...] = (
    KIND_PARENT_CHILD,
    KIND_TREE_ROOT,
    KIND_FOREST,
    KIND_EXTERNAL,
    KIND_REALM,
    KIND_DCE,
    KIND_AZURE_AD,
    KIND_DOWNLEVEL,
    KIND_UNKNOWN,
)

#: The kinds whose two domains live in the SAME forest. Their trust is created
#: and maintained by Active Directory itself, so it is structure rather than a
#: decision somebody made and can revisit.
WITHIN_FOREST_KINDS: frozenset[str] = frozenset({KIND_PARENT_CHILD, KIND_TREE_ROOT})

#: Labels a client reads. Each names the relation rather than the flag.
TRUST_KIND_LABELS: dict[str, str] = {
    KIND_PARENT_CHILD: "Parent and child domain",
    KIND_TREE_ROOT: "Domain tree in the same forest",
    KIND_FOREST: "Forest trust",
    KIND_EXTERNAL: "External trust",
    KIND_REALM: "Non-Windows Kerberos trust",
    KIND_DCE: "DCE trust",
    KIND_AZURE_AD: "Entra ID trust",
    KIND_DOWNLEVEL: "Windows NT trust",
    KIND_UNKNOWN: "Trust of an undetermined type",
}

#: The legacy one-word labels the CLI table, the attack graph and the report
#: findings have always printed. Kept exactly as they were: a label change here
#: would move text in a shipped deliverable for no gain.
_LEGACY_TYPE_LABELS: dict[str, str] = {
    KIND_PARENT_CHILD: "Parent-Child",
    KIND_TREE_ROOT: "Tree-Root",
    KIND_FOREST: "Forest",
    KIND_EXTERNAL: "External",
    KIND_REALM: "MIT",
    KIND_DCE: "DCE",
    KIND_AZURE_AD: "Entra ID",
    KIND_DOWNLEVEL: "Windows NT",
    KIND_UNKNOWN: "Unknown",
}

_KIND_BY_TRUST_TYPE: dict[int, str] = {
    1: KIND_DOWNLEVEL,
    2: KIND_EXTERNAL,
    3: KIND_REALM,
    4: KIND_DCE,
    5: KIND_AZURE_AD,
}


# --- transitivity ----------------------------------------------------------

TRANSITIVITY_TRANSITIVE = "transitive"
TRANSITIVITY_NON_TRANSITIVE = "non_transitive"

TRANSITIVITY_LABELS: dict[str, str] = {
    TRANSITIVITY_TRANSITIVE: "Transitive",
    TRANSITIVITY_NON_TRANSITIVE: "Not transitive",
}


# --- SID filtering ---------------------------------------------------------

SID_FILTERING_ENFORCED = "enforced"
SID_FILTERING_RELAXED_EXTERNAL = "relaxed_external"
SID_FILTERING_NOT_APPLIED = "not_applied"
SID_FILTERING_NOT_APPLICABLE = "not_applicable"
SID_FILTERING_UNKNOWN = "unknown"

SID_FILTERING_LABELS: dict[str, str] = {
    SID_FILTERING_ENFORCED: "SID filtering applies",
    SID_FILTERING_RELAXED_EXTERNAL: "SID filtering relaxed",
    SID_FILTERING_NOT_APPLIED: "SID filtering does not apply",
    SID_FILTERING_NOT_APPLICABLE: "SID filtering not applicable",
    SID_FILTERING_UNKNOWN: "SID filtering undetermined",
}


# --- selective authentication ---------------------------------------------

SELECTIVE_AUTH_ENABLED = "enabled"
SELECTIVE_AUTH_NOT_ENABLED = "not_enabled"
SELECTIVE_AUTH_NOT_APPLICABLE = "not_applicable"

SELECTIVE_AUTH_LABELS: dict[str, str] = {
    SELECTIVE_AUTH_ENABLED: "Selective authentication",
    SELECTIVE_AUTH_NOT_ENABLED: "No selective authentication",
    SELECTIVE_AUTH_NOT_APPLICABLE: "Selective authentication not applicable",
}


# --- TGT delegation -------------------------------------------------------

TGT_DELEGATION_ENABLED = "enabled"
TGT_DELEGATION_NOT_ENABLED = "not_enabled"
TGT_DELEGATION_NOT_APPLICABLE = "not_applicable"

TGT_DELEGATION_LABELS: dict[str, str] = {
    TGT_DELEGATION_ENABLED: "Ticket forwarding allowed",
    TGT_DELEGATION_NOT_ENABLED: "No ticket forwarding",
    TGT_DELEGATION_NOT_APPLICABLE: "Ticket forwarding not applicable",
}


# ---------------------------------------------------------------------------
# Exposure prose (SSOT for both the report finding and the web panel)
# ---------------------------------------------------------------------------

#: Canonical vuln-catalog keys the two trust-posture conditions map to.
TRUST_TGT_DELEGATION_FINDING_KEY = "trust_tgt_delegation_enabled"
TRUST_SID_FILTERING_FINDING_KEY = "trust_sid_filtering_disabled"

#: The sentence a client reads when a forest trust forwards Kerberos
#: ticket-granting tickets across the boundary. Authored once here, consumed by
#: the report finding (``evaluate_trust_posture``) and by the web trust panel,
#: so the two cannot word the same condition differently.
TGT_DELEGATION_EXPOSURE_NOTE: str = (
    "The forest trust is configured to forward Kerberos ticket-granting "
    "tickets across the trust boundary "
    "(CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION is set), which permits "
    "unconstrained-delegation abuse to reach across the trust."
)

#: Shown when a cross-forest trust has been relaxed to external-level SID
#: filtering.
SID_FILTERING_RELAXED_EXPOSURE_NOTE: str = (
    "The cross-forest trust is relaxed to external-level SID filtering "
    "(TREAT_AS_EXTERNAL is set), weakening the SID filtering that normally "
    "protects the forest boundary."
)

#: Shown when an external trust applies no domain quarantine at all.
SID_FILTERING_ABSENT_EXPOSURE_NOTE: str = (
    "The external trust does not apply domain quarantine / SID filtering "
    "(QUARANTINED_DOMAIN is not set), so SID-History values from the trusted "
    "domain are honoured across the boundary."
)


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------


def decode_trust_attribute_flags(value: int | None) -> list[str]:
    """Return the ``trustAttributes`` bit names set on ``value``."""
    if not value:
        return []
    return [name for bit, name in TRUST_ATTRIBUTE_BITS if int(value) & bit]


def normalize_trust_direction(raw: object) -> tuple[str, int | None]:
    """Return ``(canonical direction, raw integer)`` for any observed form.

    Accepts the raw ``trustDirection`` integer, the decoded label the collector
    persists into the inventory notes ("Bidirectional"), or the canonical value
    itself. An unreadable or absent value returns
    ``(DIRECTION_UNKNOWN, None)``: resolving it to a real direction would
    assert a fact about the client's directory that was never observed, and
    resolving it to the attack-relevant direction would manufacture an
    exposure.
    """
    if raw is None:
        return DIRECTION_UNKNOWN, None
    if isinstance(raw, bool):
        return DIRECTION_UNKNOWN, None
    if isinstance(raw, int):
        return _DIRECTION_BY_RAW.get(int(raw), DIRECTION_UNKNOWN), int(raw)

    text = str(raw).strip()
    if not text:
        return DIRECTION_UNKNOWN, None
    label = _DIRECTION_BY_LABEL.get(text.casefold())
    if label is not None:
        return label, _RAW_BY_DIRECTION.get(label)
    try:
        value = int(text)
    except ValueError:
        return DIRECTION_UNKNOWN, None
    return _DIRECTION_BY_RAW.get(value, DIRECTION_UNKNOWN), value


def is_dns_descendant(child: str, parent: str) -> bool:
    """Return whether ``child`` is a proper DNS descendant of ``parent``."""
    low_child = str(child or "").strip().rstrip(".").casefold()
    low_parent = str(parent or "").strip().rstrip(".").casefold()
    if not low_child or not low_parent or low_child == low_parent:
        return False
    return low_child.endswith("." + low_parent)


def classify_trust_kind(
    trust_attributes: int | None,
    trust_type: int | None,
    *,
    local_domain: str | None = None,
    partner_domain: str | None = None,
) -> str:
    """Return the canonical kind of one trust.

    Precedence follows the engine's historical order (within-forest, then
    forest-transitive, then the external markers, then the ``trustType``
    fallback) so no label already printed in a shipped report moves.

    Within one forest the relation is refined by DNS-name containment: a
    partner that is a descendant or ancestor of the local domain is a
    parent-child relation, anything else is a second tree in the same forest.
    With no names to compare, the parent-child reading is kept, which is both
    the common case and the engine's previous answer.
    """
    flags = set(decode_trust_attribute_flags(trust_attributes))

    if "WITHIN_FOREST" in flags:
        if local_domain and partner_domain:
            related = is_dns_descendant(partner_domain, local_domain) or (
                is_dns_descendant(local_domain, partner_domain)
            )
            return KIND_PARENT_CHILD if related else KIND_TREE_ROOT
        return KIND_PARENT_CHILD
    if "FOREST_TRANSITIVE" in flags:
        return KIND_FOREST
    if "TREAT_AS_EXTERNAL" in flags or "CROSS_ORGANIZATION" in flags:
        return KIND_EXTERNAL
    if trust_type is not None:
        kind = _KIND_BY_TRUST_TYPE.get(int(trust_type))
        if kind is not None:
            return kind
    return KIND_UNKNOWN


def legacy_trust_type_label(kind: str) -> str:
    """Return the one-word type label the CLI and report have always printed."""
    return _LEGACY_TYPE_LABELS.get(kind, "Unknown")


@dataclass(frozen=True)
class TrustFacts:
    """The decoded facts of one trust, ready for any surface to render.

    Attributes:
        kind: Canonical trust kind, one of :data:`TRUST_KINDS`.
        kind_label: Client-facing label for the kind.
        legacy_type_label: The one-word label the CLI and report print.
        within_forest: Whether both domains live in the same forest.
        direction: Canonical direction, one of :data:`TRUST_DIRECTIONS`.
        direction_raw: The raw ``trustDirection`` integer when it was readable.
        transitivity: Whether the trust can be used transitively.
        sid_filtering: Whether SID filtering applies on this trust.
        selective_authentication: Whether principals arriving over the trust
            are marked as coming from another organization.
        tgt_delegation: Whether Kerberos tickets are forwarded over the trust.
        trust_attributes: The raw ``trustAttributes`` bitmask.
        attribute_flags: The decoded ``trustAttributes`` bit names (evidence).
        exposure_notes: Client-facing sentences for each observed weakening.
        finding_keys: Vuln-catalog keys the weakenings map to.
    """

    kind: str
    kind_label: str
    legacy_type_label: str
    within_forest: bool
    direction: str
    direction_raw: int | None
    transitivity: str
    sid_filtering: str
    selective_authentication: str
    tgt_delegation: str
    trust_attributes: int
    attribute_flags: tuple[str, ...] = ()
    exposure_notes: tuple[str, ...] = ()
    finding_keys: tuple[str, ...] = ()

    @property
    def is_exposure(self) -> bool:
        """Whether any weakening was observed on this trust."""
        return bool(self.exposure_notes)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable mapping of every fact and its label."""
        return {
            "trust_kind": self.kind,
            "trust_kind_label": self.kind_label,
            "within_forest": self.within_forest,
            "direction": self.direction,
            "trust_direction_raw": self.direction_raw,
            "transitivity": self.transitivity,
            "transitivity_label": TRANSITIVITY_LABELS.get(self.transitivity, ""),
            "sid_filtering": self.sid_filtering,
            "sid_filtering_label": SID_FILTERING_LABELS.get(self.sid_filtering, ""),
            "selective_authentication": self.selective_authentication,
            "selective_authentication_label": SELECTIVE_AUTH_LABELS.get(
                self.selective_authentication, ""
            ),
            "tgt_delegation": self.tgt_delegation,
            "tgt_delegation_label": TGT_DELEGATION_LABELS.get(
                self.tgt_delegation, ""
            ),
            "trust_attributes": self.trust_attributes,
            "attribute_flags": list(self.attribute_flags),
            "exposure_notes": list(self.exposure_notes),
            "finding_keys": list(self.finding_keys),
        }


def _resolve_transitivity(kind: str, flags: set[str]) -> str:
    """Return whether the trust can be used transitively.

    Within a forest and across a forest trust the relation is transitive;
    an external trust is not, by definition. Otherwise the ``NON_TRANSITIVE``
    bit decides. The branch order matches the vendored badldap ``to_bh()``
    derivation, so a trust reads the same here and in the graph export.
    """
    if kind in WITHIN_FOREST_KINDS or kind == KIND_FOREST:
        return TRANSITIVITY_TRANSITIVE
    if kind == KIND_EXTERNAL:
        return TRANSITIVITY_NON_TRANSITIVE
    if "NON_TRANSITIVE" in flags:
        return TRANSITIVITY_NON_TRANSITIVE
    return TRANSITIVITY_TRANSITIVE


def _resolve_sid_filtering(kind: str, flags: set[str]) -> str:
    """Return whether SID filtering applies on this trust.

    Inside one forest the forest itself is the trust boundary, so SID
    filtering is not applicable unless the domain was deliberately
    quarantined. A forest trust enforces forest-wide filtering by default and
    is therefore never flagged for it; ``TREAT_AS_EXTERNAL`` relaxes that to
    the weaker external level, and an external trust without
    ``QUARANTINED_DOMAIN`` applies none at all. Those two are the observed
    weakenings, and the only ones reported.
    """
    quarantined = "QUARANTINED_DOMAIN" in flags
    if kind in WITHIN_FOREST_KINDS:
        return SID_FILTERING_ENFORCED if quarantined else SID_FILTERING_NOT_APPLICABLE
    if kind == KIND_FOREST:
        if "TREAT_AS_EXTERNAL" in flags:
            return SID_FILTERING_RELAXED_EXTERNAL
        return SID_FILTERING_ENFORCED
    if kind in (KIND_EXTERNAL, KIND_DOWNLEVEL):
        return SID_FILTERING_ENFORCED if quarantined else SID_FILTERING_NOT_APPLIED
    return SID_FILTERING_UNKNOWN


def _resolve_selective_authentication(kind: str, flags: set[str]) -> str:
    """Return whether the trust carries the cross-organization marker.

    Enabling selective authentication on a trust sets
    ``TRUST_ATTRIBUTE_CROSS_ORGANIZATION``, which is what makes a domain
    controller stamp the OTHER_ORGANIZATION SID into tickets arriving over the
    trust (MS-KILE 3.3.5.7.5). So the bit is the observable, and the flag list
    on the facts carries it as the evidence. Inside one forest the setting does
    not exist.
    """
    if kind in WITHIN_FOREST_KINDS:
        return SELECTIVE_AUTH_NOT_APPLICABLE
    if "CROSS_ORGANIZATION" in flags:
        return SELECTIVE_AUTH_ENABLED
    if kind in (KIND_FOREST, KIND_EXTERNAL, KIND_DOWNLEVEL, KIND_REALM):
        return SELECTIVE_AUTH_NOT_ENABLED
    return SELECTIVE_AUTH_NOT_APPLICABLE


def _resolve_tgt_delegation(kind: str, flags: set[str]) -> str:
    """Return whether Kerberos tickets are forwarded over the trust."""
    if kind in WITHIN_FOREST_KINDS:
        return TGT_DELEGATION_NOT_APPLICABLE
    if "CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION" in flags:
        return TGT_DELEGATION_ENABLED
    return TGT_DELEGATION_NOT_ENABLED


def decode_trust_facts(
    *,
    trust_attributes: int | None,
    trust_type: int | None = None,
    trust_direction: object = None,
    local_domain: str | None = None,
    partner_domain: str | None = None,
) -> TrustFacts:
    """Decode one trust's directory values into the facts every surface renders.

    Args:
        trust_attributes: The raw ``trustAttributes`` bitmask.
        trust_type: The raw ``trustType`` integer, when it was read.
        trust_direction: The raw ``trustDirection`` integer, or the decoded
            label the collector persists, or the canonical value.
        local_domain: The domain whose ``trustedDomain`` object this is.
        partner_domain: The ``trustPartner`` domain.

    Returns:
        The decoded :class:`TrustFacts`. Never raises: an unreadable value
        becomes an explicit undetermined state rather than a guess.
    """
    attributes = int(trust_attributes or 0)
    flag_list = decode_trust_attribute_flags(attributes)
    flags = set(flag_list)

    kind = classify_trust_kind(
        attributes,
        trust_type,
        local_domain=local_domain,
        partner_domain=partner_domain,
    )
    direction, direction_raw = normalize_trust_direction(trust_direction)

    sid_filtering = _resolve_sid_filtering(kind, flags)
    tgt_delegation = _resolve_tgt_delegation(kind, flags)

    notes: list[str] = []
    keys: list[str] = []
    if kind == KIND_FOREST and tgt_delegation == TGT_DELEGATION_ENABLED:
        notes.append(TGT_DELEGATION_EXPOSURE_NOTE)
        keys.append(TRUST_TGT_DELEGATION_FINDING_KEY)
    if sid_filtering == SID_FILTERING_RELAXED_EXTERNAL:
        notes.append(SID_FILTERING_RELAXED_EXPOSURE_NOTE)
        keys.append(TRUST_SID_FILTERING_FINDING_KEY)
    elif sid_filtering == SID_FILTERING_NOT_APPLIED:
        notes.append(SID_FILTERING_ABSENT_EXPOSURE_NOTE)
        keys.append(TRUST_SID_FILTERING_FINDING_KEY)

    return TrustFacts(
        kind=kind,
        kind_label=TRUST_KIND_LABELS.get(kind, TRUST_KIND_LABELS[KIND_UNKNOWN]),
        legacy_type_label=legacy_trust_type_label(kind),
        within_forest=kind in WITHIN_FOREST_KINDS,
        direction=direction,
        direction_raw=direction_raw,
        transitivity=_resolve_transitivity(kind, flags),
        sid_filtering=sid_filtering,
        selective_authentication=_resolve_selective_authentication(kind, flags),
        tgt_delegation=tgt_delegation,
        trust_attributes=attributes,
        attribute_flags=tuple(flag_list),
        exposure_notes=tuple(notes),
        finding_keys=tuple(keys),
    )


def direction_sentence(
    direction: str, *, local_domain: str, partner_domain: str
) -> str:
    """Return one sentence naming who trusts whom, and what that permits.

    An arrowhead is not readable without a legend and a double arrow says
    nothing about which side accepts whose principals, so the direction is
    written out. The reading is MS-ADTS 6.1.6.7.12: an outbound trust means the
    domain holding the object trusts the partner, so the partner's principals
    can authenticate to this domain's resources.
    """
    local = str(local_domain or "this domain").strip()
    partner = str(partner_domain or "the partner domain").strip()
    if direction == DIRECTION_BIDIRECTIONAL:
        return (
            f"{local} and {partner} trust each other, so principals from "
            f"either side can authenticate to resources on the other."
        )
    if direction == DIRECTION_OUTBOUND:
        return (
            f"{local} trusts {partner}, so principals from {partner} can "
            f"authenticate to resources in {local}."
        )
    if direction == DIRECTION_INBOUND:
        return (
            f"{partner} trusts {local}, so principals from {local} can "
            f"authenticate to resources in {partner}."
        )
    if direction == DIRECTION_DISABLED:
        return (
            f"The trust between {local} and {partner} exists but is disabled, "
            f"so neither side accepts the other's principals."
        )
    return (
        f"A trust between {local} and {partner} was recorded without a "
        f"readable direction, so which side accepts the other's principals "
        f"was not determined."
    )


# Field list kept in one place so the API serializer, the DB model and the
# frontend type cannot drift apart silently.
FACT_FIELD_NAMES: tuple[str, ...] = (
    "trust_kind",
    "trust_kind_label",
    "within_forest",
    "direction",
    "trust_direction_raw",
    "transitivity",
    "transitivity_label",
    "sid_filtering",
    "sid_filtering_label",
    "selective_authentication",
    "selective_authentication_label",
    "tgt_delegation",
    "tgt_delegation_label",
    "trust_attributes",
    "attribute_flags",
    "exposure_notes",
    "finding_keys",
)

__all__: list[str] = [
    "FACT_FIELD_NAMES",
    "SELECTIVE_AUTH_ENABLED",
    "SELECTIVE_AUTH_LABELS",
    "SELECTIVE_AUTH_NOT_APPLICABLE",
    "SELECTIVE_AUTH_NOT_ENABLED",
    "SID_FILTERING_ABSENT_EXPOSURE_NOTE",
    "SID_FILTERING_ENFORCED",
    "SID_FILTERING_LABELS",
    "SID_FILTERING_NOT_APPLICABLE",
    "SID_FILTERING_NOT_APPLIED",
    "SID_FILTERING_RELAXED_EXPOSURE_NOTE",
    "SID_FILTERING_RELAXED_EXTERNAL",
    "SID_FILTERING_UNKNOWN",
    "TGT_DELEGATION_ENABLED",
    "TGT_DELEGATION_EXPOSURE_NOTE",
    "TGT_DELEGATION_LABELS",
    "TGT_DELEGATION_NOT_APPLICABLE",
    "TGT_DELEGATION_NOT_ENABLED",
    "TRANSITIVITY_LABELS",
    "TRANSITIVITY_NON_TRANSITIVE",
    "TRANSITIVITY_TRANSITIVE",
    "TRUST_ATTRIBUTE_BITS",
    "TRUST_ATTR_CROSS_ORG_TGT_DELEGATION",
    "TRUST_ATTR_QUARANTINED_DOMAIN",
    "TRUST_DIRECTIONS",
    "TRUST_DIRECTION_OPERATOR_LABELS",
    "TRUST_KINDS",
    "TRUST_KIND_LABELS",
    "TRUST_SID_FILTERING_FINDING_KEY",
    "TRUST_TGT_DELEGATION_FINDING_KEY",
    "DIRECTION_BIDIRECTIONAL",
    "DIRECTION_DISABLED",
    "DIRECTION_INBOUND",
    "DIRECTION_OUTBOUND",
    "DIRECTION_UNKNOWN",
    "KIND_AZURE_AD",
    "KIND_DCE",
    "KIND_DOWNLEVEL",
    "KIND_EXTERNAL",
    "KIND_FOREST",
    "KIND_PARENT_CHILD",
    "KIND_REALM",
    "KIND_TREE_ROOT",
    "KIND_UNKNOWN",
    "TrustFacts",
    "WITHIN_FOREST_KINDS",
    "classify_trust_kind",
    "decode_trust_attribute_flags",
    "decode_trust_facts",
    "direction_sentence",
    "is_dns_descendant",
    "legacy_trust_type_label",
    "normalize_trust_direction",
]
