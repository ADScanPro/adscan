"""Per-vulnerability affected-asset composition rules.

Affected assets are the TRUE per-vulnerability entities of a finding. What
"affected" means is not uniform across the catalog: an ADCS ESC finding is
affected at the enrolling principal(s) plus the abused certificate template and
CA; a Kerberoast finding is affected at the roastable service accounts; a
host-posture finding (SMB signing, SMBv1) is affected at the hosts that carry
the weak configuration; a domain-wide policy finding (weak password policy,
guest/null session) is affected at the domain object itself.

This module encodes that distinction as data — one :class:`AssetRule` per
finding-key (the ``VULN_CATALOG`` key) — so the composition logic in
``affected_assets.py`` is driven from a single, reviewable table instead of
scattered per-relation branches.

The owner's distinction, captured here:

* Keep the path TARGET except when it is a direct domain breaker (Domain
  Admins / Enterprise Admins / krbtgt / a DC) — those are where an escalation
  *lands*, not what the finding affects.
* Posture / configuration findings have no source/target principal split; they
  are host-scoped (from ``details.accounts``/``details.hosts``) or domain-wide.
* ESC findings surface the abused TEMPLATES and the CA as typed extras.
* Roasting findings surface the cracking WORDLIST as a context extra.
* Credential-in-share / GPP findings surface HOST, SHARE_PATH, ARTIFACT and a
  REDACTED password as context.

The affected asset must be a LOCATOR the reader can act on, never a category.
"A secret matched the ``DOC_CREDENTIALS`` detector" tells a sysadmin nothing;
``\\\\10.0.0.5\\HR\\Notice from HR.txt`` tells them which file to clear. Same for
an attribute leak: the account and the attribute holding the secret, not the
domain the account lives in.

**Every finding key gets an explicit rule.** A key with no rule used to fall
through to a last-resort scan that emitted whatever list the details happened to
carry — which is how CredSweeper detector names ("CMD ConvertTo-SecureString")
reached a client PDF as "affected assets". That scan is now opt-in per rule
(:attr:`AssetRule.scan_details_lists`) and off by default, so an unmapped key
degrades to the domain object: vague, but never wrong. A wrong asset is worse
than a vague one, because the client acts on it.

The coverage is enforced, not conventional: ``tests/unit/pro/reporting/
test_affected_asset_rules_drift.py`` fails the build when a ``VULN_CATALOG`` key
has no rule here, or when a rule names a key that exists nowhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class SourceMode(str, Enum):
    """Whether the FLAT extractor reads a finding's top-level source-principal keys.

    Narrow by design, and narrower than the name suggests: ``PRINCIPALS`` makes
    ``affected_assets._extract_registry_extras_from_details`` read the detail
    keys ``from`` / ``source`` / ``source_user`` / ``source_username`` / ``user``
    / ``username`` / ``credential_username`` off the TOP level of the finding's
    details, and makes ``_source_principal_names`` label those same values
    ``role="source"`` in the machine-readable appendix. That is all it does.

    It does **not** make the structured builder surface a source entity —
    :class:`Representation` decides that, and it defaults to ``TARGET_ONLY``. So
    a rule can declare ``PRINCIPALS`` and surface no principal at all, silently:
    the finding still renders, just without the account, and the tier-aware
    severity overlay (which grades a finding by the privilege tier of its
    affected assets) has nothing to grade. ``smb_share_secrets`` shipped in
    exactly that state. The two fields are not redundant and must not be
    collapsed — ``dcsync`` legitimately pairs ``source=NONE`` with
    ``representation=BOTH``, because its holder arrives from the attack-graph
    edge rather than from a top-level detail key — but a rule declaring
    ``PRINCIPALS`` whose representation drops the source role has to name the
    channel its principals really arrive through. That pairing is checked by
    ``tests/unit/pro/reporting/test_affected_asset_rules_drift.py``.
    """

    NONE = "none"
    PRINCIPALS = "principals"


class TargetMode(str, Enum):
    """How a finding's TARGET contributes to affected assets."""

    NONE = "none"
    KEEP = "keep"
    DROP_BREAKER = "drop_breaker"


class Scope(str, Enum):
    """The blast-radius shape of a finding.

    ``DC_SCOPED`` is a refinement of ``HOST_SCOPED`` for posture findings that
    the DC answered for directly (LDAP signing / channel binding, NTLM accepted,
    RC4 accepted, LDAPS unavailable). Their ``details`` carry only the domain —
    not a host list — so the affected host is resolved to the domain
    controller(s) of that domain. The owner's rule: these list the DC host(s)
    with BOTH IP and FQDN, never the bare domain object.
    """

    PER_PRINCIPAL = "per_principal"
    HOST_SCOPED = "host_scoped"
    DC_SCOPED = "dc_scoped"
    DOMAIN_WIDE = "domain_wide"


class Extra(str, Enum):
    """Optional typed context surfaced alongside affected assets."""

    TEMPLATES = "templates"
    CA = "ca"
    HOST = "host"
    SHARE_PATH = "share_path"
    ARTIFACT = "artifact"
    WORDLIST = "wordlist"
    PASSWORD_REDACTED = "password_redacted"
    # The measured objects with effective READ access to the affected file (the
    # mxac/read-set SSOT, carried on the finding's ``details.read_set``). Lets a
    # credential-in-file finding name WHO can read it — directly actionable
    # (tighten the share/NTFS ACL). Measured only; never a guessed set.
    READ_SET = "read_set"
    # An "reachable over an unauthenticated null/guest session" access vector,
    # surfaced only when the finding carries a PROVEN ``unauthenticated_reachable``
    # + ``reached_via`` (never from a broad SID alone — the Everyone != Anonymous
    # guard). Reuses the existing null-session-asset concept at the finding level.
    NULL_SESSION_VECTOR = "null_session_vector"


class RecordEntityType(str, Enum):
    """Structured entity type a rule forces for its own record containers.

    Mirrors the ``TYPE_*`` constants in :mod:`affected_assets_struct` (which
    cannot be imported here — it imports this module). Left unset, a record is
    resolved as a principal (user / computer); set it when the records are a
    different kind of object entirely, e.g. the partner DOMAIN of a trust.
    """

    DOMAIN = "domain"


class Representation(str, Enum):
    """The per-finding SHAPE of its affected assets.

    Where :class:`SourceMode` / :class:`TargetMode` / :class:`Scope` are the
    MECHANICAL read-hints the flat extractor uses, this is the DECLARATIVE intent
    of what the finding affects — so the structured builder can emit the right
    object(s) with the right role regardless of which legacy read-mode happens to
    carry them.

    * ``TARGET_ONLY`` — the affected asset is the target object(s); no source.
      Every object-hygiene / posture / host-config / domain-config finding, plus
      roasting (the roaster precondition is noise), the host-CVE / coercion
      families, and the CA-flag ADCS ESCs.
    * ``SOURCE_ONLY`` — the affected asset is the source principal(s). Rare; most
      "source" cases are ``BOTH``.
    * ``BOTH`` — the relation ``source -> target``, both named by role: DCSync
      (holder -> domain), delegation, cross-domain/cross-forest escalation, the
      ADCS enrollment ESCs.
    * ``PAIRING`` — per-edge pairs preserved (not two flat lists), so the reader
      sees who-can-do-what-to-whom: HasSession (``user @ host``),
      ForceChangePassword / shadow-creds / LAPS / gMSA (holder -> object), RBCD,
      NTLMv1-relay.
    """

    TARGET_ONLY = "target_only"
    SOURCE_ONLY = "source_only"
    BOTH = "both"
    PAIRING = "pairing"

    @property
    def wants_source(self) -> bool:
        """Return whether the finding surfaces its SOURCE principal(s)."""
        return self in (
            Representation.SOURCE_ONLY,
            Representation.BOTH,
            Representation.PAIRING,
        )

    @property
    def wants_target(self) -> bool:
        """Return whether the finding surfaces its TARGET object(s)."""
        return self in (
            Representation.TARGET_ONLY,
            Representation.BOTH,
            Representation.PAIRING,
        )


@dataclass(frozen=True)
class AssetRule:
    """Declarative composition rule for one finding's affected assets.

    Attributes:
        source: Whether/how source principals are included.
        target: Whether/how the path target is included.
        extras: Typed context to surface (templates, CA, host, share, ...).
        scope: The blast-radius shape (per-principal / host / domain-wide).
        record_containers: Extra ``details`` keys holding the finding's own
            per-principal records, on top of the conventional ``accounts`` /
            ``hosts``. Some detectors persist their affected accounts under a
            detector-specific key (``findings``, ``samples``); naming it here
            keeps the scan generic-key-safe — a finding never picks up an
            unrelated list just because it happens to be called ``findings``.
        record_qualifier: Field inside each record that says WHICH part of the
            principal is affected (e.g. the LDAP attribute holding a secret).
            Appended to the display so the reader gets ``jdoe · description``
            instead of a bare account name. A list value is joined, so a record
            carrying several SPNs still reads as one line. Empty when there is
            nothing to qualify.
        record_name_field: Field inside each record that NAMES it, checked ahead
            of the conventional ``samaccountname`` / ``name`` / ``hostname``
            keys. Needed when a detector keys its records on its own vocabulary
            (a trust names its counterpart ``partner``).
        record_entity_type: Forces the structured entity type for records from
            ``record_containers`` (see :class:`RecordEntityType`). Unset, the
            record is resolved as a principal.
        scan_details_lists: Opt in to the last-resort scan that treats ANY list
            in the finding details as affected assets. Off by default and
            deliberately so: it is what turned detector rule names into
            "affected assets" in a client report. Turn it on only for a finding
            whose asset list genuinely has no stable key, and say why.
        collapse_exchange_system_targets: Collapse Exchange health/system mailbox
            targets (HealthMailbox*, SM_*, SystemMailbox, DiscoverySearchMailbox,
            FederatedEmail, Migration.*) into a SINGLE annotated inline row on the
            deliverable PDF, instead of dumping 30+ individual mailbox rows. An
            ACL-over-user finding (ForceChangePassword) on an Exchange domain is
            dominated by the Exchange management groups resetting their own system
            mailboxes, which is expected self-management. Left flat, an
            Exchange-savvy reader dismisses the whole finding; the collapse keeps
            the genuinely over-scoped human/service-account grants itemized and
            de-emphasizes the by-design noise. Display-only: the machine-readable
            appendix and the structured entities keep every mailbox.
        representation: The declarative SHAPE of the finding's affected assets
            (see :class:`Representation`). The structured builder uses it to
            decide whether to surface the SOURCE principal(s), the TARGET
            object(s), or both, and whether to preserve per-edge pairs — the
            single SSOT for "what does this finding affect", decoupled from the
            legacy read-modes above. Defaults to ``TARGET_ONLY`` so the ~40
            object-centric / posture findings inherit the object-only shape with
            no per-key branch.
        role_labels: Maps a structured entity's role axis
            (``source`` / ``target`` / ``affected`` / ``template`` / ``ca``) to
            the client-facing role LABEL for this finding (``holder``,
            ``roastable-target``, ``session-host``, ``delegating-account``, …).
            Stored as a tuple of pairs so the rule stays frozen/hashable; read
            via :meth:`role_label_for`. Empty when the generic role is label
            enough.
    """

    source: SourceMode = SourceMode.PRINCIPALS
    target: TargetMode = TargetMode.KEEP
    extras: tuple[Extra, ...] = field(default_factory=tuple)
    scope: Scope = Scope.PER_PRINCIPAL
    record_containers: tuple[str, ...] = field(default_factory=tuple)
    record_qualifier: str = ""
    record_name_field: str = ""
    record_entity_type: str = ""
    scan_details_lists: bool = False
    collapse_exchange_system_targets: bool = False
    representation: Representation = Representation.TARGET_ONLY
    role_labels: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    #: For a PAIRING finding whose constituent edges carry DIFFERENT relations
    #: (the grouped "Excessive Rights Across a Tier Boundary" finding collects
    #: GenericAll / WriteDacl / ForceChangePassword / AllExtendedRights / … under
    #: one key), surface the specific right per pair so the client reads
    #: ``holder (tier) -> <right> -> controlled-object (tier)`` rather than a bare
    #: arrow that hides WHICH excessive right each entry is. Off by default: a
    #: single-relation PAIRING finding (sessions, LAPS, gMSA) needs no per-pair
    #: right and its connector stays the plain arrow.
    show_relation_in_pairing: bool = False

    def role_label_for(self, role: str) -> str:
        """Return this finding's client role LABEL for a structured role, or ``""``.

        ``role`` is the structured axis (``source`` / ``target`` / ``affected``
        / ``template`` / ``ca``); the returned label is the finding-specific
        name the deliverable renders (``holder`` for a DCSync source, …).
        """
        key = str(role or "").strip().lower()
        for candidate, label in self.role_labels:
            if candidate == key:
                return label
        return ""


# Fallback for a finding key with no rule. Source principals + non-breaker
# target, and NO last-resort details scan: an unmapped finding degrades to the
# domain object rather than to whatever list its details happen to hold.
DEFAULT_RULE = AssetRule(
    source=SourceMode.PRINCIPALS,
    target=TargetMode.KEEP,
    extras=(),
    scope=Scope.PER_PRINCIPAL,
)


#: Role labels shared by every ADCS ESC finding for its typed template / CA.
_ADCS_TEMPLATE_CA_LABELS: tuple[tuple[str, str], ...] = (
    ("template", "vulnerable-template"),
    ("ca", "certificate-authority"),
)


def _adcs_rule(
    *,
    representation: Representation = Representation.BOTH,
    source_label: str = "enrollee",
) -> AssetRule:
    """Shared rule for an ADCS ESC finding (templates + CA, breaker dropped).

    ``representation`` is ``BOTH`` for the enrollment / ACL ESCs (the enrolling
    or writing principal plus the abused template / CA) and ``TARGET_ONLY`` for
    the CA-flag / web-enrollment ESCs (ESC6/8/11/16 and certighost), where the
    affected asset is the CA itself and the broad source principal is noise.
    ``source_label`` names the client role of the source principal when one is
    surfaced.

    Every per-source field hangs off that ONE switch — the role label, and the
    :class:`SourceMode` read too. A CA-flag ESC that kept declaring
    ``SourceMode.PRINCIPALS`` while its representation dropped the source role
    was claiming to surface an enrolling principal it could never emit; the
    declaration now follows the shape, so the two cannot drift apart as new ESCs
    are added.
    """
    role_labels: tuple[tuple[str, str], ...] = _ADCS_TEMPLATE_CA_LABELS
    if representation.wants_source and source_label:
        role_labels = (("source", source_label), *role_labels)
    return AssetRule(
        source=(
            SourceMode.PRINCIPALS
            if representation.wants_source
            else SourceMode.NONE
        ),
        target=TargetMode.DROP_BREAKER,
        extras=(Extra.TEMPLATES, Extra.CA),
        scope=Scope.PER_PRINCIPAL,
        representation=representation,
        role_labels=role_labels,
    )


def _attack_step_rule(
    *,
    source: SourceMode = SourceMode.PRINCIPALS,
    representation: Representation | None = None,
    role_labels: tuple[tuple[str, str], ...] = (),
) -> AssetRule:
    """Shared rule for a finding materialized from an attack-graph edge.

    The edge SOURCE is who can abuse it, the edge TARGET is what gets taken
    over; both are affected assets of the finding. ``source=NONE`` for the CVE
    families whose edge source is the scanner itself rather than a client
    principal. ``representation`` / ``role_labels`` declare the finding's shape
    and client role labels for the structured builder.

    When ``representation`` is left unset it defaults to ``BOTH`` for a
    source-bearing finding and ``TARGET_ONLY`` for a ``source=NONE`` one — so a
    CVE whose edge source is the scanner never surfaces a bogus source entity.
    """
    if representation is None:
        representation = (
            Representation.BOTH
            if source is SourceMode.PRINCIPALS
            else Representation.TARGET_ONLY
        )
    return AssetRule(
        source=source,
        target=TargetMode.KEEP,
        scope=Scope.PER_PRINCIPAL,
        representation=representation,
        role_labels=role_labels,
    )


def _host_list_rule(*containers: str, scope: Scope = Scope.HOST_SCOPED) -> AssetRule:
    """Shared rule for a posture finding that persists its own host lists.

    The affected assets are the hosts the detector recorded, taken from the
    detector's own containers (``dcs`` / ``non_dcs`` / ``all_computers`` …), and
    resolved to FQDN + IP on the structured side.

    ``scope`` stays ``HOST_SCOPED`` when the host list is the ONLY source. A
    finding that can also arrive as an attack-graph edge passes
    ``PER_PRINCIPAL`` so the edge endpoints are read as well.
    """
    return AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=scope,
        record_containers=containers,
    )


#: Shared rule for the five coercion primitives — see the table entries.
_COERCION_RULE = _host_list_rule(
    "dcs", "non_dcs", "all_computers", scope=Scope.PER_PRINCIPAL
)

#: Rule keys that are live finding keys but carry no ``VULN_CATALOG`` entry.
#: The drift test allows exactly these and nothing else, so a typo in a rule key
#: still fails the build.
NON_CATALOG_RULE_KEYS: frozenset[str] = frozenset(
    {
        # Emitted by the unauthenticated LDAP/SAMR description sweep; predates
        # the catalog entry ``credential_in_ldap_attribute`` and still ships.
        "ldap_user_description_password_leak",
        # Emitted by the null-session probe alongside ``smb_null_domain``.
        "smb_null_session",
        # Emitted by the Tier-0 identity concentration check. The catalog knows
        # it as ``tier0_highvalue_sprawl``; the detector still writes this key.
        "control_exposure_sprawl",
    }
)


# ADCS ESC families by representation (see the per-finding mapping table):
#   * enrollment ESCs — the enrolling principal -> the vulnerable template (+CA).
#   * ACL ESCs — the writing/holding principal -> the template or CA ACL.
#   * CA-flag / web-enrollment ESCs — the CA itself (dangerous flag / HTTP enroll);
#     the broad source principal is noise, so TARGET_ONLY.
_ADCS_ESC_ENROLLMENT: tuple[str, ...] = tuple(
    f"adcs_esc{n}" for n in (1, 2, 3, 9, 10, 13, 15, 17)
)
_ADCS_ESC_ACL_HOLDER: tuple[str, ...] = tuple(f"adcs_esc{n}" for n in (4, 5, 7, 14))
_ADCS_ESC_CA_FLAG: tuple[str, ...] = tuple(f"adcs_esc{n}" for n in (6, 8, 11, 16))


# Keyed by the canonical VULN_CATALOG finding-key.
AFFECTED_ASSET_RULES: dict[str, AssetRule] = {
    # --- ADCS ESC findings: enrolling/holding principal + abused template + CA
    **{
        key: _adcs_rule(representation=Representation.BOTH, source_label="enrollee")
        for key in _ADCS_ESC_ENROLLMENT
    },
    **{
        key: _adcs_rule(representation=Representation.BOTH, source_label="holder")
        for key in _ADCS_ESC_ACL_HOLDER
    },
    **{
        key: _adcs_rule(representation=Representation.TARGET_ONLY)
        for key in _ADCS_ESC_CA_FLAG
    },
    # Certighost (CVE-2026-54121): the affected asset is the certificate
    # authority itself (a CA-level EditFlags + patch weakness), so TARGET_ONLY,
    # mirroring the ESC6/8/11/16 CA-flag findings.
    "certighost": _adcs_rule(representation=Representation.TARGET_ONLY),
    # --- Decommissioned CA still trusted in NTAuthCertificates ----------------
    # The affected assets are the retired CA host(s), carried as
    # details.certificate_authorities[] keyed by ``ca_host``. The host is orphaned
    # (no live computer object), so it is surfaced as the record itself rather than
    # resolved against the graph — the trust anchor to withdraw, not an enrolling
    # principal. HOST_SCOPED so iter_account_records reads the record container.
    "adcs_orphaned_ca_ntauth": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
        record_containers=("certificate_authorities",),
        record_name_field="ca_host",
        role_labels=(("affected", "decommissioned-ca"),),
    ),
    # --- Roasting: roastable principals + the cracking wordlist --------------
    # TARGET_ONLY: the affected asset is the roastable service account; the edge
    # SOURCE (Authenticated Users — anyone can request the ticket) is a
    # precondition, not an asset, so the structured builder drops it.
    "kerberoast": AssetRule(
        source=SourceMode.PRINCIPALS,
        target=TargetMode.KEEP,
        extras=(Extra.WORDLIST,),
        scope=Scope.PER_PRINCIPAL,
        representation=Representation.TARGET_ONLY,
        role_labels=(("target", "roastable-target"),),
    ),
    "asreproast": AssetRule(
        source=SourceMode.PRINCIPALS,
        target=TargetMode.KEEP,
        extras=(Extra.WORDLIST,),
        scope=Scope.PER_PRINCIPAL,
        representation=Representation.TARGET_ONLY,
        role_labels=(("target", "asrep-roastable-target"),),
    ),
    # Timeroast: the affected asset is the CRACKED machine account (the edge is
    # emitted only on a successful crack), so the target computer is what gets
    # named. The entry-vector source (ANONYMOUS LOGON) is noise, hence TARGET_ONLY.
    "timeroast": AssetRule(
        source=SourceMode.PRINCIPALS,
        target=TargetMode.KEEP,
        extras=(Extra.WORDLIST,),
        scope=Scope.PER_PRINCIPAL,
        representation=Representation.TARGET_ONLY,
        role_labels=(("target", "cracked-machine-account"),),
    ),
    # --- Delegation: principals + the delegation target (kept, not a breaker) -
    # Constrained delegation: the delegating account (what you re-scope) and the
    # target service(s) it can impersonate to (the blast radius), both named.
    "constrained_delegation": AssetRule(
        source=SourceMode.PRINCIPALS,
        target=TargetMode.KEEP,
        scope=Scope.PER_PRINCIPAL,
        representation=Representation.BOTH,
        role_labels=(
            ("source", "delegating-account"),
            ("target", "target-service"),
        ),
    ),
    # RBCD (AllowedToAct): the grantee principal -> the target computer whose
    # ``msDS-AllowedToActOnBehalfOfOtherIdentity`` is the object to clear.
    "rbcd_configured": AssetRule(
        source=SourceMode.PRINCIPALS,
        target=TargetMode.KEEP,
        scope=Scope.PER_PRINCIPAL,
        representation=Representation.PAIRING,
        role_labels=(("source", "grantee"), ("target", "at-risk")),
    ),
    # Unconstrained delegation: the delegating host (UAC bit) is the affected
    # asset; the broad source is noise, so TARGET_ONLY.
    "unconstrained_delegation": AssetRule(
        source=SourceMode.PRINCIPALS,
        target=TargetMode.KEEP,
        scope=Scope.PER_PRINCIPAL,
        representation=Representation.TARGET_ONLY,
        role_labels=(("target", "delegating-host"),),
    ),
    # --- Credentials in shares: principals + host + share + redacted secret --
    # The exposed ACCOUNT is an affected asset of this finding, not only the file
    # holding its password: it is what the client rotates, and its privilege tier
    # is what makes the finding critical rather than routine. The producer writes
    # the account the source file named next to each secret into that hit's
    # ``secret_locations`` record (``principal``), so the record walker surfaces
    # it with the AFFECTED role and the stamped tier. A hit the file named no
    # owner for contributes no principal and its file entry stands alone.
    "smb_share_secrets": AssetRule(
        source=SourceMode.PRINCIPALS,
        target=TargetMode.KEEP,
        extras=(Extra.HOST, Extra.SHARE_PATH, Extra.PASSWORD_REDACTED),
        scope=Scope.PER_PRINCIPAL,
        record_containers=("secret_locations",),
        record_name_field="principal",
    ),
    # --- Secrets in directory attributes: the account AND the attribute ------
    # Both detectors persist one record per leaking account under their own
    # container key. The affected asset is that account plus the attribute the
    # secret sits in — the two things a sysadmin needs to go clear it. Without a
    # rule these fell through to the domain object, which is unactionable.
    # The CANONICAL key of the description-secret alias family, so this rule is
    # what runs over the MERGED record when more than one of the three
    # detectors fired. It therefore reads every detector's own container —
    # ``findings`` (credential-field analyzer and unauthenticated sweep) and
    # ``samples`` (LDAP description sweep) — or the merged finding would list
    # only the accounts one producer happened to see.
    "credential_in_ldap_attribute": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
        record_containers=("findings", "samples"),
        record_qualifier="field",
    ),
    "ldap_user_description_password_leak": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
        record_containers=("samples",),
        # This detector sweeps every credential-bearing attribute, not only
        # ``description``, so each sample names the attribute the secret sits
        # in — the same qualifier the canonical merged rule above reads.
        record_qualifier="field",
    ),
    # The unauthenticated-enrichment sibling of the two above. Read from the
    # producer (``cli/scan.py`` ``record_technical_finding(key=
    # "user_description_credential_leak")``) rather than inferred from the
    # name: it writes ONE record per hit into ``details`` carrying
    # ``username`` + ``field``, so it takes the ``findings`` container and the
    # ``field`` qualifier like ``credential_in_ldap_attribute`` — NOT the
    # ``samples`` shape its closer-sounding neighbour above uses.
    "user_description_credential_leak": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
        record_containers=("findings",),
        record_qualifier="field",
    ),
    # --- GPP passwords: the SYSVOL artifact + redacted secret, plus the
    # two-axis unauthenticated-reach context -----------------------------------
    # One canonical GPP-cpassword finding. Beyond the SYSVOL artifact and the
    # redacted recovered secret, the affected assets carry the two facts the
    # client needs to remediate, both honesty-gated on the finding's own details:
    #   * READ_SET — the measured objects with effective READ access to the file
    #     (``details.read_set``, from the mxac/read-set SSOT); the client tightens
    #     the share/NTFS ACL. Present only when the read-set was measured.
    #   * NULL_SESSION_VECTOR — an "reachable over an unauthenticated null/guest
    #     session" access vector, surfaced only when the finding carries
    #     ``unauthenticated_reachable`` + a proven ``reached_via`` (an
    #     authenticated-only GPP finding shows the read-set but NOT this vector).
    # The exposed ACCOUNT is an affected asset here too: the GPP XML names the
    # owner in the same entry as the ``cpassword``, so both producers (the share
    # / loot scan and the unauthenticated enrichment sweep) carry it. Read from
    # BOTH vocabularies — the list every owner lands in and the single
    # ``username`` the unauth sweep writes — so the merged finding names every
    # account it observed rather than whichever producer ran last.
    "gpp_passwords": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.KEEP,
        extras=(
            Extra.ARTIFACT,
            Extra.PASSWORD_REDACTED,
            Extra.READ_SET,
            Extra.NULL_SESSION_VECTOR,
        ),
        scope=Scope.PER_PRINCIPAL,
        record_containers=("credential_username", "username"),
    ),
    # --- DCSync: the holder of the replication right -> the domain (scope) ----
    # BOTH: the client cannot remediate the domain object; what they fix is the
    # non-Tier-0 principal HOLDING the DS-Replication ACE. The structured builder
    # surfaces that holder (edge source) alongside the domain it replicates (the
    # DOMAIN_WIDE scope base, relabelled ``scope``). The flat side keeps the
    # domain-wide shape unchanged.
    "dcsync": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.DROP_BREAKER,
        scope=Scope.DOMAIN_WIDE,
        representation=Representation.BOTH,
        role_labels=(("source", "holder"), ("affected", "scope")),
    ),
    # --- Accounts whose plaintext password was recovered ----------------------
    # The affected objects are the ACCOUNTS, named, with the administrative ones
    # first (the engine orders them that way): what the client acts on is a list
    # of accounts to reset, not a count.
    "recovered_account_passwords": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.PER_PRINCIPAL,
    ),
    # --- Directory replication to a tenant that is not the organization's -----
    # The affected object is the SYNC ACCOUNT, not the domain: what the client
    # confirms or revokes is that one account's replication grant. The engine
    # persists one record per account under ``accounts`` carrying the tenant it
    # replicates to, and the qualifier surfaces that tenant next to the account
    # (``msol_… · fabrikam0.onmicrosoft.com``) so the reader sees WHICH account
    # ships credentials WHERE without opening the appendix.
    "unauthorized_external_tenant_replication": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.PER_PRINCIPAL,
        record_qualifier="sync_target",
    ),
    # --- Excessive rights across a tier boundary (grouped control finding) ----
    # The generic control primitives (GenericAll / GenericWrite / WriteDacl /
    # WriteOwner / Owns / AddMember / AddSelf / WriteSPN / AddKeyCredentialLink /
    # WriteAccountRestrictions / WriteLogonScript) PLUS ForceChangePassword and
    # AllExtendedRights share one grouped finding: a lower-tier holder that
    # controls a higher-tier object. PAIRING keeps each edge's holder -> object
    # pair, and ``show_relation_in_pairing`` surfaces the specific right per pair
    # (``holder (tier) -> Full Control of the Target Object -> object (tier)``) so
    # the one finding does not hide WHICH excessive right each entry is. The
    # Exchange self-management collapse is kept: on an Exchange domain the reset
    # grants over health/system mailboxes are by-design noise that would bury the
    # genuinely over-scoped cross-tier grants.
    "excessive_cross_tier_rights": AssetRule(
        source=SourceMode.PRINCIPALS,
        target=TargetMode.KEEP,
        scope=Scope.PER_PRINCIPAL,
        collapse_exchange_system_targets=True,
        representation=Representation.PAIRING,
        role_labels=(("source", "holder"), ("target", "controlled-object")),
        show_relation_in_pairing=True,
    ),
    # --- Session exposure ----------------------------------------------------
    # A privileged session on a lower-tier host: the edge (``Computer ->
    # HasSession -> User``) names the host the session sits on (source) and the
    # privileged account exposed on it (target). PAIRING keeps the pair so the
    # client sees WHICH privileged user is exposed on WHICH host and can go clear
    # that one session.
    "da_sessions": _attack_step_rule(
        representation=Representation.PAIRING,
        role_labels=(("source", "session-host"), ("target", "logged-on-user")),
    ),
    # --- Readable managed secrets (gMSA / LAPS) ------------------------------
    # PAIRING: the holder who can read the secret -> the account (gMSA) / machine
    # (LAPS) whose password is at risk. The remediator needs both — which object
    # to re-scope and whose access to remove.
    "gmsa_readable": _attack_step_rule(
        representation=Representation.PAIRING,
        role_labels=(("source", "holder"), ("target", "at-risk")),
    ),
    "laps_readable": _attack_step_rule(
        representation=Representation.PAIRING,
        role_labels=(("source", "holder"), ("target", "at-risk")),
    ),
    # --- Shadow credentials --------------------------------------------------
    # PAIRING: the holder who can write ``msDS-KeyCredentialLink`` -> the target
    # object whose key material they can forge. The detector records one entry per
    # object carrying a value (the at-risk targets); an attack-graph edge adds the
    # holder when present.
    "shadow_credentials_present": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
        record_containers=("objects",),
        representation=Representation.PAIRING,
        role_labels=(
            ("source", "holder"),
            ("target", "at-risk"),
            ("affected", "at-risk"),
        ),
    ),
    # --- SQL Server bulk-operations over-privilege ---------------------------
    # The MSSQL collector records one entry per NON-sysadmin principal holding
    # ADMINISTER BULK OPERATIONS, under ``principals`` — each names the principal
    # (``principal``) and the SQL host it holds the permission on (``instance``),
    # which qualifies WHICH instance is exposed. No source/target principal split
    # (it is a config over-privilege, not a traversal).
    "mssql_bulk_operations_overprivilege": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
        record_containers=("principals",),
        record_name_field="principal",
        record_qualifier="instance",
    ),
    # --- NTLMv1 escalation avenues -------------------------------------------
    # The affected asset is the machine account whose NetNTLMv1 response is
    # recoverable (typically a DC) — the edge TARGET, plus the ``dc_hosts`` /
    # ``tier_zero_accounts`` the detector stamps from those same targets so the
    # asset survives even when the edge is summarized away. The edge SOURCE is
    # dropped: on these it is Domain Users (anyone), which names no asset a
    # remediator can act on and only dilutes the list.
    # crackntlmv1: TARGET_ONLY — the at-risk machine account(s) whose NetNTLMv1
    # response is recoverable; the broad edge source (Domain Users) is noise.
    "ntlmv1_crack": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.KEEP,
        scope=Scope.PER_PRINCIPAL,
        record_containers=("dc_hosts", "tier_zero_accounts"),
        role_labels=(("target", "at-risk"),),
    ),
    # ntlmv1relay{rbcd,shadowcreds}: PAIRING — the coercible source host whose
    # NetNTLMv1 is relayed -> the relay-target it is relayed to. Remediate by
    # disabling NTLMv1 and enforcing SMB/LDAP signing + EPA.
    "ntlmv1_relay_rbcd": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.KEEP,
        scope=Scope.PER_PRINCIPAL,
        record_containers=("dc_hosts", "tier_zero_accounts"),
        representation=Representation.PAIRING,
        role_labels=(("source", "coercible-host"), ("target", "relay-target")),
    ),
    "ntlmv1_relay_shadowcreds": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.KEEP,
        scope=Scope.PER_PRINCIPAL,
        record_containers=("dc_hosts", "tier_zero_accounts"),
        representation=Representation.PAIRING,
        role_labels=(("source", "coercible-host"), ("target", "relay-target")),
    ),
    # --- Remotely exploitable CVEs -------------------------------------------
    # The affected asset is the vulnerable host on the edge TARGET. The edge
    # source of a CVE probe is the scanner, not a client principal, so it is
    # dropped — naming it would put ADscan itself in the client's asset list.
    # TARGET_ONLY (the _attack_step_rule default for a ``source=NONE`` finding).
    "zerologon": _attack_step_rule(
        source=SourceMode.NONE, role_labels=(("target", "vulnerable-host"),)
    ),
    "nopac": _attack_step_rule(
        source=SourceMode.NONE, role_labels=(("target", "vulnerable-host"),)
    ),
    "printnightmare": _attack_step_rule(
        source=SourceMode.NONE, role_labels=(("target", "vulnerable-host"),)
    ),
    "ms17-010": _attack_step_rule(
        source=SourceMode.NONE, role_labels=(("target", "vulnerable-host"),)
    ),
    # --- Coercion primitives -------------------------------------------------
    # Each records the hosts that answered the coercion call, split DC / non-DC.
    # They also materialize from an attack-graph edge when the coercion is part
    # of a chain, so both sources are read: ``PER_PRINCIPAL`` for the edge, the
    # containers for the probe's own host list.
    "petitpotam": _COERCION_RULE,
    "printerbug": _COERCION_RULE,
    "dfscoerce": _COERCION_RULE,
    "mseven": _COERCION_RULE,
    "webdav": _COERCION_RULE,
    # --- Relay surface / LAPS coverage (host inventories) --------------------
    "smb_relay_targets": _host_list_rule("dcs", "non_dcs", "all_computers", "sample"),
    # ``laps`` is the coverage gap: the hosts with NO LAPS-managed password.
    "laps": _host_list_rule("dcs", "non_dcs", "all_computers"),
    # --- Kerberos web-service (HTTP SPN) relay surface -----------------------
    # One record per principal publishing an HTTP SPN; the SPN itself qualifies
    # which service on that principal is the exposure.
    "http_spn_relay_surface": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
        record_qualifier="http_spns",
    ),
    # --- Intra-forest child->forest-root escalation (RaiseChild) -------------
    # Materialized from a derived escalation edge (``couple_raise_child_edges``):
    # ``from`` = the compromised child domain node, ``to`` = the parent /
    # forest-root domain it escalates INTO. The forest root is the asset taken
    # over (target), the child-domain principals are who abuse it (source) — the
    # standard attack-step edge shape, both endpoints carried on the edge. BOTH:
    # name both domains (they are different domains in one forest).
    "raise_child_forest_root": _attack_step_rule(
        representation=Representation.BOTH,
        role_labels=(
            ("source", "child-domain"),
            ("target", "forest-root-domain"),
        ),
    ),
    # --- Trust posture: the partner domain on the far side of the trust ------
    # The locator is the counterpart domain, qualified by the trust type, so the
    # reader knows which trust relationship to go reconfigure.
    "trust_sid_filtering_disabled": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
        record_containers=("trusts",),
        record_name_field="partner",
        record_qualifier="trust_type",
        record_entity_type=RecordEntityType.DOMAIN.value,
    ),
    "trust_tgt_delegation_enabled": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
        record_containers=("trusts",),
        record_name_field="partner",
        record_qualifier="trust_type",
        record_entity_type=RecordEntityType.DOMAIN.value,
    ),
    # --- Host-posture findings (carry their own host/account list) -----------
    # These persist their affected hosts as ``details.accounts[]`` /
    # ``details.hosts[]`` keyed by sAMAccountName (+ object_id SID). The host
    # representation is resolved to BOTH IP and FQDN at composition time.
    "smb_signing_disabled": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
    ),
    # The verdict is per-host (the SAMR stage runs against each computer), so the
    # affected asset is the host(s) whose SAM-RPC interface answered a non-admin
    # session — resolved from the direct host keys, like smb_signing_disabled.
    "smbv1_enabled": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
    ),
    # Canonical key of the SMBv1 alias family. No extra containers are needed:
    # the SMB scan posture path persists its hosts under ``all_computers`` /
    # ``dcs`` / ``non_dcs``, which the direct-asset keys already harvest, so a
    # merged record names every host either producer saw.
    "smb_v1_enabled": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
    ),
    "smb_guest_shares": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
    ),
    # --- Host-local registry credential-protection posture --------------------
    # Admin-gated \winreg reads (audit_analyzer._registry_hardening_findings). The
    # verdict is per-host, so the affected asset is the host(s) whose HKLM value
    # was observed insecure — resolved from the direct host keys, exactly like
    # smb_signing_disabled.
    "lsa_protection_disabled": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
    ),
    "wdigest_enabled": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
    ),
    "lm_hash_storage_enabled": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
    ),
    "weak_lm_compatibility_level": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
    ),
    "ntlm_min_session_security_weak": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
    ),
    "lsass_custom_ssp_allowed": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
    ),
    # The host to go disable NTLMv1 on, not the domain. Two producer shapes:
    # the coercion capture names the machine account it observed
    # (``captured_user``); the attack-graph materialization stamps the same
    # victims into ``dc_hosts`` / ``tier_zero_accounts``.
    "ntlmv1_enabled": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
        record_containers=("captured_user", "dc_hosts", "tier_zero_accounts"),
    ),
    "obsolete_computers": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
    ),
    "stale_enabled_computers": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
    ),
    "duplicate_computer_dns": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
    ),
    "machine_password_rotation_disabled": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
    ),
    "machine_password_rotation_relaxed": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
    ),
    # --- Account-posture findings (per-user, sAMAccountName) ------------------
    "password_not_req": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
    ),
    "password_not_required": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
    ),
    "password_never_expires": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
    ),
    # The identity-hygiene sweep records one entry per account under the same
    # ``accounts`` container as the rules above (sAMAccountName + object SID).
    "stale_enabled_users": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
    ),
    "stale_passwords": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
    ),
    "rc4_only_accounts": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
    ),
    # The krbtgt account itself is the record the age check writes.
    "krbtgt_password_age": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
    ),
    # Live key for the Tier-0 identity concentration check (catalog name:
    # ``tier0_highvalue_sprawl``). The affected accounts are the control-exposed
    # identities the check intersected out of the enabled-user baseline.
    "control_exposure_sprawl": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
        record_containers=("control_exposure_users",),
    ),
    # --- DC-answered posture findings (resolve to the DC host, IP + FQDN) ----
    # The DC itself accepted/declined the control; details carry only ``domain``.
    "ldap_security_posture": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.DC_SCOPED,
    ),
    "ldaps_unavailable": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.DC_SCOPED,
    ),
    "ntlm_authentication_accepted": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.DC_SCOPED,
    ),
    "kerberos_rc4_domain_accepted": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.DC_SCOPED,
    ),
    # --- Domain-wide policy / unauth findings --------------------------------
    "kerberos_aes_not_forced": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.DOMAIN_WIDE,
    ),
    "weak_password_policy": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.DOMAIN_WIDE,
    ),
    # Reversible password storage is a policy of the domain (pwdProperties 0x10)
    # or of a PSO — a domain-wide weakness, not a per-host one. The finding is
    # resolved to the domain controller(s), like weak_password_policy.
    "reversible_encryption_enabled": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.DOMAIN_WIDE,
    ),
    "machine_account_quota_risk": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.DOMAIN_WIDE,
    ),
    "ldap_anonymous": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.DOMAIN_WIDE,
    ),
    "smb_null_session": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.DOMAIN_WIDE,
    ),
    "smb_null_domain": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.DOMAIN_WIDE,
    ),
    # --- Domain-wide by nature, and honest about it --------------------------
    # These four resolve to the domain object because the detector records no
    # locator today, not because the domain is the interesting answer. Each is a
    # producer-side gap worth closing at its source; until then a vague-but-true
    # asset beats a fabricated one.
    #   * krbtgt_pass — the age check persists a boolean verdict only.
    #   * tier0_highvalue_sprawl — the catalog key has no detector; the live
    #     ``control_exposure_sprawl`` above carries the accounts.
    #   * gpp_autologin — persists a status flag; the SYSVOL path and the account
    #     go to the separate per-credential finding. The artifact/secret extras
    #     are declared so the moment the detector persists them they surface.
    "krbtgt_pass": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.DOMAIN_WIDE,
    ),
    "tier0_highvalue_sprawl": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
        record_containers=("control_exposure_users",),
    ),
    # Tier-0 access exposure (axis 2): the affected assets are the Tier-0 targets
    # the non-privileged principals can reach (the DCs / ADCS CA / Exchange in
    # ``tier0_targets``), plus the exposed principals themselves. Host-scoped: a
    # named machine the reader can act on, never a category.
    "tier0_access_exposure": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
        record_containers=("tier0_targets", "exposed_principals"),
    ),
    "gpp_autologin": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        extras=(Extra.ARTIFACT, Extra.PASSWORD_REDACTED),
        scope=Scope.DOMAIN_WIDE,
    ),
}


def rule_for(finding_key: str) -> AssetRule:
    """Return the :class:`AssetRule` for *finding_key* (or the default).

    A ``password_*`` family key not explicitly listed is treated as host-scoped
    (those are per-account posture findings), matching the owner's spec.

    Any other unmapped key gets :data:`DEFAULT_RULE`, which does NOT scan the
    finding details for arbitrary lists — an unknown finding names the domain
    rather than risking a category list rendered as if it were an asset.
    """
    key = str(finding_key or "").strip().lower()
    rule = AFFECTED_ASSET_RULES.get(key)
    if rule is not None:
        return rule
    if key.startswith("password_"):
        return AssetRule(
            source=SourceMode.NONE,
            target=TargetMode.NONE,
            scope=Scope.HOST_SCOPED,
        )
    return DEFAULT_RULE


def extract_adcs_ca_names(details: Mapping[str, Any] | None) -> list[str]:
    """Extract distinct Enterprise CA names from ADCS edge notes / details.

    The CA name lives heterogeneously across the data model:

    * ``details.enterpriseca_name`` / ``details.enterpriseca`` — the explicit
      CA fields set by the legacy and native ADCS collectors.
    * ``details.vulnerable_resources[]`` entries with ``kind == "EnterpriseCA"``
      — the canonical post-derivation resource list (where templates live too,
      under ``kind == "CertTemplate"``). The SSOT
      ``adcs_path_display.extract_adcs_template_names`` deliberately does NOT
      separate these by kind, so the CA must be pulled out here.

    The SSOT template extractor stays the source of truth for TEMPLATE names;
    this is its sibling for CA names, kept in the rules module because
    ``adcs_path_display`` is read-only in this work stream.
    """
    if not isinstance(details, Mapping):
        return []

    names: list[str] = []
    seen: set[str] = set()

    def _append(candidate: object) -> None:
        if not isinstance(candidate, str):
            return
        name = candidate.strip()
        if not name:
            return
        if "@" in name:
            name = name.split("@", 1)[0].strip()
        key = name.lower()
        if name and key not in seen:
            seen.add(key)
            names.append(name)

    _append(details.get("enterpriseca_name"))
    _append(details.get("enterpriseca"))

    raw_resources = details.get("vulnerable_resources")
    if isinstance(raw_resources, list):
        for entry in raw_resources:
            if (
                isinstance(entry, dict)
                and str(entry.get("kind") or "") == "EnterpriseCA"
            ):
                _append(entry.get("name"))

    return names
