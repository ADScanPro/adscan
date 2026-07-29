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
    """How a finding's SOURCE principals contribute to affected assets."""

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


class RecordEntityType(str, Enum):
    """Structured entity type a rule forces for its own record containers.

    Mirrors the ``TYPE_*`` constants in :mod:`affected_assets_struct` (which
    cannot be imported here — it imports this module). Left unset, a record is
    resolved as a principal (user / computer); set it when the records are a
    different kind of object entirely, e.g. the partner DOMAIN of a trust.
    """

    DOMAIN = "domain"


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


# Fallback for a finding key with no rule. Source principals + non-breaker
# target, and NO last-resort details scan: an unmapped finding degrades to the
# domain object rather than to whatever list its details happen to hold.
DEFAULT_RULE = AssetRule(
    source=SourceMode.PRINCIPALS,
    target=TargetMode.KEEP,
    extras=(),
    scope=Scope.PER_PRINCIPAL,
)


def _adcs_rule() -> AssetRule:
    """Shared rule for every ADCS ESC finding (templates + CA, breaker dropped)."""
    return AssetRule(
        source=SourceMode.PRINCIPALS,
        target=TargetMode.DROP_BREAKER,
        extras=(Extra.TEMPLATES, Extra.CA),
        scope=Scope.PER_PRINCIPAL,
    )


def _attack_step_rule(*, source: SourceMode = SourceMode.PRINCIPALS) -> AssetRule:
    """Shared rule for a finding materialized from an attack-graph edge.

    The edge SOURCE is who can abuse it, the edge TARGET is what gets taken
    over; both are affected assets of the finding. ``source=NONE`` for the CVE
    families whose edge source is the scanner itself rather than a client
    principal.
    """
    return AssetRule(
        source=source,
        target=TargetMode.KEEP,
        scope=Scope.PER_PRINCIPAL,
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

#: The ADCS ESC finding keys that exist in ``VULN_CATALOG``. ESC12 is absent
#: there on purpose (no detector), so it is absent here — the drift test flags
#: the day a catalog entry appears without a rule.
_ADCS_ESC_KEYS: tuple[str, ...] = tuple(
    f"adcs_esc{n}" for n in (*range(1, 12), *range(13, 18))
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


# Keyed by the canonical VULN_CATALOG finding-key.
AFFECTED_ASSET_RULES: dict[str, AssetRule] = {
    # --- ADCS ESC findings: enrolling principal(s) + abused template + CA ----
    **{key: _adcs_rule() for key in _ADCS_ESC_KEYS},
    # --- Roasting: roastable principals + the cracking wordlist --------------
    "kerberoast": AssetRule(
        source=SourceMode.PRINCIPALS,
        target=TargetMode.KEEP,
        extras=(Extra.WORDLIST,),
        scope=Scope.PER_PRINCIPAL,
    ),
    "asreproast": AssetRule(
        source=SourceMode.PRINCIPALS,
        target=TargetMode.KEEP,
        extras=(Extra.WORDLIST,),
        scope=Scope.PER_PRINCIPAL,
    ),
    # --- Delegation: principals + the delegation target (kept, not a breaker) -
    "constrained_delegation": AssetRule(
        source=SourceMode.PRINCIPALS,
        target=TargetMode.KEEP,
        scope=Scope.PER_PRINCIPAL,
    ),
    "rbcd_exploitable": AssetRule(
        source=SourceMode.PRINCIPALS,
        target=TargetMode.KEEP,
        scope=Scope.PER_PRINCIPAL,
    ),
    "unconstrained_delegation": AssetRule(
        source=SourceMode.PRINCIPALS,
        target=TargetMode.KEEP,
        scope=Scope.PER_PRINCIPAL,
    ),
    # --- Credentials in shares: principals + host + share + redacted secret --
    "smb_share_secrets": AssetRule(
        source=SourceMode.PRINCIPALS,
        target=TargetMode.KEEP,
        extras=(Extra.HOST, Extra.SHARE_PATH, Extra.PASSWORD_REDACTED),
        scope=Scope.PER_PRINCIPAL,
    ),
    # --- Secrets in directory attributes: the account AND the attribute ------
    # Both detectors persist one record per leaking account under their own
    # container key. The affected asset is that account plus the attribute the
    # secret sits in — the two things a sysadmin needs to go clear it. Without a
    # rule these fell through to the domain object, which is unactionable.
    "credential_in_ldap_attribute": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
        record_containers=("findings",),
        record_qualifier="field",
    ),
    "ldap_user_description_password_leak": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
        record_containers=("samples",),
        # No qualifier: this detector reads ``description`` by definition, and
        # each record's other field is the matched secret itself.
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
    # --- GPP passwords: the SYSVOL artifact + redacted secret ----------------
    "gpp_passwords": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.KEEP,
        extras=(Extra.ARTIFACT, Extra.PASSWORD_REDACTED),
        scope=Scope.PER_PRINCIPAL,
    ),
    # --- DCSync: domain-wide (the breaker target is dropped) -----------------
    "dcsync": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.DROP_BREAKER,
        scope=Scope.DOMAIN_WIDE,
    ),
    # --- ACL abuse: principals + the controlled target -----------------------
    "force_change_password": AssetRule(
        source=SourceMode.PRINCIPALS,
        target=TargetMode.KEEP,
        scope=Scope.PER_PRINCIPAL,
    ),
    # ``AllExtendedRights`` over an object grants every extended right on it —
    # the affected assets are the principal holding it and the object it holds
    # it over, both carried on the attack-graph edge.
    "all_extended_rights": _attack_step_rule(),
    # --- Session exposure ----------------------------------------------------
    # A privileged session on a lower-tier host: the edge names the host the
    # session sits on and the privileged account exposed on it. Both are the
    # finding — the host is where the credential material lives, the account is
    # what an attacker gets.
    "da_sessions": _attack_step_rule(),
    # --- Readable managed secrets (gMSA / LAPS) ------------------------------
    # The edge target is the account or machine whose password is readable; the
    # edge source is who can read it. A remediator needs both: which object to
    # re-scope, and whose access to remove.
    "gmsa_readable": _attack_step_rule(),
    "laps_readable": _attack_step_rule(),
    # --- Shadow credentials --------------------------------------------------
    # The detector records one entry per object carrying a
    # ``msDS-KeyCredentialLink`` value, which is the object to go clear.
    "shadow_credentials_present": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
        record_containers=("objects",),
    ),
    # --- NTLMv1 escalation avenues -------------------------------------------
    # The affected asset is the machine account whose NetNTLMv1 response is
    # recoverable (typically a DC) — the edge TARGET, plus the ``dc_hosts`` /
    # ``tier_zero_accounts`` the detector stamps from those same targets so the
    # asset survives even when the edge is summarized away. The edge SOURCE is
    # dropped: on these it is Domain Users (anyone), which names no asset a
    # remediator can act on and only dilutes the list.
    "ntlmv1_crack": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.KEEP,
        scope=Scope.PER_PRINCIPAL,
        record_containers=("dc_hosts", "tier_zero_accounts"),
    ),
    "ntlmv1_relay_rbcd": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.KEEP,
        scope=Scope.PER_PRINCIPAL,
        record_containers=("dc_hosts", "tier_zero_accounts"),
    ),
    "ntlmv1_relay_shadowcreds": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.KEEP,
        scope=Scope.PER_PRINCIPAL,
        record_containers=("dc_hosts", "tier_zero_accounts"),
    ),
    # --- Remotely exploitable CVEs -------------------------------------------
    # The affected asset is the vulnerable host on the edge TARGET. The edge
    # source of a CVE probe is the scanner, not a client principal, so it is
    # dropped — naming it would put ADscan itself in the client's asset list.
    "zerologon": _attack_step_rule(source=SourceMode.NONE),
    "nopac": _attack_step_rule(source=SourceMode.NONE),
    "printnightmare": _attack_step_rule(source=SourceMode.NONE),
    "ms17-010": _attack_step_rule(source=SourceMode.NONE),
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
    "smb_relay_targets": _host_list_rule(
        "dcs", "non_dcs", "all_computers", "sample"
    ),
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
    "smbv1_enabled": AssetRule(
        source=SourceMode.NONE,
        target=TargetMode.NONE,
        scope=Scope.HOST_SCOPED,
    ),
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
            if isinstance(entry, dict) and str(entry.get("kind") or "") == "EnterpriseCA":
                _append(entry.get("name"))

    return names
