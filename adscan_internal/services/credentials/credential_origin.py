"""Canonical credential-provenance origin slugs and their display labels.

Single source of truth for the machine-readable ``credential_origin`` value
persisted into ``credentials_meta[user]["credential_origin"]`` (see
:func:`adscan_internal.services.credentials.privilege_role.set_credential_origin`)
and the human-readable "via X" label rendered in the ``creds show`` Provenance
column.

Two design rules:

1. **Slug alignment with the attack-step catalog.** Where a provenance origin
   corresponds to an offensive technique that also exists as an
   ``attack_step_catalog`` entry, the *canonical* origin slug EQUALS that
   catalog join key (``kerberoasting``, ``asreproasting``, ``dcsync``,
   ``adcsesc1``..``adcsesc17``, ``passwordinshare``, ``allowedtoact``, ...).
   That makes ``credential → attack step → KB`` a single join. Legacy slugs
   that predate this rule are kept as aliases so already-persisted workspaces
   still render correctly.

2. **Exact-match lookup, never substring.** The previous label map matched by
   substring in dict-insertion order, so ``adcsesc1`` matched
   ``adcsesc10``..``adcsesc17`` and mislabeled them. Resolution here normalizes
   the slug (lowercase, strip, collapse ``-``/``_``) and looks it up by EXACT
   key. Unmapped slugs degrade to a title-cased rendering of the slug, never to
   "unknown".
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from adscan_internal.services.attack_relation_labels import format_relation_label

# ---------------------------------------------------------------------------
# Canonical origin slugs aligned with attack_step_catalog join keys.
# ---------------------------------------------------------------------------
# These EQUAL the catalog entry keys so provenance and the attack step share a
# single join key. New code should prefer these slugs.
ORIGIN_KERBEROAST = "kerberoasting"
ORIGIN_ASREPROAST = "asreproasting"
ORIGIN_TIMEROAST = "timeroasting"
ORIGIN_DCSYNC = "dcsync"
ORIGIN_PASSWORD_IN_SHARES = "passwordinshares"
ORIGIN_ALLOWED_TO_ACT = "allowedtoact"
ORIGIN_FORCE_CHANGE_PASSWORD = "force_change_password"
ORIGIN_USER_DESCRIPTION = "user_description"
ORIGIN_GPP_CPASSWORD = "gpp_cpassword"
ORIGIN_GPP_AUTOLOGON = "gpp_autologon"
ORIGIN_PASSWORD_IN_KEEPASS = "passwordinkeepass"
ORIGIN_BROWSER_CREDENTIAL_STORE = "browser_credential_store"
ORIGIN_PRINTNIGHTMARE = "printnightmare"
ORIGIN_ZEROLOGON = "zerologon"
#: Captured-and-cracked network authentication (LLMNR/NBT-NS/mDNS poisoning
#: followed by an offline crack of the captured challenge/response).
ORIGIN_NTLMV2_CAPTURE_CRACK = "poisoncapturentlmv2crack"
ORIGIN_NTLMV1_CAPTURE_CRACK = "crackntlmv1"

# Dump / offline / host-local origins.
ORIGIN_NTDS = "ntds"
ORIGIN_SAM_DUMP = "sam_dump"
ORIGIN_SECRETSDUMP = "secretsdump"
ORIGIN_LSASS_DUMP = "lsass_dump"
ORIGIN_LSA_SECRETS = "lsa_secrets"
ORIGIN_DPAPI = "dpapi"
# Offline transform of material ADscan ALREADY held: the stored NT hash is
# resolved to its plaintext without any further interaction with the target
# environment. This is a DERIVED acquisition (see CredentialAcquisition) — it
# never earns a "recovered via" claim of its own; the executed technique that
# produced the hash keeps that credit.
ORIGIN_OFFLINE_CRACK = "offline_crack"

# Account / ticket / credential-material origins.
ORIGIN_MACHINE_ACCOUNT = "machine_account"
ORIGIN_GMSA = "gmsa"
ORIGIN_READ_LAPS = "readlapspassword"
ORIGIN_SYNC_LAPS = "synclapspassword"
ORIGIN_RODC_KEY_LIST = "rodc_key_list"
ORIGIN_SHADOW_CREDENTIALS = "shadow_credentials"
ORIGIN_BACKUP_OPERATORS = "backup_operators"
ORIGIN_WRITE_LOGON_SCRIPT = "writelogonscript"
# Spray origins, differentiated by spray TYPE. The canonical slugs equal the
# matching attack_step_catalog join keys (normalized) so provenance and the
# entry-vector attack step share one join: ``passwordspray`` / ``useraspass`` /
# ``blankpassword`` / ``computerpre2k``. ORIGIN_SPRAY stays as the generic
# fallback for any spray path whose specific mode is not determinable, and
# ORIGIN_CREDENTIAL_REUSE covers SAM->domain / owned-password reuse.
ORIGIN_SPRAY = "spray"
ORIGIN_PASSWORD_SPRAY = "passwordspray"
ORIGIN_USERNAME_AS_PASSWORD = "useraspass"
ORIGIN_BLANK_PASSWORD = "blankpassword"
ORIGIN_COMPUTER_PRE2K = "computerpre2k"
ORIGIN_CREDENTIAL_REUSE = "credential_reuse"
ORIGIN_LOCAL_CRED_RETRY = "local_cred_retry"
ORIGIN_CREDENTIAL_RECOVERY = "credential_recovery"
ORIGIN_WINRM_SESSION = "winrm_creds"
ORIGIN_RDP_SESSION = "rdp_creds"
ORIGIN_MSSQL_CREDS = "mssql_creds"

# Non-compromise origins (self-introduced — see
# session_compromise_state_service.NON_COMPROMISE_ORIGINS).
ORIGIN_AUTHENTICATED_SCAN = "authenticated_scan"
ORIGIN_USER_PROVIDED = "user_provided"
ORIGIN_MANUAL = "manual"


def _normalize_origin(origin: str) -> str:
    """Return the canonical lookup form of a raw origin slug.

    Lowercases, strips surrounding whitespace, and collapses ``-`` and ``_``
    separators so ``ADCS-ESC1`` / ``adcs_esc1`` / ``adcsesc1`` all map to one
    key. This is the SAME normalization the attack-step catalog applies to its
    relation keys.
    """
    return str(origin or "").strip().lower().replace("-", "").replace("_", "")


# ---------------------------------------------------------------------------
# Per-ESC display labels (ESC1..ESC17), built once.
# ---------------------------------------------------------------------------
_ESC_PRETTY: dict[str, str] = {
    "adcsesc1": "ADCS ESC1",
    "adcsesc2": "ADCS ESC2",
    "adcsesc3": "ADCS ESC3",
    "adcsesc4": "ADCS ESC4",
    "adcsesc5": "ADCS ESC5",
    "adcsesc6": "ADCS ESC6",
    "adcsesc7": "ADCS ESC7",
    "adcsesc8": "ADCS ESC8",
    "adcsesc9": "ADCS ESC9",
    "adcsesc10": "ADCS ESC10",
    "adcsesc11": "ADCS ESC11",
    "adcsesc13": "ADCS ESC13",
    "adcsesc14": "ADCS ESC14",
    "adcsesc15": "ADCS ESC15",
    "adcsesc16": "ADCS ESC16",
    "adcsesc17": "ADCS ESC17",
    # ESC12 is intentionally absent (no catalog entry); a future entry would
    # render via the title-case fallback rather than being silently wrong.
}


# ---------------------------------------------------------------------------
# EXACT-match origin slug → display label map.
# ---------------------------------------------------------------------------
# Keys are stored in NORMALIZED form (see _normalize_origin). Both canonical
# slugs and legacy aliases are present so already-persisted workspaces render.
_ORIGIN_LABELS: dict[str, str] = {
    # Roasting.
    "kerberoasting": "kerberoast",
    "kerberoast": "kerberoast",
    "asreproasting": "AS-REP roast",
    "asreproast": "AS-REP roast",
    "asrep": "AS-REP roast",
    "timeroasting": "timeroast",
    "timeroast": "timeroast",
    # Replication / sync.
    "dcsync": "DCSync",
    # LAPS / gMSA.
    "readlapspassword": "LAPS read",
    "synclapspassword": "LAPS sync",
    "gmsa": "gMSA",
    # GPP.
    "gpppassword": "GPP cpassword",
    "gppcpassword": "GPP cpassword",
    "gppautologon": "GPP autologon",
    "autologon": "autologon",
    # ACL-driven.
    "userdescription": "user description",
    "forcechangepassword": "ForceChangePassword",
    "shadowcredentials": "shadow credentials",
    "writelogonscript": "WriteLogonScript",
    "backupoperators": "Backup Operators",
    "allowedtoact": "AllowedToAct (RBCD)",
    # Dumps / offline. The `dump*` / `getchanges*` / `readgmsapassword` keys are
    # attack-graph RELATION tokens: an origin derived from the executing attack
    # step arrives in that form, and these curated entries keep the client
    # deliverable saying "LSASS dump" rather than the raw BloodHound edge name.
    "ntds": "NTDS dump",
    "samdump": "SAM dump",
    "dumplsass": "LSASS dump",
    "dumplsa": "LSA secrets",
    "dumpdpapi": "DPAPI",
    "readgmsapassword": "gMSA",
    "getchanges": "DCSync",
    "getchangesall": "DCSync",
    "getchangesinfilteredset": "DCSync",
    "kerberoskeylist": "RODC key list",
    "hasshadowcredentials": "shadow credentials",
    "addkeycredentiallink": "shadow credentials",
    "hassession": "session credential harvest",
    "localadminpassreuse": "password reuse",
    "domainpassreuse": "password reuse",
    "localcredtodomainreuse": "local→domain reuse",
    "xpcmdshell": "database command execution",
    # Vendor-neutral: names the activity, never the cracking tool or service.
    "offlinecrack": "offline password crack",
    # Vendor-neutral: this label flows verbatim into the client PDF report's
    # credential-provenance table, so it must not name the offensive tool.
    "secretsdump": "credential dump",
    "lsassdump": "LSASS dump",
    "lsasecrets": "LSA secrets",
    "dpapi": "DPAPI",
    "rodckeylist": "RODC key list",
    # Account / ticket material.
    "machineaccount": "machine account",
    "relayrbcdmintedmachineaccount": "RBCD machine account",
    # Spray / reuse — differentiated by spray type. Canonical slugs equal the
    # catalog join keys (passwordspray / useraspass / blankpassword /
    # computerpre2k); "spray" / "passwordspray" both render "password spray".
    "spray": "password spray",
    "passwordspray": "password spray",
    "useraspass": "username-as-password spray",
    "usernameaspassword": "username-as-password spray",
    "blankpassword": "blank-password spray",
    "computerpre2k": "pre-2k computer (hostname as password)",
    "pre2k": "pre-2k computer (hostname as password)",
    "credentialreuse": "password reuse",
    "localcredretry": "local→domain reuse",
    "credentialrecovery": "credential recovery",
    # Shares / files.
    "passwordinshares": "password in share",
    "passwordinshare": "password in share",
    "passwordinfile": "password in file",
    "passwordinkeepass": "password in KeePass database",
    "browsercredentialstore": "browser credential store",
    # Captured network authentication, resolved offline. Vendor-neutral: names
    # the activity, never the capture or cracking tool.
    "poisoncapturentlmv2crack": "captured NTLMv2 authentication, cracked offline",
    "crackntlmv1": "captured NTLMv1 authentication, cracked offline",
    # Session-derived.
    "winrmcreds": "WinRM session",
    "rdpcreds": "RDP session",
    "mssqlcreds": "MSSQL credential",
    "mssqlseimpersonate": "MSSQL SeImpersonate",
    # Self-introduced (non-compromise).
    "authenticatedscan": "authenticated scan",
    "userprovided": "user-provided",
    "manual": "manual save",
}
# Merge per-ESC labels (already normalized keys).
_ORIGIN_LABELS.update(_ESC_PRETTY)


def origin_display_label(origin: str) -> str:
    """Return the human-readable "via X" label for a raw origin slug.

    EXACT-match keyed (after normalization) — ``adcsesc1`` and ``adcsesc10``
    resolve to distinct labels. Unmapped slugs degrade to a title-cased
    rendering of the slug (never "unknown"), so a brand-new technique that
    forgets to register a label still shows something meaningful.

    Args:
        origin: Raw machine-readable origin slug as persisted in
            ``credentials_meta[user]["credential_origin"]``.

    Returns:
        Display label such as ``"DCSync"``, ``"ADCS ESC1"``, or a title-cased
        fallback. Empty input returns ``""`` (caller decides the neutral
        marker).
    """
    raw = str(origin or "").strip()
    if not raw:
        return ""
    normalized = _normalize_origin(raw)
    label = _ORIGIN_LABELS.get(normalized)
    if label is not None:
        return label
    # Second lookup: the slug may be an attack-graph RELATION token, because an
    # origin derived from the executing attack step IS the catalog join key (see
    # `origin_slug_for_relation`). Route those through the shared relation-label
    # vocabulary rather than re-declaring a second casing map here — that is the
    # SSOT the report and the web already render, so a relation added tomorrow
    # gets a correctly-cased label for free instead of the title-case fallback
    # turning ``genericall`` into "Genericall" inside a client PDF.
    relation_key = raw.lower()
    relation_label = format_relation_label(relation_key)
    if relation_label and relation_label != relation_key:
        return relation_label
    # Fallback: title-case the original slug with separators turned into spaces.
    pretty = raw.replace("_", " ").replace("-", " ").strip()
    return pretty.title() if pretty else raw


def origin_slug_for_relation(relation: str) -> str:
    """Return the canonical credential-origin slug for an attack-graph relation.

    The origin vocabulary is deliberately aligned with the attack-step catalog
    join keys (rule 1 in the module docstring), so "which technique produced
    this credential" and "which attack step ran" are the SAME token. This helper
    is the one place that conversion happens: it routes the relation through the
    catalog's own :func:`~adscan_internal.services.attack_step_catalog.normalize_relation`
    (alias-aware, so a BloodHound alias resolves to its canonical key) instead
    of an ad-hoc ``.lower()`` that would mint a slug the catalog cannot join on.

    Args:
        relation: Raw attack-graph relation label, e.g. ``"ADCSESC1"``,
            ``"DCSync"``, ``"ReadLAPSPassword"``.

    Returns:
        The canonical origin slug (``"adcsesc1"``, ``"dcsync"``,
        ``"readlapspassword"``), or ``""`` when the relation is empty.
    """
    raw = str(relation or "").strip()
    if not raw:
        return ""
    try:
        from adscan_internal.services.attack_step_catalog import (  # noqa: PLC0415
            normalize_relation,
        )
    except Exception:  # noqa: BLE001 — catalog import must never break a capture
        return raw.lower()
    return normalize_relation(raw) or raw.lower()


# ---------------------------------------------------------------------------
# Acquisition class — did ADscan ACT to obtain this credential?
# ---------------------------------------------------------------------------


class CredentialAcquisition(str, Enum):
    """How a recorded origin came to hold this credential.

    The distinction governs what the client deliverable is allowed to claim.
    Only :attr:`EXECUTED` may ever be presented as "recovered via <method>":
    it asserts that ADscan ran that technique against the environment and that
    run produced the secret. Presenting a derived acquisition the same way
    would credit ADscan with an attack it never performed.
    """

    #: ADscan ran a technique against the target environment and THAT run
    #: produced the secret — a certificate enrolment plus PKINIT, a
    #: replication request, an LSASS read, an authenticating spray. The act
    #: is observable from the defender's side.
    EXECUTED = "executed"

    #: No new act against the environment produced this credential. Either an
    #: offline transform of material already held (resolving a stored hash to
    #: its plaintext), or a re-attribution / re-observation of a secret some
    #: other technique had already recovered.
    DERIVED = "derived"


#: Origins whose acquisition is DERIVED by construction. Deliberately small and
#: evidence-based: an origin belongs here only when the code path provably
#: performs no network act against the target that yields the secret.
#:
#: * ``offline_crack`` — the stored NT hash is resolved to its plaintext by an
#:   offline lookup; nothing is sent to the domain.
#: * ``credential_recovery`` — the USER_NOT_FOUND recovery flow re-points a
#:   secret ADscan ALREADY held at the account that actually owns it. The
#:   secret was produced by whichever technique originally recovered it; this
#:   origin only fixes the pointer.
#:
#: Everything else defaults to EXECUTED. Note in particular that credential
#: REUSE is executed, not derived: those paths authenticate the known secret
#: against the domain before persisting a hit, so the (principal, secret)
#: binding is proven by an act against the environment.
DERIVED_ORIGINS: frozenset[str] = frozenset(
    {
        _normalize_origin(ORIGIN_OFFLINE_CRACK),
        _normalize_origin(ORIGIN_CREDENTIAL_RECOVERY),
    }
)


def classify_origin_acquisition(origin: str) -> CredentialAcquisition:
    """Return the acquisition class for a raw origin slug.

    Args:
        origin: Raw machine-readable origin slug.

    Returns:
        :attr:`CredentialAcquisition.DERIVED` for the offline-transform and
        re-attribution origins in :data:`DERIVED_ORIGINS`;
        :attr:`CredentialAcquisition.EXECUTED` otherwise.
    """
    if _normalize_origin(origin) in DERIVED_ORIGINS:
        return CredentialAcquisition.DERIVED
    return CredentialAcquisition.EXECUTED


def build_method_set(primary_origin: str, recorded_origins: Any) -> list[dict[str, str]]:
    """Return the ordered, de-duplicated method set for one credential.

    Every acquisition the credential store recorded becomes one entry, in
    first-seen order with the PRIMARY origin first so the existing single-method
    rendering stays stable. Each entry carries the client-safe label and the
    acquisition class, so a consumer can present executed routes as "recovered
    via" and still show a derived one for completeness.

    Layer 1 of the reporting split (``CLAUDE.md`` § "Dual-tier reporting"): this
    is shared DERIVATION, so the ``creds show`` Provenance column, the PRO PDF
    and the web platform all read the same routes off the same store. A contract
    test asserts the web mirror derives the same set from the same fixtures.

    Args:
        primary_origin: ``credentials_meta[user]["credential_origin"]``.
        recorded_origins: ``credentials_meta[user]["origins"]`` — the
            append-only acquisition list. Absent on workspaces written before
            the list existed, in which case the primary origin is the whole set.

    Returns:
        List of ``{method, method_label, acquisition}`` dicts. Empty when no
        origin was ever recorded.
    """
    ordered: list[str] = []
    acquisitions: dict[str, str] = {}

    def _remember(slug: Any, acquisition: Any) -> None:
        text = str(slug or "").strip()
        if not text:
            return
        key = text.lower()
        resolved = str(acquisition or "").strip().lower()
        if resolved not in {
            CredentialAcquisition.EXECUTED.value,
            CredentialAcquisition.DERIVED.value,
        }:
            resolved = classify_origin_acquisition(text).value
        if key not in acquisitions:
            ordered.append(text)
            acquisitions[key] = resolved
        elif resolved == CredentialAcquisition.EXECUTED.value:
            # An executed acquisition outranks a derived one for the same slug.
            acquisitions[key] = resolved

    _remember(primary_origin, None)
    if isinstance(recorded_origins, list):
        for entry in recorded_origins:
            if isinstance(entry, dict):
                _remember(entry.get("origin"), entry.get("acquisition"))

    return [
        {
            "method": slug,
            "method_label": origin_display_label(slug),
            "acquisition": acquisitions[slug.lower()],
        }
        for slug in ordered
    ]
