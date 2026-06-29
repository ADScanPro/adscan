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

# Dump / offline / host-local origins.
ORIGIN_NTDS = "ntds"
ORIGIN_SAM_DUMP = "sam_dump"
ORIGIN_SECRETSDUMP = "secretsdump"
ORIGIN_LSASS_DUMP = "lsass_dump"
ORIGIN_LSA_SECRETS = "lsa_secrets"
ORIGIN_DPAPI = "dpapi"

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
    # Dumps / offline.
    "ntds": "NTDS dump",
    "samdump": "SAM dump",
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
    # Fallback: title-case the original slug with separators turned into spaces.
    pretty = raw.replace("_", " ").replace("-", " ").strip()
    return pretty.title() if pretty else raw
