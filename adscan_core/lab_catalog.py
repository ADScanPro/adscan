"""Shared CTF lab catalog and whitelist helpers.

This module centralizes provider display options and AD-focused lab lists so
CLI/workspace flows do not maintain duplicated provider mappings.
"""

from __future__ import annotations

from adscan_core.lab_context import normalize_lab_provider


CTF_LAB_PROVIDER_OPTIONS: tuple[str, ...] = (
    "HackTheBox",
    "TryHackMe",
    "Certifications",
    "DockerLabs",
    "VulnHub",
    "GOAD",
    "Proving Grounds",
    "Other lab environment",
    "Local practice only",
)


_PROVIDER_DISPLAY_TO_CANONICAL: dict[str, str] = {
    "HackTheBox": "hackthebox",
    "TryHackMe": "tryhackme",
    "Certifications": "certifications",
    "DockerLabs": "dockerlabs",
    "VulnHub": "vulnhub",
    "GOAD": "goad",
    "Proving Grounds": "proving_grounds",
    "Other lab environment": "other",
    "Local practice only": "local_test",
}

_PROVIDER_DISPLAY_LOOKUP: dict[str, str] = {
    key.casefold(): value for key, value in _PROVIDER_DISPLAY_TO_CANONICAL.items()
}


_AD_LABS_BY_PROVIDER: dict[str, tuple[str, ...]] = {
    "hackthebox": (
        "Forest",
        "Active",
        "Escape",
        "Sauna",
        "Blackfield",
        "Shibuya",
        "Fluffy",
        "Voleur",
        "RustyKey",
        "TombWatcher",
        "Manager",
        "Certified",
        "Baby",
        "Delegate",
        "Retrotwo",
        "Sendai",
        "Phantom",
        "Retro",
        "Reel",
        "Resolute",
        "Support",
        "Cascade",
        "Intelligence",
        "Search",
        "Sizzle",
        "Remote",
        "Fuse",
        "Monteverde",
        "Mantis",
        "BankRobber",
        "Fries",
        "Eighteen",
        "DarkZero",
        "Signed",
        "Cicada",
        "Rebound",
        "Administrator",
        "EscapeTwoAuthority",
        "Scrambled",
        "StreamIO",
        "Reel2",
        "Vintage",
        "Pirate",
        "Overwatch",
        "Intercept",
        "Sidecar",
        "Push",
        "Tea",
        "Kaiju",
        "Ifrit",
        "Unintended",
        "Tengu",
        "Heron",
        "Klendathu",
        "Mythical",
        "Puppet",
        "Ascension",
        "Eldritch",
        "Solar",
        "RPG",
        "Hades",
        "P.O.O",
        "XEN",
        "Orion",
        "FullHouse",
        "Zephyr",
        "Breakpoint",
        "Dante",
        "Offshore",
        "RastaLabs",
        "Cybernetics",
        "APTLabs",
    ),
    "tryhackme": (
        "VulnNet_Roasted",
        "Attacktive_Directory",
        "Active_Directory_Basics",
        "Post_Exploitation_Basics",
        "Breaching_Active_Directory",
        "Enumerating_Active_Directory",
        "Attacking_Kerberos",
        "Credentials_Harvesting",
        "VulnNet_Active",
        "Enterprise",
        "Exploiting_Active_Directory",
        "Persisting_Active_Directory",
        "Soupedecode"
    ),
    # Certification paths frequently include AD-specific lab sets. This list is
    # intentionally curated rather than exhaustive; operators can still enter a
    # custom lab/certification name when their path is not listed here.
    #
    # Naming convention:
    #   "<CERT>"      — practice lab environment (domain fingerprints available)
    #   "<CERT>_Exam" — official exam environment (domain private; manual selection only)
    #
    # CARTE is Azure AD focused (no traditional on-prem DC) — no _Exam variant since
    # ADscan targets on-prem AD; included for telemetry completeness.
    "certifications": (
        # HTB Academy
        "CPTS",
        "CPTS_Exam",
        # OffSec
        "OSCP",
        "OSCP_Exam",
        "OSEP",
        "OSEP_Exam",
        # Altered Security
        "CRTP",
        "CRTP_Exam",
        "CRTE",
        "CRTE_Exam",
        "CRTM",
        "CRTM_Exam",
        "CRTA",
        "CRTA_Exam",
        # Other
        "CARTE",
        "CAPE",
        "CAPE_Exam",
    ),
    # DockerLabs currently exposes a large public catalog, but its official API
    # and public writeups did not provide enough reliable AD-specific machine
    # fingerprints to justify whitelisting generic host labels.  Keeping
    # placeholders such as ``dc01``/``web``/``sql`` created false positives in
    # domain inference, so we intentionally leave the provider empty until
    # machine names, domains, and PDC hostnames are verified.
    "dockerlabs": (),
    # VulnHub suffers from the same issue here: the previous entries were
    # generic/non-AD boxes and were not backed by stable AD fingerprints.
    # Leave the provider empty rather than risking incorrect inference.
    "vulnhub": (),
    "goad": (),
    "proving_grounds": (),
    "other": (),
    "local_test": (),
}

# ---------------------------------------------------------------------------
# Machine domain fingerprints
# ---------------------------------------------------------------------------
#
# Exact domain → (canonical_provider, canonical_lab_name) index for
# high-confidence lab identification at scan start.
#
# Design rules (see domain_inference.py for full rationale):
#   1. Only domains UNIQUE to a single machine in this catalog.
#      Ambiguous domains (multiple machines share the same domain) are omitted:
#        htb.local      → Forest / Mantis / Reel / Sizzle
#        megabank.local → Resolute / Monteverde
#      For ambiguous domains, PDC hostname inference distinguishes machines.
#   2. Only domains where the second-level label does NOT already match the
#      machine name — those are caught by the SLD inference rule at no cost.
#      (e.g. blackfield.local → SLD "blackfield" matches catalog; not listed)
#      This also covers platform FQDNs whose visible label differs from the
#      actual machine name (e.g. sequel.htb → Escape).
#   3. Subdomains resolve automatically: the consumer strips leading labels.
#
# To add a new entry: confirm domain uniqueness via public writeups, then
# add ONE line here.  No other file needs changing.
_MACHINE_DOMAIN_FINGERPRINTS: dict[str, tuple[str, str]] = {
    # Sauna (HTB) — domain: egotistical-bank.local, DC: SAUNA.egotistical-bank.local
    "egotistical-bank.local": ("hackthebox", "sauna"),
    # Fuse (HTB) — domain: fabricorp.local, DC: FUSE.fabricorp.local
    "fabricorp.local": ("hackthebox", "fuse"),
    # Escape (HTB) — domain: sequel.htb, DC: DC.sequel.htb
    # Generic .htb extraction yields "sequel", so this explicit override
    # must win before the TLD heuristic runs.
    "sequel.htb": ("hackthebox", "escape"),
    # Scrambled (HTB) — domain: scrm.local, DC: DC1.scrm.local
    # SLD "scrm" and PDC "dc1" both fail → only explicit fingerprint works.
    "scrm.local": ("hackthebox", "scrambled"),
    # VulnNet_Roasted (THM) — domain: vulnnet-rst.local, DC: WIN-2BO8M1OE1M1.vulnnet-rst.local
    # SLD "vulnnet-rst" and PDC hostname don't match the catalog entry.
    "vulnnet-rst.local": ("tryhackme", "vulnnet_roasted"),
    # Attacktive_Directory (THM) — domain: spookysec.local, DC: ATTACKTIVEDIRECTORY.spookysec.local
    # SLD "spookysec" doesn't match the catalog entry.
    "spookysec.local": ("tryhackme", "attacktive_directory"),
    # VulnNet_Active (THM) — domain: vulnnet.local, DC: VULNNET-BC3TCK1.vulnnet.local
    # SLD "vulnnet" doesn't match the catalog entry; PDC hostname is random.
    "vulnnet.local": ("tryhackme", "vulnnet_active"),
    # Retrotwo (HTB/VulnLab) — domain: retro2.vl, DC: BLN01.retro2.vl
    # SLD "retro2" doesn't match catalog entry "retrotwo"; PDC hostname also differs.
    "retro2.vl": ("hackthebox", "retrotwo"),
    # Mythical (HTB/VulnLab) — two-forest lab: mythical-eu.vl + mythical-us.vl
    # SLD "mythical-eu"/"mythical-us" don't match catalog entry "mythical".
    "mythical-eu.vl": ("hackthebox", "mythical"),
    "mythical-us.vl": ("hackthebox", "mythical"),
    # CRTP (Altered Security) — lab: dollarcorp.moneycorp.local (child), moneycorp.local (parent)
    # Parent "moneycorp.local" covers both direct input and subdomain-stripped input.
    # SLD "moneycorp" doesn't match catalog entry "crtp".
    "moneycorp.local": ("certifications", "crtp"),
    # CRTP_Exam (Altered Security) — exam: garrison.castle.local (child), castle.local (parent)
    # Subdomain stripping on garrison.castle.local resolves to castle.local → fingerprint fires.
    # SLD "castle" doesn't match catalog entry "crtp_exam".
    "castle.local": ("certifications", "crtp_exam"),
    # CRTE (Altered Security) — lab: us.techcorp.local (child), techcorp.local (parent)
    # Also uses theshire.local as a separate forest in the lab environment.
    # SLD "techcorp"/"theshire" don't match catalog entry "crte".
    "techcorp.local": ("certifications", "crte"),
    "theshire.local": ("certifications", "crte"),
    # CRTM (Altered Security) — Global Central Bank lab/exam (same environment).
    # gcb.local covers it.gcb.local via subdomain stripping.
    # gcbfinance.local is a separate forest in the same lab.
    # SLD "gcb"/"gcbfinance" don't match catalog entry "crtm".
    "gcb.local": ("certifications", "crtm"),
    "gcbfinance.local": ("certifications", "crtm"),
    # CRTA_Exam (CyberWarFare Labs) — exam: redteam.corp (parent), child.redteam.corp (child)
    # Subdomain stripping covers child.redteam.corp → redteam.corp → fingerprint fires.
    # SLD "redteam" doesn't match catalog entry "crta_exam".
    "redteam.corp": ("certifications", "crta_exam"),
    # OSCP_Exam (OffSec PEN-200) — exam AD set: DC01/MS01/MS02 joined to oscp.exam
    # Non-standard TLD (.exam) bypasses all SLD heuristics; explicit fingerprint required.
    "oscp.exam": ("certifications", "oscp_exam"),
    # CPTS (HTB Academy) — lab and exam both use inlanefreight.local
    # SLD "inlanefreight" doesn't match catalog entry "cpts".
    "inlanefreight.local": ("certifications", "cpts"),
}


_AD_LABS_LOWER_BY_PROVIDER: dict[str, set[str]] = {
    provider: {entry.lower() for entry in entries}
    for provider, entries in _AD_LABS_BY_PROVIDER.items()
}


def provider_display_to_canonical(provider_display: str | None) -> str | None:
    """Normalize provider display/canonical values to canonical provider key."""
    if provider_display is None:
        return None
    raw = str(provider_display).strip()
    if not raw:
        return None

    mapped = _PROVIDER_DISPLAY_LOOKUP.get(raw.casefold())
    if mapped:
        return mapped
    return normalize_lab_provider(raw)


def get_labs_for_provider(provider: str | None) -> list[str]:
    """Return AD-focused lab list for provider (display or canonical name)."""
    canonical = provider_display_to_canonical(provider)
    if not canonical:
        return []
    return list(_AD_LABS_BY_PROVIDER.get(canonical, ()))


def get_machine_domain_index() -> dict[str, tuple[str, str]]:
    """Return the exact domain → (provider, lab_name) fingerprint index.

    Used by domain inference (Rule 2.5) to match known unique machine domains
    before falling back to SLD and PDC hostname heuristics.

    Returns:
        Mapping of lowercased domain strings to ``(canonical_provider,
        canonical_lab_name)`` tuples.  The returned dict is a copy — callers
        may not mutate ``_MACHINE_DOMAIN_FINGERPRINTS`` through it.
    """
    return dict(_MACHINE_DOMAIN_FINGERPRINTS)


def is_lab_whitelisted(provider: str | None, lab_name: str | None) -> bool:
    """Return True when lab is in the provider whitelist (case-insensitive)."""
    canonical = provider_display_to_canonical(provider)
    if not canonical or not lab_name:
        return False
    return str(lab_name).strip().lower() in _AD_LABS_LOWER_BY_PROVIDER.get(
        canonical, set()
    )
