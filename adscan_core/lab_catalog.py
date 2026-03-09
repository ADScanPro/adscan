"""Shared CTF lab catalog and whitelist helpers.

This module centralizes provider display options and AD-focused lab lists so
CLI/workspace flows do not maintain duplicated provider mappings.
"""

from __future__ import annotations

from adscan_core.lab_context import normalize_lab_provider


CTF_LAB_PROVIDER_OPTIONS: tuple[str, ...] = (
    "HackTheBox",
    "TryHackMe",
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
    ),
    "dockerlabs": (
        "dc01",
        "dc02",
        "dc03",
        "web",
        "sql",
        "exchange",
    ),
    "vulnhub": (
        "Zico2",
        "FristiLeaks",
        "Breach",
        "HackLAB",
    ),
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
#   3. Subdomains resolve automatically: the consumer strips leading labels.
#
# To add a new entry: confirm domain uniqueness via public writeups, then
# add ONE line here.  No other file needs changing.
_MACHINE_DOMAIN_FINGERPRINTS: dict[str, tuple[str, str]] = {
    # Sauna (HTB) — domain: egotistical-bank.local, DC: SAUNA.egotistical-bank.local
    "egotistical-bank.local": ("hackthebox", "sauna"),
    # Fuse (HTB) — domain: fabricorp.local, DC: FUSE.fabricorp.local
    "fabricorp.local": ("hackthebox", "fuse"),
    # Scrambled (HTB) — domain: scrm.local, DC: DC1.scrm.local
    # SLD "scrm" and PDC "dc1" both fail → only explicit fingerprint works.
    "scrm.local": ("hackthebox", "scrambled"),
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

