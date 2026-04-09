"""Impacket output parsers.

This module provides parsers for Impacket tools output including:
- GetUserSPNs (Kerberoasting)
- GetNPUsers (AS-REP Roasting)
- secretsdump (DCSync, SAM extraction)

These parsers are resilient to output format variations and focus on
extracting structured data from Impacket command outputs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


# Regex patterns for hash extraction
_KERBEROAST_HASH_RE = re.compile(r"\$krb5tgs\$23\$\*([^\$]*)\$", re.MULTILINE)
_ASREP_HASH_RE = re.compile(r"\$krb5asrep\$23\$([^@]+)@", re.MULTILINE)
_NTLM_HASH_RE = re.compile(r"([a-fA-F0-9]{32})", re.MULTILINE)
_USERNAME_ONLY_RE = re.compile(r"^[A-Za-z0-9_.\-]+\$?$")


@dataclass(frozen=True)
class KerberoastHash:
    """Parsed Kerberoast hash entry."""

    username: str
    hash_value: str
    spn: Optional[str] = None


@dataclass(frozen=True)
class ASREPHash:
    """Parsed AS-REP Roast hash entry."""

    username: str
    hash_value: str


@dataclass(frozen=True)
class NTLMHash:
    """Parsed NTLM hash entry from secretsdump."""

    username: str
    rid: Optional[int]
    lm_hash: Optional[str]
    ntlm_hash: str
    is_machine_account: bool = False


def parse_kerberoast_output(output: str) -> List[KerberoastHash]:
    """Parse GetUserSPNs output for Kerberoast hashes.

    Extracts TGS tickets from GetUserSPNs.py output. Handles both
    the verbose output and the hash-only output formats.

    Args:
        output: GetUserSPNs stdout/stderr text

    Returns:
        List of parsed Kerberoast hash entries
    """
    if not output:
        return []

    hashes: List[KerberoastHash] = []
    lines = output.splitlines()

    # Pattern 1: Full hash lines (starting with $krb5tgs$)
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("Name"):
            continue

        # Extract username from hash
        match = _KERBEROAST_HASH_RE.search(line)
        if match:
            username = match.group(1)
            # Get the full hash (from $ to end of line or next whitespace)
            hash_start = line.find("$krb5tgs$")
            if hash_start >= 0:
                # Find end of hash (usually end of line or whitespace)
                hash_end = len(line)
                for end_char in [" ", "\t", "\n"]:
                    pos = line.find(end_char, hash_start)
                    if pos > 0 and pos < hash_end:
                        hash_end = pos

                full_hash = line[hash_start:hash_end].strip()
                hashes.append(
                    KerberoastHash(username=username, hash_value=full_hash)
                )

    # Pattern 2: Username extraction from output (when grepping for usernames only)
    # This handles output like: grep -oP '\$krb5tgs\$23\$\*\K[^\$]*(?=\$)'
    if not hashes:
        # If we only have usernames (no full hashes), collect them
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#") and line != "Name":
                # Only accept bare username-style tokens. This prevents Impacket
                # banners, LDAP/NTLM errors, and other prose from being treated as
                # roastable users in downstream flows.
                if (
                    "$" not in line
                    and "@" not in line
                    and ":" not in line
                    and " " not in line
                    and _USERNAME_ONLY_RE.match(line)
                ):
                    hashes.append(
                        KerberoastHash(username=line, hash_value="", spn=None)
                    )

    return hashes


def extract_kerberoast_candidate_users(output: str) -> List[str]:
    """Extract roastable usernames from GetUserSPNs stdout.

    This parser handles both:
    - raw hash output (``$krb5tgs$...``)
    - tabular SPN listings returned by GetUserSPNs before/without hashes in stdout
    """
    if not output:
        return []

    discovered: List[str] = []
    seen: set[str] = set()

    for item in parse_kerberoast_output(output):
        if not item.hash_value.strip():
            continue
        username = item.username.strip()
        if username and username.lower() not in seen:
            discovered.append(username)
            seen.add(username.lower())

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower()
        if (
            lowered.startswith("serviceprincipalname")
            or set(line) == {"-"}
            or lowered.startswith("impacket ")
            or lowered.startswith("[-]")
            or lowered.startswith("[*]")
            or "ccache file is not found" in lowered
            or "no entries found" in lowered
            or "$krb5tgs$" in lowered
        ):
            continue

        columns = re.split(r"\s{2,}", line)
        if len(columns) < 2:
            continue
        if all(column and set(column) == {"-"} for column in columns):
            continue

        username = columns[1].strip()
        if not username or username.lower() == "name":
            continue
        lowered_username = username.lower()
        if lowered_username in seen:
            continue
        discovered.append(username)
        seen.add(lowered_username)

    return discovered


def parse_asreproast_output(output: str) -> List[ASREPHash]:
    """Parse GetNPUsers output for AS-REP Roast hashes.

    Extracts AS-REP hashes from GetNPUsers.py output. Handles both
    hashcat format and raw output.

    Args:
        output: GetNPUsers stdout/stderr text

    Returns:
        List of parsed AS-REP hash entries
    """
    if not output:
        return []

    hashes: List[ASREPHash] = []
    lines = output.splitlines()

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Pattern 1: Full hash line (hashcat format)
        # $krb5asrep$23$username@DOMAIN:hash...
        match = _ASREP_HASH_RE.search(line)
        if match:
            username = match.group(1)
            # Get the full hash
            hash_start = line.find("$krb5asrep$")
            if hash_start >= 0:
                full_hash = line[hash_start:].strip()
                hashes.append(ASREPHash(username=username, hash_value=full_hash))

        # Pattern 2: Username-only output (when using grep to extract usernames)
        elif "krb5asrep" in line.lower():
            # Try to extract username from various formats
            parts = line.replace("$", " ").replace("@", " ").split()
            for part in parts:
                if part and not part.startswith("krb5") and not part.isdigit():
                    # Likely a username
                    hashes.append(ASREPHash(username=part, hash_value=""))
                    break

    return hashes


def parse_secretsdump_output(output: str) -> List[NTLMHash]:
    """Parse secretsdump output for NTLM hashes.

    Extracts NTLM hashes from secretsdump.py output. Handles various
    output formats including:
    - Domain dumps (username:RID:LM:NTLM:::)
    - Local SAM dumps (username:RID:LM:NTLM:::)
    - Registry dumps

    Args:
        output: secretsdump stdout/stderr text

    Returns:
        List of parsed NTLM hash entries
    """
    if not output:
        return []

    hashes: List[NTLMHash] = []
    lines = output.splitlines()

    for line in lines:
        line = line.strip()
        if not line or line.startswith("["):
            continue

        # Standard secretsdump format: username:RID:LM:NTLM:::
        if ":::" in line:
            parts = line.split(":")
            if len(parts) >= 4:
                username = parts[0].strip()
                rid_str = parts[1].strip()
                lm_hash = parts[2].strip() if parts[2].strip() else None
                ntlm_hash = parts[3].strip()

                # Skip empty hashes
                if not ntlm_hash or ntlm_hash == "31d6cfe0d16ae931b73c59d7e0c089c0":
                    continue

                # Parse RID
                rid = None
                try:
                    rid = int(rid_str) if rid_str else None
                except ValueError:
                    pass

                # Detect machine accounts (end with $)
                from adscan_internal.principal_utils import is_machine_account

                is_machine = is_machine_account(username)

                hashes.append(
                    NTLMHash(
                        username=username,
                        rid=rid,
                        lm_hash=lm_hash,
                        ntlm_hash=ntlm_hash,
                        is_machine_account=is_machine,
                    )
                )

    return hashes


def extract_usernames_from_kerberoast(output: str) -> List[str]:
    """Extract only usernames from Kerberoast output.

    This is a convenience function for when you only need usernames,
    not the full hash objects.

    Args:
        output: GetUserSPNs output

    Returns:
        List of usernames that have SPNs set
    """
    hashes = parse_kerberoast_output(output)
    return [h.username for h in hashes if h.username]


def extract_usernames_from_asreproast(output: str) -> List[str]:
    """Extract only usernames from AS-REP Roast output.

    This is a convenience function for when you only need usernames,
    not the full hash objects.

    Args:
        output: GetNPUsers output

    Returns:
        List of usernames vulnerable to AS-REP Roasting
    """
    hashes = parse_asreproast_output(output)
    return [h.username for h in hashes if h.username]


def count_hashes(output: str, hash_type: str) -> int:
    """Count hashes in output by type.

    Args:
        output: Tool output text
        hash_type: Type of hash ('kerberoast', 'asreproast', 'ntlm')

    Returns:
        Number of hashes found
    """
    if hash_type == "kerberoast":
        return len(parse_kerberoast_output(output))
    elif hash_type == "asreproast":
        return len(parse_asreproast_output(output))
    elif hash_type == "ntlm":
        return len(parse_secretsdump_output(output))
    else:
        return 0
