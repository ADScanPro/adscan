"""The closed family taxonomy every scan-policy check belongs to.

A *family* groups checks the way an Active Directory pentester already thinks
about them ("turn off everything in Kerberos delegation"). The list is CLOSED:
a catalog entry must name one of these ids, and a structural test fails CI when
an entry names anything else or nothing at all. Order is the rendered order.

Labels and descriptions are client-facing copy (scan-policy UI, policy export,
report scope section). Ids are stable contract keys and are never renamed in
place.

Design: docs/superpowers/specs/2026-11-04-scan-policy-checks-by-family-design.md § 4.2.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Family:
    """One check family.

    Attributes:
        family_id: Stable id (persisted in saved policies as ``family:<id>``).
        label: Client-facing family name.
        description: One client-facing line on what the family covers.
        order: Rendered position.
    """

    family_id: str
    label: str
    description: str
    order: int


FAMILIES: tuple[Family, ...] = (
    Family(
        "collection",
        "Discovery & Collection",
        "Reads the directory, host sessions, share permissions and SQL Server "
        "roles that the other checks build on.",
        1,
    ),
    Family(
        "unauthenticated",
        "Unauthenticated Access",
        "What someone on the network can read or reach without an account.",
        2,
    ),
    Family(
        "credentials_exposed",
        "Exposed Credentials",
        "Passwords left in directory attributes, Group Policy files and readable shares.",
        3,
    ),
    Family(
        "password_attacks",
        "Password Guessing & Reuse",
        "Password spraying, predictable passwords and passwords reused across accounts.",
        4,
    ),
    Family(
        "kerberos_roasting",
        "Kerberos Roasting",
        "Kerberos tickets and responses that can be cracked offline to recover a password.",
        5,
    ),
    Family(
        "acl_abuse",
        "ACL & Object Control",
        "Permissions on directory objects that let one account take over another.",
        6,
    ),
    Family(
        "password_changes",
        "Password Changes",
        "Setting a new password on an account, whether by abusing a right over it or "
        "because the domain requires the account to change it.",
        7,
    ),
    Family(
        "delegation_trusts",
        "Delegation & Trusts",
        "Kerberos delegation settings and domain trusts that let access cross a boundary.",
        8,
    ),
    Family(
        "adcs",
        "AD Certificate Services",
        "Certificate templates and authorities that can issue a certificate for another identity.",
        9,
    ),
    Family(
        "coercion_relay",
        "Coercion, Poisoning & NTLM Relay",
        "Making machines authenticate to the scanner, then relaying or capturing that authentication.",
        10,
    ),
    Family(
        "lateral_movement",
        "Lateral Movement & Remote Execution",
        "Using access on one machine to run commands or open sessions on another.",
        11,
    ),
    Family(
        "credential_dumping",
        "Credential Dumping & Secret Reads",
        "Reading password hashes and secrets from domain controllers, hosts and the directory.",
        12,
    ),
    Family(
        "privileged_groups",
        "Privileged Groups & Tier 0",
        "Built-in groups and sessions that hand an account control of the domain.",
        13,
    ),
    Family(
        "mssql",
        "SQL Server",
        "SQL Server permissions and features that lead to command execution or other accounts.",
        14,
    ),
    Family(
        "cve",
        "Known Vulnerabilities",
        "Read-only checks for published vulnerabilities on domain controllers and hosts.",
        15,
    ),
    Family(
        "auth_hardening",
        "Authentication & Protocol Hardening",
        "How NTLM, Kerberos, LDAP and SMB are configured to authenticate and protect credentials.",
        16,
    ),
    Family(
        "hygiene",
        "Account & Asset Hygiene",
        "Stale accounts, password policy, unsupported systems and other directory housekeeping.",
        17,
    ),
    Family(
        "connection_posture",
        "Connection Posture Probes",
        "Short requests to a domain controller, before the scan connects, that learn which "
        "signing, encryption and authentication settings it enforces.",
        18,
    ),
    Family(
        "new_credential",
        "Checks Run With Each Credential Obtained",
        "What ADscan checks as an account once it holds that account's password, hash or "
        "ticket: which hosts accept it and which shares it can open.",
        19,
    ),
)

FAMILY_IDS: frozenset[str] = frozenset(f.family_id for f in FAMILIES)
FAMILIES_BY_ID: dict[str, Family] = {f.family_id: f for f in FAMILIES}

__all__ = ("FAMILIES", "FAMILIES_BY_ID", "FAMILY_IDS", "Family")
