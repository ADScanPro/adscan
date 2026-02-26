"""Attack step execution support registry.

This module centralizes the "what can ADscan execute" mapping so that:
- new steps can be classified at creation time (supported vs unsupported vs policy-blocked)
- workspace loads can refresh existing graphs when ADscan is upgraded

Important:
- `unsupported` means ADscan has no implementation for the relation (tool limitation).
- `unavailable` is runtime-only and depends on credentials/metadata, so it is not part
  of this registry.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RelationSupport:
    kind: str
    reason: str


CONTEXT_ONLY_RELATIONS: dict[str, str] = {
    "memberof": "Context only (membership expansion); not executed",
}

POLICY_BLOCKED_RELATIONS: dict[str, str] = {
    "zerologon": "High-risk / potentially disruptive (disabled by design)",
    "nopac": "High-risk / potentially disruptive (disabled by design)",
    "printnightmare": "High-risk / potentially disruptive (disabled by design)",
}

# Relations that have an execution mapping in ADscan.
SUPPORTED_RELATION_NOTES: dict[str, str] = {
    "allowedtodelegate": "Kerberos delegation exploitation (constrained/unconstrained)",
    "kerberoasting": "Extract and crack Kerberos TGS hashes for a target user",
    "asreproasting": "Extract and crack Kerberos AS-REP hashes for a target user",
    "adminto": "Confirm local admin access via SMB (AdminTo)",
    "sqladmin": "Confirm MSSQL administrative access (SQLAdmin)",
    "canrdp": "Confirm RDP login capability (CanRDP)",
    "canpsremote": "Confirm remote PowerShell/WinRM capability (CanPSRemote)",
    "adcsesc1": "Request an authentication certificate via ADCS ESC1",
    "adcsesc3": "Request an agent certificate and impersonate a target via ADCS ESC3",
    "adcsesc4": "Make a certificate template vulnerable via ADCS ESC4",
    # ACL/ACE abuse (implemented via ace_step_execution)
    "genericall": "ACL/ACE abuse (GenericAll)",
    "genericwrite": "ACL/ACE abuse (GenericWrite)",
    "forcechangepassword": "ACL/ACE abuse (ForceChangePassword)",
    "addself": "ACL/ACE abuse (AddSelf)",
    "addmember": "ACL/ACE abuse (AddMember)",
    "readgmsapassword": "ACL/ACE abuse (ReadGMSAPassword)",
    "readlapspassword": "ACL/ACE abuse (ReadLAPSPassword)",
    "writedacl": "ACL/ACE abuse (WriteDacl)",
    "writeowner": "ACL/ACE abuse (WriteOwner)",
    "writespn": "ACL/ACE abuse (WriteSPN / targeted Kerberoast)",
    "dcsync": "ACL/ACE abuse / post-exploitation (DCSync)",
}


def _norm(relation: str) -> str:
    return (relation or "").strip().lower()


def classify_relation_support(relation: str) -> RelationSupport:
    """Classify a relation by execution support.

    Returns:
        RelationSupport(kind=...) where kind is one of:
        - context
        - policy_blocked
        - supported
        - unsupported
    """
    key = _norm(relation)
    if not key:
        return RelationSupport(kind="unsupported", reason="Missing relation")
    if key in CONTEXT_ONLY_RELATIONS:
        return RelationSupport(kind="context", reason=CONTEXT_ONLY_RELATIONS[key])
    if key in POLICY_BLOCKED_RELATIONS:
        return RelationSupport(
            kind="policy_blocked", reason=POLICY_BLOCKED_RELATIONS[key]
        )
    if key in SUPPORTED_RELATION_NOTES:
        return RelationSupport(kind="supported", reason=SUPPORTED_RELATION_NOTES[key])
    return RelationSupport(kind="unsupported", reason="Not implemented yet in ADscan")
