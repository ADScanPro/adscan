"""Client labels for the attack-step catalog's enum fields, declared once.

The attack-step catalog (``adscan_internal.services.attack_step_catalog``)
types each step with enums: how it is executed (``support_kind``), what its
terminal step does (``compromise_semantics``), how hard the fix is
(``remediation_complexity``), its family (``category``), and a per-run
``status``. Those values are engine vocabulary. The report translated
``compromise_semantics`` through a map in ``attack_step_support_registry``,
while the Enterprise web printed the raw value ("Impact:
direct_target_compromise", "Execution: supported") or kept its own
TypeScript copy of a map that had already drifted (it lacked the
credential-recovery class the report names).

This module is that map, for every one of those fields, and both the report
(through ``attack_step_support_registry``, which re-exports it) and the web
backend (which stamps a ``*_label`` beside each raw value it serves) read it.
Standard library only, so the appliance backend imports it without the engine.

:func:`label_for` never returns a raw token: a value the map does not know yet
(a new enum member shipped before its label) is title-cased from its words,
so the worst case is an unpolished label, never ``snake_case`` in front of a
client.
"""

from __future__ import annotations

from typing import Mapping

#: What the step's terminal action gives the attacker.
COMPROMISE_SEMANTICS_LABELS: dict[str, str] = {
    "direct_target_compromise": "Direct Compromise",
    "indirect_target_compromise": "Indirect Compromise",
    "access_capability_only": "Privileged Access",
    "context_only": "Contextual",
    # Terminal step recovers secrets (e.g. DCSync) rather than taking over a
    # single target object; "Other" read as a missing classification.
    "credential_access_only": "Credential Recovery",
    "other": "Other",
}

#: How much work the attacker needs once the step is reachable.
COMPROMISE_EFFORT_LABELS: dict[str, str] = {
    "none": "None",
    "immediate": "Immediate",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "other": "Other",
}

#: How ADscan treats the step during an assessment, in the client's terms.
#: Never a statement that ADscan "cannot" do something: an unsupported step is
#: still a finding read out of the directory, and that is what the client is told.
EXECUTION_SUPPORT_LABELS: dict[str, str] = {
    "supported": "Validated by execution",
    "unsupported": "Read from the directory configuration",
    "policy_blocked": "Withheld for safety",
    "context": "Context step",
}

#: The effort a fix takes, as the remediation tables print it.
REMEDIATION_COMPLEXITY_LABELS: dict[str, str] = {
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "very_high": "Very high",
}

#: The step's family.
CATEGORY_LABELS: dict[str, str] = {
    "adcs": "Certificate Services (AD CS)",
    "acl_ace": "Directory permissions",
    "credential_access": "Credential access",
    "privilege": "Privileged group",
    "lateral_movement": "Lateral movement",
    "entry_vector": "Initial access",
    "cve": "Known vulnerability",
    "kerberos": "Kerberos",
    "delegation": "Kerberos delegation",
    "context": "Context",
    "coercion": "Authentication coercion",
    "ntlm_relay": "NTLM relay",
    "ntlm": "NTLM",
    "trust": "Domain trust",
    "execution": "Code execution",
    "collection": "Collection",
}

#: One step's state in this assessment. Mirrors the step-status vocabulary of
#: the Nomenclature Standard: ``partial`` is its own term, ``blocked`` without a
#: safety marker is an attempt (never a claim that a control stopped it), and a
#: not-assessed step is a coverage gap, not a clean result.
STEP_STATUS_LABELS: dict[str, str] = {
    "theoretical": "Mapped, not executed",
    "success": "Executed",
    "succeeded": "Executed",
    "exploited": "Executed",
    "domain_compromised": "Executed",
    "partial": "Partially validated",
    "attempted": "Attempted",
    "failed": "Attempted",
    "error": "Attempted",
    "blocked": "Attempted",
    "closed_by_configuration": "Closed by configuration",
    "not_vulnerable": "Not vulnerable",
    "structural": "Structural",
    "unsupported": "Not assessed",
    "unavailable": "Not assessed",
    "not_assessed": "Not assessed",
}


def label_for(labels: Mapping[str, str], value: object) -> str:
    """The client label for ``value`` in ``labels``, never a raw token.

    Args:
        labels: One of the maps above.
        value: The raw enum value (any type; empty yields ``""``).

    Returns:
        The mapped label; for an unknown value, its words title-cased
        (``"new_kind"`` -> ``"New kind"``); ``""`` for an empty value.
    """
    key = str(value or "").strip()
    if not key:
        return ""
    mapped = labels.get(key.lower())
    if mapped is not None:
        return mapped
    words = key.replace("_", " ").replace("-", " ").split()
    return " ".join(words).capitalize() if words else ""


def compromise_semantics_label(value: object) -> str:
    return label_for(COMPROMISE_SEMANTICS_LABELS, value)


def compromise_effort_label(value: object) -> str:
    return label_for(COMPROMISE_EFFORT_LABELS, value)


def execution_support_label(value: object) -> str:
    return label_for(EXECUTION_SUPPORT_LABELS, value)


def remediation_complexity_label(value: object) -> str:
    return label_for(REMEDIATION_COMPLEXITY_LABELS, value)


def category_label(value: object) -> str:
    return label_for(CATEGORY_LABELS, value)


def step_status_label(value: object) -> str:
    return label_for(STEP_STATUS_LABELS, value)


__all__ = [
    "CATEGORY_LABELS",
    "COMPROMISE_EFFORT_LABELS",
    "COMPROMISE_SEMANTICS_LABELS",
    "EXECUTION_SUPPORT_LABELS",
    "REMEDIATION_COMPLEXITY_LABELS",
    "STEP_STATUS_LABELS",
    "category_label",
    "compromise_effort_label",
    "compromise_semantics_label",
    "execution_support_label",
    "label_for",
    "remediation_complexity_label",
    "step_status_label",
]
