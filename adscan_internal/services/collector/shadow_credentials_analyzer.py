"""Detect AD objects that already have msDS-KeyCredentialLink entries (shadow credentials).

An EXISTING shadow credential is a PERSISTENCE indicator — a possible attacker
backdoor, or a legitimate Windows Hello for Business enrolment — NOT a traversable
attack edge. Using one to authenticate as the object (PKINIT → UnPAC-the-hash)
requires the PRE-EXISTING private key, which the operator does not hold; whoever
planted the key does. So this analyzer emits ONLY the ``shadow_credentials_present``
FINDING (surfaced in the CLI intelligence panel + the client report, and mapped by
every compliance framework). It deliberately does NOT write a ``HasShadowCredentials``
graph edge: modelling "reaching an object that already has a shadow credential" as a
``direct_target_compromise`` self-loop was an overclaim (ADscan cannot use the
credential) and, because it rendered as a ``X → X`` self-loop, it also defeated the
redundant-MemberOf minimiser and truncated legitimate domain-compromise chains at the
computer. The real, operator-executable attack is the distinct ``AddKeyCredentialLink``
control edge (write access → plant OUR OWN key → PKINIT), emitted separately by the
ACL parser and left fully traversable.
"""

from __future__ import annotations

from adscan_internal.services.collector.models import (
    CollectionResult,
    ShadowCredentialFinding,
)

_SHADOW_CRED_KINDS = {"User", "Computer"}


def analyze_shadow_credentials(
    result: CollectionResult,
) -> list[ShadowCredentialFinding]:
    """Find nodes with existing msDS-KeyCredentialLink entries.

    Returns one :class:`ShadowCredentialFinding` per object carrying a key
    credential. Emits NO graph edge — an existing shadow credential is a persistence
    IoC finding, not an attack step (see the module docstring).
    """
    findings: list[ShadowCredentialFinding] = []
    for node in result.nodes.values():
        if node.kind not in _SHADOW_CRED_KINDS:
            continue
        key_count = int(node.properties.get("shadow_cred_count") or 0)
        if key_count <= 0:
            continue
        findings.append(
            ShadowCredentialFinding(
                object_id=node.object_id,
                samaccountname=node.samaccountname,
                kind=node.kind,
                distinguished_name=node.distinguished_name,
                key_count=key_count,
            )
        )
    return findings


__all__ = ["analyze_shadow_credentials"]
