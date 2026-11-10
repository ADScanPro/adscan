"""The canonical remediation-token vocabulary, and what a command says when a
token could not be resolved.

A remediation command in a client deliverable is meant to be pasted and run, so
the catalog never authors a made-up-but-real-looking object name in one (see
``CLAUDE.md`` § "NEVER author a fictional-but-real-looking example object"). It
writes a CANONICAL token instead, and the shared personalizer
(``adscan_internal.pro.reporting.remediation_placeholders``) fills it with the
object the finding actually pinned.

Two things then have to be true, and only the first one was:

1. Where a value is resolvable, the token is filled. That is the personalizer's
   job and it does it.
2. Where no value is resolvable, the token must not SHIP. ``dsacls
   "<DOMAIN-DN>" /R "DOMAIN\\<TRUSTEE>"`` reached a paid Security Assessment
   Report, in the remediation of the technique that takes an ordinary account to
   the whole domain. A canonical token is an internal contract between the
   catalog and the personalizer; it reads to a client as a defect, because
   nothing on the page says what belongs in it. An OBVIOUS fill-in does say
   so, which is why the catalog already uses that form for an object the
   operator has to choose (``<new_gmsa_name>``, ``<privileged_account>``).

So this module declares both halves of the vocabulary in one dependency-light
place: the canonical token for each object a finding can pin, and the obvious
fill-in each one degrades to when nothing resolved it. Both the FINDING path
(the personalizer, in ``adscan_internal.pro``) and the ATTACK-STEP path (the
technique prose rendered by ``adscan_internal.services.attack_step_catalog``,
which is LITE-safe and cannot import ``pro``) read it, so the two surfaces can
never word the same unresolved object differently.

It also owns the two derivations a command needs from the assessed domain, for
the same reason: the step path has a domain in hand and no way to reach the
personalizer's copy.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = [
    "CANONICAL_TOKEN_FILL_INS",
    "COMMAND_BEARING_FIELDS",
    "ENVIRONMENT_TOKENS",
    "degrade_canonical_tokens",
    "degrade_canonical_tokens_in_commands",
    "domain_to_dn",
    "domain_to_netbios",
    "names_finding_object",
]

#: Canonical token -> the obvious fill-in it degrades to when nothing resolved
#: it. Each fill-in NAMES the object the reader has to supply, in the
#: lower-snake form the catalog already uses for an operator-chosen object, so a
#: client meets a question rather than a token. Keys are the canonical tokens
#: declared by the personalizer; a contract test asserts the two sets match, so
#: a new canonical token cannot be added without deciding what it says when it
#: cannot be filled.
#:
#: ``<DOMAIN>`` / ``<DOMAIN-DN>`` are here for completeness only: both resolve
#: from the assessed domain, which every rendered report knows. They degrade
#: rather than ship canonical on the one path that has no domain at all.
CANONICAL_TOKEN_FILL_INS: dict[str, str] = {
    "<ACCOUNT>": "<affected_account>",
    "<TRUSTEE>": "<unauthorised_trustee>",
    "<TEMPLATE>": "<template_name>",
    "<CA>": "<ca_name>",
    "<SPN-HOST>": "<spn_host_fqdn>",
    "<COMPUTER>": "<computer_name>",
    "<SHARE>": "<share_name>",
    "<SHARE-FILE>": "<file_in_share>",
    "<DC-FQDN>": "<domain_controller_fqdn>",
    "<DOMAIN-DN>": "<domain_distinguished_name>",
    "<DOMAIN>": "<domain_name>",
}

#: Catalog fields whose strings are meant to be RUN (an inline command, a
#: numbered procedure, a validation recipe) or are the remediation a client
#: acts on. An unresolved canonical token in one of these reaches a client's
#: shell; in a prose field (``description`` / ``impact``) it is the
#: personalizer's documented fill-in and stays. Same set the catalog contract
#: test scans, so the gate and the fix cannot disagree about what a command is.
COMMAND_BEARING_FIELDS: frozenset[str] = frozenset(
    {"commands", "validation", "validation_commands", "steps", "remediation"}
)

#: Longest token first, so ``<SHARE-FILE>`` is never consumed as ``<SHARE>``
#: followed by stray text. Case-insensitive for the same reason the personalizer
#: is: the catalog is hand-written and ``<trustee>`` was eventually typed where
#: ``<TRUSTEE>`` was meant.
_FILL_IN_PATTERN = re.compile(
    "|".join(
        re.escape(token)
        for token in sorted(CANONICAL_TOKEN_FILL_INS, key=len, reverse=True)
    ),
    re.IGNORECASE,
)

#: Fill-in lookup keyed by the canonical token upper-cased, so a lower-case
#: spelling in the catalog degrades to the same wording.
_FILL_IN_BY_UPPER: dict[str, str] = {
    token.upper(): fill_in for token, fill_in in CANONICAL_TOKEN_FILL_INS.items()
}


#: The canonical tokens that name the assessed ENVIRONMENT (resolvable from the
#: domain any report knows), as opposed to an object only a finding pins.
ENVIRONMENT_TOKENS: frozenset[str] = frozenset({"<DOMAIN>", "<DOMAIN-DN>", "<DC-FQDN>"})

#: Canonical tokens that name an OBJECT only a finding can pin: the holder of a
#: right, an affected account, a template, a host. Longest first, case-insensitive.
_OBJECT_TOKEN_PATTERN = re.compile(
    "|".join(
        re.escape(token)
        for token in sorted(
            set(CANONICAL_TOKEN_FILL_INS) - ENVIRONMENT_TOKENS, key=len, reverse=True
        )
    ),
    re.IGNORECASE,
)


def names_finding_object(text: str) -> bool:
    """Whether ``text`` names an object through a token only a finding can fill.

    A technique-level remediation line that does ("Revoke the replication rights
    held by <TRUSTEE>") is about a SPECIFIC holder. Rendered for a step whose
    holder needs no change (a domain controller replicating), it told the client
    to revoke a right from an unauthorised trustee that does not exist and left
    the token unfilled; such a line has no place on that step.
    """
    return isinstance(text, str) and bool(_OBJECT_TOKEN_PATTERN.search(text))


def degrade_canonical_tokens(text: str) -> str:
    """Return ``text`` with every unresolved canonical token made an obvious fill-in.

    The terminal fallback, so it runs AFTER every filler: a token still standing
    at this point is one no surface could resolve.

    Args:
        text: A rendered client-facing string.

    Returns:
        The string with each canonical token replaced by its fill-in. Returns
        the input unchanged when it carries none, and for a non-string input,
        because a renderer must never fail on this.
    """
    if not isinstance(text, str) or "<" not in text:
        return text
    return _FILL_IN_PATTERN.sub(
        lambda match: _FILL_IN_BY_UPPER.get(match.group(0).upper(), match.group(0)),
        text,
    )


def degrade_canonical_tokens_in_commands(
    value: Any, *, in_command_field: bool = False
) -> Any:
    """Degrade unresolved canonical tokens inside a catalog entry's COMMAND fields.

    Walks a catalog entry (nested dicts and lists) and rewrites only the strings
    that live under a :data:`COMMAND_BEARING_FIELDS` key. Prose keeps its
    documented canonical fill-in.

    Args:
        value: A catalog entry, or any nested fragment of one.
        in_command_field: True when an enclosing key was command-bearing. The
            caller passes an entry with the default, so only the right subtrees
            are rewritten.

    Returns:
        A value of the same shape with the command strings degraded. Lists and
        dicts are rebuilt; anything that is neither is returned as-is.
    """
    if isinstance(value, str):
        return degrade_canonical_tokens(value) if in_command_field else value
    if isinstance(value, list):
        return [
            degrade_canonical_tokens_in_commands(item, in_command_field=in_command_field)
            for item in value
        ]
    if isinstance(value, tuple):
        return tuple(
            degrade_canonical_tokens_in_commands(item, in_command_field=in_command_field)
            for item in value
        )
    if isinstance(value, dict):
        return {
            key: degrade_canonical_tokens_in_commands(
                item,
                in_command_field=in_command_field or key in COMMAND_BEARING_FIELDS,
            )
            for key, item in value.items()
        }
    return value


def domain_to_dn(domain: str) -> str:
    """Return a domain's naming context: ``essos.local`` -> ``DC=essos,DC=local``.

    Returns an empty string for an empty or malformed input, which leaves the
    token to the degrade above rather than producing a broken DN.
    """
    labels = [label for label in str(domain or "").strip().split(".") if label]
    if not labels:
        return ""
    return ",".join(f"DC={label}" for label in labels)


def domain_to_netbios(domain: str, *, netbios: str = "") -> str:
    """Return the NetBIOS (flat) name for a domain.

    Prefers an explicitly-known flat name (the workspace's persisted
    ``netbios`` field); otherwise derives it from the DNS domain, the first
    label uppercased (``htb.local`` -> ``HTB``), which is the flat name for the
    overwhelming majority of directories. ``dsacls`` and ``NTAccount`` reject
    the DNS form, so a command that names a principal needs this one.

    Returns an empty string for empty input.
    """
    resolved = str(netbios or "").strip()
    if resolved:
        return resolved.upper()
    first_label = str(domain or "").strip().split(".")[0].strip()
    return first_label.upper() if first_label else ""
