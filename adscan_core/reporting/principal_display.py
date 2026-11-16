"""Client-facing principal / node-label DISPLAY humanization — the shared SSOT.

This is the single source of truth for turning a raw attack-graph node / principal
label into its CLIENT-FACING display form, shared by EVERY deliverable surface:

* the PDF report graph and prose (via
  :mod:`adscan_internal.services.node_label_display` /
  :mod:`adscan_internal.services.well_known_principals`, which re-export from here);
* the paid web CTEM (``adscan_web/backend/app/services`` —
  ``edge_detail_service`` / ``attack_paths_service`` / ``shares_service``).

It lives in ``adscan_core`` on purpose. ``adscan_core`` is importable EVERYWHERE —
the CLI runtime, the launcher, AND the web/appliance backend, which must NOT import
``adscan_internal`` (locked by the appliance import contract and the
``edge_detail_service`` source grep in
``tests/unit/web/test_unauthenticated_reach_web_parity.py``). Putting the DISPLAY
humanizer here is what lets the ``adscan_internal``-free web backend name a principal
EXACTLY as the PDF report does, with no cross-tier import and no re-authored copy —
so the report graph and the web CTEM can never disagree on whether an ordinary
principal reads ``michael.wrightson`` or the shouting UPN ``MICHAEL.WRIGHTSON@CICADA.HTB``.

Scope: DISPLAY only. This module carries the public, non-IP well-known-SID display
table + the pure humanizers. The SEMANTIC classification of a principal (which
identities are dynamic / have no manageable membership, Tier-0 well-known groups,
non-grantee owner abstractions) stays in
:mod:`adscan_internal.services.well_known_principals` — it is attack-graph logic,
not a display concern, and never needs to reach the web.

Dependency-light (``__future__`` + ``typing`` only), so it is safe to bundle and
distribute.
"""

from __future__ import annotations

import functools
import inspect
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Callable, Iterable, Iterator, Mapping, TypeVar

_F = TypeVar("_F", bound=Callable[..., Any])

# Well-known SID → (display_name, kind). Stable across all Windows/AD environments
# — no LDAP lookup needed. Public Microsoft data (no IP).
_WELL_KNOWN: dict[str, tuple[str, str]] = {
    # Universal
    "S-1-1-0": ("Everyone", "Group"),
    "S-1-2-0": ("Local", "Group"),
    "S-1-2-1": ("Console Logon", "Group"),
    "S-1-3-0": ("Creator Owner", "User"),
    "S-1-3-1": ("Creator Group", "Group"),
    "S-1-3-4": ("Owner Rights", "Group"),
    # NT Authority
    "S-1-5-1": ("Dialup", "Group"),
    "S-1-5-2": ("Network", "Group"),
    "S-1-5-3": ("Batch", "Group"),
    "S-1-5-4": ("Interactive", "Group"),
    "S-1-5-6": ("Service", "Group"),
    "S-1-5-7": ("Anonymous Logon", "User"),
    "S-1-5-8": ("Proxy", "Group"),
    "S-1-5-9": ("Enterprise Domain Controllers", "Group"),
    "S-1-5-10": ("Principal Self", "User"),
    "S-1-5-11": ("Authenticated Users", "Group"),
    "S-1-5-12": ("Restricted Code", "Group"),
    "S-1-5-13": ("Terminal Server User", "Group"),
    "S-1-5-14": ("Remote Interactive Logon", "Group"),
    "S-1-5-15": ("This Organization", "Group"),
    "S-1-5-17": ("IUSR", "User"),
    "S-1-5-18": ("System", "User"),
    "S-1-5-19": ("Local Service", "User"),
    "S-1-5-20": ("Network Service", "User"),
    # BUILTIN local groups
    "S-1-5-32-544": ("Administrators", "Group"),
    "S-1-5-32-545": ("Users", "Group"),
    "S-1-5-32-546": ("Guests", "Group"),
    "S-1-5-32-547": ("Power Users", "Group"),
    "S-1-5-32-548": ("Account Operators", "Group"),
    "S-1-5-32-549": ("Server Operators", "Group"),
    "S-1-5-32-550": ("Print Operators", "Group"),
    "S-1-5-32-551": ("Backup Operators", "Group"),
    "S-1-5-32-552": ("Replicators", "Group"),
    "S-1-5-32-554": ("Pre-Windows 2000 Compatible Access", "Group"),
    "S-1-5-32-555": ("Remote Desktop Users", "Group"),
    "S-1-5-32-556": ("Network Configuration Operators", "Group"),
    "S-1-5-32-557": ("Incoming Forest Trust Builders", "Group"),
    "S-1-5-32-558": ("Performance Monitor Users", "Group"),
    "S-1-5-32-559": ("Performance Log Users", "Group"),
    "S-1-5-32-560": ("Windows Authorization Access Group", "Group"),
    "S-1-5-32-561": ("Terminal Server License Servers", "Group"),
    "S-1-5-32-562": ("Distributed COM Users", "Group"),
    "S-1-5-32-568": ("IIS_IUSRS", "Group"),
    "S-1-5-32-569": ("Cryptographic Operators", "Group"),
    "S-1-5-32-573": ("Event Log Readers", "Group"),
    "S-1-5-32-574": ("Certificate Service DCOM Access", "Group"),
    "S-1-5-32-575": ("RDS Remote Access Servers", "Group"),
    "S-1-5-32-576": ("RDS Endpoint Servers", "Group"),
    "S-1-5-32-577": ("RDS Management Servers", "Group"),
    "S-1-5-32-578": ("Hyper-V Administrators", "Group"),
    "S-1-5-32-579": ("Access Control Assistance Operators", "Group"),
    # BUILTIN alias 581 is the System Managed Accounts Group (the DefaultAccount
    # user is the domain RID 503, not a BUILTIN SID).
    "S-1-5-32-581": ("System Managed Accounts Group", "Group"),
    "S-1-5-32-582": ("Storage Replica Administrators", "Group"),
    "S-1-5-32-583": ("Device Owners", "Group"),
    # Other NT Authority
    "S-1-5-64-10": ("NTLM Authentication", "Group"),
    "S-1-5-64-14": ("SChannel Authentication", "Group"),
    "S-1-5-64-21": ("Digest Authentication", "Group"),
    "S-1-5-80-0": ("All Services", "Group"),
    "S-1-16-0": ("Untrusted Mandatory Level", "Group"),
    "S-1-16-4096": ("Low Mandatory Level", "Group"),
    "S-1-16-8192": ("Medium Mandatory Level", "Group"),
    "S-1-16-8448": ("Medium Plus Mandatory Level", "Group"),
    "S-1-16-12288": ("High Mandatory Level", "Group"),
    "S-1-16-16384": ("System Mandatory Level", "Group"),
    "S-1-16-20480": ("Protected Process Mandatory Level", "Group"),
    "S-1-16-28672": ("Secure Process Mandatory Level", "Group"),
}

# Domain-relative RIDs whose display name is stable across every AD domain.
# A domain-specific SID ``S-1-5-21-<domain>-<RID>`` is NOT in :data:`_WELL_KNOWN`
# (which keys fixed OS/NT-authority SIDs), so when a bare SID label leaks into
# client prose — a collector artifact where a principal was referenced by SID
# before, or instead of, its resolved LDAP object — this map humanizes it.
_DOMAIN_RELATIVE_RID_NAMES: dict[str, str] = {
    "500": "Administrator",
    "501": "Guest",
    "502": "krbtgt",
    "512": "Domain Admins",
    "513": "Domain Users",
    "514": "Domain Guests",
    "515": "Domain Computers",
    "516": "Domain Controllers",
    "517": "Cert Publishers",
    "518": "Schema Admins",
    "519": "Enterprise Admins",
    "520": "Group Policy Creator Owners",
    "521": "Read-only Domain Controllers",
    "522": "Cloneable Domain Controllers",
    "525": "Protected Users",
    "526": "Key Admins",
    "527": "Enterprise Key Admins",
    "553": "RAS and IAS Servers",
    "571": "Allowed RODC Password Replication Group",
    "572": "Denied RODC Password Replication Group",
}

# Case-insensitive lookup of the CANONICAL display casing for every well-known /
# domain-relative identity NAME (``domain users`` -> ``Domain Users``,
# ``anonymous logon`` -> ``Anonymous Logon``, ``authenticated users`` ->
# ``Authenticated Users``). Derived from the same two tables the node injector
# uses, so a prose resolver can never disagree with the canonical name. A
# well-known identity is a proper noun / a defined AD term, so its casing must
# come from here, never from the object-class de-shout (which would lower-case a
# well-known GROUP whenever no ``kind`` is stamped).
_CANONICAL_WELLKNOWN_NAME_BY_LOWER: dict[str, str] = {
    **{name.lower(): name for name, _kind in _WELL_KNOWN.values()},
    **{name.lower(): name for name in _DOMAIN_RELATIVE_RID_NAMES.values()},
}


#: Lower-case function words whose PRESENCE marks a name written in a language
#: that sentence-cases these built-ins rather than title-casing them.
#:
#: There is no single re-casing rule that is right for every language, so the
#: de-shouter has to discriminate instead of picking one wrong answer everywhere:
#:
#: * Romance languages write the built-ins in SENTENCE case, and CLAUDE.md's
#:   worked example for this rule is one of them (``Computer del dominio``,
#:   lower-case preposition).
#: * English TITLE-cases a group name (``Helpdesk Admins``).
#: * German capitalizes its nouns, including across a hyphen
#:   (``Domänen-Benutzer``).
#:
#: A particle only ever appears in the first group, so its presence is the signal
#: that selects sentence case. The set is deliberately the closed list of
#: articles and prepositions that occur in Windows' own localized object names,
#: not a general stopword list: a word here is lower-cased only inside a name
#: ADscan is ALREADY re-casing, which means one it never read the true form of.
_SENTENCE_CASE_PARTICLES: frozenset[str] = frozenset(
    {
        # Italian
        "del", "della", "dello", "dei", "degli", "delle", "di", "da", "dal",
        # Spanish
        "de", "la", "las", "el", "los", "y",
        # French
        "du", "des", "le", "les", "et", "aux",
        # Portuguese
        "do", "dos", "das",
        # Dutch
        "van",
    }
)

#: Elided articles that mark the same convention. An apostrophe elision does not
#: occur in English or German object names, so a word opening with one is as
#: strong a Romance signal as a bare particle, and ``.title()``'s habit of
#: capitalizing the letter after the apostrophe is one of the forms it broke.
_SENTENCE_CASE_ELISIONS: tuple[str, ...] = (
    "l'",
    "d'",
    "dell'",
    "nell'",
    "all'",
    "sull'",
    "un'",
)


def deshout_directory_name(name: str) -> str:
    """De-shout an ALL-CAPS directory object name to its likely written form.

    ``str.title()`` cannot be used for this and must never be reintroduced: it
    capitalizes after every non-alphabetic character, so it renders a localized
    built-in as ``Computer Del Dominio`` and ``Gruppo L'Ufficio``. That is a
    broken deliverable rather than a cosmetic defect, because the decisive reason
    for the casing rule is COMMANDS: remediation and verify commands reference
    the object by its real ``CN``/``DN``, and on a localized domain controller
    that IS the localized name, so a client pasting
    ``Get-Acl "AD:CN=Computer Del Dominio,…"`` gets an error from their own
    directory.

    Only a name that is ENTIRELY upper case is re-cased. Anything carrying the
    directory's own mixed or lower casing is ground truth and is returned
    verbatim, because the rule is to RESTORE the directory's form, never to
    re-case past it.

    For a shouted name there is no ground truth, so the convention is selected by
    the discriminator in :data:`_SENTENCE_CASE_PARTICLES`: a name containing a
    particle is sentence-cased (the Romance convention), and one without keeps
    word-wise capitalization (English title case, German noun capitalization).
    Capitalization is applied per whitespace-separated word, and within a word
    per HYPHEN-separated segment but nothing finer. The hyphen is deliberate and
    the apostrophe is deliberately not: German compounds capitalize both halves
    (``Domänen-Benutzer``) while no language capitalizes after an elision
    (``l'ufficio``), which is one of the places ``.title()`` went wrong.

    Args:
        name: The object name as the graph or the collector stored it.

    Returns:
        The de-shouted name, or ``name`` unchanged when it is not shouted.
    """
    raw = str(name or "")
    if not raw.strip() or not raw.isupper():
        return raw

    def _capitalize_word(word: str) -> str:
        """Capitalize a word, and each hyphen-separated segment inside it."""
        return "-".join(part.capitalize() for part in word.split("-"))

    words = raw.split(" ")
    lowered = {word.strip().lower() for word in words if word.strip()}
    sentence_case = bool(lowered & _SENTENCE_CASE_PARTICLES) or any(
        word.startswith(_SENTENCE_CASE_ELISIONS) for word in lowered
    )
    out: list[str] = []
    seen_first = False
    for word in words:
        if not word:
            out.append(word)
            continue
        if sentence_case and seen_first:
            out.append(word.lower())
        else:
            out.append(_capitalize_word(word))
        seen_first = True
    return " ".join(out)


def _looks_like_sid(value: str) -> bool:
    """Return True when ``value`` is a Windows SID string (``S-1-...``)."""
    return str(value or "").strip().upper().startswith("S-1-")


#: The attack graph keys some nodes by a typed id (``name:<SID>`` for an edge
#: endpoint, ``name:<username>`` for a user node). The prefix is an internal key
#: format, never part of the object's name, so every display helper drops it.
_GRAPH_NODE_ID_PREFIX = "name:"


def strip_graph_node_id_prefix(value: str) -> str:
    """Drop the attack graph's internal ``name:`` node-id prefix, if present.

    ``name:S-1-5-11`` -> ``S-1-5-11``. Case-insensitive. Any other value is
    returned stripped and otherwise unchanged.
    """
    text = str(value or "").strip()
    if text[: len(_GRAPH_NODE_ID_PREFIX)].lower() == _GRAPH_NODE_ID_PREFIX:
        return text[len(_GRAPH_NODE_ID_PREFIX):].strip()
    return text


def well_known_sid_display_name(sid: str) -> str | None:
    """Return the client-readable display name for a well-known Windows SID.

    Single source of truth for "what does this fixed OS/NT-authority SID mean
    to a reader": the same :data:`_WELL_KNOWN` table used to inject the
    synthetic collector nodes, so a resolver can never disagree with the
    node it names. A BUILTIN local-group SID (``S-1-5-32-*``) is qualified as
    ``BUILTIN\\<Name>`` so a reader never confuses ``BUILTIN\\Users`` with
    ``Domain Users``. Any other well-known SID (Everyone, Authenticated Users,
    Anonymous Logon, ...) returns its bare display name.

    Args:
        sid: The candidate SID, any case.

    Returns:
        The display name, or ``None`` when ``sid`` is not a recognized
        well-known SID.
    """
    sid_upper = str(sid or "").strip().upper()
    if not sid_upper:
        return None
    entry = _WELL_KNOWN.get(sid_upper)
    if entry is None:
        return None
    name, _kind = entry
    if sid_upper.startswith("S-1-5-32-"):
        return f"BUILTIN\\{name}"
    return name


def resolve_sid_display_name(sid: str) -> str | None:
    """Return the friendly display name for any well-known or domain-relative SID.

    Superset of :func:`well_known_sid_display_name`: the fixed OS/NT-authority
    table first (BUILTIN-qualified where it applies), then the domain-relative
    RID map (``...-501`` -> ``Guest``). ``None`` when unrecognized.
    """
    sid_upper = str(sid or "").strip().upper()
    if not sid_upper:
        return None
    name = well_known_sid_display_name(sid_upper)
    if name:
        return name
    if sid_upper.startswith("S-1-5-21-"):
        return _DOMAIN_RELATIVE_RID_NAMES.get(sid_upper.rsplit("-", 1)[-1])
    return None


def humanize_domain_for_display(domain: str) -> str:
    """Return the canonical client-facing display form of a domain / FQDN token.

    Active Directory and DNS names are case-INSENSITIVE, so the attack graph's
    BloodHound-convention SHOUTING label (``ACTIVE.HTB`` for the domain node,
    ``DC.ACTIVE.HTB`` for a host FQDN) and the canonical lower-case form
    (``active.htb`` / ``dc.active.htb``) name the same object. The graph STORES
    the shouting form as its identity model (locked by the attack-path snapshot),
    but every CLIENT surface — PDF report, writeup, web CTEM — must render the
    canonical lower-case form so a domain never appears in TWO casings in one
    deliverable (the rest of the report reads ``active.htb`` from the workspace
    while the attack-path / graph / playbook layer shouted ``ACTIVE.HTB``). The
    CLI keeps the technical upper-case label; this is the client-render boundary
    transform only.

    Lower-cases, strips surrounding whitespace and a trailing FQDN root dot.
    Empty-safe; never raises.

    Args:
        domain: A bare domain token or a domain-suffixed host FQDN, any case.

    Returns:
        The canonical lower-case display form (``""`` for an empty input).
    """
    return str(domain or "").strip().rstrip(".").lower()


# Common connector words kept lower-case inside a de-shouted multi-word name, so
# a localized display name reads naturally (``Controller di dominio`` /
# ``Autenticazione Kerberos``) instead of an all-title ``Controller Di Dominio``.
# Language-agnostic small set (EN + Latin-language articles/prepositions); NEVER a
# translation, only casing — the words themselves are preserved verbatim.
_DISPLAY_CONNECTOR_WORDS: frozenset[str] = frozenset(
    {
        "of", "and", "the", "for", "to", "a", "an", "in", "on", "by", "or",
        "di", "del", "della", "dei", "degli", "delle", "dello", "dell",
        "da", "e", "il", "la", "lo", "i", "gli", "le", "per", "con", "su",
        "al", "allo", "alla", "ai", "agli", "alle",
        "de", "y", "el", "los", "las", "un", "una",
    }
)


def deshout_display_label(name: str) -> str:
    """De-shout an ALL-CAPS display label to the directory's own casing.

    A directory can return an object's display name SHOUTING (an ADCS template
    display ``CONTROLLER DI DOMINIO`` / ``AUTENTICAZIONE KERBEROS``), and a
    client deliverable must never render it that way beside the same object's
    properly-cased siblings. This restores a readable casing WITHOUT translating:
    the words are preserved verbatim in the environment's own language, only their
    case changes. Each word is title-cased, except a common connector word kept
    lower-case when it is not the first word (so ``CONTROLLER DI DOMINIO`` reads
    ``Controller di Dominio``, not ``Controller Di Dominio``).

    Only a MULTI-WORD all-caps name is de-shouted: a localized display name is a
    phrase with spaces (``CONTROLLER DI DOMINIO``), whereas a SINGLE-token all-caps
    name is almost always a CN / short identifier whose exact case matters
    (``ESC1``, ``MACHINE``, ``DomainController``) — those are returned VERBATIM, as
    is any already mixed/proper-cased display. Empty-safe.

    Args:
        name: The candidate display label, any case.

    Returns:
        The de-shouted label, or the input unchanged when it is not a multi-word
        all-caps phrase.
    """
    text = str(name or "").strip()
    if not text or not text.isupper() or " " not in text:
        return text
    words = text.split(" ")
    out: list[str] = []
    for i, word in enumerate(words):
        if not word:
            out.append(word)
            continue
        lowered = word.lower()
        if i > 0 and lowered in _DISPLAY_CONNECTOR_WORDS:
            out.append(lowered)
        else:
            out.append(word[:1].upper() + word[1:].lower())
    return " ".join(out)


def humanize_principal_label(label: str) -> str:
    """Return the client-facing display form of a graph node / principal label.

    The single source of truth for turning a raw attack-graph node label into
    client prose. Two normalizations, so no deliverable — PDF report, writeup, or
    web CTEM — ever shows a raw ``S-1-...`` SID or the synthetic ``@WELLKNOWN``
    realm qualifier:

    * A bare SID (or ``SID@REALM``) is resolved to its well-known / domain-relative
      friendly name (``S-1-5-21-...-501`` -> ``Guest``, ``S-1-5-11`` ->
      ``Authenticated Users``).
    * A well-known identity's synthetic ``@WELLKNOWN`` realm suffix is stripped
      (``Authenticated Users@WELLKNOWN`` -> ``Authenticated Users``).

    A normal ``NAME@DOMAIN`` label for a real directory principal is returned
    UNCHANGED — realm stripping and casing for those stay the caller's concern
    (the writeup lowercases accounts, the report keeps the realm), so this never
    disturbs a working label.
    """
    raw = strip_graph_node_id_prefix(label)
    if not raw:
        return raw
    name_part, sep, realm = raw.partition("@")
    name_part = name_part.strip()
    realm = realm.strip()
    if _looks_like_sid(name_part):
        resolved = resolve_sid_display_name(name_part)
        if resolved:
            return resolved
        # Unresolvable SID: still strip a synthetic @WELLKNOWN realm; otherwise
        # leave the label untouched rather than fabricate a name.
        return name_part if realm.upper() == "WELLKNOWN" else raw
    if sep and realm.upper() == "WELLKNOWN":
        return name_part
    return raw


def humanize_principal_for_prose(
    *,
    label: str,
    samaccountname: str = "",
    kind: str = "",
    report_domain: str = "",
) -> str:
    """Return the client-PROSE display form of a principal.

    A consultant writes a principal in a SENTENCE the way an operator types it:
    the human-cased account or group name (``michael.wrightson``,
    ``Backup Operators``), never the collector's shouting UPN label
    (``MICHAEL.WRIGHTSON@CICADA.HTB``), and NEVER a ``@domain`` UPN suffix on a
    group — a group has no UPN. The fully-qualified ``NAME@DOMAIN`` form is an
    IDENTIFIER: correct inside a command argument (the ``source_identity`` /
    ``*_dn`` placeholders keep it) or to disambiguate a principal that lives in a
    DIFFERENT domain than the report's, and wrong in running prose.

    This is the SSOT for the ``{source}`` / ``{target}`` prose substitution every
    catalog surface inherits (report narrative + remediation, writeup, web CTEM),
    so no deliverable shows a shouting UPN in a sentence. Resolution order:

    * First run :func:`humanize_principal_label` so a raw SID or a synthetic
      ``@WELLKNOWN`` label is already a friendly name.
    * Prefer the graph node's real ``samaccountname`` (the correct human casing:
      ``michael.wrightson`` / ``Backup Operators``, stamped by
      ``attack_graph_core._stamp_step_identity``) over the (usually upper-cased)
      label name. When it is absent, a well-known / domain-relative identity name
      (``DOMAIN USERS`` / ``ANONYMOUS LOGON``) is rendered in its CANONICAL case
      (``Domain Users`` / ``Anonymous Logon``) from
      :data:`_CANONICAL_WELLKNOWN_NAME_BY_LOWER` — it is a proper noun, not a
      shouting account to de-shout by object class. Any other name is de-shouted
      by object class: a shouting group reads as words (title case), a shouting
      user account is typed lower case. A mixed-case label is left as authored.
    * Strip the ``@REALM`` suffix for a group always, and for anything whose realm
      matches the report's domain (single-domain prose). Keep it — lower-cased —
      only for a USER whose realm is KNOWN to differ from the report domain
      (cross-domain / cross-forest), where the foreign realm is information the
      reader needs.

    Best-effort and total: any unexpected shape returns the humanized label
    unchanged, so a working label is never disturbed.

    Args:
        label: The raw graph-node / principal label.
        samaccountname: The principal's real sAMAccountName, when stamped.
        kind: The node object class (``"Group"`` / ``"User"`` / ...), when known.
        report_domain: The report / path domain, for cross-domain detection.

    Returns:
        The prose display form of the principal.
    """
    humanized = humanize_principal_label(label)
    raw = str(humanized or "").strip()
    if not raw:
        return raw
    name_part, sep, realm = raw.partition("@")
    name_part = name_part.strip()
    realm = realm.strip()
    # A still-unresolved SID: leave it to the label SSOT (never fabricate a name).
    if _looks_like_sid(name_part):
        return raw
    is_group = str(kind or "").strip().lower() == "group"
    sam = str(samaccountname or "").strip()
    canonical_wellknown = _CANONICAL_WELLKNOWN_NAME_BY_LOWER.get(name_part.lower())
    if sam:
        # A stamped sAMAccountName is ground truth for the NAME, and for its
        # CASING when the collector stored a real (mixed / lower) case. It is ONLY
        # the SHOUTING case that must be de-shouted: AD sAMAccountNames are
        # case-insensitive, so a collector that stored a user ALL-CAPS (``SVC_TGS``)
        # must not make the deliverable SHOUT it while the graph and the writeup
        # render ``svc_tgs``. A shouting well-known proper noun renders canonical
        # (``BACKUP OPERATORS`` -> ``Backup Operators``); a shouting group is
        # de-shouted through ``deshout_directory_name`` (NEVER ``.title()``, which
        # mangles a localized name's particles); a shouting user account is typed
        # lower case. A
        # mixed/lower-case sam is left verbatim (never re-cased) — so a real
        # ``administrator`` user stays ``administrator``, not the well-known form.
        if sam.isupper():
            sam_wellknown = _CANONICAL_WELLKNOWN_NAME_BY_LOWER.get(sam.lower())
            if sam_wellknown is not None:
                display_name = sam_wellknown
            elif is_group:
                display_name = deshout_directory_name(sam)
            else:
                display_name = sam.lower()
        else:
            display_name = sam
    elif canonical_wellknown is not None:
        # A well-known / domain-relative identity is a proper noun / defined AD
        # term: render its canonical case (``Domain Users``, ``Anonymous Logon``)
        # regardless of the label's shouting and independent of the object-class
        # de-shout, which would lower-case a well-known GROUP when no kind stamped.
        display_name = canonical_wellknown
    elif name_part.isupper():
        # No ground-truth casing: de-shout by object class.
        display_name = (
            deshout_directory_name(name_part) if is_group else name_part.lower()
        )
    else:
        display_name = name_part
    if not sep or not realm:
        return display_name
    if is_group:
        # A group never carries a @domain UPN in prose.
        return display_name
    report_up = str(report_domain or "").strip().rstrip(".").upper()
    realm_up = realm.rstrip(".").upper()
    if report_up and realm_up and realm_up != report_up:
        # Cross-domain user: keep the qualifier so the foreign realm is visible.
        return f"{display_name}@{realm.lower()}"
    # Single-domain prose (realm matches the report domain, or no report domain
    # to compare against): the realm is noise, drop it.
    return display_name


# --------------------------------------------------------------------------- #
# Node identity: what a label alone cannot say
# --------------------------------------------------------------------------- #
#
# The graph stores every principal label SHOUTING (``CASTELBLACKADMINS@...``),
# so a label cannot say whether the object is a group or an account, nor how the
# directory writes its name. The two are cased by opposite rules: an account is
# typed lower case, a group keeps the directory's own display name. A formatter
# given only the label has to guess, and it guessed "account", which lower-cased
# every client-created group in the attack-route section of the report, the CLI
# panels and the web graph while the remediation sections (which hold the node)
# wrote the same group correctly.
#
# The identity therefore travels with the data being rendered. Every attack-path
# record already carries it on its steps (``details.source_kind`` /
# ``source_samaccountname`` and the ``target_*`` twins, stamped from the graph
# node), and a graph carries it on its nodes. A surface declares the records or
# the graph it is about to render with :func:`node_identity_scope`, and every
# label-only call made inside resolves a group through that declaration. A caller
# holding the node passes ``kind=`` / ``samaccountname=`` directly.
#
# Scoped (a ``ContextVar``), never process-global: a long-lived web backend
# renders many workspaces, and a label is only meaningful beside its own data.

NodeIdentities = Mapping[str, tuple[str, str]]

_NODE_IDENTITIES: ContextVar[NodeIdentities | None] = ContextVar(
    "adscan_node_identities", default=None
)


def node_identity_key(label: Any) -> str:
    """Return the lookup key of a node label (id prefix stripped, upper-cased)."""
    return strip_graph_node_id_prefix(str(label or "")).upper()


def _remember_identity(
    out: dict[str, tuple[str, str]], label: Any, kind: Any, samaccountname: Any
) -> None:
    key = node_identity_key(label)
    kind_text = str(kind or "").strip()
    if not key or not kind_text:
        return
    sam_text = str(samaccountname or "").strip()
    known = out.get(key)
    # A later sighting only completes an entry (adds the missing account name);
    # it never replaces what an earlier one established.
    if known is None or (not known[1] and sam_text):
        out[key] = (known[0] if known else kind_text, sam_text or (known[1] if known else ""))


def collect_node_identities(
    *,
    records: Iterable[Any] | None = None,
    graph: Any = None,
    nodes: Iterable[Any] | None = None,
) -> dict[str, tuple[str, str]]:
    """Read ``label -> (kind, sAMAccountName)`` from path records and graph nodes.

    Args:
        records: Attack-path records; each step's ``details`` names its two
            endpoints (``from`` / ``to``) with their stamped kind and account name.
        graph: An attack graph (``{"nodes": {id: node}}``).
        nodes: Graph node dicts (``label`` / ``kind`` / ``properties``).

    Returns:
        The identities found. Total: a malformed entry is skipped, never raised.
    """
    out: dict[str, tuple[str, str]] = {}
    for record in records or ():
        steps = record.get("steps") if isinstance(record, Mapping) else None
        for step in steps if isinstance(steps, (list, tuple)) else ():
            details = step.get("details") if isinstance(step, Mapping) else None
            if not isinstance(details, Mapping):
                continue
            _remember_identity(
                out,
                details.get("from"),
                details.get("source_kind"),
                details.get("source_samaccountname"),
            )
            _remember_identity(
                out,
                details.get("to"),
                details.get("target_kind"),
                details.get("target_samaccountname"),
            )
    node_iter: list[Any] = list(nodes or ())
    graph_nodes = graph.get("nodes") if isinstance(graph, Mapping) else None
    if isinstance(graph_nodes, Mapping):
        node_iter.extend(graph_nodes.values())
    elif isinstance(graph_nodes, (list, tuple)):
        node_iter.extend(graph_nodes)
    for node in node_iter:
        if not isinstance(node, Mapping):
            continue
        raw_kind = node.get("kind") or node.get("type") or node.get("labels")
        if isinstance(raw_kind, (list, tuple)):
            raw_kind = raw_kind[0] if raw_kind else ""
        props = node.get("properties")
        props = props if isinstance(props, Mapping) else {}
        sam = props.get("samaccountname") or props.get("sAMAccountName") or ""
        _remember_identity(out, node.get("label") or node.get("name"), raw_kind, sam)
    return out


def report_data_path_records(report_data: Any) -> list[Any]:
    """Return every attack-path record a report data mapping carries.

    A report's data is keyed by domain, each domain block holding its
    ``attack_paths``. Reserved non-domain keys are skipped by shape.
    """
    out: list[Any] = []
    if not isinstance(report_data, Mapping):
        return out
    for block in report_data.values():
        paths = block.get("attack_paths") if isinstance(block, Mapping) else None
        if isinstance(paths, (list, tuple)):
            out.extend(paths)
    return out


@contextmanager
def node_identity_scope(
    identities: NodeIdentities | None = None,
    *,
    records: Iterable[Any] | None = None,
    graph: Any = None,
    nodes: Iterable[Any] | None = None,
) -> Iterator[None]:
    """Declare the data a surface is about to render, for its label-only calls.

    Inside the block :func:`format_graph_node_label` resolves a label's kind and
    account name from these identities when the caller did not pass them. Scopes
    nest: an inner scope adds to the outer one and wins on a conflict.
    """
    merged: dict[str, tuple[str, str]] = dict(_NODE_IDENTITIES.get() or {})
    merged.update(identities or {})
    if records is not None or graph is not None or nodes is not None:
        merged.update(collect_node_identities(records=records, graph=graph, nodes=nodes))
    token = _NODE_IDENTITIES.set(merged)
    try:
        yield
    finally:
        _NODE_IDENTITIES.reset(token)


def _as_records(value: Any) -> list[Any]:
    """One record, a list of records, or a report data mapping, as a record list."""
    if isinstance(value, Mapping):
        if isinstance(value.get("steps"), (list, tuple)):
            return [value]
        return report_data_path_records(value)
    if isinstance(value, (list, tuple)):
        # A bare list of steps (each with its ``details``) is one record's steps.
        if any(
            isinstance(item, Mapping) and "details" in item and "steps" not in item
            for item in value
        ):
            return [{"steps": list(value)}]
        return list(value)
    return []


def declares_node_identities(
    *, records: str | tuple[str, ...] = (), graph: str = ""
) -> Callable[[_F], _F]:
    """Run a renderer inside the identity scope of the data it was handed.

    The one-line way for a surface to declare what it renders: name the
    parameter(s) holding its attack-path record(s) and/or its graph, and every
    label-only node display made during the call resolves through them.

    Args:
        records: Parameter name(s) holding one record, a list of records, or a
            report data mapping.
        graph: Parameter name holding an attack graph.
    """
    record_params = (records,) if isinstance(records, str) else tuple(records)

    def decorate(func: _F) -> _F:
        signature = inspect.signature(func)

        def _identities(args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, tuple[str, str]]:
            try:
                bound = signature.bind_partial(*args, **kwargs).arguments
            except TypeError:
                return {}
            found: list[Any] = []
            for name in record_params:
                if name:
                    found.extend(_as_records(bound.get(name)))
            return collect_node_identities(
                records=found, graph=bound.get(graph) if graph else None
            )

        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_inner(*args: Any, **kwargs: Any) -> Any:
                with node_identity_scope(_identities(args, kwargs)):
                    return await func(*args, **kwargs)

            return async_inner  # type: ignore[return-value]

        @functools.wraps(func)
        def inner(*args: Any, **kwargs: Any) -> Any:
            with node_identity_scope(_identities(args, kwargs)):
                return func(*args, **kwargs)

        return inner  # type: ignore[return-value]

    return decorate


def scoped_node_identity(label: Any) -> tuple[str, str]:
    """Return the ``(kind, sAMAccountName)`` the active scope holds for a label."""
    identities = _NODE_IDENTITIES.get()
    if not identities:
        return ("", "")
    return identities.get(node_identity_key(label), ("", ""))


def format_graph_node_label(
    node: str,
    domain: str | None,
    context_domain: str | None = None,
    *,
    kind: str = "",
    samaccountname: str = "",
) -> str:
    """Compact an attack-graph node label while preserving cross-domain clarity.

    The SSOT for turning a raw attack-graph node label into its client-facing
    display form, shared by the PDF report graph and the web CTEM attack-graph so
    the two can never disagree.

    The ``@``-principal case delegates to :func:`humanize_principal_for_prose`
    (human casing, no shouting UPN, no ``@domain`` on a single-domain name, a
    well-known name in its canonical case). The NetBIOS ``DOMAIN\\name`` and FQDN
    ``host.domain`` branches (and the domain-node passthrough) keep their own
    compaction — they are node-type-specific and are NOT principals, so routing
    them through the principal humanizer would mangle a host FQDN.

    A well-known principal (label ends ``@WELLKNOWN``) carries an internal sentinel
    domain that is never a real directory. When ``context_domain`` is supplied (the
    domain of the node's edge-partner in the path), the well-known node's effective
    domain is rebound to that partner domain FIRST — so a cross-forest well-known
    source keeps a real ``@<partner-domain>`` signal — and then humanized (the
    shared SSOT also strips a bare ``@WELLKNOWN`` with no context, so the raw
    sentinel never reaches the client). A cross-domain object keeps its ``@domain``
    qualifier; an intra-domain one drops it.

    Args:
        node: The raw attack-graph node label.
        domain: The report / path domain, for intra- vs cross-domain compaction.
        context_domain: The edge-partner node's domain, used only to rebind a
            ``@WELLKNOWN`` sentinel to a real partner domain (cross-forest signal).
        kind: The node's object class when the caller holds the node. A GROUP
            keeps the directory's own display name (only a shouted name is
            re-cased); without it the active :func:`node_identity_scope` is asked,
            and a label nobody can place is cased as an account.
        samaccountname: The node's real sAMAccountName, the directory's casing.

    Returns:
        The client-facing display label. ``"N/A"`` for an empty node.
    """
    node_value = strip_graph_node_id_prefix(node)
    if not node_value:
        return "N/A"
    domain_value = str(domain or "").strip().lower()
    node_value_lower = node_value.lower()
    # A BARE SID node label (no @realm) — resolve a well-known / domain-relative
    # SID to its friendly name so no client surface shows a raw ``S-1-...``. An
    # unresolvable SID is left untouched (never fabricate a name). The ``SID@REALM``
    # shape is handled by the ``@`` branch below (via the prose humanizer).
    if "@" not in node_value and _looks_like_sid(node_value):
        return humanize_principal_label(node_value)
    if "@" in node_value:
        name, _, node_domain = node_value.partition("@")
        # Well-known sentinel: rebind its effective domain to the adjacent node's
        # domain BEFORE humanizing, so a cross-forest well-known source keeps a
        # real partner-domain signal. Display-only — the graph node identity
        # (name/objectId/@WELLKNOWN key) is never touched.
        if node_domain.strip().lower() == "wellknown" and name:
            partner_domain = str(context_domain or "").strip()
            if partner_domain:
                node_value = f"{name}@{partner_domain}"
        kind_value = str(kind or "").strip()
        sam_value = str(samaccountname or "").strip()
        if not kind_value:
            kind_value, scoped_sam = scoped_node_identity(node)
            sam_value = sam_value or scoped_sam
        if kind_value.lower() == "group":
            # A group is named as its directory writes it. The prose humanizer
            # drops a group's realm; a graph node keeps it when the group lives
            # in another domain, exactly as an account does.
            display = humanize_principal_for_prose(
                label=node_value,
                samaccountname=sam_value,
                kind="Group",
                report_domain=domain or "",
            )
            realm = node_value.partition("@")[2].strip().rstrip(".")
            if (
                domain_value
                and realm
                and realm.lower() not in {domain_value, "wellknown"}
                and "@" not in display
            ):
                return f"{display}@{realm.lower()}"
            return display
        return humanize_principal_for_prose(label=node_value, report_domain=domain or "")
    if "\\" in node_value:
        prefix, _, name = node_value.partition("\\")
        if name:
            prefix_value = prefix.strip().lower()
            if not domain_value or prefix_value == domain_value:
                return name
        return node_value
    if domain_value and node_value_lower.endswith(f".{domain_value}"):
        host, _, _ = node_value[: -(len(domain_value) + 1)].partition(".")
        # AD / DNS host names are case-insensitive; render the short host name
        # lower-case so it matches the lower-case domain the rest of the report
        # uses (``dc``, not the graph's shouting ``DC``).
        return (host or node_value).lower()
    # A bare DOMAIN terminal node (``ACTIVE.HTB``) or a cross-domain host FQDN
    # (``SRV.OTHER.HTB``): both are case-insensitive DNS names the graph stores in
    # the BloodHound SHOUTING convention. A client surface renders the canonical
    # lower-case form so a domain never appears in two casings in one deliverable
    # (the CLI keeps the technical upper-case label). Only a dotted token with no
    # whitespace is a domain / FQDN; any other passthrough shape is left untouched.
    if "." in node_value and not any(ch.isspace() for ch in node_value):
        return humanize_domain_for_display(node_value)
    return node_value


def humanize_chokepoint_node_label(node_label: str, domain: str | None = None) -> str:
    """Return the client-facing display for a choke-point object / target label.

    The ONE humanizer both report tiers share for the choke-point remediation
    table — LITE (``lite_html_report._build_chokepoint_remediation``) and PRO
    (``html_pdf_generator.build_chokepoint_section``) both render the persisted
    ``ranked_chokepoints`` rows, whose ``node_label`` / ``protected_terminal_label``
    are the RAW attack-graph labels (a shouting UPN, a machine account, a
    ``@WELLKNOWN`` sentinel, a locale-translated built-in group). Routing both
    tiers through this SSOT is what keeps the free and paid choke-point tables
    from naming the same object differently, and keeps a raw label out of either.

    The raw label is humanized through the node-label SSOT
    :func:`format_graph_node_label` (shouting UPN de-shouted, ``@WELLKNOWN``
    stripped, well-known name canonical, domain lower-cased). A directory's
    LOCALIZED built-in group name (Italian ``Computer del dominio``,
    ``Controller di dominio``) is rendered in its OWN directory language, never
    translated to English — the client's remediation commands reference the
    object by the CN it actually has on their (localized) DC.

    Best-effort and total: an empty label returns ``""`` (so an absent
    protected-target stays absent, not the node-label ``"N/A"`` sentinel); any
    unexpected shape is humanized rather than passed through raw.
    """
    if not str(node_label or "").strip():
        return ""
    return format_graph_node_label(node_label, domain)
