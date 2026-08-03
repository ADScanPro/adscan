"""Single source of truth for "does this directory attribute disclose a secret?".

Three producers ask that question about the same data — the authenticated LDAP
description sweep (``cli/ldap.py``, finding ``ldap_user_description_password_leak``),
the unauthenticated LDAP/SAMR enrichment sweep
(``services/unauth_enrichment_service.py``, feeding ``user_description_credential_leak``
and the operator's "N sensitive" counter), and any future consumer. They used to
carry two independent copies of one bare-substring regex::

    (?i)password|pwd|pass|secret|cred|key|p@ss|p4ss

which reported a leaked credential on every Active Directory domain in
existence: ``key`` matches inside ``Key Distribution Center Service Account``,
the description Windows itself writes on ``krbtgt``. The finding reached the
client report as a MEDIUM with remediation "rotate those accounts' passwords" —
on krbtgt that invalidates every Kerberos ticket in the domain.

The rule this module implements
-------------------------------

A value discloses a credential when one of these holds:

1. **The attribute is a password attribute.** ``userPassword`` and
   ``unixUserPassword`` exist to hold a password; any non-empty readable value
   is a disclosure and no keyword is required. (The old blob-keyword rule
   missed these unless the password itself happened to contain the letters
   "pass" — a leaked plaintext password going unreported.)

2. **A credential keyword AND an accompanying value.** A free-text attribute
   (``description`` / ``info`` / ``comment``) must contain both a keyword from
   :data:`_KEYWORD_PATTERNS` *and* evidence that a secret travels with it:
   either an explicit assignment (``Password : Heartsbane``, ``pwd=Summer24``,
   ``password is aRt$Lp#7t*VQ!3``) or a high-entropy token anywhere in the
   value. A keyword on its own is prose, not a leak — "user must change
   password at next logon" discloses nothing.

Token choices, and what was dropped
-----------------------------------

Word boundaries alone do not save every token, so each one was judged on
whether it can still carry signal once anchored:

* ``key`` — **dropped as a standalone token.** ``\\bkey\\b`` still matches the
  krbtgt description word-for-word, and otherwise matches "Key Account
  Manager", "low-key", "keyholder". It survives only in the compound forms
  that genuinely name a secret (``API key``, ``SSH key``, ``private key``,
  ``pre-shared key``…), which no stock Windows description contains.
* ``pass`` — **dropped as a standalone token.** Unanchored it matched
  "bypass", "passive", "compass"; anchored it matches the ordinary English
  word ("building pass", "season pass"). Every credential spelling it was
  meant to catch is covered by the ``passw`` prefix (password, passwords,
  passwd, Passwort, Passw0rd) plus the explicit leet spellings.
* ``cred`` — **narrowed to ``credential(s)``.** Bare ``cred`` matched "credit",
  "Credit Control", "credo".
* ``secret`` — **kept, but anchored on both sides.** A left-anchored ``secret``
  matches "Secretary" and "Secretaría", which are common job titles in a
  description field.
* ``password`` / ``pwd`` / ``p@ss`` / ``p4ss`` — **kept.** ``password`` becomes
  the ``passw`` prefix so it still covers suffixed spellings; the leet forms
  are listed explicitly so that plain ``pass`` cannot slip back in through a
  character class.

Localisation
------------

Both halves of this detector are locale-aware, because a Spanish or German
domain is not a rounding error:

* The keyword list carries the unambiguous non-English spellings of
  "password" (``contraseña``, ``Kennwort``, ``wachtwoord``, ``senha``,
  ``mot de passe``, ``hasło``, ``lösenord``, ``salasana``). Deliberately
  absent: the words meaning *key* (``clave``, ``clé``, ``Schlüssel``) — those
  appear verbatim in the localised krbtgt description, which is the exact
  false positive this module exists to kill.
* Built-in accounts are recognised by **RID**, never by description text. The
  krbtgt description is localised in every install; its RID is 502 everywhere.
  ``Administrator`` (500) and ``Guest`` (501) can also be renamed by policy, so
  matching their name would fail on precisely the hardened domains that matter.
  On a built-in account, prose plus an assignment is not enough — only a
  high-entropy token is, because the operating system authors those strings and
  never writes a credential into one.

None of this suppresses the real finding. A password written into any
account's description — including a built-in's — still fires, and the two true
positives this detector was built against (``Just in case I forget my password
is aRt$Lp#7t*VQ!3``; ``Samwell Tarly (Password : Heartsbane)``) both still
report.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Mapping

__all__ = [
    "CredentialDisclosure",
    "PASSWORD_ATTRIBUTES",
    "detect_credential_disclosure",
    "is_builtin_principal",
    "rid_from_sid",
    "scan_attribute_values",
]


#: LDAP attributes whose whole purpose is to hold a password. A readable
#: non-empty value in one of these is a disclosure on its own.
PASSWORD_ATTRIBUTES: frozenset[str] = frozenset(
    {"userpassword", "unixuserpassword", "ms-mcs-admpwd", "mcsadmpwd"}
)

#: Highest RID reserved for built-in principals. Windows starts issuing RIDs to
#: real objects at 1000; everything below is created by the operating system
#: (500 Administrator, 501 Guest, 502 krbtgt, 503 DefaultAccount,
#: 504 WDAGUtilityAccount, 512+ the built-in groups).
_BUILTIN_RID_CEILING = 1000

#: Built-in accounts whose sAMAccountName Windows never localises or renames,
#: used only when no SID is available to read a RID from.
_BUILTIN_NAMES: frozenset[str] = frozenset(
    {"krbtgt", "defaultaccount", "wdagutilityaccount"}
)

# ---------------------------------------------------------------------------
# Keyword vocabulary
# ---------------------------------------------------------------------------

_KEYWORD_PATTERNS: tuple[str, ...] = (
    # password / passwords / passwd / Passwort / Passw0rd / passwörter
    r"\bpassw",
    r"\bpass[\s\-_]?phrase\b",
    r"\bpwd(?:s)?\b",
    r"\bpw\b",
    # Explicit leet spellings. Listed literally rather than as a character
    # class so that plain "pass" can never re-enter through the back door.
    r"\bp@ss",
    r"\bp4ss",
    r"\bpa\$\$",
    r"\bp@\$\$",
    r"\bpa55",
    r"\bp4\$\$",
    # Anchored on the right so "Secretary" / "Secretaría" do not match.
    r"\bsecrets?\b",
    r"\bcredentials?\b",
    # "key" only in the compounds that actually name a secret.
    r"\b(?:api|ssh|gpg|pgp|secret|private|access|licen[sc]e|master|recovery|"
    r"pre[\s\-]?shared|shared)[\s\-_]?keys?\b",
    r"\bkeypass\b",
    # Non-English spellings of "password". No word meaning "key" is listed —
    # those appear in the localised krbtgt description.
    r"\bcontrase(?:ñ|n)as?\b",
    r"\bkennw(?:ort|örter)\b",
    r"\bwachtwoord(?:en)?\b",
    r"\bsenhas?\b",
    r"\bmots? de passe\b",
    r"\bhas(?:ł|l)os?\b",
    r"\bl(?:ö|o)senord\b",
    r"\bsalasana\b",
)

_KEYWORD_RE = re.compile("|".join(_KEYWORD_PATTERNS), re.IGNORECASE | re.UNICODE)

# ---------------------------------------------------------------------------
# Evidence that a value travels with the keyword
# ---------------------------------------------------------------------------

#: Separators an operator actually types between the label and the secret.
#: A bare hyphen is only accepted when surrounded by whitespace, so
#: "Password-Reset-Portal" is not read as an assignment.
_SEPARATOR = (
    r"(?:\s*(?:[:=]+|->|=>|\|)\s*|\s*/\s*|\s+(?:is|are|es|ist|sind)\s*[:=]?\s+"
    r"|\s+[-–—]\s+)"
)

_ASSIGNMENT_RE = re.compile(
    "(?:" + "|".join(_KEYWORD_PATTERNS) + r")\w*" + _SEPARATOR + r"(?P<value>\S+)",
    re.IGNORECASE | re.UNICODE,
)

#: Words that commonly follow "password:" in prose without being a secret.
#: Deliberately absent: "default", "changeme", "welcome" and friends — those
#: are real passwords far more often than they are filler, and a miss here
#: costs a reported credential.
_NON_SECRET_VALUES: frozenset[str] = frozenset(
    {
        "above", "and", "as", "ask", "at", "below", "blank", "change", "changed",
        "chg", "disabled", "empty", "enabled", "expire", "expired", "expires",
        "expiry", "for", "from", "has", "in", "is", "manager", "must", "n/a",
        "na", "need", "needed", "needs", "never", "next", "no", "none", "not",
        "ok", "on", "pending", "policy", "portal", "protected", "rerequired",
        "require", "required", "requirement", "reset", "resets", "rotate",
        "rotated", "rotation", "same", "see", "self", "service", "set", "tbd",
        "the", "this", "to", "todo", "unknown", "unset", "until", "user",
        "vault", "was", "will", "with", "yes",
    }
)

#: The keyword words themselves, so a keyword cannot serve as its own evidence
#: ("Password never expires" must not read ``Password`` as the leaked secret).
#: Matching is on the WHOLE token, never a substring: ``P@ssw0rd`` and
#: ``Password123`` are among the most common passwords an admin writes into a
#: description, and rejecting any value that merely contains "pass" would drop
#: exactly those.
_BARE_KEYWORD_WORDS: frozenset[str] = frozenset(
    {
        "contraseña", "contrasena", "contraseñas", "contrasenas", "credential",
        "credentials", "hasło", "haslo", "kennwort", "kennwörter", "key", "keys",
        "lösenord", "losenord", "pass", "passe", "passphrase", "passwd",
        "password", "passwords", "passwort", "passwörter", "pw", "pwd", "pwds",
        "salasana", "secret", "secrets", "senha", "senhas", "wachtwoord",
    }
)

#: Trimmed from both ends of a candidate value before it is judged.
_VALUE_TRIM = " \t\"'`()[]{}<>,;.!?*«»“”"

_HIGH_ENTROPY_BLOB_RE = re.compile(r"\A[A-Za-z0-9+/=_\-]{16,}\Z")


def _is_bare_keyword(token: str) -> bool:
    """Return ``True`` when the token is the keyword word and nothing more."""
    return token.strip(_VALUE_TRIM).lower() in _BARE_KEYWORD_WORDS


@dataclass(frozen=True)
class CredentialDisclosure:
    """One attribute value judged to disclose a credential.

    Attributes:
        field: The attribute the value came from (``description``,
            ``userPassword``, ...).
        value: The attribute value, verbatim.
        reason: Why it was reported — ``password_attribute`` (the attribute is
            a password field), ``assignment`` (a keyword followed by a value),
            or ``secret_token`` (a keyword plus a high-entropy token).
        keyword: The keyword that matched, empty for ``password_attribute``.
    """

    field: str
    value: str
    reason: str
    keyword: str = ""


def rid_from_sid(sid: str | None) -> int | None:
    """Return the trailing RID of a SID string, or ``None`` when unreadable."""
    if not sid:
        return None
    try:
        return int(str(sid).strip().rstrip("/").rsplit("-", 1)[-1])
    except (ValueError, IndexError):
        return None


def is_builtin_principal(
    *, samaccountname: str = "", object_sid: str = "", rid: int | None = None
) -> bool:
    """Return ``True`` when the principal is created by Windows, not an admin.

    Identity is taken from the RID whenever one is available — ``Administrator``
    (500) and ``Guest`` (501) are renameable by policy and were localised in
    older installs, so their names are not a reliable key. The name list is a
    fallback for callers that have no SID, and holds only the names Windows
    never localises.
    """
    effective_rid = rid if rid is not None else rid_from_sid(object_sid)
    if effective_rid is not None:
        return effective_rid < _BUILTIN_RID_CEILING
    return str(samaccountname or "").strip().lower() in _BUILTIN_NAMES


def _character_classes(token: str) -> int:
    """Return how many of lower / upper / digit / symbol the token spans."""
    classes = 0
    if any(c.islower() for c in token):
        classes += 1
    if any(c.isupper() for c in token):
        classes += 1
    if any(c.isdigit() for c in token):
        classes += 1
    if any(not c.isalnum() for c in token):
        classes += 1
    return classes


def looks_like_secret_token(token: str) -> bool:
    """Return ``True`` when the token has the shape of a real secret.

    Deliberately conservative: this is the ONLY evidence accepted on a built-in
    account, and the only evidence accepted when the keyword and the value are
    not adjacent. An ordinary capitalised word ("Heartsbane") does not qualify
    here — it qualifies through the assignment form instead, where the
    surrounding ``Password :`` supplies the missing signal.
    """
    token = token.strip(_VALUE_TRIM)
    if len(token) < 6:
        return False
    if _is_bare_keyword(token):
        return False
    classes = _character_classes(token)
    if len(token) >= 6 and classes >= 3:
        return True
    if (
        len(token) >= 10
        and any(c.isdigit() for c in token)
        and any(c.isupper() for c in token)
    ):
        return True
    return bool(
        len(token) >= 16
        and _HIGH_ENTROPY_BLOB_RE.match(token)
        and any(c.isdigit() for c in token)
    )


def _find_secret_token(text: str) -> str:
    """Return the first secret-shaped token in the text, or ``""``."""
    for raw in re.split(r"[\s,;|]+", text):
        token = raw.strip(_VALUE_TRIM)
        if token and looks_like_secret_token(token):
            return token
    return ""


def _find_assignment_value(text: str) -> str:
    """Return the value a keyword assigns in the text, or ``""``.

    ``Samwell Tarly (Password : Heartsbane)`` yields ``Heartsbane``;
    ``Password Reset Portal`` yields nothing, because no separator stands
    between the keyword and the following word.
    """
    for match in _ASSIGNMENT_RE.finditer(text):
        value = (match.group("value") or "").strip(_VALUE_TRIM)
        if len(value) < 4:
            continue
        if value.lower() in _NON_SECRET_VALUES:
            continue
        if _is_bare_keyword(value):
            continue
        return value
    return ""


def detect_credential_disclosure(
    field: str, value: str, *, builtin: bool = False
) -> CredentialDisclosure | None:
    """Judge one attribute value. Returns ``None`` when nothing is disclosed.

    Args:
        field: The attribute name the value came from.
        value: The attribute value.
        builtin: ``True`` when the owning principal is a Windows built-in (see
            :func:`is_builtin_principal`). Raises the bar to a high-entropy
            token, because a stock description is written by the operating
            system and its wording differs per install language.
    """
    text = str(value or "").strip()
    if not text:
        return None

    if str(field or "").strip().lower().replace("_", "-") in PASSWORD_ATTRIBUTES:
        return CredentialDisclosure(field=field, value=text, reason="password_attribute")

    keyword_match = _KEYWORD_RE.search(text)
    if not keyword_match:
        return None
    keyword = keyword_match.group(0)

    token = _find_secret_token(text)
    if token:
        return CredentialDisclosure(
            field=field, value=text, reason="secret_token", keyword=keyword
        )
    if builtin:
        return None
    if _find_assignment_value(text):
        return CredentialDisclosure(
            field=field, value=text, reason="assignment", keyword=keyword
        )
    return None


def scan_attribute_values(
    fields: Mapping[str, str], *, builtin: bool = False
) -> list[CredentialDisclosure]:
    """Judge every attribute of one principal, in the order given."""
    disclosures: list[CredentialDisclosure] = []
    for field_name, raw in fields.items():
        hit = detect_credential_disclosure(field_name, raw, builtin=builtin)
        if hit is not None:
            disclosures.append(hit)
    return disclosures
