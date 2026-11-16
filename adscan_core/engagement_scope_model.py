"""Asset-level engagement scope: the model layer (entry grammar, matchers, digest).

A client can scope ASSETS, not only domains: a deny-list (objects ADscan must
never touch), an allow-list (only these may be touched), or both, where deny
always wins. This module is the part every entry point shares: the launcher
rejects a syntax error before Docker starts, the engine builds its verdicts on
the matcher, and the web previews an entry with the same parser. It is stdlib
only so all three, and the Windows bundle, import the same code.

Entry grammar (one entry per line in a file, or per comma-separated value on a
flag, in the REPL or in the web form). The type is detected from the shape, and
an explicit prefix forces it:

=================  ==============  ==============================================
Shape              Type            Example (fabricated)
=================  ==============  ==============================================
IPv4 / IPv6        ``ip``          ``192.0.2.10``, ``2001:db8::10``
CIDR               ``cidr``        ``198.51.100.0/24``
Range              ``range``       ``192.0.2.10-192.0.2.20``, ``192.0.2.10-20``
Dotted name        ``fqdn``        ``fs01.corp.example``
``*.`` + name      ``dns_suffix``  ``*.ot.corp.example``
Bare token         ``short_host``  ``fs01``
``S-1-...``        ``sid``         ``S-1-5-21-...-1105``
``CN=``/``OU=``    ``dn``          ``OU=OT,DC=corp,DC=example`` (the object and
                                   everything below it)
``NETBIOS\\name``  ``principal``   ``CORP\\svc_backup``, ``CORP\\FS01$``
``name@realm``     ``upn``         ``svc_backup@corp.example``
=================  ==============  ==============================================

Prefixes: ``ip:``, ``cidr:``, ``range:``, ``host:``, ``suffix:``, ``sid:``,
``dn:``, ``subtree:`` (same as ``dn:``), ``user:``, ``group:``, ``computer:``.
A bare token is ALWAYS a host: a principal must be qualified or carry a
``user:``/``group:`` prefix, so ``admin`` in a deny file can never silently mean
an account.

Matching (:class:`AssetMatcher`) is constant per check: address networks are
grouped by prefix length (at most 33 or 129 probes, typically one to three),
names, SIDs and account keys are set probes, and a DN or DNS suffix is walked
component by component. Nothing scales with the number of entries or hosts.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

#: Bounds of one scope input (a file, or an inline list). The entry cap is the
#: binding one for ordinary lines: 100 000 IPv6 or FQDN lines fit in 8 MiB.
#:
#: ``MAX_FILE_BYTES`` is THE size limit of a scope file. Everything that states
#: or enforces it reads this constant: :func:`read_scope_file`, the help of
#: ``--scope-allow-file`` / ``--scope-deny-file`` (and so the launcher's
#: pass-through help), the web's request model and, mirrored under a contract
#: test, the web's upload check. Never write the number anywhere else.
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 100_000
MAX_LINE_CHARS = 1024
#: The file size limit in mebibytes, for wording.
MAX_FILE_MIB = MAX_FILE_BYTES // (1024 * 1024)
#: The two limits a help text states, as one phrase.
SCOPE_FILE_LIMITS_PHRASE = f"at most {MAX_FILE_MIB} MiB and {MAX_ENTRIES} entries"
_LIMITS_TEXT = (
    f"the limits are {MAX_ENTRIES} entries, {MAX_FILE_MIB} MiB "
    f"and {MAX_LINE_CHARS} characters per line"
)

#: Persisted format of the ``asset_scope`` block's entry lists.
ASSET_SCOPE_FORMAT = 1

#: ``dc_access`` values: the domain controllers of in-scope domains are used for
#: directory reads only, or assessed as hosts like any other.
DC_ACCESS_DIRECTORY_ONLY = "directory_only"
DC_ACCESS_FULL = "full"
DC_ACCESS_VALUES = (DC_ACCESS_DIRECTORY_ONLY, DC_ACCESS_FULL)
_DC_ACCESS_ALIASES = {
    "directory": DC_ACCESS_DIRECTORY_ONLY,
    "directory_only": DC_ACCESS_DIRECTORY_ONLY,
    "directory-only": DC_ACCESS_DIRECTORY_ONLY,
    "full": DC_ACCESS_FULL,
}

#: Entry types.
TYPE_IP = "ip"
TYPE_CIDR = "cidr"
TYPE_RANGE = "range"
TYPE_FQDN = "fqdn"
TYPE_DNS_SUFFIX = "dns_suffix"
TYPE_SHORT_HOST = "short_host"
TYPE_SID = "sid"
TYPE_DN = "dn"
TYPE_PRINCIPAL = "principal"
TYPE_UPN = "upn"
ENTRY_TYPES = (
    TYPE_IP,
    TYPE_CIDR,
    TYPE_RANGE,
    TYPE_FQDN,
    TYPE_DNS_SUFFIX,
    TYPE_SHORT_HOST,
    TYPE_SID,
    TYPE_DN,
    TYPE_PRINCIPAL,
    TYPE_UPN,
)
#: Types that name an address, matched against the address being connected to.
ADDRESS_TYPES = frozenset({TYPE_IP, TYPE_CIDR, TYPE_RANGE})
#: Types that name a directory object; they resolve to an identity through the
#: inventory and stay ``pending`` until it is collected.
IDENTITY_TYPES = frozenset(
    {TYPE_SHORT_HOST, TYPE_SID, TYPE_DN, TYPE_PRINCIPAL, TYPE_UPN}
)

#: Kind hints an entry can carry.
KIND_COMPUTER = "computer"
KIND_USER = "user"
KIND_GROUP = "group"
_KIND_PREFIXES = {"user": KIND_USER, "group": KIND_GROUP, "computer": KIND_COMPUTER}

_PREFIXES = frozenset(
    {
        "ip",
        "cidr",
        "range",
        "host",
        "suffix",
        "sid",
        "dn",
        "subtree",
        "user",
        "group",
        "computer",
    }
)

_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
_SHORT_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_.-]{0,62})?$")
_SAM_RE = re.compile(r"^[^\s\\/\[\]:;|=,+*?<>\"@]{1,256}$")
_NETBIOS_RE = re.compile(r"^[a-z0-9_][a-z0-9_.!#&'()^{}~ -]{0,62}$")
_SID_RE = re.compile(r"^S-1-\d+(?:-\d+)+$", re.IGNORECASE)
_IPV4_SHAPE = re.compile(r"^\d+(?:\.\d+){3}$")
_DN_HEAD = re.compile(r"^\s*(?:CN|OU|DC|O|L|ST|C)\s*=", re.IGNORECASE)
_RDN_HEAD = re.compile(r"^\s*[A-Za-z][A-Za-z0-9-]*\s*=")
_PREFIX_RE = re.compile(r"^([a-z]+):(?!//)(.*)$", re.IGNORECASE | re.DOTALL)


class ScopeSyntaxError(ValueError):
    """An engagement-scope entry, file or record that cannot be parsed.

    Attributes:
        source: The file name (or ``cli``, ``web``...) the entry came from.
        line: 1-based line number, ``0`` when the error is not on one line.
        reason: What is wrong, in plain words.
        is_write_failure: False here; True on the engine's
            ``ScopeRecordWriteError`` subclass (the scope was valid and the
            workspace could not be written).
    """

    is_write_failure = False

    def __init__(self, source: str, line: int, reason: str) -> None:
        self.source = str(source or "")
        self.line = int(line or 0)
        self.reason = str(reason or "")
        where = self.source or "scope"
        if self.line:
            where = f"{where} line {self.line}"
        super().__init__(f"{where}: {self.reason}")


@dataclass(frozen=True)
class ScopeEntry:
    """One normalised scope entry.

    Attributes:
        type: One of :data:`ENTRY_TYPES`.
        value: Canonical value (lower-cased names, compressed IPv6, canonical DN,
            upper-cased SID). A range keeps its two ends, ``first-last``.
        kind: Kind hint (``computer``/``user``/``group``) or ``""``.
        origin: Where it came from (``cli``, ``file:deny.txt:3``, ``web``...).
        id: Stable id within its list (``a1``, ``d2``), set by :class:`AssetScope`.
    """

    type: str
    value: str
    kind: str = ""
    origin: str = ""
    id: str = ""

    @property
    def key(self) -> tuple[str, str, str]:
        """Identity of the entry for de-duplication and the digest."""
        return (self.type, self.value, self.kind)

    def to_dict(self) -> dict[str, str]:
        """The persisted row."""
        row = {
            "id": self.id,
            "type": self.type,
            "value": self.value,
            "origin": self.origin,
        }
        if self.kind:
            row["kind"] = self.kind
        return row


@dataclass(frozen=True)
class ParsedScope:
    """Entries parsed from one input, with warnings the operator should see."""

    entries: tuple[ScopeEntry, ...] = ()
    warnings: tuple[str, ...] = ()


# ── Grammar ────────────────────────────────────────────────────────────────


def _err(source: str, line: int, reason: str) -> ScopeSyntaxError:
    return ScopeSyntaxError(source, line, reason)


def _normalise_name(text: str) -> str:
    """Lower-case a DNS name, strip one trailing dot, encode IDN labels."""
    name = text.strip().rstrip(".")
    if not name.isascii():
        try:
            name = name.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError(f"'{text}' is not a valid internationalised name") from exc
    return name.lower()


def _fqdn(text: str) -> str:
    name = _normalise_name(text)
    if not name or len(name) > 253:
        raise ValueError(f"'{text}' is not a valid host name")
    labels = name.split(".")
    for label in labels:
        if not _LABEL_RE.match(label):
            raise ValueError(f"'{text}' is not a valid host name")
    if labels[-1].isdigit():
        raise ValueError(
            f"'{text}' is neither a valid IP address nor a valid host name"
        )
    return name


def _short_host(text: str) -> str:
    name = text.strip()
    if name.endswith("$"):
        name = name[:-1]
    name = _normalise_name(name)
    if not name or "." in name or len(name) > 63 or not _SHORT_RE.match(name):
        raise ValueError(f"'{text}' is not a valid short host name")
    if name.isdigit():
        raise ValueError(
            f"'{text}' is a number, not a host name; write an IP address in dotted form"
        )
    return name


def unmap_address(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """An IPv4-mapped IPv6 address (``::ffff:192.0.2.10``) as its IPv4 address."""
    if addr.version == 6 and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _address(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        return unmap_address(ipaddress.ip_address(text.strip().strip("[]")))
    except ValueError as exc:
        raise ValueError(f"'{text}' is not a valid IP address") from exc


def _unmap_network(
    net: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    mapped = net.network_address.ipv4_mapped if net.version == 6 else None
    if mapped is not None and net.prefixlen >= 96:
        return ipaddress.ip_network(f"{mapped}/{net.prefixlen - 96}")
    return net


def _network(text: str) -> tuple[str, list[str]]:
    try:
        net = _unmap_network(ipaddress.ip_network(text.strip(), strict=True))
    except ValueError as exc:
        if "host bits set" in str(exc):
            raise ValueError(
                f"'{text}' has bits set after the prefix: write the network's first "
                "address, or check the prefix length"
            ) from exc
        raise ValueError(f"'{text}' is not a valid network (CIDR)") from exc
    if net.prefixlen == 0:
        raise ValueError(
            f"'{text}' covers every address; leave the allow-list empty instead of "
            "allowing everything, and a deny-all cannot run"
        )
    warnings = []
    if (net.version == 4 and net.prefixlen < 8) or (
        net.version == 6 and net.prefixlen < 32
    ):
        warnings.append(f"{net} is a very wide network; check it is the one you meant.")
    return str(net), warnings


def _range(text: str) -> tuple[str, list[str]]:
    first_text, _, last_text = text.strip().partition("-")
    first = _address(first_text)
    last_text = last_text.strip()
    if first.version == 4 and last_text.isdigit():
        octets = str(first).split(".")
        last_text = ".".join([*octets[:3], last_text])
    last = _address(last_text)
    if first.version != last.version:
        raise ValueError(f"'{text}' mixes IPv4 and IPv6 ends")
    if int(last) < int(first):
        raise ValueError(f"'{text}' ends before it starts")
    nets = list(ipaddress.summarize_address_range(first, last))
    if any(n.prefixlen == 0 for n in nets):
        raise ValueError(f"'{text}' covers every address")
    warnings = []
    width = int(last) - int(first) + 1
    limit = 2**24 if first.version == 4 else 2**96
    if width > limit:
        warnings.append(
            f"{first}-{last} is a very wide range; check it is the one you meant."
        )
    return f"{first}-{last}", warnings


def _split_dn(text: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for char in text:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == ",":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


_DN_SPECIALS = ',+"\\<>;=#'
_DN_ESCAPE = re.compile(r"((?:\\[0-9A-Fa-f]{2})+)|(\\.)", re.DOTALL)


def _dn_value(value: str) -> str:
    """A DN value with hex escapes decoded (specials kept in ``\\c`` form).

    ``Plant\\2C North`` and ``Plant\\, North`` are the same value. A run of hex
    escapes is one UTF-8 sequence (RFC 4514), so ``Caf\\C3\\A9`` is ``Café``;
    bytes that are not UTF-8 are read one by one. An escaped backslash is never
    the start of a hex escape.
    """

    def _token(match: re.Match[str]) -> str:
        if match.group(2):
            return match.group(2)
        raw = bytes(int(pair, 16) for pair in match.group(1).split("\\")[1:])
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1")
        return "".join("\\" + char if char in _DN_SPECIALS else char for char in text)

    return _DN_ESCAPE.sub(_token, value)


def canonical_dn(text: str) -> str:
    """The canonical form of a distinguished name (attribute types upper-cased).

    Component order is kept and spaces around ``=`` and ``,`` are dropped; values
    keep their case for display (matching is case-insensitive), and a hex escape
    of a special character takes its ``\\c`` form. A DN must end in its domain
    components (``DC=``): a relative DN such as ``OU=OT`` names no object.

    Raises:
        ValueError: ``text`` is not a full distinguished name.
    """
    rdns = []
    for part in _split_dn(str(text or "")):
        attr, sep, value = part.partition("=")
        attr = attr.strip()
        value = _dn_value(value.strip())
        if (
            not sep
            or not attr
            or not value
            or not re.match(r"^[A-Za-z][A-Za-z0-9-]*$", attr)
        ):
            raise ValueError(f"'{text}' is not a valid distinguished name")
        rdns.append(f"{attr.upper()}={value}")
    if not rdns:
        raise ValueError(f"'{text}' is not a valid distinguished name")
    if not rdns[-1].startswith("DC="):
        raise ValueError(
            f"'{text}' is not a full distinguished name: it must end in the domain "
            "components (DC=...)"
        )
    return ",".join(rdns)


def _dn_key(dn: str) -> str:
    """Case-insensitive match key of a canonical DN."""
    return dn.casefold()


def _sid(text: str) -> str:
    value = text.strip()
    if not _SID_RE.match(value):
        raise ValueError(f"'{text}' is not a valid SID")
    return value.upper()


def _sam(text: str) -> str:
    name = text.strip().lower()
    if not name or not _SAM_RE.match(name):
        raise ValueError(f"'{text}' is not a valid account name")
    return name


def _principal(text: str, kind: str = "") -> str:
    netbios, _, name = text.strip().partition("\\")
    netbios = netbios.strip().lower()
    if not netbios or not _NETBIOS_RE.match(netbios):
        raise ValueError(f"'{text}' is not DOMAIN\\name")
    name = _sam(name)
    if kind == KIND_COMPUTER and not name.endswith("$"):
        name += "$"
    return f"{netbios}\\{name}"


def _upn(text: str) -> str:
    name, _, realm = text.strip().partition("@")
    name = _sam(name)
    realm = _normalise_name(realm)
    if not realm:
        raise ValueError(f"'{text}' is not name@realm")
    for label in realm.split("."):
        if not _LABEL_RE.match(label):
            raise ValueError(f"'{text}' is not name@realm")
    return f"{name}@{realm}"


def _parse_typed(prefix: str, body: str) -> tuple[str, str, str, list[str]]:
    """Parse a value whose type an explicit prefix forces."""
    if not body.strip():
        raise ValueError(f"'{prefix}:' needs a value")
    if prefix == "ip":
        return TYPE_IP, str(_address(body)), "", []
    if prefix == "cidr":
        value, warnings = _network(body)
        return TYPE_CIDR, value, "", warnings
    if prefix == "range":
        value, warnings = _range(body)
        return TYPE_RANGE, value, "", warnings
    if prefix == "suffix":
        return TYPE_DNS_SUFFIX, _fqdn(body.strip().removeprefix("*.")), "", []
    if prefix == "sid":
        return TYPE_SID, _sid(body), "", []
    if prefix in ("dn", "subtree"):
        return TYPE_DN, canonical_dn(body), "", []
    if prefix in ("host", "computer"):
        kind = KIND_COMPUTER
        text = body.strip()
        if "\\" in text and prefix == "computer":
            return TYPE_PRINCIPAL, _principal(text, KIND_COMPUTER), kind, []
        etype, value, _, warnings = _parse_auto(text)
        if etype in (TYPE_FQDN, TYPE_SHORT_HOST, TYPE_IP):
            # A host type is a computer by definition; no hint to carry.
            return etype, value, "", warnings
        if prefix == "computer" and etype in (TYPE_SID, TYPE_DN, TYPE_UPN):
            return etype, value, kind, warnings
        raise ValueError(f"'{body}' is not a host")
    kind = _KIND_PREFIXES[prefix]
    text = body.strip()
    if "\\" in text:
        return TYPE_PRINCIPAL, _principal(text, kind), kind, []
    if "@" in text:
        return TYPE_UPN, _upn(text), kind, []
    if _SID_RE.match(text):
        return TYPE_SID, _sid(text), kind, []
    if _DN_HEAD.match(text):
        return TYPE_DN, canonical_dn(text), kind, []
    return TYPE_PRINCIPAL, _sam(text), kind, []


def _parse_auto(text: str) -> tuple[str, str, str, list[str]]:
    """Detect the type of an unprefixed value."""
    value = text.strip()
    if not value:
        raise ValueError("empty entry")
    if _SID_RE.match(value):
        return TYPE_SID, _sid(value), "", []
    if value.upper().startswith("S-1-"):
        raise ValueError(f"'{value}' is not a valid SID")
    if _DN_HEAD.match(value):
        return TYPE_DN, canonical_dn(value), "", []
    if "\\" in value:
        kind = KIND_COMPUTER if value.rstrip().endswith("$") else ""
        return TYPE_PRINCIPAL, _principal(value), kind, []
    if "@" in value:
        return TYPE_UPN, _upn(value), "", []
    if value.startswith("*."):
        return TYPE_DNS_SUFFIX, _fqdn(value[2:]), "", []
    if "/" in value:
        net, warnings = _network(value)
        return TYPE_CIDR, net, "", warnings
    if "-" in value and (
        ":" in value.split("-", 1)[0]
        or _IPV4_SHAPE.match(value.split("-", 1)[0].strip())
    ):
        rng, warnings = _range(value)
        return TYPE_RANGE, rng, "", warnings
    if ":" in value or _IPV4_SHAPE.match(value):
        return TYPE_IP, str(_address(value)), "", []
    if "." in value:
        return TYPE_FQDN, _fqdn(value), "", []
    return TYPE_SHORT_HOST, _short_host(value), "", []


def parse_entry(
    text: str, *, origin: str = "", source: str = "", line: int = 0
) -> tuple[ScopeEntry, list[str]]:
    """Parse one entry. Returns the entry and any warnings.

    Raises:
        ScopeSyntaxError: The entry is not valid; names ``source`` and ``line``.
    """
    raw = str(text or "").strip()
    try:
        if not raw:
            raise ValueError("empty entry")
        if any(ch.isspace() for ch in raw) and not _DN_HEAD.match(
            raw.split(":", 1)[-1]
        ):
            raise ValueError(f"'{raw}' contains a space")
        match = _PREFIX_RE.match(raw)
        if match and match.group(1).lower() in _PREFIXES:
            etype, value, kind, warnings = _parse_typed(
                match.group(1).lower(), match.group(2)
            )
        elif match and not (
            "\\" in raw.split(":", 1)[0] or _IPV4_SHAPE.match(raw.split(":", 1)[0])
        ):
            # ``word:...`` with an unknown word, not an IPv6 literal.
            head = match.group(1).lower()
            try:
                ipaddress.ip_address(raw.split("-", 1)[0].split("/", 1)[0].strip("[]"))
            except ValueError as exc:
                raise ValueError(f"unknown prefix '{head}:'") from exc
            etype, value, kind, warnings = _parse_auto(raw)
        else:
            etype, value, kind, warnings = _parse_auto(raw)
    except ValueError as exc:
        raise _err(source or origin, line, str(exc)) from exc
    return ScopeEntry(type=etype, value=value, kind=kind, origin=origin), warnings


def split_inline_values(values: Iterable[str]) -> list[str]:
    """Split comma-separated inline values, keeping a distinguished name whole.

    ``OU=OT,DC=corp,DC=example,192.0.2.11`` is two values: the DN components
    after the first are glued back to it, and an escaped comma never splits.
    """
    out: list[str] = []
    for value in values or ():
        pieces = _split_dn(str(value or ""))
        in_dn = False
        for piece in pieces:
            token = piece.strip()
            if not token:
                in_dn = False
                continue
            if in_dn and _RDN_HEAD.match(token):
                out[-1] = f"{out[-1]},{token}"
                continue
            head = token.split(":", 1)[1] if _PREFIX_RE.match(token) else token
            in_dn = bool(_DN_HEAD.match(head))
            out.append(token)
    return out


def _collect(items: Iterable[tuple[str, str, int]], *, source: str) -> ParsedScope:
    entries: list[ScopeEntry] = []
    seen: set[tuple[str, str, str]] = set()
    warnings: list[str] = []
    for text, origin, line in items:
        entry, notes = parse_entry(text, origin=origin, source=source, line=line)
        warnings.extend(notes)
        if entry.key in seen:
            continue
        seen.add(entry.key)
        entries.append(entry)
        if len(entries) > MAX_ENTRIES:
            raise _err(
                source, line, f"more than {MAX_ENTRIES} entries ({_LIMITS_TEXT})"
            )
    return ParsedScope(entries=tuple(entries), warnings=tuple(warnings))


def _is_full_dn(text: str) -> bool:
    body = text.strip()
    match = _PREFIX_RE.match(body)
    if match and match.group(1).lower() in _PREFIXES:
        body = match.group(2)
    if not _DN_HEAD.match(body):
        return False
    try:
        canonical_dn(body)
    except ValueError:
        return False
    return True


def _strip_comment(line: str) -> str:
    """Drop a ``#`` comment (whole line, or after whitespace).

    On a DN line a ``#`` is a comment only once what precedes it is a full DN
    (``CN=Lab #1,OU=OT,DC=corp,DC=example`` keeps its ``#``), and an escaped
    ``\\#`` is never one.
    """
    is_dn = bool(
        _DN_HEAD.match(
            line.split(":", 1)[-1] if _PREFIX_RE.match(line.strip()) else line
        )
    )
    for index, char in enumerate(line):
        if char != "#":
            continue
        if index and line[index - 1] == "\\":
            continue
        if index == 0 or line[index - 1].isspace():
            head = line[:index]
            if is_dn and head.strip() and not _is_full_dn(head):
                continue
            return head
    return line


#: Reason of a scope input the operator gave that holds no entry.
EMPTY_TEXT_REASON = "no entries: the input holds only comments or blank lines"
EMPTY_VALUE_REASON = "no entries: the value is empty"


def _text_lines(text: str) -> list[tuple[int, str, str]]:
    """``(line number, raw line, entry text)`` of file-shaped text.

    The entry text has its comment and surrounding spaces removed (``""`` for a
    blank or comment-only line). A leading BOM is dropped; CRLF is accepted.
    """
    body = str(text or "")
    if body.startswith("﻿"):
        body = body[1:]
    return [
        (number, raw, _strip_comment(raw).strip())
        for number, raw in enumerate(body.splitlines(), start=1)
    ]


def parse_scope_text(
    text: str, *, source: str, origin_prefix: str = "file", allow_empty: bool = False
) -> ParsedScope:
    """Parse file-shaped text: one entry per line, ``#`` comments, blank lines.

    Accepts a leading BOM and CRLF line ends. Each entry's origin is
    ``<origin_prefix>:<source>:<line>``. An input the operator gave that holds
    no entry is an error (an empty allow file must never mean "no allow-list");
    ``allow_empty`` is for a caller composing an optional, absent input.

    Raises:
        ScopeSyntaxError: An invalid line, a line over :data:`MAX_LINE_CHARS`
            characters, more than :data:`MAX_ENTRIES` entries, or no entry at
            all (:data:`EMPTY_TEXT_REASON`).
    """
    items: list[tuple[str, str, int]] = []
    for number, raw, value in _text_lines(text):
        if len(raw) > MAX_LINE_CHARS:
            raise _err(source, number, f"line longer than {MAX_LINE_CHARS} characters")
        if value:
            items.append((value, f"{origin_prefix}:{source}:{number}", number))
    if not items and not allow_empty:
        raise _err(source, 0, EMPTY_TEXT_REASON)
    return _collect(items, source=source)


@dataclass(frozen=True)
class ScopeLineResult:
    """The outcome of one line of file-shaped scope text (for a preview).

    Attributes:
        line: 1-based line number.
        text: The entry as written, without its comment.
        entry: The parsed entry, or ``None`` when the line is invalid.
        error: Why the line is invalid (``""`` when it parsed).
        warnings: Warnings the entry carries (a very wide range, for example).
        duplicate_of: Line number of an earlier identical entry (``0`` if none).
    """

    line: int
    text: str
    entry: ScopeEntry | None = None
    error: str = ""
    warnings: tuple[str, ...] = ()
    duplicate_of: int = 0


def preview_scope_text(text: str, *, source: str) -> list[ScopeLineResult]:
    """Parse every entry line of file-shaped text, without stopping at an error.

    The same grammar as :func:`parse_scope_text` (it is the same line reader and
    the same :func:`parse_entry`), but every line gets a result, so a form can
    show each error beside its line. Blank and comment-only lines are skipped.
    The text as a whole is valid exactly when no result carries an ``error``
    and there are at most :data:`MAX_ENTRIES` distinct entries.
    """
    results: list[ScopeLineResult] = []
    first_line: dict[tuple[str, str, str], int] = {}
    for number, raw, value in _text_lines(text):
        if not value:
            continue
        if len(raw) > MAX_LINE_CHARS:
            results.append(
                ScopeLineResult(
                    number, value[:80], error=f"line longer than {MAX_LINE_CHARS} characters"
                )
            )
            continue
        try:
            entry, warnings = parse_entry(
                value, origin=f"{source}:{number}", source=source, line=number
            )
        except ScopeSyntaxError as exc:
            results.append(ScopeLineResult(number, value, error=exc.reason))
            continue
        duplicate = first_line.setdefault(entry.key, number)
        results.append(
            ScopeLineResult(
                number,
                value,
                entry=entry,
                warnings=tuple(warnings),
                duplicate_of=duplicate if duplicate != number else 0,
            )
        )
    return results


def widening_changes(old: "AssetScope | None", new: "AssetScope") -> list[str]:
    """What in ``new`` lets ADscan touch more than ``old`` did (empty: it does not).

    Widening: a deny entry removed, an allow entry added to an existing
    allow-list, the allow-list removed, or domain controllers opened to host
    assessment while an allow-list applies. Starting an allow-list, adding a
    deny entry or removing an allow entry only narrow. Shared by the REPL
    ``scope`` command and the web platform, which both ask before widening.
    """
    if old is None or old.empty:
        return []

    def _keys(entries: Iterable[ScopeEntry]) -> set[tuple[str, str, str]]:
        return {e.key for e in entries}

    changes: list[str] = []
    dropped_deny = _keys(old.deny) - _keys(new.deny)
    if dropped_deny:
        changes.append(
            f"{len(dropped_deny)} deny entr{'y' if len(dropped_deny) == 1 else 'ies'} removed"
        )
    if old.allow and not new.allow:
        changes.append("the allow-list removed (every host becomes eligible)")
    elif old.allow:
        added = _keys(new.allow) - _keys(old.allow)
        if added:
            changes.append(f"{len(added)} allow entr{'y' if len(added) == 1 else 'ies'} added")
    if (
        old.dc_access == DC_ACCESS_DIRECTORY_ONLY
        and new.dc_access == DC_ACCESS_FULL
        and (new.allow or old.allow)
    ):
        changes.append("domain controllers opened to host assessment")
    return changes


def narrowing_changes(old: "AssetScope | None", new: "AssetScope | None") -> list[str]:
    """What in ``new`` keeps ADscan from something ``old`` let it touch (empty: nothing).

    The mirror of :func:`widening_changes`: a deny entry added, an allow-list
    started, an allow entry removed from an allow-list that stays, or domain
    controllers kept to directory reads while an allow-list applies. Entry
    counts only, never an entry's value.
    """
    if new is None or new.empty:
        return []

    def _keys(entries: Iterable[ScopeEntry]) -> set[tuple[str, str, str]]:
        return {e.key for e in entries}

    old_allow = tuple(old.allow) if old is not None else ()
    old_deny = tuple(old.deny) if old is not None else ()
    changes: list[str] = []
    added_deny = _keys(new.deny) - _keys(old_deny)
    if added_deny:
        changes.append(f"{len(added_deny)} deny entr{'y' if len(added_deny) == 1 else 'ies'} added")
    if new.allow and not old_allow:
        changes.append("an allow-list started (only the hosts it names are assessed)")
    elif new.allow:
        removed = _keys(old_allow) - _keys(new.allow)
        if removed:
            changes.append(f"{len(removed)} allow entr{'y' if len(removed) == 1 else 'ies'} removed")
    if (
        old is not None
        and old.dc_access == DC_ACCESS_FULL
        and new.dc_access == DC_ACCESS_DIRECTORY_ONLY
        and (new.allow or old_allow)
    ):
        changes.append("domain controllers kept to directory reads")
    return changes


def parse_scope_values(
    values: Iterable[str], *, origin: str, allow_empty: bool = False
) -> ParsedScope:
    """Parse inline values (a flag, the REPL, a web field): comma-separated.

    An explicitly given value that holds no entry (``--scope-allow ""``) is an
    error; ``allow_empty`` is for a caller composing an optional input.

    Raises:
        ScopeSyntaxError: An invalid value, more than :data:`MAX_ENTRIES`, or
            no entry at all (:data:`EMPTY_VALUE_REASON`).
    """
    tokens = split_inline_values(values)
    for token in tokens:
        if len(token) > MAX_LINE_CHARS:
            raise _err(origin, 0, f"entry longer than {MAX_LINE_CHARS} characters")
    if not tokens and not allow_empty:
        raise _err(origin, 0, EMPTY_VALUE_REASON)
    return _collect(((t, origin, 0) for t in tokens), source=origin)


def parse_scope_entries(
    text_or_values: str | Iterable[str], *, origin: str, allow_empty: bool = False
) -> ParsedScope:
    """Parse a text block (file shape) or a sequence of inline values."""
    if isinstance(text_or_values, str):
        return parse_scope_text(
            text_or_values, source=origin, origin_prefix=origin, allow_empty=allow_empty
        )
    return parse_scope_values(text_or_values, origin=origin, allow_empty=allow_empty)


def read_scope_file(path: str | os.PathLike[str]) -> ParsedScope:
    """Read and parse one scope file (UTF-8, at most :data:`MAX_FILE_BYTES`).

    Raises:
        ScopeSyntaxError: The file is missing, too large, not UTF-8, or holds an
            invalid line (named with its number).
    """
    name = os.path.basename(os.fspath(path))
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise _err(name, 0, f"cannot read the file ({exc.strerror or exc})") from exc
    if size > MAX_FILE_BYTES:
        raise _err(name, 0, f"the file is too large ({_LIMITS_TEXT})")
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise _err(name, 0, f"cannot read the file ({exc.strerror or exc})") from exc
    if len(data) > MAX_FILE_BYTES:
        raise _err(name, 0, f"the file is too large ({_LIMITS_TEXT})")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        line = data[: exc.start].count(b"\n") + 1
        raise _err(name, line, "the file is not UTF-8 text") from exc
    return parse_scope_text(text, source=name)


def normalise_dc_access(value: Any) -> str:
    """``directory``/``directory_only``/``full`` to the stored value.

    Raises:
        ScopeSyntaxError: Any other value.
    """
    text = str(value or DC_ACCESS_DIRECTORY_ONLY).strip().lower()
    if text not in _DC_ACCESS_ALIASES:
        raise _err("dc_access", 0, f"'{value}' is not one of directory, full")
    return _DC_ACCESS_ALIASES[text]


# ── The scope ──────────────────────────────────────────────────────────────


def _with_ids(entries: Iterable[ScopeEntry], prefix: str) -> tuple[ScopeEntry, ...]:
    out: list[ScopeEntry] = []
    seen: set[tuple[str, str, str]] = set()
    for entry in entries or ():
        if entry.key in seen:
            continue
        seen.add(entry.key)
        out.append(
            ScopeEntry(
                type=entry.type,
                value=entry.value,
                kind=entry.kind,
                origin=entry.origin,
                id=f"{prefix}{len(out) + 1}",
            )
        )
    return tuple(out)


@dataclass(frozen=True)
class AssetScope:
    """An allow-list and a deny-list, and how domain controllers are treated."""

    allow: tuple[ScopeEntry, ...] = ()
    deny: tuple[ScopeEntry, ...] = ()
    dc_access: str = DC_ACCESS_DIRECTORY_ONLY

    @classmethod
    def create(
        cls,
        *,
        allow: Iterable[ScopeEntry] = (),
        deny: Iterable[ScopeEntry] = (),
        dc_access: Any = DC_ACCESS_DIRECTORY_ONLY,
    ) -> "AssetScope":
        """Build a scope, merging duplicates and numbering entries per list."""
        return cls(
            allow=_with_ids(allow, "a"),
            deny=_with_ids(deny, "d"),
            dc_access=normalise_dc_access(dc_access),
        )

    @property
    def empty(self) -> bool:
        """True when neither list names anything."""
        return not self.allow and not self.deny

    def entry(self, entry_id: str) -> ScopeEntry | None:
        """The entry with ``entry_id`` (``a1``, ``d2``), or ``None``."""
        for entry in (*self.allow, *self.deny):
            if entry.id == entry_id:
                return entry
        return None

    def in_both_lists(self) -> tuple[str, ...]:
        """Values named in both lists (legal: deny wins), for the summary."""
        allowed = {e.key for e in self.allow}
        return tuple(e.value for e in self.deny if e.key in allowed)

    def digest(self) -> str:
        """``sha256:<hex>`` over the canonical, order-independent entry lists."""
        canonical = {
            "format": ASSET_SCOPE_FORMAT,
            "dc_access": self.dc_access,
            "allow": sorted(list(e.key) for e in self.allow),
            "deny": sorted(list(e.key) for e in self.deny),
        }
        blob = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """The scope part of the persisted ``asset_scope`` block."""
        return {
            "format": ASSET_SCOPE_FORMAT,
            "digest": self.digest(),
            "dc_access": self.dc_access,
            "allow": [e.to_dict() for e in self.allow],
            "deny": [e.to_dict() for e in self.deny],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> "AssetScope":
        """Rebuild a scope from its persisted block; every entry is re-validated.

        Raises:
            ScopeSyntaxError: An entry no longer parses, or a format this build
                does not read.
        """
        if not isinstance(data, Mapping):
            return cls()
        fmt = data.get("format", ASSET_SCOPE_FORMAT)
        if fmt != ASSET_SCOPE_FORMAT:
            raise _err("scope.json", 0, f"asset_scope format {fmt!r} is not readable")

        def _rows(name: str) -> list[ScopeEntry]:
            out: list[ScopeEntry] = []
            raw = data.get(name, ())
            if not isinstance(raw, (list, tuple)):
                # null, a string, an object: a list that is not a list is a
                # damaged block, never "no entries".
                raise _err("scope.json", 0, f"its {name} list is not a list")
            for row in raw:
                if not isinstance(row, Mapping):
                    raise _err("scope.json", 0, f"an {name} entry is not an object")
                etype = str(row.get("type") or "")
                if etype not in ENTRY_TYPES:
                    raise _err("scope.json", 0, f"unknown entry type {etype!r}")
                kind = str(row.get("kind") or "")
                if kind not in ("", KIND_COMPUTER, KIND_USER, KIND_GROUP):
                    raise _err("scope.json", 0, f"unknown entry kind {kind!r}")
                prefix = _TYPE_PREFIX[etype]
                if etype == TYPE_PRINCIPAL and kind:
                    prefix = kind
                elif etype == TYPE_PRINCIPAL:
                    prefix = ""
                text = (
                    f"{prefix}:{row.get('value')}"
                    if prefix
                    else str(row.get("value") or "")
                )
                entry, _ = parse_entry(
                    text, origin=str(row.get("origin") or ""), source="scope.json"
                )
                if entry.type != etype:
                    # The value does not read as the type the row says: the row
                    # was edited. A value that reads as the same type but is
                    # SPELLED differently from this version's canonical form
                    # (another version's normalisation) is the same entry, and
                    # is read in this version's form.
                    raise _err(
                        "scope.json", 0, f"entry {row.get('value')!r} is not canonical"
                    )
                out.append(
                    ScopeEntry(
                        etype,
                        entry.value,
                        kind or entry.kind,
                        entry.origin,
                        str(row.get("id") or ""),
                    )
                )
            return out

        allow = _rows("allow")
        deny = _rows("deny")
        if cls.ids_consistent(data):
            return cls(
                allow=tuple(allow),
                deny=tuple(deny),
                dc_access=normalise_dc_access(data.get("dc_access")),
            )
        # A deny row stored as ``a1`` would project its identities into the
        # ALLOW index: renumber both lists (the caller drops the resolution).
        return cls(
            allow=_with_ids(allow, "a"),
            deny=_with_ids(deny, "d"),
            dc_access=normalise_dc_access(data.get("dc_access")),
        )

    @staticmethod
    def ids_consistent(data: Mapping[str, Any] | None) -> bool:
        """Whether the persisted ids are unique and carry their list's prefix.

        When they are not, :meth:`from_dict` renumbers the entries and the
        persisted resolution (keyed by id) must be discarded.
        """
        if not isinstance(data, Mapping):
            return True
        seen: set[str] = set()
        for name, prefix in (("allow", "a"), ("deny", "d")):
            for row in data.get(name) or ():
                entry_id = str(row.get("id") or "") if isinstance(row, Mapping) else ""
                if (
                    not entry_id.startswith(prefix)
                    or not entry_id[1:].isdigit()
                    or entry_id in seen
                ):
                    return False
                seen.add(entry_id)
        return True


_TYPE_PREFIX = {
    TYPE_IP: "ip",
    TYPE_CIDR: "cidr",
    TYPE_RANGE: "range",
    TYPE_FQDN: "host",
    TYPE_DNS_SUFFIX: "suffix",
    TYPE_SHORT_HOST: "host",
    TYPE_SID: "sid",
    TYPE_DN: "dn",
    TYPE_PRINCIPAL: "",
    TYPE_UPN: "",
}


# ── Identities and the matcher ─────────────────────────────────────────────


@dataclass(frozen=True)
class AssetIdentity:
    """What is known about one directory object or host.

    Every field is optional: a target may be known only by an address, only by a
    name, or by its full directory record.
    """

    kind: str = ""
    object_id: str = ""
    domain: str = ""
    dn: str = ""
    fqdn: str = ""
    samaccountname: str = ""
    netbios: str = ""
    upn: str = ""
    addresses: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """The persisted resolution row (empty fields dropped)."""
        out: dict[str, Any] = {}
        for name in (
            "kind",
            "object_id",
            "domain",
            "dn",
            "fqdn",
            "samaccountname",
            "netbios",
            "upn",
        ):
            value = getattr(self, name)
            if value:
                out[name] = value
        if self.addresses:
            out["addresses"] = list(self.addresses)
        return out

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AssetIdentity":
        """Inverse of :meth:`to_dict` (unknown keys ignored)."""
        if not isinstance(data, Mapping):
            return cls()
        return cls(
            kind=str(data.get("kind") or ""),
            object_id=str(data.get("object_id") or ""),
            domain=str(data.get("domain") or ""),
            dn=str(data.get("dn") or ""),
            fqdn=str(data.get("fqdn") or ""),
            samaccountname=str(data.get("samaccountname") or ""),
            netbios=str(data.get("netbios") or ""),
            upn=str(data.get("upn") or ""),
            addresses=tuple(str(a) for a in data.get("addresses") or () if str(a)),
        )


@dataclass(frozen=True)
class MatchResult:
    """Which entry of each list matched (``""`` when none)."""

    deny_entry: str = ""
    allow_entry: str = ""

    @property
    def denied(self) -> bool:
        """A deny entry matched."""
        return bool(self.deny_entry)

    @property
    def allowed(self) -> bool:
        """An allow entry matched."""
        return bool(self.allow_entry)

    @property
    def excluded(self) -> bool:
        """Deny wins: matched by a deny entry, whatever the allow-list says."""
        return self.denied


NO_MATCH = MatchResult()


def _norm_name(value: Any) -> str:
    return str(value or "").strip().rstrip(".").lower()


def _sam_key(value: Any) -> str:
    return str(value or "").strip().lower()


_NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")


def embedded_ipv4(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | None:
    """The IPv4 address an IPv6 address carries inside it, if it carries one.

    IPv4-mapped (``::ffff:a.b.c.d``), the NAT64 well-known prefix
    (``64:ff9b::/96``), 6to4 (``2002:AABB:CCDD::/48``), Teredo, and the
    deprecated IPv4-compatible form (``::a.b.c.d``). A packet to any of these
    is delivered to, or through, that IPv4 host, so the DENY side reads the
    carried address too. (Only the mapped form is the same host on the allow
    side: :func:`unmap_address`.)
    """
    if addr.version != 6:
        return None
    if addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    if addr in _NAT64_PREFIX:
        return ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    if addr.sixtofour is not None:
        return addr.sixtofour
    if addr.teredo is not None:
        return addr.teredo[1]
    value = int(addr)
    if 1 < value <= 0xFFFFFFFF:
        return ipaddress.IPv4Address(value)
    return None


@dataclass
class _ListIndex:
    """The matchers of one list."""

    nets: dict[int, dict[int, dict[int, str]]] = field(
        default_factory=lambda: {4: {}, 6: {}}
    )
    fqdns: dict[str, str] = field(default_factory=dict)
    suffixes: dict[str, str] = field(default_factory=dict)
    shorts: dict[str, str] = field(default_factory=dict)
    #: First labels of denied FQDNs, consulted only for a target with no FQDN
    #: (a bare short name or a computer account), so ``fs01`` is caught while
    #: ``fs01.other.example`` is not.
    fqdn_shorts: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    sids: dict[str, str] = field(default_factory=dict)
    dns: dict[str, str] = field(default_factory=dict)
    principals: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    upns: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    host_capable: bool = False
    principal_capable: bool = False
    address_rules: bool = False
    entry_address_rules: bool = False
    #: Prefix lengths present per IP version, longest first (probe order).
    prefixes: dict[int, tuple[int, ...]] = field(default_factory=dict)

    def add_net(
        self, net: ipaddress.IPv4Network | ipaddress.IPv6Network, entry_id: str
    ) -> None:
        by_len = self.nets[net.version].setdefault(net.prefixlen, {})
        by_len.setdefault(int(net.network_address), entry_id)
        self.address_rules = True

    def add_address(self, text: str, entry_id: str) -> None:
        try:
            addr = unmap_address(ipaddress.ip_address(str(text).strip().strip("[]")))
        except ValueError:
            return
        self.add_net(ipaddress.ip_network(addr), entry_id)

    def add_fqdn_short(self, fqdn: str, entry_id: str) -> None:
        held = self.fqdn_shorts.setdefault(fqdn.split(".", 1)[0], [])
        if (fqdn, entry_id) not in held:
            held.append((fqdn, entry_id))

    def match_fqdn_short(self, label: str, domain: str) -> str:
        """A denied FQDN with this first label that a computer account of
        ``domain`` could carry: any when the domain is not known, else one
        inside that domain's DNS namespace (so ``DC01$`` of one domain is not
        excluded by another domain's ``dc01``)."""
        for fqdn, entry_id in self.fqdn_shorts.get(label, ()):
            if not domain or fqdn.endswith("." + domain):
                return entry_id
        return ""

    def add_principal(self, key: str, entry_id: str, kind: str) -> None:
        self.principals.setdefault(key, []).append((entry_id, kind))

    def finish(self) -> None:
        self.prefixes = {
            version: tuple(sorted(by_len, reverse=True))
            for version, by_len in self.nets.items()
        }

    def add_identity(
        self,
        identity: AssetIdentity,
        entry_id: str,
        *,
        with_addresses: bool = True,
        deny: bool = False,
    ) -> None:
        """Project a resolved identity's identifiers into this list.

        ``with_addresses=False`` leaves the addresses out (the allow side keeps
        them in a separate index: a resolved allow address must not grant a
        target known by another name). ``deny`` also indexes the FQDN's first
        label for targets that carry no FQDN.
        """
        kind = _sam_key(identity.kind)
        if identity.fqdn:
            self.fqdns.setdefault(_norm_name(identity.fqdn), entry_id)
            if deny:
                self.add_fqdn_short(_norm_name(identity.fqdn), entry_id)
        if identity.object_id:
            self.sids.setdefault(identity.object_id.strip().upper(), entry_id)
        if identity.dn:
            try:
                self.dns.setdefault(_dn_key(canonical_dn(identity.dn)), entry_id)
            except ValueError:
                pass
        if identity.samaccountname:
            sam = _sam_key(identity.samaccountname)
            if identity.netbios:
                self.add_principal(f"{_sam_key(identity.netbios)}\\{sam}", entry_id, "")
            if identity.domain:
                self.add_principal(
                    f"{_norm_name(identity.domain)}\\{sam}", entry_id, ""
                )
            if deny and not identity.netbios and not identity.domain:
                # A denied account whose domain is not known yet (an entry
                # qualifier no recorded domain answers to): every holder of
                # the name is excluded until the directory says which one.
                self.add_principal(sam, entry_id, kind)
        if identity.upn:
            self.upns.setdefault(_sam_key(identity.upn), []).append((entry_id, ""))
        if with_addresses:
            for address in identity.addresses:
                self.add_address(address, entry_id)
        if kind == KIND_COMPUTER or identity.fqdn or identity.addresses:
            self.host_capable = True
        if kind and kind != KIND_COMPUTER:
            self.principal_capable = True

    def match_address(self, addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
        addr = unmap_address(addr)
        nets = self.nets[addr.version]
        if not nets:
            return ""
        value = int(addr)
        bits = 32 if addr.version == 4 else 128
        full = (1 << bits) - 1
        for prefixlen in self.prefixes.get(addr.version, ()):
            mask = full ^ ((1 << (bits - prefixlen)) - 1) if prefixlen < bits else full
            hit = nets[prefixlen].get(value & mask)
            if hit:
                return hit
        return ""

    def _match_names(self, identity: AssetIdentity, *, generous: bool) -> str:
        """FQDN, DNS suffix, SID and DN (with every subtree above it)."""
        fqdn = _norm_name(identity.fqdn)
        if fqdn:
            hit = self.fqdns.get(fqdn)
            if hit:
                return hit
            labels = fqdn.split(".")
            for index in range(1, len(labels)):
                hit = self.suffixes.get(".".join(labels[index:]))
                if hit:
                    return hit
            if generous:
                hit = self.shorts.get(labels[0])
                if hit:
                    return hit
        if identity.object_id:
            hit = self.sids.get(identity.object_id.strip().upper())
            if hit:
                return hit
        if identity.dn:
            try:
                parts = _split_dn(canonical_dn(identity.dn))
            except ValueError:
                parts = []
            for index in range(len(parts)):
                hit = self.dns.get(_dn_key(",".join(parts[index:])))
                if hit:
                    return hit
        return ""

    def _match_keys(
        self, table: dict[str, list[tuple[str, str]]], keys: Iterable[str], kind: str
    ) -> str:
        for key in keys:
            for entry_id, hint in table.get(key, ()):
                if not hint or not kind or hint == kind:
                    return entry_id
        return ""

    def _match_addresses(self, identity: AssetIdentity) -> str:
        for address in identity.addresses:
            try:
                hit = self.match_address(
                    ipaddress.ip_address(str(address).strip().strip("[]"))
                )
            except ValueError:
                continue
            if hit:
                return hit
        return ""

    def match_deny(self, identity: AssetIdentity, *, by_label: bool = True) -> str:
        """GENEROUS match of one reading of a target: any way it could be named.

        ``by_label=False`` leaves out the match of a computer account against a
        denied FQDN by first label alone (for a reading whose domain other
        readings already carry).

        Over-matching is the safe direction for a deny-list. On top of the
        exact identifiers: a host is caught by a short entry carrying its
        first label; a target with no FQDN (a bare name, a computer account)
        by any denied FQDN with that first label; an account by the bare
        name, by ``qualifier\\name`` under its NetBIOS name, its DNS domain
        and that domain's first label, and by its implicit UPN
        (``name@domain``).
        """
        kind = _sam_key(identity.kind)
        hit = self._match_names(identity, generous=True)
        if hit:
            return hit
        if identity.samaccountname:
            sam = _sam_key(identity.samaccountname)
            domain = _norm_name(identity.domain)
            if kind in ("", KIND_COMPUTER) and sam.endswith("$"):
                hit = self.shorts.get(sam[:-1])
                if not hit and not identity.fqdn and by_label:
                    hit = self.match_fqdn_short(sam[:-1], domain)
                if hit:
                    return hit
            keys = [sam]
            # The domain's first label stands in for its NetBIOS name only
            # while that name is not known: once it is, another domain may
            # carry the first label AS its NetBIOS name.
            first_label = "" if identity.netbios else domain.split(".", 1)[0]
            for qualifier in (identity.netbios, domain, first_label):
                if qualifier:
                    keys.append(f"{_sam_key(qualifier)}\\{sam}")
            hit = self._match_keys(self.principals, keys, kind)
            if not hit and domain:
                hit = self._match_keys(self.upns, [f"{sam}@{domain}"], kind)
            if hit:
                return hit
        if identity.upn:
            hit = self._match_keys(self.upns, [_sam_key(identity.upn)], kind)
            if hit:
                return hit
        return self._match_addresses(identity)

    def match_allow(self, identity: AssetIdentity, *, addresses: bool = True) -> str:
        """STRICT match of one reading of a target: only what certainly names it.

        Under-matching is the safe direction for an allow-list. Exact
        identifiers only: the FQDN (or a suffix entry above it), the SID, the
        DN (or a subtree entry above it), ``qualifier\\name`` under the
        target's recorded NetBIOS name or its full DNS domain, the UPN (or the
        implicit ``name@domain``), and, with ``addresses``, an address entry.
        Never a first label, never a bare account name.
        """
        kind = _sam_key(identity.kind)
        hit = self._match_names(identity, generous=False)
        if hit:
            return hit
        if identity.samaccountname:
            sam = _sam_key(identity.samaccountname)
            domain = _norm_name(identity.domain)
            keys = [
                f"{_sam_key(qualifier)}\\{sam}"
                for qualifier in (identity.netbios, domain)
                if qualifier
            ]
            hit = self._match_keys(self.principals, keys, kind)
            if not hit and domain:
                hit = self._match_keys(self.upns, [f"{sam}@{domain}"], kind)
            if hit:
                return hit
        if identity.upn:
            hit = self._match_keys(self.upns, [_sam_key(identity.upn)], kind)
            if hit:
                return hit
        return self._match_addresses(identity) if addresses else ""

    def match_identity(self, identity: AssetIdentity, *, short_raw: bool) -> str:
        """Either reading by flag (``short_raw``: the generous, deny-side one)."""
        return self.match_deny(identity) if short_raw else self.match_allow(identity)


def _index_entry(
    index: _ListIndex, entry: ScopeEntry, *, raw_shorts: bool
) -> tuple[bool, bool] | None:
    """Index one entry. Returns its (host, principal) reach when only resolution can tell.

    A SID or DN without a kind hint may name a computer or an account; until it
    resolves it counts for both. Every other type's reach is fixed and is set on
    the index directly (``None`` returned).
    """
    etype = entry.type
    if etype in ADDRESS_TYPES:
        if etype == TYPE_IP:
            index.add_address(entry.value, entry.id)
        elif etype == TYPE_CIDR:
            index.add_net(ipaddress.ip_network(entry.value), entry.id)
        else:
            first, _, last = entry.value.partition("-")
            for net in ipaddress.summarize_address_range(
                ipaddress.ip_address(first), ipaddress.ip_address(last)
            ):
                index.add_net(net, entry.id)
        index.entry_address_rules = True
        index.host_capable = True
        return None
    if etype == TYPE_FQDN:
        index.fqdns.setdefault(entry.value, entry.id)
        if raw_shorts:
            index.add_fqdn_short(entry.value, entry.id)
        index.host_capable = True
        return None
    if etype == TYPE_DNS_SUFFIX:
        index.suffixes.setdefault(entry.value, entry.id)
        index.host_capable = True
        return None
    if etype == TYPE_SHORT_HOST:
        if raw_shorts:
            index.shorts.setdefault(entry.value, entry.id)
        index.host_capable = True
        return None
    if etype == TYPE_PRINCIPAL:
        qualified = "\\" in entry.value
        # An unqualified ALLOW principal grants only through its resolution
        # (several domains may hold the name); a DENY one matches every holder.
        if qualified or raw_shorts:
            index.add_principal(entry.value, entry.id, entry.kind)
        if raw_shorts and entry.value.endswith("$") and not qualified:
            # A denied computer account written without a domain catches the
            # host by its label in every domain. A QUALIFIED one is narrower:
            # the engine resolves it to the domains its qualifier could denote
            # (provisionally to every candidate while that is not settled), so
            # ``CORP\DC01$`` does not also exclude another domain's DC01.
            index.shorts.setdefault(entry.value[:-1], entry.id)
        if entry.kind == KIND_COMPUTER or entry.value.endswith("$"):
            index.host_capable = True
        else:
            index.principal_capable = True
        return None
    if etype == TYPE_UPN:
        index.upns.setdefault(entry.value, []).append((entry.id, entry.kind))
        if entry.kind == KIND_COMPUTER:
            index.host_capable = True
        else:
            index.principal_capable = True
        return None
    if etype == TYPE_SID:
        index.sids.setdefault(entry.value, entry.id)
    elif etype == TYPE_DN:
        index.dns.setdefault(_dn_key(entry.value), entry.id)
    if entry.kind == KIND_COMPUTER:
        index.host_capable = True
        return None
    if entry.kind:
        index.principal_capable = True
        return None
    return (True, True)


def _identity_reach(identities: Sequence[AssetIdentity]) -> tuple[bool, bool]:
    host = principal = False
    for identity in identities:
        kind = _sam_key(identity.kind)
        if kind == KIND_COMPUTER or (
            not kind and (identity.fqdn or identity.addresses)
        ):
            host = True
        elif kind:
            principal = True
        else:
            host = principal = True
    return host, principal


@dataclass(frozen=True)
class AssetMatcher:
    """Immutable matcher over one :class:`AssetScope` and its resolved identities.

    Two layers: the ENTRY indexes, built once per scope revision (cost grows with
    the scope), and the IDENTITY indexes, built from what the entries resolved to
    (cost grows with the resolved identities only). :meth:`with_resolved` rebuilds
    the second layer alone, so learning a host's second address never re-indexes
    100 000 entries. Swap the matcher by reference: readers on other threads and
    event loops need no lock.
    """

    scope: AssetScope
    _allow: _ListIndex
    _deny: _ListIndex
    _allow_id: _ListIndex
    _deny_id: _ListIndex
    _allow_open: tuple[tuple[str, bool, bool], ...] = ()
    _allow_host_reach: bool = False
    _allow_principal_reach: bool = False
    #: Addresses of resolved ALLOW identities, kept apart: they may grant an
    #: address-only target, never a target known by a name the list does not allow.
    _allow_addr: _ListIndex = field(default_factory=_ListIndex)
    #: DENY entries whose reach only resolution can tell (a SID or DN with no
    #: kind hint), and whether the deny-list reaches hosts at all.
    _deny_open: tuple[tuple[str, bool, bool], ...] = ()
    _deny_host_reach: bool = False
    #: First label -> entry of every ALLOW short-host entry that resolved to
    #: exactly one computer: that bare name is then unambiguous.
    _allow_unique_shorts: Mapping[str, str] = field(default_factory=dict)
    _allow_short_entries: tuple[tuple[str, str], ...] = ()

    @classmethod
    def build(
        cls,
        scope: AssetScope,
        resolved: Mapping[str, Sequence[AssetIdentity]] | None = None,
    ) -> "AssetMatcher":
        """Index ``scope`` plus the identities its entries resolved to.

        Args:
            scope: The scope.
            resolved: ``entry id -> identities`` from the engine's resolution.
                A resolved identity projects its addresses, names, SID and DN
                into the entry's list, so an IP entry blocks the host's name and
                a name entry blocks every address the host is known by.

        A short host name in the DENY list also matches any host whose first
        label is that name (every candidate is excluded); in the ALLOW list it
        grants access only through its resolved identity.
        """
        allow = _ListIndex()
        deny = _ListIndex()
        open_entries: list[tuple[str, bool, bool]] = []
        deny_open: list[tuple[str, bool, bool]] = []
        for entry in scope.allow:
            reach = _index_entry(allow, entry, raw_shorts=False)
            if reach is not None:
                open_entries.append((entry.id, reach[0], reach[1]))
        for entry in scope.deny:
            reach = _index_entry(deny, entry, raw_shorts=True)
            if reach is not None:
                deny_open.append((entry.id, reach[0], reach[1]))
        allow.finish()
        deny.finish()
        base = cls(
            scope=scope,
            _allow=allow,
            _deny=deny,
            _allow_id=_ListIndex(),
            _deny_id=_ListIndex(),
            _allow_open=tuple(open_entries),
            _deny_open=tuple(deny_open),
            _allow_short_entries=tuple(
                (e.id, e.value) for e in scope.allow if e.type == TYPE_SHORT_HOST
            ),
        )
        return base.with_resolved(resolved)

    def with_resolved(
        self, resolved: Mapping[str, Sequence[AssetIdentity]] | None
    ) -> "AssetMatcher":
        """A matcher sharing this one's entry indexes, with new resolved identities."""
        allow_id = _ListIndex()
        deny_id = _ListIndex()
        allow_addr = _ListIndex()
        resolved = resolved or {}
        for entry_id, identities in resolved.items():
            deny = entry_id.startswith("d")
            for identity in identities or ():
                if not isinstance(identity, AssetIdentity):
                    continue
                if deny:
                    deny_id.add_identity(identity, entry_id, deny=True)
                else:
                    allow_id.add_identity(identity, entry_id, with_addresses=False)
                    for address in identity.addresses:
                        allow_addr.add_address(address, entry_id)
        allow_id.finish()
        deny_id.finish()
        allow_addr.finish()
        host_reach = self._allow.host_capable
        principal_reach = self._allow.principal_capable
        for entry_id, host, principal in self._allow_open:
            identities = [
                i for i in resolved.get(entry_id) or () if isinstance(i, AssetIdentity)
            ]
            if identities:
                host, principal = _identity_reach(identities)
            host_reach = host_reach or host
            principal_reach = principal_reach or principal
        deny_host_reach = self._deny.host_capable or deny_id.host_capable
        for entry_id, host, _principal in self._deny_open:
            identities = [
                i for i in resolved.get(entry_id) or () if isinstance(i, AssetIdentity)
            ]
            if identities:
                host, _principal = _identity_reach(identities)
            deny_host_reach = deny_host_reach or host
        unique_shorts: dict[str, str] = {}
        for entry_id, label in self._allow_short_entries:
            identities = [
                i for i in resolved.get(entry_id) or () if isinstance(i, AssetIdentity)
            ]
            if len(identities) == 1 and identities[0].fqdn:
                unique_shorts[label] = entry_id
        return AssetMatcher(
            scope=self.scope,
            _allow=self._allow,
            _deny=self._deny,
            _allow_id=allow_id,
            _deny_id=deny_id,
            _allow_open=self._allow_open,
            _allow_host_reach=host_reach,
            _allow_principal_reach=principal_reach,
            _allow_addr=allow_addr,
            _deny_open=self._deny_open,
            _deny_host_reach=deny_host_reach,
            _allow_unique_shorts=unique_shorts,
            _allow_short_entries=self._allow_short_entries,
        )

    @property
    def empty(self) -> bool:
        """No entry at all: every verdict takes the fast path."""
        return self.scope.empty

    @property
    def has_allow(self) -> bool:
        """An allow-list exists."""
        return bool(self.scope.allow)

    @property
    def allow_applies_to_hosts(self) -> bool:
        """The allow-list names hosts, so a host it does not name is refused."""
        return self._allow_host_reach

    @property
    def allow_applies_to_principals(self) -> bool:
        """The allow-list names accounts or groups, so other ones are refused."""
        return self._allow_principal_reach

    @property
    def has_address_rules(self) -> bool:
        """Some entry or resolved identity is matched by address."""
        return any(
            index.address_rules
            for index in (
                self._allow,
                self._deny,
                self._allow_id,
                self._deny_id,
                self._allow_addr,
            )
        )

    @property
    def has_address_entries(self) -> bool:
        """An IP, CIDR or range ENTRY exists (not a resolved identity's address).

        Only these make a target's own addresses necessary to decide: a name
        entry is matched by name.
        """
        return self._allow.entry_address_rules or self._deny.entry_address_rules

    @property
    def has_deny_address_entries(self) -> bool:
        """An IP, CIDR or range entry exists in the deny-list."""
        return self._deny.entry_address_rules

    def match_address(self, address: str) -> MatchResult:
        """Match one IP literal (anything else matches nothing).

        An IPv4-mapped IPv6 address matches as its IPv4 address.
        """
        try:
            addr = unmap_address(
                ipaddress.ip_address(str(address or "").strip().strip("[]"))
            )
        except ValueError:
            return NO_MATCH
        deny = self._deny.match_address(addr) or self._deny_id.match_address(addr)
        allow = (
            self._allow.match_address(addr)
            or self._allow_id.match_address(addr)
            or self._allow_addr.match_address(addr)
        )
        if not deny and not allow:
            return NO_MATCH
        return MatchResult(deny_entry=deny, allow_entry=allow)

    def match_identity(
        self, identity: AssetIdentity, *, allow_resolved_addresses: bool = True
    ) -> MatchResult:
        """Match every identifier ``identity`` carries (addresses included).

        Args:
            identity: The target.
            allow_resolved_addresses: Whether an address a resolved ALLOW entry
                was known by may grant. Pass ``False`` for a target known by a
                name: an address reused by DHCP must not carry the allowance of
                the host that held it to another named host. Raw IP, CIDR and
                range allow entries always grant by address.
        """
        deny = self.match_deny(identity)
        allow = self.match_allow(identity)
        if not allow and allow_resolved_addresses and identity.addresses:
            allow = self._allow_addr.match_allow(
                AssetIdentity(addresses=identity.addresses)
            )
        if not deny and not allow:
            return NO_MATCH
        return MatchResult(deny_entry=deny, allow_entry=allow)

    # The two sides, asked separately. A target can be read several ways (a
    # bare name in each domain, a dotted label as an account or as a host):
    # the engine asks the deny side about EVERY reading and refuses on any
    # hit, and asks the allow side to cover every reading that could be true.

    def match_deny(self, identity: AssetIdentity, *, by_label: bool = True) -> str:
        """The deny entry that could name this reading of a target (generous)."""
        return self._deny.match_deny(identity, by_label=by_label) or self._deny_id.match_deny(
            identity, by_label=by_label
        )

    def match_allow(self, identity: AssetIdentity, *, addresses: bool = True) -> str:
        """The allow entry that certainly names this reading of a target (strict).

        ``addresses`` lets an IP, CIDR or range ENTRY grant by the reading's
        addresses. An address a resolved allow NAME was known by never grants
        here: ask :meth:`allow_resolved_address_entry` and check its freshness.
        """
        return self._allow.match_allow(
            identity, addresses=addresses
        ) or self._allow_id.match_allow(identity, addresses=False)

    @staticmethod
    def _parse(address: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
        try:
            return unmap_address(
                ipaddress.ip_address(str(address or "").strip().strip("[]"))
            )
        except ValueError:
            return None

    def deny_address_entry(self, address: Any) -> str:
        """The deny entry covering an address (an entry, or a denied object's address)."""
        addr = self._parse(address)
        if addr is None:
            return ""
        return self._deny.match_address(addr) or self._deny_id.match_address(addr)

    def allow_address_entry(self, address: Any) -> str:
        """The IP, CIDR or range allow ENTRY covering an address."""
        addr = self._parse(address)
        return self._allow.match_address(addr) if addr is not None else ""

    def allow_resolved_address_entry(self, address: Any) -> str:
        """The allow NAME entry whose resolution holds this address.

        Evidence, not a rule: it grants only while that resolution is fresh,
        which the engine checks.
        """
        addr = self._parse(address)
        return self._allow_addr.match_address(addr) if addr is not None else ""

    def allow_unique_short(self, label: str) -> str:
        """The allow short-host entry that resolved to exactly one computer."""
        return self._allow_unique_shorts.get(_norm_name(label), "")

    @property
    def deny_applies_to_hosts(self) -> bool:
        """The deny-list names at least one host (or may: an unresolved SID or DN)."""
        return self._deny_host_reach

    @property
    def has_deny_address_rules(self) -> bool:
        """A deny entry, or a denied object's resolution, is matched by address."""
        return self._deny.address_rules or self._deny_id.address_rules

    @property
    def has_allow_address_entries(self) -> bool:
        """An IP, CIDR or range entry exists in the allow-list."""
        return self._allow.entry_address_rules


__all__ = (
    "ADDRESS_TYPES",
    "ASSET_SCOPE_FORMAT",
    "AssetIdentity",
    "AssetMatcher",
    "AssetScope",
    "DC_ACCESS_DIRECTORY_ONLY",
    "DC_ACCESS_FULL",
    "DC_ACCESS_VALUES",
    "ENTRY_TYPES",
    "IDENTITY_TYPES",
    "KIND_COMPUTER",
    "KIND_GROUP",
    "KIND_USER",
    "MAX_ENTRIES",
    "MAX_FILE_BYTES",
    "MAX_FILE_MIB",
    "MAX_LINE_CHARS",
    "SCOPE_FILE_LIMITS_PHRASE",
    "MatchResult",
    "NO_MATCH",
    "ParsedScope",
    "ScopeEntry",
    "ScopeLineResult",
    "ScopeSyntaxError",
    "EMPTY_TEXT_REASON",
    "EMPTY_VALUE_REASON",
    "canonical_dn",
    "unmap_address",
    "normalise_dc_access",
    "parse_entry",
    "parse_scope_entries",
    "parse_scope_text",
    "parse_scope_values",
    "preview_scope_text",
    "read_scope_file",
    "split_inline_values",
    "narrowing_changes",
    "widening_changes",
)
