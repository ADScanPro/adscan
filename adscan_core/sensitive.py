"""Sensitive marker primitives shared across the codebase.

ADscan uses invisible Unicode marker pairs to tag sensitive values in terminal
output so that telemetry/session-recording sanitization can replace them with
placeholders/pseudonyms before uploading.

This module must stay dependency-light because it is intended to ship in the
open-source PyPI launcher as well as the full runtime image.
"""

from __future__ import annotations

import os
from typing import Dict, Set, Tuple

# Sensitive data markers (invisible to user, used for automatic sanitization).
# IMPORTANT: Keep these stable across versions to avoid breaking deterministic
# sanitization and marker-based parsing in telemetry.
# NOTE on the marker alphabet: U+200D (ZERO WIDTH JOINER) MUST NOT appear here.
# ZWJ is a grapheme *joiner* (the emoji-combining char, e.g. \ud83c\udff4\u200d\u2620\ufe0f). Grapheme-aware
# width measurement \u2014 used by Rich >= 14 (rich.cells.cell_len) and by real
# terminals \u2014 counts a ZWJ-adjacent token as one cell narrower than it displays.
# Because markers are stripped from the visible stream only AFTER Rich has laid
# out a table/panel (see console_runtime.MarkerStrippingTextIO), a ZWJ marker
# made every table column/border that contained a domain/hostname/password
# mis-align. U+2061 (FUNCTION APPLICATION) is the safe replacement: invisible,
# zero-width, and NON-joining, so cell_len(marked) == cell_len(plain).
SENSITIVE_MARKERS: Dict[str, Tuple[str, str]] = {
    "user": ("\u200b\u200c", "\u200c\u200b"),
    "domain": ("\u200b\u2061", "\u2061\u200b"),
    "ip": ("\u200b\u2060", "\u2060\u200b"),
    "password": ("\u200c\u2061", "\u2061\u200c"),
    "service": ("\u200c\u2060", "\u2060\u200c"),
    "path": ("\u2061\u2060", "\u2060\u2061"),
    "hostname": ("\u2060\u2061", "\u2061\u2060"),
    # Workspace markers use different zero-width characters (LTR/RTL marks)
    # to avoid overlapping with other marker sequences.
    "workspace": ("\u200e\u200f", "\u200f\u200e"),
    # U+2064 (INVISIBLE PLUS) belongs to the same invisible-operator block as
    # U+2061 already used above: zero-width, non-joining, so it does not perturb
    # grapheme-aware cell width. It anchors the categories added later, keeping
    # every new pair trivially distinct from the pairs above.
    "sid": ("\u2064\u200b", "\u200b\u2064"),
    "hash": ("\u2064\u200c", "\u200c\u2064"),
    "share": ("\u2064\u2061", "\u2061\u2064"),
}

# Category names that are ALIASES of a real category above. A call site that
# writes ``mark_sensitive(host, "host")`` means "hostname"; before these were
# resolved, the value came back completely UNWRAPPED and the sanitizer never saw
# a span to scrub -- which is how a DC's short hostname ("KINGSLANDING") reached
# an uploaded session recording verbatim while the IP and the FQDN next to it on
# the same line were correctly pseudonymized.
#
# "hostname" -> "domain" is the long-standing remap kept for marker-sequence
# compatibility (a hostname and a domain share one marker pair); it is expressed
# here so there is ONE resolution mechanism instead of a special case.
CATEGORY_ALIASES: Dict[str, str] = {
    "cmd": "command",
    "fqdn": "hostname",
    "host": "hostname",
    "hostname": "domain",
    "myip": "ip",
    "secret": "password",
    "source_domain": "domain",
    "target_domain": "domain",
    "username": "user",
}

# Categories that are DELIBERATELY not wrapped: the value is a display token,
# not customer data, and wrapping it would either corrupt the rendered string or
# opaque text an operator must be able to read in the recording.
#
# "detail" is the important entry. It tags free-form diagnostic text -- most
# often ``str(exc)`` -- which routinely embeds a hostname, an LDAP DN or a share
# path. Replacing the whole span with one pseudonym would destroy the only
# readable record of what failed, and unwrapping it after the fact produces
# byte-identical output to not wrapping it at all. So "detail" declares "this is
# prose that MAY carry sensitive values"; the protection those values need is a
# ``mark_sensitive`` at THEIR own source plus the structural nets in
# ``adscan_core.telemetry`` -- not a marker around the sentence containing them.
PASSTHROUGH_CATEGORIES: frozenset[str] = frozenset(
    {
        "command",
        "company",
        "detail",
        "error",
        "group",
        "id",
        "interface",
        "json",
        "lab",
        "pid",
        "provider",
        "status",
        "text",
        "title",
        "unknown",
        "url",
    }
)

# Built-in AD principal names (users, groups, NT AUTHORITY identities, with the
# common Spanish equivalents). Public, not org-specific: telemetry keeps them
# readable in a domain-qualified label and scrubs only the domain part, and the
# ``node`` category below leaves such a label for that rule to handle. Moved
# here from ``adscan_core.telemetry`` (which reads it) so the marker SSOT does
# not import the telemetry module.
WELL_KNOWN_PRINCIPAL_NAMES: frozenset[str] = frozenset(
    {
        # Built-in users (commonly referenced across tool outputs)
        "administrator",
        "guest",
        "krbtgt",
        # Spanish built-in user names
        "administrador",
        "invitado",
        # Common well-known groups
        "domain admins",
        "enterprise admins",
        "schema admins",
        "administrators",
        "remote management users",
        "remote desktop users",
        "account operators",
        "backup operators",
        "server operators",
        "print operators",
        "dnsadmins",
        "cert publishers",
        "protected users",
        "authenticated users",
        "everyone",
        # NT AUTHORITY well-known security principals (public SIDs, not org-specific).
        # Both the bare label and the "NT AUTHORITY\<name>" qualified form resolve
        # via _is_well_known_principal (whole-string) and _preserve_well_known_qualified
        # (split on \\). S-1-5-18 / -19 / -20 / -11 / -9 / -2 / -7.
        "system",
        "nt authority\\system",
        "local service",
        "nt authority\\local service",
        "network service",
        "nt authority\\network service",
        "authenticated users",
        "nt authority\\authenticated users",
        "enterprise domain controllers",
        "nt authority\\enterprise domain controllers",
        "anonymous logon",
        "nt authority\\anonymous logon",
        # Additional public BUILTIN groups
        "users",
        "guests",
        "replicator",
        "performance log users",
        "performance monitor users",
        "distributed com users",
        "network configuration operators",
        "iis_iusrs",
        "event log readers",
        "access control assistance operators",
        "rds remote access servers",
        "rds endpoint servers",
        "rds management servers",
        "hyper-v administrators",
        "key admins",
        "enterprise key admins",
        "cloneable domain controllers",
        "dnsupdateproxy",
        "group policy creator owners",
        "read-only domain controllers",
        "enterprise read-only domain controllers",
        "domain controllers",
        "domain computers",
        "domain users",
        "domain guests",
        # Spanish group name equivalents (best-effort; environments may differ)
        "administradores del dominio",
        "usuarios del dominio",
        "invitados del dominio",
        "administradores de empresa",
        "administradores de esquema",
        "administradores",
        "usuarios de administracion remota",
        "usuarios de administracion",
        "usuarios de escritorio remoto",
        "operadores de cuenta",
        "operadores de copia de seguridad",
        "operadores de servidor",
        "operadores de impresion",
        "usuarios autenticados",
        "todos",
    }
)

# Categories whose REAL marker is chosen from the value's shape at mark time.
# ``node`` is an attack-graph object label: a user, a group, a host, a domain, a
# Group Policy object. It used to be a passthrough, which left about 55 call
# sites printing object labels unmarked (a GPO's {GUID} reached a recording in
# clear). Routing it here covers every call site without editing one; see
# :func:`_mark_object_label_by_shape`.
SHAPE_ROUTED_CATEGORIES: frozenset[str] = frozenset({"node"})

# Passthrough markers (invisible) for non-sensitive values.
PASSTHROUGH_MARKERS: Dict[str, Tuple[str, str]] = {
    "passthrough": (
        "\u2062\u2063",
        "\u2063\u2062",
    ),  # INVISIBLE TIMES + INVISIBLE SEPARATOR
}


def _chars_of(markers: Dict[str, Tuple[str, str]]) -> str:
    """Return every distinct character used by a marker map, in a stable order."""
    seen: list[str] = []
    for start, end in markers.values():
        for char in start + end:
            if char not in seen:
                seen.append(char)
    return "".join(seen)


# All zero-width characters used by the SENSITIVE marker system. Derived from
# the map above so adding a category can never leave a marker character out of
# the regex character classes and the defensive cleanup below.
MARKER_CHARS = _chars_of(SENSITIVE_MARKERS)

# Every marker character, sensitive and passthrough, for defensive stripping.
_ALL_MARKER_CHARS = MARKER_CHARS + _chars_of(PASSTHROUGH_MARKERS)

# Unknown categories already reported, so a hot loop warns once, not per call.
_REPORTED_UNKNOWN_CATEGORIES: Set[str] = set()


def _strict_categories_enabled() -> bool:
    """Return whether an unknown marker category must raise instead of warn.

    Off in production: a print helper must never abort a scan. On in the test
    suite (``ADSCAN_STRICT_SENSITIVE_MARKERS=1``), where a typo'd category is a
    defect to surface immediately rather than a silent pass-through.
    """
    value = os.environ.get("ADSCAN_STRICT_SENSITIVE_MARKERS", "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _report_unknown_category(data_type: str) -> None:
    """Surface a category that is neither a marker, an alias, nor a passthrough.

    Such a category used to be a SILENT no-op: ``mark_sensitive`` returned the
    value unwrapped and the call site believed it was protected. Every future
    occurrence is now either a hard error (strict mode) or a debug warning, and
    ``tests/unit/test_sensitive_marker_categories.py`` fails CI on any new one.
    """
    if _strict_categories_enabled():
        raise ValueError(
            f"mark_sensitive: unknown category {data_type!r}. Register it in "
            "SENSITIVE_MARKERS, alias it in CATEGORY_ALIASES, or declare it in "
            "PASSTHROUGH_CATEGORIES."
        )
    if data_type in _REPORTED_UNKNOWN_CATEGORIES:
        return
    _REPORTED_UNKNOWN_CATEGORIES.add(data_type)
    try:  # Lazy import: keeps this module importable by the standalone launcher.
        from adscan_core.rich_output import print_warning_debug

        print_warning_debug(
            f"mark_sensitive called with unknown category {data_type!r}; "
            "the value was NOT marked for telemetry sanitization."
        )
    except Exception:  # pragma: no cover - never break a print path
        pass


def resolve_category(data_type: str) -> str:
    """Resolve a marker category through :data:`CATEGORY_ALIASES`.

    Args:
        data_type: The category name a call site passed.

    Returns:
        The canonical category name, or ``data_type`` unchanged when it is not
        an alias. Alias chains are followed (``host`` -> ``hostname`` ->
        ``domain``) with a bound so a future cycle cannot hang a print call.
    """
    resolved = data_type
    for _ in range(len(CATEGORY_ALIASES) + 1):
        nxt = CATEGORY_ALIASES.get(resolved)
        if nxt is None or nxt == resolved:
            return resolved
        resolved = nxt
    return resolved


def strip_sensitive_markers(text: str) -> str:
    """Remove invisible marker characters from a string.

    This is used when preparing Rich exports for post-processing or for
    defensive cleanup before passing strings to subprocesses.
    """
    if not isinstance(text, str):
        return text

    for start, end in SENSITIVE_MARKERS.values():
        text = text.replace(start, "").replace(end, "")
    for start, end in PASSTHROUGH_MARKERS.values():
        text = text.replace(start, "").replace(end, "")

    # Defensive cleanup in case only a partial marker sequence was copied.
    # Derived from the marker maps so a newly registered category cannot leave a
    # stray zero-width character on the operator's terminal.
    for marker in _ALL_MARKER_CHARS:
        text = text.replace(marker, "")

    return text


def mark_passthrough(value: str) -> str:
    """Wrap a non-sensitive value with invisible passthrough markers."""
    if not value or not isinstance(value, str):
        return value
    start, end = PASSTHROUGH_MARKERS["passthrough"]
    return f"{start}{value}{end}"


def mark_sensitive(value: str, data_type: str) -> str:
    """Wrap a sensitive value with invisible markers for later sanitization.

    Args:
        value: The value to mark. Non-strings and empty strings pass through.
        data_type: A category from :data:`SENSITIVE_MARKERS`, an alias from
            :data:`CATEGORY_ALIASES`, or a declared display-only category from
            :data:`PASSTHROUGH_CATEGORIES`.

    Returns:
        The value wrapped in the category's invisible markers, or unchanged for
        a declared passthrough category.

    Raises:
        ValueError: Only when ``ADSCAN_STRICT_SENSITIVE_MARKERS`` is set and the
            category is not registered anywhere. In production an unknown
            category warns once and returns the value unchanged, so a mistyped
            category can never abort a scan mid-print.
    """
    if not value or not isinstance(value, str):
        return value

    resolved = resolve_category(data_type)
    if resolved in SHAPE_ROUTED_CATEGORIES:
        return _mark_object_label_by_shape(value)
    markers = SENSITIVE_MARKERS.get(resolved)
    if markers is None:
        if resolved not in PASSTHROUGH_CATEGORIES:
            _report_unknown_category(data_type)
        return value
    start, end = markers
    return f"{start}{value}{end}"


_NETBIOS_SEPARATOR = "\\"


def _is_public_constant(value: str) -> bool:
    """A label that identifies no client: a public SID or a public AD GUID.

    Never raises (a print path calls it): when the check cannot run, the label
    is treated as client data and gets marked, the safe direction.
    """
    try:
        from adscan_core.ad_public_guids import is_public_ad_guid  # noqa: PLC0415
        from adscan_core.reporting.well_known_principals import (  # noqa: PLC0415
            is_public_well_known_sid,
        )

        return is_public_well_known_sid(value) or is_public_ad_guid(value)
    except Exception:  # noqa: BLE001 - marking must never break a print
        return False


def _is_well_known_name(name: str) -> bool:
    return name.strip().lower() in WELL_KNOWN_PRINCIPAL_NAMES


def _mark_name_part(name: str) -> str:
    if _is_public_constant(name):
        return name
    return mark_sensitive(name, "hostname" if name.endswith("$") else "user")


def _mark_object_label_by_shape(label: str) -> str:
    """Mark an attack-graph object label with the real category its shape names.

    * A public constant (a SID with no domain part, an extended-right, schema
      or default-GPO GUID) is returned as it is: it names no client and a
      reviewer needs it readable. That is what the old passthrough did for it.
    * ``name@realm`` and ``REALM`` + backslash + ``name``: a built-in name
      (Domain Admins, Everyone) marks the whole label as a user, so telemetry
      keeps the public name and scrubs only the realm; otherwise the name is
      marked as a user (a host for ``NAME$``) and the realm as a domain,
      separately, so the realm gets the same pseudonym it gets everywhere else.
      The ``@WELLKNOWN`` sentinel is not a directory and is left as it is.
    * A dotted label with no space, or ``NAME$``: a host (the hostname/domain pair).
    * Anything else (a group or GPO name, a ``{GUID}``): a user name.

    On screen the label is unchanged: only invisible markers are added.
    """
    text = label.strip()
    if _is_public_constant(text):
        return label
    if "@" in text:
        name, _, realm = text.rpartition("@")
        if realm.upper() == "WELLKNOWN":
            return label
        if name and realm:
            if _is_well_known_name(name):
                return mark_sensitive(label, "user")
            return f"{_mark_name_part(name)}@{mark_sensitive(realm, 'domain')}"
    if _NETBIOS_SEPARATOR in text:
        realm, _, name = text.partition(_NETBIOS_SEPARATOR)
        if name and realm:
            if _is_well_known_name(text) or _is_well_known_name(name):
                return mark_sensitive(label, "user")
            return f"{mark_sensitive(realm, 'domain')}{_NETBIOS_SEPARATOR}{_mark_name_part(name)}"
    if text.endswith("$") or ("." in text and not any(ch.isspace() for ch in text)):
        return mark_sensitive(label, "hostname")
    return mark_sensitive(label, "user")


def mark_object_label(label: str) -> str:
    """Mark a directory object's label for telemetry: ``mark_sensitive(label, "node")``.

    Kept as the readable name for call sites that mark an object label; the
    routing itself lives in :func:`mark_sensitive` so every ``"node"`` call
    site gets it too.
    """
    return mark_sensitive(label, "node")
