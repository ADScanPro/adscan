"""Protocol-recognizable native-stack secret scrubber (label-free, fail-closed).

This module is the **single source of truth** for redacting authentication
material that the native AD stack (aiosmb, badauth, kerbad, badldap, …) can emit
into log lines or the session recording. It lives in ``adscan_core`` — the
dependency-light layer that ships in both the host launcher and the container
runtime — so the two consumers can share one implementation:

* :mod:`adscan_internal.services.native_log_taming` — LAYER 2 of the
  no-exfiltration defence: scrubs every line the native-stack logging bridge
  forwards, *before* it reaches the telemetry buffer or the ``--debug`` console.
* :mod:`adscan_core.telemetry` — the export-time, whole-buffer, fail-closed
  last line of defence: scrubs the exported session recording per line, so even
  material that did NOT travel through the bridge (e.g. ``--debug`` console
  mirroring of a vendor ``print()``) is redacted before upload.

================================================================================
Two redaction strategies, combined
================================================================================

1. **Protocol-recognizable, LABEL-FREE detectors** (the gap this module closes).
   Real leaks observed in the wild are NOT preceded by a known secret label, so
   the historical label-gated approach missed them entirely:

   * NTLMSSP messages — any hex run beginning with the magic ``4e544c4d53535000``
     (``NTLMSSP\\0``). Catches ``[SRV] AUTHDATA: 4e544c4d53535000...`` regardless
     of the (unknown) ``AUTHDATA`` label.
   * NetNTLMv1/v2 hashcat-format lines — ``user::DOMAIN:<hex>:<hex>[:<hex>]``.
     The crackable response is redacted; ``user::DOMAIN`` is kept (it is not the
     secret, and keeping it preserves debuggability).
   * Server/NTLM challenge byte-reprs — ``ServerChallenge: b'...'``.
   * rclone backend connection-string passwords — ``:smb,...,pass=<obscured>``.
     ``rclone obscure`` is reversible with a static public key, so the echoed
     connection string in rclone's STDERR carries a recoverable cleartext
     credential. The value after ``pass=`` / ``password=`` is redacted.

2. **LABEL-GATED hex/base64 redaction** (the conservative complement). A long
   hex OR base64 run is redacted ONLY when a known secret label immediately
   precedes it (crypto keys, NTLM/Kerberos response fields, Kerberos ticket /
   enc-part / cipher blobs). This keeps false positives near zero: hostnames,
   domain names, ``NegotiateFlags: 0xe28a8215``, Kerberos etypes (``18``),
   sequence numbers and short hex are never touched because no secret label
   precedes them.

================================================================================
False-positive guard (hard requirement)
================================================================================
Every detector is anchored on a protocol-recognizable shape or a known secret
label and bounded by a minimum length, so NON-secrets stay verbatim:

* ``web01.pirate.htb`` (hostname) — never matches (no label, not hex/NTLMSSP).
* ``PIRATE`` (NetBIOS / domain) — never matches.
* ``NegotiateFlags: 0xe28a8215`` — the ``0x`` flags value is short and not
  label-gated as a secret; left untouched.
* etype ``18`` / ``0x709`` — too short for any hex floor.
* IPv4 addresses — handled by the dedicated IP sanitizer upstream; never
  matched here.

Every public function is best-effort and NEVER raises — a scrub failure must not
break the logging bridge nor weaken the telemetry export's fail-closed contract
(if the export sanitizer raises, the caller skips the upload).
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Strategy 1 — protocol-recognizable, label-free detectors
# ---------------------------------------------------------------------------

# NTLMSSP signature: the 8-byte magic "NTLMSSP\0" rendered as hex. Any hex run
# that STARTS with this magic is a serialized NTLM NEGOTIATE / CHALLENGE /
# AUTHENTICATE message (the AUTHENTICATE message carries the NetNTLM response).
# We redact the entire run regardless of the (possibly unknown) preceding label.
_NTLMSSP_MAGIC_HEX = "4e544c4d53535000"
_NTLMSSP_MESSAGE_RE = re.compile(
    rf"(?i){_NTLMSSP_MAGIC_HEX}(?:[0-9a-f]{{2}})*",
)

# NetNTLMv1/v2 hashcat capture format:
#   user::DOMAIN:<hex>:<hex>[:<hex>]
# The two (or three) trailing hex fields are the crackable response material.
# We keep ``user::DOMAIN`` visible (not secret, aids debugging) and redact the
# response fields. ``[^\s:]{1,256}`` bounds the user/domain so we never run away
# across a whole line; the hex floors (>=16 chars) keep flags/etypes safe.
_NETNTLM_HASHCAT_RE = re.compile(
    r"(?i)(?P<head>(?<![A-Za-z0-9._@\\/-])[^\s:]{1,256}::[^\s:]{1,256}:)"
    r"(?P<resp>[0-9a-f]{16,}:[0-9a-f]{16,}(?::[0-9a-f]{1,})?)"
)

# Challenge byte-repr / quoted value:
#   ServerChallenge: b'Mp\xf2xj\xc1[^'   |   challenge = "....."
# We redact the quoted payload (>=4 chars) and keep the label.
_CHALLENGE_REPR_RE = re.compile(
    r"(?i)(?P<label>(?:server)?challenge)(?P<sep>\b[\s:=]*)"
    r"(?P<prefix>b?)(?P<quote>['\"])(?P<value>(?:\\.|[^'\"\\]){4,}?)(?P=quote)"
)

# secretsdump / NTDS / DCSync key-line shape, LABEL-FREE:
#   <principal>:<enctype>:<hexkey>
# e.g. ``krbtgt:aes256-cts-hmac-sha1-96:0123...<64 hex>`` or the legacy
# ``Administrator:des-cbc-md5:0011223344556677``. The enc-type sits between two
# colons and the trailing field is the raw key — we redact ONLY the hex key and
# keep ``<principal>:<enctype>`` visible (aids debugging; the enc-type NAME is
# not secret). The hex floor (>=16) keeps DES (16 hex) covered while never
# matching a short non-key token, and the enc-type alternation anchors the shape
# so an arbitrary ``foo:bar:deadbeef…`` elsewhere is not eaten.
_KEY_ENCTYPE_ALT = "|".join(
    re.escape(et)
    for et in (
        "aes256-cts-hmac-sha1-96",
        "aes128-cts-hmac-sha1-96",
        "des-cbc-md5",
        "des-cbc-crc",
        "des3-cbc-sha1",
        "rc4-hmac",
        "rc4-hmac-nt",
        "aes256",
        "aes128",
    )
)
_KEY_LINE_RE = re.compile(
    rf"(?i)(?P<head>[^\s:]{{1,256}}:(?:{_KEY_ENCTYPE_ALT}):)(?P<val>[0-9a-f]{{16,}})"
)

# rclone backend connection-string password, LABEL-FREE on the rclone shape.
#   :smb,host=h,user=u,pass=<obscured>,domain=d:share
#   :smb,host=h,user=u,password=<obscured>:share
# ``rclone obscure`` is reversible with a STATIC PUBLIC key — anyone holding the
# recording can run ``rclone reveal <blob>`` and recover the customer's cleartext
# password. The obscured value is a base64url-ish run; rclone echoes the whole
# connection string verbatim inside its STDERR error lines (``Creating backend
# with remote ":smb,...,pass=<obscured>:share"``), which then lands in the
# recorded command preview. We redact the VALUE after ``pass=`` / ``password=``
# and keep the key name. Anchored on the rclone connection-string shape (a
# ``:<backend>,`` prefix somewhere before the ``pass=``) so an unrelated
# ``pass=`` in prose is NOT eaten; the >=16-char base64-ish floor keeps short
# benign ``pass=ok`` tokens safe while erring toward redaction for any real blob.
_RCLONE_PASS_RE = re.compile(
    r"(?i)(?P<pre>:[a-z0-9_]+,(?:[^\s:]*,)*?)(?P<key>pass(?:word)?=)"
    r"(?P<val>[A-Za-z0-9_\-+/=]{16,})"
)


def _redact_ntlmssp(match: "re.Match[str]") -> str:
    blob = match.group(0)
    n_bytes = len(blob) // 2
    return f"<redacted NTLM message: {n_bytes} bytes>"


def _redact_netntlm(match: "re.Match[str]") -> str:
    return f"{match.group('head')}<redacted NetNTLM response>"


def _redact_challenge(match: "re.Match[str]") -> str:
    return (
        f"{match.group('label')}{match.group('sep')}"
        f"{match.group('prefix')}{match.group('quote')}"
        f"<redacted challenge>{match.group('quote')}"
    )


def _redact_key_line(match: "re.Match[str]") -> str:
    n_bytes = len(match.group("val")) // 2
    return f"{match.group('head')}<redacted key: {n_bytes} bytes>"


def _redact_rclone_pass(match: "re.Match[str]") -> str:
    return f"{match.group('pre')}{match.group('key')}<redacted>"


# ---------------------------------------------------------------------------
# Strategy 2 — label-gated hex / base64 redaction
# ---------------------------------------------------------------------------

# Labels that are immediately (modulo a separator) followed by raw secret
# material. Case-insensitive. The crackable / relayable material is concentrated
# here: crypto keys (seal/sign/session/key-exchange), captured NTLM/Kerberos
# challenge-response fields, and Kerberos ticket/enc-part/cipher blobs.
SECRET_LABELS: tuple[str, ...] = (
    # NTLM / SMB crypto keys.
    "sealkey",
    "signkey",
    "sessionkey",
    "session_key",
    "sessionbasekey",
    "exportedsessionkey",
    "keyexchangekey",
    "randomsessionkey",
    "encryptedrandomsessionkey",
    # NTLM / Kerberos challenge-response and crypto fields.
    "response",
    "ntchallenge",
    "lmchallenge",
    "ntproofstr",
    "challengefromclient",
    "challengefromclinet",  # upstream typo kept on purpose — match both spellings
    "serverchallenge",
    "authdata",
    "channel_binding",
    "channelbinding",
    "cipher",
    # Kerberos ticket / key material.
    "ticket",
    "enc-part",
    "encpart",
    "enc_part",
    "subkey",
    "as-rep",
    "asrep",
    "ap-req",
    "apreq",
    "tgs-rep",
    "tgsrep",
    "tgt",
    "kerberos key",
    "kerberoskey",
    # Kerberos enc-type key material (secretsdump / NTDS / DCSync key lines).
    # The LABEL is the enc-type name; the VALUE that follows it (after a ":"
    # separator) is the raw key and is what we redact. The enc-type name itself,
    # when mentioned WITHOUT a trailing hex value (e.g. "negotiated etype
    # aes256-cts-hmac-sha1-96"), is never touched because the hex floor below is
    # not reached.
    "aes256-cts-hmac-sha1-96",
    "aes128-cts-hmac-sha1-96",
    "aes256",
    "aes128",
    "des-cbc-md5",
    "des-cbc-crc",
    "rc4-hmac",
    # NTDS bootkey / encryption key material.
    "pek",
    "syskey",
    "dckey",
)

_LABEL_ALT = "|".join(re.escape(lbl) for lbl in SECRET_LABELS)

# A separator between the label and the value: optional ``to`` / whitespace /
# ``:`` / ``=`` / quotes / parens / brackets. ``(?:bytes\.)?`` is implicitly
# tolerated by the generic separator class.
_SEP = r"(?P<sep>(?:\s+to\b)?[\s:=\'\"\(\[]*)"

# Label-gated HEX run, >=16 hex chars (>= 8 bytes). Short hex (flags, seq
# numbers, etypes) is left untouched because the floor is not reached.
_LABEL_HEX_RE = re.compile(
    rf"(?i)(?P<label>{_LABEL_ALT}){_SEP}(?P<val>[0-9a-fA-F]{{16,}})"
)

# Label-gated BASE64 run, >=40 chars (Kerberos tickets / enc-parts are long).
# Conservative on purpose: only fires behind a known Kerberos/secret label so an
# ordinary long base64 token elsewhere in the buffer is never eaten. Requires at
# least one base64-only signal would be ideal, but the label gate already does
# that job; the >=40 floor avoids short tokens.
_LABEL_B64_RE = re.compile(
    rf"(?i)(?P<label>{_LABEL_ALT}){_SEP}(?P<val>[A-Za-z0-9+/]{{40,}}={{0,2}})"
)


def _redact_label_hex(match: "re.Match[str]") -> str:
    n_bytes = len(match.group("val")) // 2
    return f"{match.group('label')}{match.group('sep')}<redacted:{n_bytes} bytes>"


def _redact_label_b64(match: "re.Match[str]") -> str:
    return f"{match.group('label')}{match.group('sep')}<redacted secret blob>"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scrub_native_secrets(line: str) -> str:
    """Redact native-stack authentication material from a single text line.

    Combines the protocol-recognizable, label-free detectors (NTLMSSP messages,
    NetNTLM hashcat lines, challenge byte-reprs) with the conservative
    label-gated hex/base64 redaction (crypto keys, Kerberos ticket/enc-part
    blobs). Non-secret tokens — hostnames, domain names, ``NegotiateFlags``,
    Kerberos etypes, sequence numbers, short hex, IPs — are never touched because
    every detector is anchored on a protocol shape or a known secret label and
    bounded by a minimum length.

    Best-effort and idempotent: re-running over already-redacted text is a no-op
    (the redaction markers contain no hex/NTLMSSP/base64 the detectors match).
    NEVER raises — a scrub failure must not break the logging bridge nor weaken
    the telemetry export's fail-closed contract.

    Args:
        line: A single log line or recording line.

    Returns:
        The line with native authentication material redacted.
    """
    if not line:
        return line
    try:
        # Strategy 1 — protocol-recognizable, label-free (run first; these are
        # the highest-confidence redactions and shrink the surface the
        # label-gated pass then scans).
        line = _NTLMSSP_MESSAGE_RE.sub(_redact_ntlmssp, line)
        line = _NETNTLM_HASHCAT_RE.sub(_redact_netntlm, line)
        line = _CHALLENGE_REPR_RE.sub(_redact_challenge, line)
        # Label-free secretsdump/NTDS key line: <principal>:<enctype>:<hexkey>.
        line = _KEY_LINE_RE.sub(_redact_key_line, line)
        # Label-free rclone backend connection-string password (reversible
        # ``rclone obscure`` blob — recoverable cleartext credential).
        line = _RCLONE_PASS_RE.sub(_redact_rclone_pass, line)
        # Strategy 2 — label-gated hex then base64.
        line = _LABEL_HEX_RE.sub(_redact_label_hex, line)
        line = _LABEL_B64_RE.sub(_redact_label_b64, line)
        return line
    except Exception:  # noqa: BLE001 — the bridge / export must survive a bad line
        return line


def scrub_native_secrets_buffer(content: str) -> str:
    """Apply :func:`scrub_native_secrets` over an entire multi-line buffer.

    Used by the telemetry export path as a whole-buffer, fail-closed last line of
    defence: every line of the exported session recording is scrubbed so native
    authentication material is redacted even when it did NOT travel through the
    native-stack logging bridge (e.g. ``--debug`` console mirroring of a vendor
    ``print()``). Preserves the line structure (and trailing newline) of the
    input so it composes cleanly with the marker-based sanitizer.

    Best-effort: never raises.

    Args:
        content: The full exported recording text/HTML.

    Returns:
        The buffer with each line scrubbed.
    """
    if not content:
        return content
    try:
        return "\n".join(scrub_native_secrets(line) for line in content.split("\n"))
    except Exception:  # noqa: BLE001
        return content
