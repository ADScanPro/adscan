"""Telemetry for the ``unauth -> credential`` funnel.

The path from an unauthenticated foothold to the first domain credential was
almost blind: the only signals were ``capture_exception`` calls and CTF-UX
events. There was no event for the RESULT of a spray, for the username pattern
ADscan infers, or for the METHOD that produced the first credential. This module
adds those, plus the shared attribution key that lets a credential be joined back
to the unauth session that produced it.

Design rules (mirror ``scan_outcome_telemetry``):

* **Secret-free by construction.** Payloads carry ONLY integer counts, enum
  labels, ratios, durations and the ``workspace_id_hash`` correlation key — never
  usernames, passwords, hashes, domains or SIDs. There is therefore nothing to
  ``mark_sensitive`` in a well-formed payload; the emitters additionally coerce
  every value to an int/float/str/bool/None so a caller cannot smuggle a raw
  object through.
* **Best-effort.** Every emitter swallows its own errors via
  ``telemetry.capture_exception`` and never breaks the scan flow.
* **CI-safe.** ``telemetry.capture`` is fire-and-forget (queued, non-blocking) and
  is gated on the telemetry preference; it never prompts, so it is safe under
  ``adscan ci`` / the web-PoV worker without any ``is_non_interactive`` guard.
* **audit AND ctf.** The events fire the same way in both workspace types; the
  ``workspace_type`` field (from the shared attribution helper) carries the
  segment so PostHog can split the funnel.

Event names added here are also added to ``_ALLOWED_EVENT_NAMES`` in
``adscan_core/telemetry.py`` — the fail-closed event-name allow-list. An event
missing from that set is bucketed to ``telemetry_event_unlisted`` and lost.
"""

from __future__ import annotations

from typing import Any, Optional

from adscan_core import telemetry
from adscan_core.rich_output import print_exception


# ── Event names (kept in sync with adscan_core.telemetry._ALLOWED_EVENT_NAMES) ──
EVENT_SPRAY_COMPLETED = "spray_completed"
EVENT_USERNAME_PATTERN_INFERRED = "username_pattern_inferred"
EVENT_POISONING_CAPTURE = "poisoning_capture"


# ── Closed enums ────────────────────────────────────────────────────────────

# Canonical hash-type vocabulary for the cracking events. The raw ``hash_type``
# threaded into ``run_cracking`` can be a per-account label like
# ``"ZTJC378$.NTLMv2"`` (machine account + version) or an artifact label like
# ``"ansible artifact"`` — those must never reach telemetry as-is (unbounded
# cardinality + a leaked account name). This maps ANY input to a small closed set.
HASH_TYPE_NTLMV1 = "ntlmv1"
HASH_TYPE_NTLMV2 = "ntlmv2"
HASH_TYPE_KERBEROAST = "kerberoast"
HASH_TYPE_ASREPROAST = "asreproast"
HASH_TYPE_TIMEROAST = "timeroast"
HASH_TYPE_NTLM = "ntlm"
HASH_TYPE_ARTIFACT = "artifact"
HASH_TYPE_OTHER = "other"

_HASH_TYPES: frozenset[str] = frozenset(
    {
        HASH_TYPE_NTLMV1,
        HASH_TYPE_NTLMV2,
        HASH_TYPE_KERBEROAST,
        HASH_TYPE_ASREPROAST,
        HASH_TYPE_TIMEROAST,
        HASH_TYPE_NTLM,
        HASH_TYPE_ARTIFACT,
        HASH_TYPE_OTHER,
    }
)


def normalize_hash_type_for_telemetry(raw: Any) -> str:
    """Coerce an arbitrary ``hash_type`` value to the closed telemetry enum.

    Matches on the CANONICAL substrings the internal call sites use so that
    ``"ZTJC378$.NTLMv2"``, ``"NTLMv2"`` and ``"netntlmv2"`` all collapse to
    ``"ntlmv2"``, ``"ansible artifact"`` -> ``"artifact"``, and anything
    unrecognized -> ``"other"``. Order matters: the more specific NetNTLM
    versions are tested before the bare ``ntlm`` fallback.
    """
    text = str(raw or "").strip().lower()
    if not text:
        return HASH_TYPE_OTHER
    # Already canonical?
    if text in _HASH_TYPES:
        return text
    if "ntlmv2" in text or "netntlmv2" in text:
        return HASH_TYPE_NTLMV2
    if "ntlmv1" in text or "netntlmv1" in text:
        return HASH_TYPE_NTLMV1
    if "kerberoast" in text or "krb5tgs" in text:
        return HASH_TYPE_KERBEROAST
    if "asrep" in text or "krb5asrep" in text:
        return HASH_TYPE_ASREPROAST
    if "timeroast" in text:
        return HASH_TYPE_TIMEROAST
    if "artifact" in text:
        return HASH_TYPE_ARTIFACT
    if "ntlm" in text:
        return HASH_TYPE_NTLM
    return HASH_TYPE_OTHER


# Canonical spray-type vocabulary. The human spray labels in ``cli/spraying.py``
# ("Username as Password", "Custom Password", "Blank Password", "Computer Pre2k",
# "Adaptive Year Password", ...) map to these stable machine keys.
SPRAY_TYPE_USER_AS_PASS = "user_as_pass"
SPRAY_TYPE_CUSTOM = "custom"
SPRAY_TYPE_BLANK = "blank"
SPRAY_TYPE_MONTH_SEASON = "month_season"
SPRAY_TYPE_YEAR_VARIATION = "year_variation"
SPRAY_TYPE_PRE2K = "pre2k"
SPRAY_TYPE_CREDENTIAL_REUSE = "credential_reuse"
SPRAY_TYPE_OTHER = "other"

_SPRAY_TYPES: frozenset[str] = frozenset(
    {
        SPRAY_TYPE_USER_AS_PASS,
        SPRAY_TYPE_CUSTOM,
        SPRAY_TYPE_BLANK,
        SPRAY_TYPE_MONTH_SEASON,
        SPRAY_TYPE_YEAR_VARIATION,
        SPRAY_TYPE_PRE2K,
        SPRAY_TYPE_CREDENTIAL_REUSE,
        SPRAY_TYPE_OTHER,
    }
)


def normalize_spray_type_for_telemetry(raw: Any) -> str:
    """Coerce a human spray label / key to the closed spray-type enum."""
    text = str(raw or "").strip().lower()
    if not text:
        return SPRAY_TYPE_OTHER
    if text in _SPRAY_TYPES:
        return text
    if "username as password" in text or "user_as_pass" in text or "useraspass" in text:
        return SPRAY_TYPE_USER_AS_PASS
    if "blank" in text:
        return SPRAY_TYPE_BLANK
    if "pre2k" in text or "pre-2k" in text or "computer pre2k" in text:
        return SPRAY_TYPE_PRE2K
    if "month" in text or "season" in text:
        return SPRAY_TYPE_MONTH_SEASON
    if "year" in text or "variation" in text:
        return SPRAY_TYPE_YEAR_VARIATION
    if "reuse" in text:
        return SPRAY_TYPE_CREDENTIAL_REUSE
    if "custom" in text or "password" in text:
        return SPRAY_TYPE_CUSTOM
    return SPRAY_TYPE_OTHER


# Poisoning protocol vocabulary.
PROTOCOL_LLMNR = "llmnr"
PROTOCOL_NBT_NS = "nbt_ns"
PROTOCOL_MDNS = "mdns"
PROTOCOL_SMB = "smb"
PROTOCOL_UNKNOWN = "unknown"

_PROTOCOLS: frozenset[str] = frozenset(
    {PROTOCOL_LLMNR, PROTOCOL_NBT_NS, PROTOCOL_MDNS, PROTOCOL_SMB, PROTOCOL_UNKNOWN}
)


def normalize_protocol_for_telemetry(raw: Any) -> str:
    """Coerce a poisoning protocol label to the closed enum."""
    text = str(raw or "").strip().lower().replace("-", "_")
    if not text:
        return PROTOCOL_UNKNOWN
    if text in _PROTOCOLS:
        return text
    if "llmnr" in text:
        return PROTOCOL_LLMNR
    if "nbt" in text or "netbios" in text:
        return PROTOCOL_NBT_NS
    if "mdns" in text:
        return PROTOCOL_MDNS
    if "smb" in text:
        return PROTOCOL_SMB
    return PROTOCOL_UNKNOWN


# ── Value coercion (defence-in-depth against a raw object slipping through) ────

def _as_int(value: Any) -> Optional[int]:
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_float(value: Any) -> Optional[float]:
    try:
        if value is None:
            return None
        return round(float(value), 3)
    except (TypeError, ValueError):
        return None


def _attribution(shell: Any) -> dict[str, Any]:
    """Return the shared ``{workspace_type, workspace_id_hash}`` attribution key.

    Imported lazily so this service module carries no import-time dependency on
    the CLI layer (keeps the dependency direction clean and the module cheap to
    import in tests).
    """
    try:
        from adscan_internal.cli.common import build_workspace_attribution_fields

        return build_workspace_attribution_fields(shell)
    except Exception:  # noqa: BLE001 — attribution is best-effort
        return {}


# ── Emitters ──────────────────────────────────────────────────────────────

def emit_spray_completed(
    shell: Any,
    *,
    spray_type: Any,
    accounts_tried: Any,
    valid_creds_found: Any,
    accounts_locked: Any = None,
    accounts_excluded_near_lockout: Any = None,
    lockout_threshold: Any = None,
    pattern_used: Optional[str] = None,
    duration_s: Any = None,
) -> None:
    """Emit ``spray_completed`` for one finished spray pass (audit AND ctf).

    The gap-#1 event: the RESULT of a spray, so the acquisition rate can be
    measured by spray type and workspace type. Counts only — never a credential
    in clear. Missing fields (e.g. ``lockout_threshold`` when the caller ran with
    no eligibility data) are emitted as ``None`` rather than guessed.
    """
    try:
        properties: dict[str, Any] = {
            "spray_type": normalize_spray_type_for_telemetry(spray_type),
            "accounts_tried": _as_int(accounts_tried),
            "valid_creds_found": _as_int(valid_creds_found),
            "accounts_locked": _as_int(accounts_locked),
            "accounts_excluded_near_lockout": _as_int(accounts_excluded_near_lockout),
            "lockout_threshold": _as_int(lockout_threshold),
            "pattern_used": str(pattern_used) if pattern_used else None,
            "duration_s": _as_float(duration_s),
        }
        properties.update(_attribution(shell))
        _add_lab_fields(shell, properties)
        telemetry.capture(EVENT_SPRAY_COMPLETED, properties)
    except Exception as exc:  # noqa: BLE001 — telemetry must not break the spray
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def emit_username_pattern_inferred(
    shell: Any,
    *,
    fmt: Optional[str],
    score: Any,
    sample_size: Any,
) -> None:
    """Emit ``username_pattern_inferred`` after ADscan infers the username format.

    Measures the central playbook step (``first.last`` / ``flast`` / ``sam`` /
    ...) that was previously invisible. ``confidence`` is the winning pattern's
    score as a fraction of the analyzed sample (``score / sample_size``, clamped
    to ``[0, 1]``), so it is comparable across sessions of different sizes. The
    ``format`` itself is a bounded enum of pattern keys, safe to emit verbatim.
    """
    try:
        score_int = _as_int(score)
        sample_int = _as_int(sample_size)
        confidence: Optional[float] = None
        if score_int is not None and sample_int and sample_int > 0:
            confidence = round(min(max(score_int / sample_int, 0.0), 1.0), 3)
        properties: dict[str, Any] = {
            "format": str(fmt) if fmt else None,
            "score": score_int,
            "confidence": confidence,
            "sample_size": sample_int,
        }
        properties.update(_attribution(shell))
        _add_lab_fields(shell, properties)
        telemetry.capture(EVENT_USERNAME_PATTERN_INFERRED, properties)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def emit_poisoning_capture(
    shell: Any,
    *,
    hashes_captured: Any,
    unique_accounts: Any,
    protocol: Any = None,
    version: Optional[str] = None,
) -> None:
    """Emit ``poisoning_capture`` when a responder/poisoning capture is processed.

    Responder/poisoning were bare command events with no result. This records the
    yield of a capture: how many hashes, from how many distinct accounts, over
    which protocol. Counts + enums only.
    """
    try:
        properties: dict[str, Any] = {
            "hashes_captured": _as_int(hashes_captured),
            "unique_accounts": _as_int(unique_accounts),
            "protocol": normalize_protocol_for_telemetry(protocol),
            "version": str(version).strip().lower() if version else None,
        }
        properties.update(_attribution(shell))
        _add_lab_fields(shell, properties)
        telemetry.capture(EVENT_POISONING_CAPTURE, properties)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def _add_lab_fields(shell: Any, properties: dict[str, Any]) -> None:
    """Merge the shared lab context fields (best-effort)."""
    try:
        from adscan_internal.cli.common import build_lab_event_fields

        properties.update(build_lab_event_fields(shell=shell, include_slug=True))
    except Exception:  # noqa: BLE001
        pass
