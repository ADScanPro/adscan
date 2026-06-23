"""Weakpass API client and the single egress guard that gates its use.

weakpass.com is an EXTERNAL service: looking up an NT hash there sends that
hash out of the customer's network. ADscan sells a "no data leaves your
network" guarantee to sovereignty-restricted customers (banking, public
sector). To honour that guarantee without removing the feature (it is part of
the free community/CTF value), every weakpass call MUST pass through
``weakpass_allowed(shell)`` before any request is made.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any
import threading

import requests

from adscan_core.rich_output import (
    print_info_debug,
    print_info_verbose,
    print_warning,
)
from adscan_core.interaction import is_non_interactive

# The offline / no-external kill switch is now defined once in
# adscan_core.offline (the dependency-light base layer) so this guard AND
# adscan_core.telemetry consume one definition. Re-exported here for
# backwards-compatible importers (e.g. adscan.py imports offline_mode_enabled
# from this module).
from adscan_core.offline import offline_mode_enabled
from adscan_core.offline import OFFLINE_ENV_VARS as _OFFLINE_ENV_VARS  # noqa: F401


_DEFAULT_TIMEOUT = (5, 20)
_USER_AGENT = "adscan-weakpass/1.0"

def weakpass_allowed(shell: object | None) -> bool:
    """Single decision point governing whether weakpass.com may be queried.

    Every weakpass call site MUST pass through this guard before issuing any
    request. The guiding principle is *fail-safe*: when in doubt, no egress.

    Priority order:

    1. Global kill switch (highest priority): if ``ADSCAN_OFFLINE`` /
       ``ADSCAN_NO_EXTERNAL`` is truthy, weakpass is ALWAYS disabled, with no
       prompt, no matter what.
    2. By ``shell.type``:
       - ``ctf``  -> ON automatically (lab / public data; keeps the fast
         lead-magnet UX).
       - ``audit`` -> default OFF. In an interactive (TTY) session, show an
         explicit opt-in prompt (default ``False``) that spells out the egress.
       - any other / unknown / unreadable type -> fail-safe OFF.
    3. Non-interactive / CI (no TTY): never prompt and never auto-enable via a
       prompt. Falls back to the type default, so the Enterprise platform (CI)
       never uses weakpass by construction (only ``ctf`` stays ON in CI).

    Args:
        shell: The active shell. Read defensively; an unreadable shell -> OFF.

    Returns:
        True only when weakpass.com may be queried in this context.
    """
    # 1) Global kill switch — absolute, no prompt.
    if offline_mode_enabled():
        print_info_debug(
            "weakpass disabled: offline kill switch active "
            "(ADSCAN_OFFLINE / ADSCAN_NO_EXTERNAL)."
        )
        return False

    # 2) Decide by session type (fail-safe default OFF for anything unknown).
    try:
        shell_type = str(getattr(shell, "type", "") or "").strip().lower()
    except Exception:  # noqa: BLE001 - unreadable shell must fail safe
        print_info_debug("weakpass disabled: shell type unreadable (fail-safe).")
        return False

    if shell_type == "ctf":
        return True

    if shell_type != "audit":
        # Unknown / ambiguous / unset session type -> never egress.
        print_info_debug(
            f"weakpass disabled: session type '{shell_type or 'unset'}' "
            "is not opt-in eligible (fail-safe)."
        )
        return False

    # 3) audit: default OFF; only an explicit interactive opt-in turns it ON.
    if is_non_interactive(shell):
        print_info_verbose(
            "weakpass disabled: non-interactive/CI audit session "
            "(default OFF, no external NT-hash lookup)."
        )
        return False

    return _prompt_weakpass_opt_in()


def _prompt_weakpass_opt_in() -> bool:
    """Interactive, explicit opt-in for weakpass in an audit session.

    Spells out the egress and defaults to ``False``. Any failure to render the
    prompt resolves to ``False`` (fail-safe — never egress on error).
    """
    prompt = (
        "weakpass.com is an EXTERNAL service: sending the NT hash there takes it "
        "OUT of the network. Do NOT use it for customers with data-sovereignty "
        "restrictions (banking, etc.). Use weakpass to crack NTLM?"
    )
    try:
        from adscan_core.rich_output import confirm_ask

        return bool(confirm_ask(prompt, default=False))
    except Exception as exc:  # noqa: BLE001 - any prompt failure -> no egress
        print_info_debug(
            f"weakpass disabled: opt-in prompt unavailable ({type(exc).__name__}); "
            "defaulting to OFF (fail-safe)."
        )
        return False


@dataclass(frozen=True)
class WeakpassLookupResult:
    """Represents the outcome of a Weakpass lookup attempt."""

    hash_value: str
    password: str | None
    used_insecure_tls_fallback: bool = False
    tls_verification_failed: bool = False
    error: str | None = None


class WeakpassService:
    """Minimal Weakpass API client used directly by ADscan."""

    def __init__(self) -> None:
        self._session = requests.Session()
        self._session.headers.update(
            {"Accept": "application/json", "User-Agent": _USER_AGENT}
        )
        self._fallback_warning_lock = threading.Lock()
        self._fallback_warning_emitted = False

    def lookup_hash(self, hash_value: str) -> WeakpassLookupResult:
        """Query the Weakpass search endpoint for one hash over verified TLS.

        TLS verification is always enforced. If the verified handshake fails we
        return a clean no-result instead of retrying over an unverified
        connection — sending an NT hash over unverified TLS is a due-diligence
        finding and is intentionally not supported.
        """
        url = f"https://weakpass.com/api/v1/search/{hash_value}.json"

        try:
            response = self._session.get(url, timeout=_DEFAULT_TIMEOUT, verify=True)
            return self._build_result(hash_value, response)
        except requests.exceptions.SSLError as exc:
            print_warning(
                "Weakpass TLS verification failed; aborting the lookup. ADscan does "
                "not fall back to an unverified connection for external hash lookups."
            )
            return WeakpassLookupResult(
                hash_value=hash_value,
                password=None,
                tls_verification_failed=True,
                error=str(exc),
            )
        except Exception as exc:  # noqa: BLE001
            return WeakpassLookupResult(
                hash_value=hash_value,
                password=None,
                error=str(exc),
            )

    def lookup_hashes(
        self, hash_values: list[str], *, max_workers: int = 8
    ) -> dict[str, WeakpassLookupResult]:
        """Query Weakpass for multiple hashes in parallel."""
        if not hash_values:
            return {}

        results: dict[str, WeakpassLookupResult] = {}
        worker_count = max(1, min(max_workers, len(hash_values)))
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            future_map = {
                executor.submit(self.lookup_hash, hash_value): hash_value
                for hash_value in hash_values
            }
            for future in as_completed(future_map):
                result = future.result()
                results[result.hash_value.lower()] = result
        return results

    def consume_tls_fallback_notice(self) -> bool:
        """Return True once when an insecure TLS fallback warning should be shown."""
        with self._fallback_warning_lock:
            if self._fallback_warning_emitted:
                return False
            self._fallback_warning_emitted = True
            return True

    @staticmethod
    def _build_result(
        hash_value: str, response: requests.Response
    ) -> WeakpassLookupResult:
        """Normalize Weakpass API responses."""
        if response.status_code == 404:
            return WeakpassLookupResult(hash_value=hash_value, password=None)

        if response.status_code != 200:
            return WeakpassLookupResult(
                hash_value=hash_value,
                password=None,
                error=f"http_status={response.status_code}",
            )

        try:
            payload: Any = response.json()
        except ValueError:
            text_payload = (response.text or "").strip()
            if text_payload in {"", "0", "[]"}:
                return WeakpassLookupResult(hash_value=hash_value, password=None)
            return WeakpassLookupResult(
                hash_value=hash_value,
                password=None,
                error="invalid_json_response",
            )

        return WeakpassService._build_result_from_payload(hash_value, payload)

    @staticmethod
    def _build_result_from_payload(
        hash_value: str, payload: Any
    ) -> WeakpassLookupResult:
        """Normalize an already-decoded Weakpass payload."""
        if payload in (0, "0", None):
            return WeakpassLookupResult(hash_value=hash_value, password=None)

        if isinstance(payload, list):
            for item in payload:
                if not isinstance(item, dict):
                    continue
                item_hash = str(item.get("hash", "")).lower()
                if item_hash == hash_value.lower():
                    password = str(item.get("pass") or "").strip() or None
                    return WeakpassLookupResult(
                        hash_value=hash_value, password=password
                    )
            if payload and isinstance(payload[0], dict) and "pass" in payload[0]:
                password = str(payload[0].get("pass") or "").strip() or None
                return WeakpassLookupResult(hash_value=hash_value, password=password)
            return WeakpassLookupResult(hash_value=hash_value, password=None)

        if isinstance(payload, dict):
            if "pass" in payload:
                password = str(payload.get("pass") or "").strip() or None
                return WeakpassLookupResult(hash_value=hash_value, password=password)
            return WeakpassLookupResult(hash_value=hash_value, password=None)

        return WeakpassLookupResult(hash_value=hash_value, password=None)
