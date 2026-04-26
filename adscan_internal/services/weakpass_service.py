"""Weakpass API client with ADscan-specific TLS fallback behavior."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any
import json
import shutil
import subprocess
import threading

import requests


_DEFAULT_TIMEOUT = (5, 20)
_USER_AGENT = "adscan-weakpass/1.0"


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
        """Query the Weakpass search endpoint for one hash."""
        url = f"https://weakpass.com/api/v1/search/{hash_value}.json"
        tls_verification_failed = False

        try:
            response = self._session.get(url, timeout=_DEFAULT_TIMEOUT, verify=True)
            return self._build_result(hash_value, response)
        except requests.exceptions.SSLError as exc:
            tls_verification_failed = True
            try:
                response = self._session.get(
                    url, timeout=_DEFAULT_TIMEOUT, verify=False
                )
                result = self._build_result(hash_value, response)
                return WeakpassLookupResult(
                    hash_value=result.hash_value,
                    password=result.password,
                    used_insecure_tls_fallback=True,
                    tls_verification_failed=True,
                    error=str(exc),
                )
            except Exception as fallback_exc:  # noqa: BLE001
                curl_result = self._lookup_hash_with_curl(hash_value, url)
                if curl_result is not None:
                    error_message = (
                        str(exc)
                        if curl_result.password
                        else str(curl_result.error or fallback_exc)
                    )
                    return WeakpassLookupResult(
                        hash_value=curl_result.hash_value,
                        password=curl_result.password,
                        used_insecure_tls_fallback=True,
                        tls_verification_failed=True,
                        error=error_message,
                    )
                return WeakpassLookupResult(
                    hash_value=hash_value,
                    password=None,
                    used_insecure_tls_fallback=False,
                    tls_verification_failed=True,
                    error=str(fallback_exc),
                )
        except Exception as exc:  # noqa: BLE001
            return WeakpassLookupResult(
                hash_value=hash_value,
                password=None,
                tls_verification_failed=tls_verification_failed,
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
    def _lookup_hash_with_curl(
        hash_value: str, url: str
    ) -> WeakpassLookupResult | None:
        """Best-effort curl fallback for hosts where Python TLS negotiation fails."""
        curl_path = shutil.which("curl")
        if not curl_path:
            return WeakpassLookupResult(
                hash_value=hash_value,
                password=None,
                error="curl_fallback_unavailable",
            )

        try:
            completed = subprocess.run(
                [
                    curl_path,
                    "-k",
                    "--silent",
                    "--show-error",
                    "--connect-timeout",
                    "8",
                    "--max-time",
                    "30",
                    "--header",
                    f"User-Agent: {_USER_AGENT}",
                    "--header",
                    "Accept: application/json",
                    url,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=35,
            )
        except Exception as exc:  # noqa: BLE001
            return WeakpassLookupResult(
                hash_value=hash_value,
                password=None,
                error=f"curl_fallback_exception={exc}",
            )

        if completed.returncode != 0:
            stderr = (completed.stderr or "").strip()
            return WeakpassLookupResult(
                hash_value=hash_value,
                password=None,
                error=f"curl_fallback_exit={completed.returncode} stderr={stderr}",
            )

        text_payload = (completed.stdout or "").strip()
        if text_payload in {"", "0", "[]"}:
            return WeakpassLookupResult(hash_value=hash_value, password=None)

        try:
            payload = json.loads(text_payload)
        except ValueError:
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
