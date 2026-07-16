"""SSOT for a captured NetNTLM hash's account type + crack policy.

The single distinction that governs whether/how a captured hash can be cracked:
a MACHINE account has a random 120-char DC-generated password (no wordlist can
hit it; only DES rainbow tables recover a machine NTLMv1, and a machine NTLMv2 is
not recoverable at all — relay-only), while a USER account has a human-chosen
password that a wordlist can crack for BOTH v1 and v2.
"""
from __future__ import annotations

from typing import Literal, Optional

from adscan_core import telemetry

AccountType = Literal["machine", "user"]
CrackPolicy = Literal["wordlist", "rainbow_only", "no_crack"]


def classify_principal(
    username: str,
    domains_data: Optional[dict] = None,
    domain: Optional[str] = None,
) -> AccountType:
    """Classify a captured principal as a machine or user account.

    A trailing ``$`` is the definitive machine-account marker. When absent, the
    name is cross-checked against the domain's known computer inventory (a
    machine may authenticate by its short name without the ``$``). Anything else
    is treated as a user. Never raises — defaults to ``"user"`` on any error.
    """
    try:
        name = str(username or "").strip()
        if not name:
            return "user"
        if name.endswith("$"):
            return "machine"
        bare = name.split("\\")[-1].split("@")[0].rstrip("$").casefold()
        if domains_data and domain:
            computers = ((domains_data.get(domain) or {}).get("computers")) or []
            for comp in computers:
                cname = str((comp or {}).get("name") or "").rstrip("$").casefold()
                if cname and cname == bare:
                    return "machine"
        return "user"
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return "user"


def crack_policy(account_type: AccountType, ntlm_version: str) -> CrackPolicy:
    """Return the crack policy for a captured hash.

    | account | v2 | v1 |
    |---|---|---|
    | user | wordlist | wordlist |
    | machine | no_crack | rainbow_only |
    """
    version = str(ntlm_version or "").strip().lower()
    is_v1 = version in {"v1", "ntlmv1", "netntlmv1"}
    if account_type == "machine":
        return "rainbow_only" if is_v1 else "no_crack"
    return "wordlist"
