"""RODC follow-up capability planning.

This module centralizes the decision of whether a runtime context should expose
RODC-specific follow-up actions such as per-RODC ``krbtgt_<RID>`` extraction or
password-replication-policy preparation.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from adscan_internal.services.credential_store_service import (
    CredentialStoreService,
    KerberosKeyMaterial,
)
from adscan_internal.services.rodc_host_access import (
    RodcHostAccessContext,
    parse_rodc_host_access_outcome,
)


@dataclass(frozen=True, slots=True)
class RodcFollowupPlan:
    """Normalized RODC follow-up availability for one runtime context."""

    is_rodc_target: bool
    domain: str
    target_domain: str
    target_computer: str
    access_source: str
    auth_username: str
    auth_secret: str
    auth_mode: str
    attacker_machine: str
    target_spn: str
    delegated_user: str
    ticket_path: str
    action_keys: tuple[str, ...]
    can_extract_krbtgt: bool
    can_prepare_credential_caching: bool
    krbtgt_key_plan: "RodcKrbtgtKeyPlan | None" = None


@dataclass(frozen=True, slots=True)
class RodcKrbtgtKeyPlan:
    """Reusable per-RODC krbtgt material already present in the workspace."""

    domain: str
    target_computer: str
    username: str
    rid: str
    key_kind: str
    source: str
    target_host: str
    has_nt_hash: bool
    has_aes256: bool
    has_aes128: bool


def resolve_rodc_followup_plan(
    shell: Any,
    *,
    domain: str,
    target_domain: str,
    target_computer: str,
    auth_username: str,
    auth_secret: str,
    auth_mode: str,
    access_source: str = "",
    attacker_machine: str = "",
    target_spn: str = "",
    delegated_user: str = "",
    ticket_path: str = "",
) -> RodcFollowupPlan | None:
    """Return the RODC follow-up plan for one host-access context."""
    effective_domain = str(domain or "").strip()
    effective_target_domain = str(target_domain or effective_domain).strip()
    effective_target_computer = str(target_computer or "").strip()
    effective_auth_username = str(auth_username or "").strip()
    effective_auth_secret = str(auth_secret or "").strip()
    effective_auth_mode = str(auth_mode or "host_access").strip().lower()
    effective_access_source = str(access_source or "").strip().lower()
    effective_attacker_machine = str(attacker_machine or "").strip()
    effective_target_spn = str(target_spn or "").strip()
    effective_delegated_user = str(delegated_user or "").strip()
    effective_ticket_path = str(ticket_path or "").strip()

    if (
        not effective_target_domain
        or not effective_target_computer
        or not effective_auth_username
        or not effective_auth_secret
    ):
        return None

    is_rodc_target = classify_rodc_target(
        shell,
        domain=effective_target_domain,
        target_computer=effective_target_computer,
    )
    if not is_rodc_target:
        return None

    krbtgt_key_plan = resolve_rodc_krbtgt_key_plan(
        shell,
        domain=effective_target_domain,
        target_computer=effective_target_computer,
    )
    action_keys = _resolve_action_keys(
        access_source=effective_access_source,
        attacker_machine=effective_attacker_machine,
        target_spn=effective_target_spn,
        has_krbtgt_key_plan=krbtgt_key_plan is not None,
    )

    return RodcFollowupPlan(
        is_rodc_target=True,
        domain=effective_domain,
        target_domain=effective_target_domain,
        target_computer=effective_target_computer,
        access_source=effective_access_source,
        auth_username=effective_auth_username,
        auth_secret=effective_auth_secret,
        auth_mode=effective_auth_mode,
        attacker_machine=effective_attacker_machine,
        target_spn=effective_target_spn,
        delegated_user=effective_delegated_user,
        ticket_path=effective_ticket_path,
        action_keys=action_keys,
        can_extract_krbtgt=True,
        can_prepare_credential_caching=krbtgt_key_plan is not None,
        krbtgt_key_plan=krbtgt_key_plan,
    )


def resolve_rodc_followup_plan_from_outcome(
    shell: Any,
    *,
    outcome: dict[str, Any] | None,
) -> RodcFollowupPlan | None:
    """Return a typed RODC plan from one normalized execution outcome."""
    context = parse_rodc_host_access_outcome(outcome)
    if context is None:
        return None
    return resolve_rodc_followup_plan_from_context(shell, context=context)


def resolve_rodc_followup_plan_from_context(
    shell: Any,
    *,
    context: RodcHostAccessContext,
) -> RodcFollowupPlan | None:
    """Return a typed RODC plan from one normalized host-access context."""
    return resolve_rodc_followup_plan(
        shell,
        domain=context.domain,
        target_domain=context.target_domain,
        target_computer=context.target_computer,
        auth_username=context.auth_username,
        auth_secret=context.auth_secret,
        auth_mode=context.auth_mode,
        access_source=context.access_source,
        attacker_machine=context.attacker_machine,
        target_spn=context.target_spn,
        delegated_user=context.delegated_user,
        ticket_path=context.ticket_path,
    )


def classify_rodc_target(
    shell: Any,
    *,
    domain: str,
    target_computer: str,
) -> bool:
    """Return True when the given computer target is classified as an RODC."""
    get_role = getattr(shell, "get_user_dc_role", None)
    if not callable(get_role):
        return False
    try:
        return str(get_role(domain, target_computer) or "").strip().lower() == "rodc"
    except Exception:
        return False


def resolve_rodc_krbtgt_key_plan(
    shell: Any,
    *,
    domain: str,
    target_computer: str,
) -> RodcKrbtgtKeyPlan | None:
    """Return the best stored per-RODC krbtgt material for one RODC target."""
    effective_domain = str(domain or "").strip()
    effective_target = str(target_computer or "").strip()
    if not effective_domain:
        return None

    domains_data = getattr(shell, "domains_data", {})
    if not isinstance(domains_data, dict):
        return None
    domain_data = domains_data.get(effective_domain, {})
    if not isinstance(domain_data, dict):
        return None
    kerberos_keys = domain_data.get("kerberos_keys", {})
    if not isinstance(kerberos_keys, dict):
        return None

    candidates: list[KerberosKeyMaterial] = []
    exact_candidates: list[KerberosKeyMaterial] = []
    store = CredentialStoreService()
    for username, raw_data in kerberos_keys.items():
        if not _is_rodc_krbtgt_account(str(username or "")):
            continue
        if not isinstance(raw_data, dict):
            continue
        material = KerberosKeyMaterial(
            username=str(username),
            nt_hash=str(raw_data.get("nt_hash") or "") or None,
            aes256=str(raw_data.get("aes256") or "") or None,
            aes128=str(raw_data.get("aes128") or "") or None,
            source=str(raw_data.get("source") or ""),
            target_host=str(raw_data.get("target_host") or ""),
            rid=str(raw_data.get("rid") or _extract_rodc_krbtgt_rid(str(username)) or ""),
        )
        if store.select_best_kerberos_key(material) is None:
            continue
        candidates.append(material)
        if _target_matches_stored_host(effective_target, material.target_host):
            exact_candidates.append(material)

    if exact_candidates:
        return _build_key_plan(
            domain=effective_domain,
            target_computer=effective_target,
            material=exact_candidates[0],
        )
    if len(candidates) == 1:
        return _build_key_plan(
            domain=effective_domain,
            target_computer=effective_target,
            material=candidates[0],
        )
    return None


def _resolve_action_keys(
    *,
    access_source: str,
    attacker_machine: str,
    target_spn: str,
    has_krbtgt_key_plan: bool,
) -> tuple[str, ...]:
    """Return ordered follow-up action keys for one RODC access source."""
    keys: list[str] = []
    if access_source == "rbcd" and attacker_machine and target_spn:
        keys.append("review_rbcd_ticket")
    if has_krbtgt_key_plan:
        keys.append("review_rodc_krbtgt_material")
        keys.append("review_rodc_final_validation_plan")
    keys.append("extract_rodc_krbtgt_secret")
    if has_krbtgt_key_plan:
        keys.append("prepare_rodc_credential_caching")
    return tuple(keys)


def _build_key_plan(
    *,
    domain: str,
    target_computer: str,
    material: KerberosKeyMaterial,
) -> RodcKrbtgtKeyPlan | None:
    """Build a key readiness plan from stored typed key material."""
    selected = CredentialStoreService.select_best_kerberos_key(material)
    if selected is None:
        return None
    key_kind, _key_value = selected
    return RodcKrbtgtKeyPlan(
        domain=domain,
        target_computer=target_computer,
        username=material.username,
        rid=material.rid or _extract_rodc_krbtgt_rid(material.username) or "",
        key_kind=key_kind,
        source=material.source,
        target_host=material.target_host,
        has_nt_hash=bool(material.nt_hash),
        has_aes256=bool(material.aes256),
        has_aes128=bool(material.aes128),
    )


def _is_rodc_krbtgt_account(username: str) -> bool:
    """Return True for per-RODC krbtgt account names."""
    return re.fullmatch(r"(?i)krbtgt[_-]\d+", str(username or "").strip()) is not None


def _extract_rodc_krbtgt_rid(username: str) -> str | None:
    """Extract the RID suffix from a per-RODC krbtgt account name."""
    match = re.fullmatch(r"(?i)krbtgt[_-](\d+)", str(username or "").strip())
    if not match:
        return None
    return match.group(1)


def _target_matches_stored_host(target_computer: str, stored_host: str) -> bool:
    """Return True when a target computer label matches stored material host."""
    target_token = _host_identity_token(target_computer)
    stored_token = _host_identity_token(stored_host)
    return bool(target_token and stored_token and target_token == stored_token)


def _host_identity_token(value: str) -> str:
    """Normalize a computer/host label to a short lowercase host token."""
    token = str(value or "").strip().lower()
    if "\\" in token:
        token = token.rsplit("\\", 1)[-1]
    if "@" in token:
        token = token.split("@", 1)[0]
    if "." in token:
        token = token.split(".", 1)[0]
    return token.rstrip("$")


__all__ = [
    "RodcFollowupPlan",
    "RodcKrbtgtKeyPlan",
    "classify_rodc_target",
    "resolve_rodc_krbtgt_key_plan",
    "resolve_rodc_followup_plan",
    "resolve_rodc_followup_plan_from_context",
    "resolve_rodc_followup_plan_from_outcome",
]
