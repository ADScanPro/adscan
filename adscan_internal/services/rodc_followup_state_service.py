"""RODC follow-up state and dependency resolution.

This service models the RODC post-exploitation workflow as capabilities and
milestones instead of a flat list of unrelated follow-up actions. It exists so
different entry vectors (RBCD, direct host admin, delegated PRP control, prior
workspace artefacts) can converge on the same next-step planner.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class RodcFollowupState:
    """Resolved workflow state for one RODC target."""

    domain: str
    target_computer: str
    target_token: str
    entry_access_source: str
    has_host_access: bool
    has_prp_capability: bool
    has_rbcd_ticket_context: bool
    has_prp_state: bool
    prp_prepared: bool
    has_krbtgt_material: bool
    has_key_list_material: bool
    has_golden_ticket: bool
    has_key_list_results: bool
    current_target_user: str
    current_golden_ticket_path: str
    action_keys: tuple[str, ...]
    primary_action_key: str
    optional_action_keys: tuple[str, ...]


class RodcFollowupStateService:
    """Persist and resolve workflow state for one RODC follow-up chain."""

    _STATE_KEY = "rodc_followup_state"

    def resolve_state(
        self,
        shell: Any,
        *,
        domain: str,
        target_computer: str,
        access_source: str,
        has_host_access: bool,
        has_prepare_prp_option: bool,
        krbtgt_key_plan: Any | None,
        default_target_user: str = "",
    ) -> RodcFollowupState:
        """Return resolved workflow state for one RODC target."""
        state_data = self._get_state_data(
            shell,
            domain=domain,
            target_computer=target_computer,
        )
        target_token = _host_identity_token(target_computer)
        persisted_target_user = str(state_data.get("target_user") or "").strip()
        current_target_user = (
            persisted_target_user or str(default_target_user or "").strip()
        )

        has_krbtgt_material = krbtgt_key_plan is not None
        has_key_list_material = bool(
            krbtgt_key_plan
            and (krbtgt_key_plan.has_aes256 or krbtgt_key_plan.has_aes128)
        )
        golden_ticket_path = self._resolve_golden_ticket_path(
            shell,
            domain=domain,
            krbtgt_key_plan=krbtgt_key_plan,
            target_user=current_target_user,
        )
        has_golden_ticket = bool(golden_ticket_path)
        has_key_list_results = self._has_key_list_results(
            shell,
            domain=domain,
            target_computer=target_computer,
            target_user=current_target_user,
            krbtgt_key_plan=krbtgt_key_plan,
        )
        prp_prepared = bool(state_data.get("prp_prepared"))
        has_prp_state = "prp_prepared" in state_data

        primary, optional = self._resolve_action_order(
            access_source=access_source,
            has_prepare_prp_option=has_prepare_prp_option,
            has_host_access=has_host_access,
            has_rbcd_ticket_context=access_source == "rbcd",
            has_prp_state=has_prp_state,
            prp_prepared=prp_prepared,
            has_krbtgt_material=has_krbtgt_material,
            has_key_list_material=has_key_list_material,
            has_golden_ticket=has_golden_ticket,
            has_key_list_results=has_key_list_results,
        )
        return RodcFollowupState(
            domain=domain,
            target_computer=target_computer,
            target_token=target_token,
            entry_access_source=access_source,
            has_host_access=has_host_access,
            has_prp_capability=has_prepare_prp_option,
            has_rbcd_ticket_context=access_source == "rbcd",
            has_prp_state=has_prp_state,
            prp_prepared=prp_prepared,
            has_krbtgt_material=has_krbtgt_material,
            has_key_list_material=has_key_list_material,
            has_golden_ticket=has_golden_ticket,
            has_key_list_results=has_key_list_results,
            current_target_user=current_target_user,
            current_golden_ticket_path=golden_ticket_path or "",
            action_keys=((primary,) if primary else ()) + optional,
            primary_action_key=primary,
            optional_action_keys=optional,
        )

    def mark_prp_prepared(
        self,
        shell: Any,
        *,
        domain: str,
        target_computer: str,
        target_user: str,
    ) -> None:
        """Persist that PRP preparation was completed for this RODC target."""
        self._update_state(
            shell,
            domain=domain,
            target_computer=target_computer,
            updates={
                "prp_prepared": True,
                "target_user": str(target_user or "").strip(),
            },
        )

    def mark_prp_restored(
        self,
        shell: Any,
        *,
        domain: str,
        target_computer: str,
        target_user: str = "",
    ) -> None:
        """Persist that temporary PRP preparation was restored during cleanup."""
        updates = {"prp_prepared": False}
        if str(target_user or "").strip():
            updates["target_user"] = str(target_user or "").strip()
        self._update_state(
            shell,
            domain=domain,
            target_computer=target_computer,
            updates=updates,
        )

    def mark_krbtgt_extracted(
        self,
        shell: Any,
        *,
        domain: str,
        target_computer: str,
    ) -> None:
        """Persist that per-RODC krbtgt material was recovered."""
        self._update_state(
            shell,
            domain=domain,
            target_computer=target_computer,
            updates={"krbtgt_extracted": True},
        )

    def mark_golden_ticket_forged(
        self,
        shell: Any,
        *,
        domain: str,
        target_computer: str,
        target_user: str,
        ticket_path: str,
    ) -> None:
        """Persist that a forged RODC golden ticket exists."""
        self._update_state(
            shell,
            domain=domain,
            target_computer=target_computer,
            updates={
                "golden_ticket_forged": True,
                "target_user": str(target_user or "").strip(),
                "golden_ticket_path": str(ticket_path or "").strip(),
            },
        )

    def mark_key_list_completed(
        self,
        shell: Any,
        *,
        domain: str,
        target_computer: str,
        target_user: str,
    ) -> None:
        """Persist that Key List was completed for this RODC target."""
        self._update_state(
            shell,
            domain=domain,
            target_computer=target_computer,
            updates={
                "key_list_completed": True,
                "target_user": str(target_user or "").strip(),
            },
        )

    def _resolve_action_order(
        self,
        *,
        access_source: str,
        has_prepare_prp_option: bool,
        has_host_access: bool,
        has_rbcd_ticket_context: bool,
        has_prp_state: bool,
        prp_prepared: bool,
        has_krbtgt_material: bool,
        has_key_list_material: bool,
        has_golden_ticket: bool,
        has_key_list_results: bool,
    ) -> tuple[str, tuple[str, ...]]:
        """Return ``(primary_action, optional_actions)`` for current state.

        Design principle: every step that is technically available is always
        included so the operator can always re-run any phase.  The primary
        action is the next recommended step in the chain; everything else
        becomes optional.  Completion state never hides a step — it only
        influences which title the UI shows (e.g. "Re-extract" vs "Extract").
        """
        access_source_normalized = str(access_source or "").strip().lower()
        prp_entrypoint = access_source_normalized in {
            "prp",
            "rodc_prp",
            "rodc_object_control",
            "writeaccountrestrictions",
        }

        # ── 1. Determine primary (next recommended step in the attack chain) ──
        primary = self._determine_primary_action(
            has_host_access=has_host_access,
            has_prepare_prp_option=has_prepare_prp_option,
            has_krbtgt_material=has_krbtgt_material,
            has_golden_ticket=has_golden_ticket,
            has_key_list_material=has_key_list_material,
            has_key_list_results=has_key_list_results,
            prp_prepared=prp_prepared,
            prp_entrypoint=prp_entrypoint,
        )

        # ── 2. Build the complete available action list ──────────────────────
        # Every action whose prerequisites are satisfied is always offered so
        # the operator can re-run any phase, regardless of prior completion.
        available: list[str] = []

        if has_rbcd_ticket_context:
            available.append("review_rbcd_ticket")

        # krbtgt extraction — primary when no material exists, otherwise keep it
        # available as a lower-priority re-extraction path after review actions.
        if has_host_access and not has_krbtgt_material:
            available.append("extract_rodc_krbtgt_secret")

        if has_krbtgt_material:
            available.append("review_rodc_krbtgt_material")
            available.append("review_rodc_final_validation_plan")
            available.append("forge_rodc_golden_ticket")

        # PRP — always available once the operator has the right permissions
        if has_prepare_prp_option:
            available.append("prepare_rodc_credential_caching")

        if has_host_access and has_krbtgt_material:
            available.append("extract_rodc_krbtgt_secret")

        # Key List — available once golden ticket and AES key both exist
        if has_key_list_material and has_golden_ticket:
            available.append("run_rodc_kerberos_key_list")

        # ── 3. Promote primary; demote the rest to optional ──────────────────
        if primary and primary not in available:
            # primary may be a step whose prerequisites were just met
            optional = [a for a in available if a != primary]
            return primary, tuple(optional)

        optional = [a for a in available if a != primary]
        return primary, tuple(optional)

    @staticmethod
    def _determine_primary_action(
        *,
        has_host_access: bool,
        has_prepare_prp_option: bool,
        has_krbtgt_material: bool,
        has_golden_ticket: bool,
        has_key_list_material: bool,
        has_key_list_results: bool,
        prp_prepared: bool,
        prp_entrypoint: bool,
    ) -> str:
        """Return the single next recommended action key for the current state."""
        if not has_krbtgt_material:
            if has_host_access:
                return "extract_rodc_krbtgt_secret"
            if has_prepare_prp_option or prp_entrypoint:
                return "prepare_rodc_credential_caching"
            return ""

        if not has_golden_ticket:
            return "forge_rodc_golden_ticket"

        if has_key_list_material and not has_key_list_results:
            # PRP is a prerequisite for tier-zero Key List.
            # If not yet prepared, guide the operator there first;
            # offer_rodc_escalation chains Key List automatically once PRP is set.
            if has_prepare_prp_option and not prp_prepared:
                return "prepare_rodc_credential_caching"
            return "run_rodc_kerberos_key_list"

        if has_key_list_results:
            return "review_rodc_final_validation_plan"

        # Krbtgt extracted, golden ticket exists, but no AES key for Key List
        if has_host_access:
            return "extract_rodc_krbtgt_secret"
        if has_prepare_prp_option and not prp_prepared:
            return "prepare_rodc_credential_caching"
        return "forge_rodc_golden_ticket"

    def _resolve_golden_ticket_path(
        self,
        shell: Any,
        *,
        domain: str,
        krbtgt_key_plan: Any | None,
        target_user: str,
    ) -> str | None:
        """Return a forged golden-ticket path when one is already present."""
        if krbtgt_key_plan is None or not krbtgt_key_plan.rid:
            return None
        if not target_user:
            return None
        workspace_dir = _resolve_workspace_dir(shell)
        if not workspace_dir:
            return None
        candidate = (
            Path(workspace_dir)
            / "domains"
            / domain
            / "kerberos"
            / "rodc_golden_tickets"
            / f"rodc_{krbtgt_key_plan.rid}"
            / f"{target_user}.ccache"
        )
        return str(candidate) if candidate.exists() else None

    def _has_key_list_results(
        self,
        shell: Any,
        *,
        domain: str,
        target_computer: str,
        target_user: str,
        krbtgt_key_plan: Any | None,
    ) -> bool:
        """Return True when Key List results are already persisted."""
        if krbtgt_key_plan is None or not krbtgt_key_plan.rid or not target_user:
            return False
        workspace_dir = _resolve_workspace_dir(shell)
        if not workspace_dir:
            return False
        safe_user = target_user.replace("\\", "_").replace("/", "_").replace(":", "_")
        candidate = (
            Path(workspace_dir)
            / "domains"
            / domain
            / "kerberos"
            / "key_list"
            / f"rodc_{krbtgt_key_plan.rid}_{safe_user}.txt"
        )
        if candidate.exists():
            return True
        state_data = self._get_state_data(
            shell,
            domain=domain,
            target_computer=target_computer,
        )
        return bool(state_data.get("key_list_completed"))

    def _update_state(
        self,
        shell: Any,
        *,
        domain: str,
        target_computer: str,
        updates: dict[str, object],
    ) -> None:
        """Persist one partial state update for a target RODC."""
        domains_data = getattr(shell, "domains_data", {})
        if not isinstance(domains_data, dict):
            return
        domain_data = domains_data.setdefault(domain, {})
        if not isinstance(domain_data, dict):
            return
        per_domain = domain_data.setdefault(self._STATE_KEY, {})
        if not isinstance(per_domain, dict):
            per_domain = {}
            domain_data[self._STATE_KEY] = per_domain
        token = _host_identity_token(target_computer)
        current = per_domain.get(token)
        if not isinstance(current, dict):
            current = {}
            per_domain[token] = current
        current.update(updates)

    def _get_state_data(
        self,
        shell: Any,
        *,
        domain: str,
        target_computer: str,
    ) -> dict[str, object]:
        """Return persisted state data for one RODC token."""
        domains_data = getattr(shell, "domains_data", {})
        if not isinstance(domains_data, dict):
            return {}
        domain_data = domains_data.get(domain, {})
        if not isinstance(domain_data, dict):
            return {}
        per_domain = domain_data.get(self._STATE_KEY, {})
        if not isinstance(per_domain, dict):
            return {}
        state = per_domain.get(_host_identity_token(target_computer))
        return state if isinstance(state, dict) else {}


def _resolve_workspace_dir(shell: Any) -> str:
    """Return the active workspace directory for artefact lookups."""
    resolver = getattr(shell, "_get_workspace_cwd", None)
    if callable(resolver):
        return str(resolver())
    return str(getattr(shell, "current_workspace_dir", "") or "")


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
    "RodcFollowupState",
    "RodcFollowupStateService",
]
