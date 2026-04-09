"""Registry for services that can establish or unlock pivots."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PivotServiceCapability:
    """Describe one service that may enable pivoting."""

    service: str
    title: str
    pivot_tooling_hint: str
    requires_privileged_access: bool = True
    supports_tunneling: bool = True
    priority: int = 100
    required_ports: tuple[int, ...] = ()
    followup_handler_name: str | None = None
    followup_workflow_intent: str | None = None
    relaunch_workflow_intent: str | None = None


_PIVOT_SERVICE_CAPABILITIES: dict[str, PivotServiceCapability] = {
    "winrm": PivotServiceCapability(
        service="winrm",
        title="WinRM",
        pivot_tooling_hint="WinRM can bootstrap Ligolo-based pivoting when privileged access is confirmed.",
        priority=10,
        required_ports=(5985, 5986),
        followup_handler_name="ask_for_winrm_access",
        followup_workflow_intent="pivot_search",
        relaunch_workflow_intent="pivot_relaunch",
    ),
}


def list_pivot_service_capabilities() -> list[PivotServiceCapability]:
    """Return all pivot-capable services sorted by priority."""

    return sorted(
        _PIVOT_SERVICE_CAPABILITIES.values(),
        key=lambda item: (item.priority, item.service),
    )


def get_pivot_service_capability(service: str) -> PivotServiceCapability | None:
    """Return capability metadata for one service if it can unlock pivots."""

    return _PIVOT_SERVICE_CAPABILITIES.get(str(service or "").strip().lower())


def is_service_pivot_capable(service: str) -> bool:
    """Return whether one service is registered as pivot-capable."""

    return get_pivot_service_capability(service) is not None
