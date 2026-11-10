"""Single source of truth for "does broadcast poisoning resolve ON?".

Broadcast poisoning (LLMNR / NBT-NS / mDNS) is the one ADscan technique that
binds to a specific network interface, and that interface cannot be inferred
from the route table. Everything else resolves its callback address per target,
so the interface is only worth asking for when poisoning is going to run.

That makes "does poisoning resolve ON" the condition under which an interface
becomes required, on every surface: the CLI consent seam, ``adscan ci``, the
web scan form and the Celery command builder. The precedence lives here, once,
so those surfaces cannot disagree:

1. ``ADSCAN_NO_POISONING=1`` (hard opt-out) wins over everything, including an
   explicit enable. It is a kill switch for monitored or out-of-scope engagements.
2. An explicit ``poisoning.enabled`` (``True`` / ``False``) from the scan config
   is authoritative and overrides the policy's default.
3. Otherwise the scan policy's ``poisoning`` setting (``on`` / ``off``), when
   the policy sets one.
4. Otherwise that setting's default for the policy's environment (a real
   environment ON, a lab OFF; an unknown environment reads as real).

The module is dependency-light on purpose (stdlib only): the web backend imports
it directly, and the Celery worker mirrors it behind a contract test because the
worker package never imports ``adscan_core``.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Mapping, Optional

#: Hard opt-out env var. A truthy value disables poisoning on every surface.
NO_POISONING_ENV = "ADSCAN_NO_POISONING"

_TRUTHY = frozenset({"1", "true", "yes"})


def no_poisoning_env_set(environ: Optional[Mapping[str, str]] = None) -> bool:
    """Return whether the hard opt-out env var is set to a truthy value."""

    source = os.environ if environ is None else environ
    return str(source.get(NO_POISONING_ENV, "")).strip().lower() in _TRUTHY


@dataclass(frozen=True)
class PoisoningResolution:
    """Outcome of resolving the poisoning decision.

    Attributes:
        enabled: Whether poisoning resolves ON (it will launch, or be offered
            with a default-yes prompt in an interactive session).
        authoritative: ``True`` when an explicit scan-config ``enabled=True``
            forced it on. An authoritative enable never asks for consent; a
            default-derived one does in an interactive run.
        reason: Which rung decided, for diagnostics.
    """

    enabled: bool
    authoritative: bool
    reason: str

    @property
    def defaulted(self) -> bool:
        """Whether a policy default decided (no explicit config or opt-out).

        Only a defaulted decision is *offered* to an interactive operator, even
        when it defaults OFF (a lab): an explicit disable or the env opt-out is
        never re-asked.
        """

        return self.reason.startswith(("environment_default", "policy_default"))


#: The scan-policy setting values (``adscan_core.scan_policy.settings``).
_POLICY_DEFAULT_ON = "on"
_POLICY_DEFAULT_OFF = "off"


def resolve_poisoning(
    *,
    environment: Optional[str],
    configured_enabled: Optional[bool],
    env_opt_out: bool = False,
    policy_default: Optional[str] = None,
) -> PoisoningResolution:
    """Resolve whether poisoning is ON for a scan.

    Args:
        environment: The scan policy's environment, ``"lab"`` / ``"real"``, or
            ``None`` when unknown (read as real, the conservative default).
        configured_enabled: The tri-state ``poisoning.enabled`` from the scan
            config: ``None`` defers to the policy.
        env_opt_out: Whether ``ADSCAN_NO_POISONING`` is set.
        policy_default: The scan policy's ``poisoning`` setting (``on`` /
            ``off``). When given it decides the default.
    """

    if env_opt_out:
        return PoisoningResolution(False, False, "env_opt_out")
    if configured_enabled is True:
        return PoisoningResolution(True, True, "scan_config_enabled")
    if configured_enabled is False:
        return PoisoningResolution(False, False, "scan_config_disabled")
    token = str(policy_default or "").strip().lower()
    if token == _POLICY_DEFAULT_ON:
        return PoisoningResolution(True, False, "policy_default_on")
    if token == _POLICY_DEFAULT_OFF:
        return PoisoningResolution(False, False, "policy_default_off")
    from adscan_core.scan_policy.settings import POISONING, SETTINGS_BY_KEY  # noqa: PLC0415

    default = SETTINGS_BY_KEY[POISONING].default_for(str(environment or "").strip().lower())
    if default == _POLICY_DEFAULT_ON:
        return PoisoningResolution(True, False, "environment_default_on")
    return PoisoningResolution(False, False, "environment_default_off")


__all__ = [
    "NO_POISONING_ENV",
    "PoisoningResolution",
    "no_poisoning_env_set",
    "resolve_poisoning",
]
