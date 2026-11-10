"""Durable-change policy — the single place that decides what a run leaves behind.

Two decisions live here and nowhere else, so no service re-derives them:

1. **Durable AD objects at workspace exit.** The ``operator_confirmed`` ledger
   class (machine account, RBCD delegation, KeyCredentialLink written by the
   relay chain) is not auto-reverted by its owning service: the exit hook asks.
   :func:`resolve_exit_keep_decision` answers for that hook.

   It follows the ONE automatic-reversion switch, :func:`resolve_auto_revert`
   (founder decision 2026-11-05: on for Enterprise and audit, off for ctf):

   * An explicit choice wins in every mode: ``scan_config.durable_changes``
     (``auto_revert``, or its legacy inverse ``keep``), then the REPL
     ``set auto_revert``, then ``ADSCAN_AUTO_REVERT`` /
     ``ADSCAN_KEEP_DURABLE_CHANGES``.
   * Otherwise a non-interactive run (``adscan ci``: the appliance worker, a
     CI lab, an unattended consultant run) applies the scan policy's
     ``auto_revert`` setting: a real environment REVERTS (nobody is there to
     decide, and an object left in a third party's directory is residue someone
     else has to find and remove; a saved real policy cannot change that); a lab
     keeps by default.
   * Otherwise (interactive) the operator is asked, with the policy's value
     preset.

   Every revert is confirmed by re-reading the object; one that cannot be
   confirmed is recorded ``manual_required`` with the object DN and a native
   command (that part lives in the revert helpers, unchanged).

2. **The CA private-key backup step of an executed path.** A copy of a CA key
   cannot be withdrawn: the only remedy is rotating the CA key, which is the
   client's change to make. :func:`ca_key_backup_allowed` gates the step.

   * Explicit choice wins: ``scan_config.durable_changes.allow_ca_key_backup``,
     then ``ADSCAN_ALLOW_CA_KEY_BACKUP``.
   * Otherwise a non-interactive run follows the scan policy's
     ``ca_key_backup`` setting: on by default for a lab (disposable), off for a
     real environment, where a saved policy cannot turn it on.
   * Interactive runs are unchanged: the operator already approved the path.

Both resolvers never raise: a malformed or absent config falls back to the
documented default.
"""

from __future__ import annotations

from adscan_core.scan_policy import settings as policy_settings

import os
from dataclasses import dataclass
from typing import Any, Callable, Optional

from adscan_internal.interaction import is_non_interactive

__all__ = [
    "AUTO_REVERT_ENV",
    "AUTO_REVERT_OFF_ENVIRONMENTS",
    "AutoRevertDecision",
    "resolve_auto_revert",
    "KEEP_DURABLE_CHANGES_ENV",
    "ALLOW_CA_KEY_BACKUP_ENV",
    "ExitKeepDecision",
    "resolve_exit_keep_decision",
    "ca_key_backup_allowed",
    "CA_KEY_BACKUP_SKIPPED_REASON",
]

#: Environment override for the exit decision (``1``/``true`` keep, ``0``/``false``
#: revert). Forwarded into the scan container by the launcher's ``ADSCAN_*``
#: wildcard, so it works for ``adscan ci`` on a host and on the appliance.
KEEP_DURABLE_CHANGES_ENV = "ADSCAN_KEEP_DURABLE_CHANGES"

#: Environment override for the CA key backup step (``1`` allow, ``0`` never).
ALLOW_CA_KEY_BACKUP_ENV = "ADSCAN_ALLOW_CA_KEY_BACKUP"

#: Client-facing reason recorded on the edge when the step is skipped by default.
#: It names what the step would have left behind, not how it works.
CA_KEY_BACKUP_SKIPPED_REASON = (
    "Copying the certificate authority's private key leaves a copy that cannot "
    "be withdrawn without rotating the CA key, so ADscan does not run this step "
    "in an unattended assessment unless the operator enables it."
)

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


@dataclass(frozen=True, slots=True)
class ExitKeepDecision:
    """How the exit hook resolves the durable ``operator_confirmed`` objects.

    Attributes:
        mode: ``"keep"`` (keep all, no prompt), ``"revert"`` (revert all, no
            prompt) or ``"ask"`` (interactive prompt).
        source: Where the decision came from: ``"scan_config"``, ``"repl"``,
            ``"env"``, ``"non_interactive_default"`` or ``"interactive"``.
            Printed so an unattended log shows why the objects were kept or
            reverted.
        preset: For ``"ask"``, the preselected answer: ``"revert"`` where
            automatic reversion defaults on (audit), ``"keep"`` where it
            defaults off (ctf).
    """

    mode: str
    source: str
    preset: str = "revert"


#: The ONE switch for automatic reversion of ADscan's directory changes
#: (founder decision 2026-11-05): on for Enterprise and audit, off for ctf.
#: ``1``/``true`` on, ``0``/``false`` off. Forwarded by the launcher wildcard.
AUTO_REVERT_ENV = "ADSCAN_AUTO_REVERT"

#: Policy environments where automatic reversion is OFF by default: a disposable
#: lab, where leaving a change standing harms nobody. Derived from the
#: ``auto_revert`` setting's defaults, which own the rule.
AUTO_REVERT_OFF_ENVIRONMENTS: frozenset[str] = frozenset(
    env
    for env in ("lab", "real")
    if policy_settings.SETTINGS_BY_KEY[policy_settings.AUTO_REVERT].default_for(env)
    == policy_settings.AUTO_REVERT_OFF
)


@dataclass(frozen=True, slots=True)
class AutoRevertDecision:
    """Whether ADscan reverts its directory changes on its own in this run.

    Attributes:
        enabled: True when changes are reverted without asking.
        source: ``"scan_config"``, ``"repl"``, ``"env"`` (an explicit per-run
            choice), ``"policy"`` (the scan policy's ``auto_revert`` setting) or
            ``"environment_default"`` (that setting's default for the policy's
            environment).
    """

    enabled: bool
    source: str

    @property
    def explicit(self) -> bool:
        """An explicit per-run choice; the policy's value is a default the operator may still be asked about."""
        return self.source not in ("policy", "environment_default")


def resolve_auto_revert(
    shell: Any, *, environ: Optional[dict[str, str]] = None
) -> AutoRevertDecision:
    """Resolve the automatic-reversion switch for this run. Never raises.

    Precedence: the scan configuration (``durable_changes.auto_revert``, then its
    legacy inverse ``durable_changes.keep``), then the operator's REPL choice
    (``set auto_revert``), then the environment (``ADSCAN_AUTO_REVERT``, then the
    legacy inverse ``ADSCAN_KEEP_DURABLE_CHANGES``), then the scan policy's
    ``auto_revert`` setting (``adscan_core.scan_policy.settings``): off by default
    for a lab (it is reset), on for a real environment and when the environment
    is unknown (every Enterprise run). A saved policy for a real environment
    cannot set it off; only an explicit per-run choice keeps changes there.
    """
    explicit = _scan_config_value(shell, "auto_revert")
    if explicit is not None:
        return AutoRevertDecision(explicit, "scan_config")
    keep = _scan_config_value(shell, "keep")
    if keep is not None:
        return AutoRevertDecision(not keep, "scan_config")
    repl_value = getattr(shell, "auto_revert", None)
    if isinstance(repl_value, bool):
        return AutoRevertDecision(repl_value, "repl")
    env_value = _env_tristate(AUTO_REVERT_ENV, environ=environ)
    if env_value is not None:
        return AutoRevertDecision(env_value, "env")
    env_keep = _env_tristate(KEEP_DURABLE_CHANGES_ENV, environ=environ)
    if env_keep is not None:
        return AutoRevertDecision(not env_keep, "env")
    value = policy_settings.policy_setting(shell, policy_settings.AUTO_REVERT)
    source = (
        "policy"
        if policy_settings.policy_sets(shell, policy_settings.AUTO_REVERT)
        else "environment_default"
    )
    return AutoRevertDecision(value == policy_settings.AUTO_REVERT_ON, source)


def _env_tristate(name: str, *, environ: Optional[dict[str, str]] = None) -> Optional[bool]:
    source = os.environ if environ is None else environ
    raw = str(source.get(name, "") or "").strip().lower()
    if raw in _TRUE:
        return True
    if raw in _FALSE:
        return False
    return None


def _scan_config_value(shell: Any, attr: str) -> Optional[bool]:
    try:
        section = getattr(getattr(shell, "scan_config", None), "durable_changes", None)
        value = getattr(section, attr, None)
    except Exception:  # noqa: BLE001 — a malformed shell falls back to the default
        return None
    return value if isinstance(value, bool) else None


def resolve_exit_keep_decision(
    shell: Any,
    *,
    environ: Optional[dict[str, str]] = None,
    non_interactive_fn: Optional[Callable[..., bool]] = None,
) -> ExitKeepDecision:
    """Decide keep / revert / ask for the durable objects at workspace exit.

    Args:
        shell: The active shell (reads ``scan_config`` and the interaction mode).
        environ: Environment mapping override (tests); defaults to ``os.environ``.
        non_interactive_fn: Non-interactive predicate override (tests); resolved
            at call time so a patched module attribute is honoured.

    Returns:
        The :class:`ExitKeepDecision` the exit hook applies.
    """
    auto = resolve_auto_revert(shell, environ=environ)
    mode = "revert" if auto.enabled else "keep"
    if auto.explicit:
        return ExitKeepDecision(mode, auto.source)
    try:
        unattended = bool((non_interactive_fn or is_non_interactive)(shell))
    except Exception:  # noqa: BLE001 — unknown mode: take the unattended default
        unattended = True
    if unattended:
        return ExitKeepDecision(mode, "non_interactive_default")
    return ExitKeepDecision("ask", "interactive", preset=mode)


def ca_key_backup_allowed(
    shell: Any,
    *,
    environ: Optional[dict[str, str]] = None,
    non_interactive_fn: Optional[Callable[..., bool]] = None,
) -> bool:
    """Return whether an executed path may run the CA key backup step.

    Args:
        shell: The active shell (reads ``scan_config``, ``type`` and the mode).
        environ: Environment mapping override (tests).
        non_interactive_fn: Non-interactive predicate override (tests).

    Returns:
        True when the step may run, False when it is skipped by policy.
    """
    explicit = _scan_config_value(shell, "allow_ca_key_backup")
    if explicit is not None:
        return explicit
    explicit = _env_tristate(ALLOW_CA_KEY_BACKUP_ENV, environ=environ)
    if explicit is not None:
        return explicit
    try:
        unattended = bool((non_interactive_fn or is_non_interactive)(shell))
    except Exception:  # noqa: BLE001
        unattended = True
    if not unattended:
        return True
    # The scan policy's ``ca_key_backup`` setting: on by default for a lab, off
    # for a real environment, where a saved policy cannot turn it on.
    return (
        policy_settings.policy_setting(shell, policy_settings.CA_KEY_BACKUP)
        == policy_settings.CA_KEY_BACKUP_ON
    )
