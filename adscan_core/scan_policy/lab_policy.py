"""Whether Lab / CTF scan policies may run on this deployment.

The Lab / CTF built-in runs every check ADscan has, including attack steps that
leave changes to clean up or cannot be undone, at the Fast pace. It is meant for
a lab. On a client appliance a PoC usually sits on the client's production
network, so the client must be able to PREVENT a lab policy from running there,
not only read afterwards that one did.

So on the Enterprise edition (the appliance and its PoC, decided by the explicit
edition marker :func:`adscan_core.tier.is_enterprise_edition`) a lab policy is
unavailable until the client's administrator turns it on:

* the web console hides it from every policy selector and the backend refuses a
  launch, a workspace default and an agreed policy that names one;
* the host worker refuses a queued scan under one right before the engine starts
  (the seam every launch, schedule and resume converges on);
* the engine itself (``adscan ci``) refuses one with exit 78 and the reason code
  :data:`REASON_LAB_POLICY_NOT_ENABLED`, so a direct run on the appliance cannot
  bypass the platform.

Off the Enterprise edition (a development stack, LITE, PRO) nothing changes.

The setting has three writers, all recorded in the file's history: the bake
(the per-deployment registry value ``ADSCAN_ALLOW_LAB_POLICY``), the appliance
console, and the web console toggle (admin only). It is one JSON file,
:data:`SETTING_FILENAME`, beside the license: that directory is the one every
process that admits a new assessment already reads (the web backend through its
mount, the host worker, the engine through the state-dir mount, the console as
root). A missing or unreadable file means NOT allowed: the gate fails closed.

Stdlib only: importable from the engine, the host worker, the web backend and
the tests.
"""

from __future__ import annotations

import json
import os
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional

#: The setting file, in the license directory (:func:`setting_path`).
SETTING_FILENAME = "lab-policy.json"
SETTING_FORMAT = 1

#: Who changed the setting. The appliance console and the bake write
#: ``console`` / ``provisioning``; the web toggle writes ``web``.
SOURCE_PROVISIONING = "provisioning"
SOURCE_CONSOLE = "console"
SOURCE_WEB = "web"
SOURCES = (SOURCE_PROVISIONING, SOURCE_CONSOLE, SOURCE_WEB)

#: How many changes the file keeps (newest last).
HISTORY_LIMIT = 50

#: Reason code the engine writes beside exit 78 (``license_refusal.json``), so
#: the host worker stores the right sentence. Mirrored by the worker, which
#: never imports ``adscan_core``.
REASON_LAB_POLICY_NOT_ENABLED = "lab_policy_not_enabled"

#: The base and environment a lab policy is recognised by (mirrors
#: ``adscan_core.scan_policy.policy``; kept literal so this module stays light).
LAB_BASE = "lab_ctf"
LAB_ENVIRONMENT = "lab"

#: The one sentence every refusal uses: the platform, the worker and the engine.
LAB_POLICY_DISABLED_MESSAGE = (
    "Lab / CTF scan policies are turned off on this appliance. They run attack steps "
    "meant for a lab, including some that cannot be undone. An administrator can turn "
    "them on under Settings > Scan policies, or on the appliance console."
)

#: The one line a policy selector shows where lab policies are hidden.
LAB_POLICY_HIDDEN_NOTICE = (
    "Lab / CTF policies are hidden on this appliance. An administrator can turn them on "
    "under Settings > Scan policies, or on the appliance console."
)


@dataclass(frozen=True)
class LabPolicySetting:
    """The stored setting.

    Attributes:
        allowed: Whether lab policies may run. ``False`` when nothing is stored.
        changed_by: Who made the last change (a user name, ``appliance console``
            or ``deployment registry``); empty when nothing is stored.
        changed_at: ISO-8601 UTC instant of the last change; empty when none.
        source: ``provisioning``, ``console`` or ``web``; empty when none.
        history: Every recorded change, oldest first (``id``, ``allowed``,
            ``changed_by``, ``changed_at``, ``source``, and ``audited`` once the
            web audit log has recorded it).
        stored: Whether a readable file exists.
    """

    allowed: bool = False
    changed_by: str = ""
    changed_at: str = ""
    source: str = ""
    history: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    stored: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": SETTING_FORMAT,
            "allowed": self.allowed,
            "changed_by": self.changed_by,
            "changed_at": self.changed_at,
            "source": self.source,
            "history": [dict(entry) for entry in self.history],
        }


def default_directory() -> Path:
    """The license directory this process reads (``adscan_core.enterprise_license``)."""
    from adscan_core.enterprise_license import license_dir

    return license_dir()


def setting_path(directory: Optional[Path] = None) -> Path:
    """Path of the setting file."""
    return (directory or default_directory()) / SETTING_FILENAME


def _history_entry(raw: Any) -> Optional[dict[str, Any]]:
    if not isinstance(raw, Mapping) or not isinstance(raw.get("allowed"), bool):
        return None
    entry = {
        "id": str(raw.get("id") or ""),
        "allowed": bool(raw["allowed"]),
        "changed_by": str(raw.get("changed_by") or ""),
        "changed_at": str(raw.get("changed_at") or ""),
        "source": str(raw.get("source") or ""),
    }
    if raw.get("audited"):
        entry["audited"] = True
    return entry


def parse_setting(raw: Any) -> LabPolicySetting:
    """The setting a parsed JSON document holds; anything malformed reads as not allowed."""
    if not isinstance(raw, Mapping) or not isinstance(raw.get("allowed"), bool):
        return LabPolicySetting()
    history = tuple(
        entry for entry in (_history_entry(item) for item in raw.get("history") or ()) if entry
    )
    return LabPolicySetting(
        allowed=bool(raw["allowed"]),
        changed_by=str(raw.get("changed_by") or ""),
        changed_at=str(raw.get("changed_at") or ""),
        source=str(raw.get("source") or ""),
        history=history,
        stored=True,
    )


def read_setting(directory: Optional[Path] = None) -> LabPolicySetting:
    """Read the setting. A missing, unreadable or malformed file is "not allowed"."""
    try:
        raw = json.loads(setting_path(directory).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return LabPolicySetting()
    return parse_setting(raw)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def changed_setting(
    current: LabPolicySetting,
    *,
    allowed: bool,
    changed_by: str,
    source: str,
    now: Optional[str] = None,
) -> LabPolicySetting:
    """The setting after one change, with the change appended to its history.

    A change made through the web is recorded as already audited: the web
    writes its audit-log entry itself in the same request.
    """
    if source not in SOURCES:
        raise ValueError(f"unknown source {source!r}")
    stamp = now or _utc_now()
    entry: dict[str, Any] = {
        "id": uuid.uuid4().hex,
        "allowed": bool(allowed),
        "changed_by": str(changed_by or ""),
        "changed_at": stamp,
        "source": source,
    }
    if source == SOURCE_WEB:
        entry["audited"] = True
    history = (*current.history, entry)[-HISTORY_LIMIT:]
    return LabPolicySetting(
        allowed=bool(allowed),
        changed_by=entry["changed_by"],
        changed_at=stamp,
        source=source,
        history=history,
        stored=True,
    )


def write_setting(setting: LabPolicySetting, directory: Optional[Path] = None) -> Path:
    """Write the setting atomically; the file takes the directory's owner when root writes it.

    Raises:
        OSError: The directory or the file could not be written.
    """
    path = setting_path(directory)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(setting.to_dict(), handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(tmp, 0o644)
        # Written by root (the console, the bake), the file still belongs to
        # the account that owns the directory, as the license beside it does.
        from adscan_core.license_storage import adopt_directory_owner

        adopt_directory_owner(Path(tmp), directory=path.parent)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def mark_audited(setting: LabPolicySetting, entry_ids: set[str]) -> LabPolicySetting:
    """The same setting with the named history entries marked as audited."""
    history = tuple(
        {**entry, "audited": True} if entry.get("id") in entry_ids else dict(entry)
        for entry in setting.history
    )
    return LabPolicySetting(
        allowed=setting.allowed,
        changed_by=setting.changed_by,
        changed_at=setting.changed_at,
        source=setting.source,
        history=history,
        stored=setting.stored,
    )


def unaudited_changes(setting: LabPolicySetting) -> list[dict[str, Any]]:
    """Changes made outside the web (bake, console) the web audit log has not recorded."""
    return [dict(entry) for entry in setting.history if not entry.get("audited")]


# ── The gate ──────────────────────────────────────────────────────────────────


def gate_applies(*, env: Optional[Mapping[str, str]] = None, marker: Optional[Path] = None) -> bool:
    """True on the Enterprise edition (the appliance and its PoC), where the gate holds."""
    from adscan_core.tier import is_enterprise_edition

    return is_enterprise_edition(env=dict(env) if env is not None else None, marker=marker)


def lab_policies_available(
    *, gated: bool, directory: Optional[Path] = None, setting: Optional[LabPolicySetting] = None
) -> bool:
    """Whether a lab policy may run: always off the appliance, else what is stored."""
    if not gated:
        return True
    current = setting if setting is not None else read_setting(directory)
    return current.allowed


def is_lab_policy(*, base: Any = "", environment: Any = "") -> bool:
    """A policy the gate covers: the Lab / CTF built-in, a policy based on it, or a lab one."""
    return (
        str(base or "").strip().lower() == LAB_BASE
        or str(environment or "").strip().lower() == LAB_ENVIRONMENT
    )


def definition_is_lab(definition: Any) -> bool:
    """:func:`is_lab_policy` for a parsed ``ScanPolicyDefinition`` (``None`` is not lab)."""
    if definition is None:
        return False
    from adscan_core.scan_policy.policy import effective_environment

    return is_lab_policy(
        base=getattr(definition, "base", ""), environment=effective_environment(definition)
    )


def lab_refusal(definition: Any, *, gated: bool, setting: Optional[LabPolicySetting] = None,
                directory: Optional[Path] = None) -> str:
    """The refusal sentence when ``definition`` is a lab policy that may not run, else ``""``."""
    if not definition_is_lab(definition):
        return ""
    if lab_policies_available(gated=gated, directory=directory, setting=setting):
        return ""
    return LAB_POLICY_DISABLED_MESSAGE


def availability_view(*, gated: bool, setting: LabPolicySetting) -> dict[str, Any]:
    """What a policy selector needs: whether lab policies are offered, and why not."""
    available = lab_policies_available(gated=gated, setting=setting)
    return {
        "gated": gated,
        "allowed": setting.allowed if gated else True,
        "available": available,
        "notice": "" if available else LAB_POLICY_HIDDEN_NOTICE,
        "changed_by": setting.changed_by if gated else "",
        "changed_at": setting.changed_at if gated else "",
        "source": setting.source if gated else "",
    }


__all__ = [
    "HISTORY_LIMIT",
    "LAB_BASE",
    "LAB_ENVIRONMENT",
    "LAB_POLICY_DISABLED_MESSAGE",
    "LAB_POLICY_HIDDEN_NOTICE",
    "LabPolicySetting",
    "REASON_LAB_POLICY_NOT_ENABLED",
    "SETTING_FILENAME",
    "SOURCES",
    "SOURCE_CONSOLE",
    "SOURCE_PROVISIONING",
    "SOURCE_WEB",
    "availability_view",
    "changed_setting",
    "default_directory",
    "definition_is_lab",
    "gate_applies",
    "is_lab_policy",
    "lab_policies_available",
    "lab_refusal",
    "mark_audited",
    "parse_setting",
    "read_setting",
    "setting_path",
    "unaudited_changes",
    "write_setting",
]
