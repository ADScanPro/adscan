"""The policy agreed with the client, and whether a scan ran under it.

An engagement is authorised for a scan policy: the client signs off on what
ADscan may do, and the policy's digest (``resolve.policy_digest``: the canonical
definition plus the check-registry version) is the value they can match against
that authorisation. A workspace records the agreed policy once; every scan
launched in it is compared against it by digest, and a run under anything else
says so, on the platform before launch, on the scan's Scope card and in the
report.

One shape and one sentence for every surface (the web launch, the scheduler, the
engine's coverage block, the PDF, the LITE report and the CTEM), so no two
surfaces word the same difference differently.

Stdlib only: importable from the engine, the renderers and the web backend.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

#: Key of the agreed policy in a scan config and in the coverage block.
AGREED_POLICY_KEY = "agreed_policy"

#: The two ways a run can differ from the agreement.
REASON_DIFFERENT_POLICY = "different_policy"
REASON_DIFFERENT_CHECKS = "different_checks"


def digest_short(digest: Any) -> str:
    """``sha256:<first 12 hex>``, the form every surface prints."""
    text = str(digest or "")
    algo, _, hexpart = text.partition(":")
    return f"{algo}:{hexpart[:12]}" if hexpart else text


def normalize_agreed_policy(raw: Any) -> Optional[dict[str, Any]]:
    """The agreed policy as ``{name, revision, digest}``, or ``None``.

    A record without a ``sha256:`` digest is no agreement: the digest is the
    only thing a comparison can rest on, so a malformed record compares as
    "no agreed policy" rather than as a difference.
    """
    if not isinstance(raw, Mapping):
        return None
    digest = str(raw.get("digest") or "").strip()
    if not digest.startswith("sha256:") or len(digest) <= len("sha256:"):
        return None
    try:
        revision = int(raw.get("revision") or 0)
    except (TypeError, ValueError):
        revision = 0
    return {
        "name": str(raw.get("name") or "").strip(),
        "revision": max(revision, 0),
        "digest": digest,
    }


def compare_to_agreed(
    agreed: Any,
    *,
    ran_name: str,
    ran_revision: int,
    ran_digest: str,
) -> Optional[dict[str, Any]]:
    """Compare what a scan runs under with the agreed policy.

    Returns ``None`` when no policy was agreed, else the agreed identity plus
    ``matches`` and, when it does not, ``reason``: ``different_policy`` when the
    name or revision differs, ``different_checks`` when the same named revision
    resolves to other checks (edited for this scan, or the check catalogue
    changed since the agreement).
    """
    normalized = normalize_agreed_policy(agreed)
    if normalized is None:
        return None
    matches = bool(ran_digest) and ran_digest == normalized["digest"]
    out = dict(normalized)
    out["matches"] = matches
    if not matches:
        same_identity = (
            str(ran_name or "") == normalized["name"]
            and int(ran_revision or 0) == normalized["revision"]
        )
        out["reason"] = REASON_DIFFERENT_CHECKS if same_identity else REASON_DIFFERENT_POLICY
    return out


def _named(name: str, revision: int) -> str:
    label = name or "an unnamed policy"
    return f"{label} revision {revision}" if revision else label


def agreed_policy_line(
    comparison: Any,
    *,
    ran_name: str,
    ran_revision: int,
    ran_digest: str,
) -> str:
    """One sentence when a scan did not run under the agreed policy, else ``""``."""
    if not isinstance(comparison, Mapping) or comparison.get("matches") is not False:
        return ""
    agreed_name = str(comparison.get("name") or "")
    agreed_revision = int(comparison.get("revision") or 0)
    agreed_digest = digest_short(comparison.get("digest"))
    ran_digest_short = digest_short(ran_digest)
    if comparison.get("reason") == REASON_DIFFERENT_CHECKS:
        return (
            f"This scan ran under {_named(agreed_name, agreed_revision)} with a different "
            f"set of checks from the one agreed for this engagement "
            f"({ran_digest_short}, agreed {agreed_digest})."
        )
    return (
        f"This scan ran under {_named(ran_name, ran_revision)} ({ran_digest_short}), not the "
        f"policy agreed for this engagement, {_named(agreed_name, agreed_revision)} "
        f"({agreed_digest})."
    )


# ── Enforcement: only an administrator may launch under another policy ────────
#
# A workspace that records an agreed policy holds its scans to it by default
# (``workspaces.agreed_policy_enforced``, on unless the administrator turns it
# off): "prevent, not detect". A launch under a different policy is refused for
# anyone who may not set the agreed policy; such a person (an administrator)
# may still launch it after confirming, and the override is recorded on the
# scan and in the audit log. A scheduled run never overrides: nobody confirms
# it, so it is refused while enforcement is on.

#: What a launch may do against an enforced agreement.
LAUNCH_ALLOWED = "allowed"
LAUNCH_REFUSED = "refused"
LAUNCH_NEEDS_CONFIRMATION = "needs_confirmation"
LAUNCH_OVERRIDE = "override"

#: Machine-readable code of a refusal and of a confirmation request, so the web
#: form can tell them apart from any other error.
CODE_AGREED_POLICY_REFUSED = "AGREED_POLICY_ENFORCED"
CODE_AGREED_POLICY_CONFIRM = "AGREED_POLICY_OVERRIDE_CONFIRMATION"


def _ran_label(name: str, revision: int, digest: str) -> str:
    return f"{_named(name, revision)} ({digest_short(digest)})"


def _agreed_label(comparison: Mapping[str, Any]) -> str:
    return (
        f"{_named(str(comparison.get('name') or ''), int(comparison.get('revision') or 0))} "
        f"({digest_short(comparison.get('digest'))})"
    )


def enforcement_refusal_line(
    comparison: Any, *, ran_name: str, ran_revision: int, ran_digest: str, scheduled: bool = False
) -> str:
    """Why a launch was refused, naming the agreed policy."""
    if not isinstance(comparison, Mapping):
        return ""
    agreed = _agreed_label(comparison)
    if scheduled:
        return (
            f"This workspace is held to the policy agreed with the client, {agreed}. A scheduled "
            f"scan runs only under that policy, and this one would run under "
            f"{_ran_label(ran_name, ran_revision, ran_digest)}. Change the schedule's policy, or "
            f"an administrator can turn off the enforcement for this workspace."
        )
    return (
        f"This workspace is held to the policy agreed with the client, {agreed}. Only an "
        f"administrator can launch a scan under another policy, and this one would run under "
        f"{_ran_label(ran_name, ran_revision, ran_digest)}."
    )


def override_confirmation_line(
    comparison: Any, *, ran_name: str, ran_revision: int, ran_digest: str
) -> str:
    """What an administrator confirms before launching under another policy."""
    if not isinstance(comparison, Mapping):
        return ""
    return (
        f"This workspace is held to the policy agreed with the client, "
        f"{_agreed_label(comparison)}. Launch this scan under "
        f"{_ran_label(ran_name, ran_revision, ran_digest)} instead? The override is recorded "
        f"on the scan and in the audit log."
    )


def override_recorded_line(override_by: Any) -> str:
    """What a scan record says when an administrator confirmed the override, else ``""``."""
    who = str(override_by or "").strip()
    if not who:
        return ""
    return (
        f"The workspace holds its scans to the agreed policy. {who} confirmed launching this "
        f"scan under another policy, as an administrator."
    )


def decide_launch(
    comparison: Any, *, enforced: bool, may_override: bool, confirmed: bool
) -> str:
    """What a launch may do: allowed, refused, needs confirmation, or an override.

    Args:
        comparison: :func:`compare_to_agreed`'s result (``None``: nothing agreed).
        enforced: The workspace holds its scans to the agreement.
        may_override: The person launching may set the agreed policy (an
            administrator). ``False`` for a scheduled run.
        confirmed: That person confirmed the override for this launch.
    """
    if not enforced or not isinstance(comparison, Mapping) or comparison.get("matches") is not False:
        return LAUNCH_ALLOWED
    if not may_override:
        return LAUNCH_REFUSED
    return LAUNCH_OVERRIDE if confirmed else LAUNCH_NEEDS_CONFIRMATION


__all__ = [
    "AGREED_POLICY_KEY",
    "CODE_AGREED_POLICY_CONFIRM",
    "CODE_AGREED_POLICY_REFUSED",
    "LAUNCH_ALLOWED",
    "LAUNCH_NEEDS_CONFIRMATION",
    "LAUNCH_OVERRIDE",
    "LAUNCH_REFUSED",
    "decide_launch",
    "enforcement_refusal_line",
    "override_confirmation_line",
    "override_recorded_line",
    "REASON_DIFFERENT_CHECKS",
    "REASON_DIFFERENT_POLICY",
    "agreed_policy_line",
    "compare_to_agreed",
    "digest_short",
    "normalize_agreed_policy",
]
