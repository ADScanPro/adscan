"""Verification level of a share-file-credential edge source: the client copy.

A share-file-credential attack step (a Group Policy Preferences password or
autologon secret, or a password recovered from a readable share or file) is
attributed to the principals that could reach the file it lived in. The strength
of that attribution is not uniform: for some principals ADscan confirmed read
access live, for others it evaluated both the share and the file's NTFS
permissions, and for others only the share-level permission was available and the
file's NTFS layer stayed unread. An auditor reading the deliverable needs to know
which of the three they are looking at, so a partial attribution is never mistaken
for a proven one.

The collector records the level as a tag on the edge ``notes.verification``. This
module is the single definition of the client-facing sentence for each tag, and
the predicate for which relations carry one. The PDF report and the paid web
platform both read from here, so the same level is worded identically wherever a
client meets it.

``self_mxac`` semantics matter for the copy and are easy to get wrong. It does
not identify the exact principal. It records that the scanning identity, a
provable member of a broad group such as Everyone or Authenticated Users, read
the file, and it attributes that read to the broad group as a verified floor. So
its sentence says the access was confirmed for the group and calls it a floor,
never "only this principal" and never an exact per-principal mapping.

Pure logic: no IO, no console, no network, no ``adscan_internal`` import. Safe to
import from ``adscan_core``, the LITE runtime, the PRO report renderer and the web
backend alike.
"""

from __future__ import annotations

from typing import Any, Mapping

#: The three verification tags the share collector stamps on a share-access edge
#: (mirrors ``adscan_internal.services.collector.share_ntfs_verification``). They
#: are stable protocol tokens, restated here so this copy layer stays free of any
#: ``adscan_internal`` import and the web backend can consume it directly.
VERIFICATION_SELF_MXAC = "self_mxac"
VERIFICATION_NTFS_COMPUTED = "ntfs_computed"
VERIFICATION_SHARE_ACL_ONLY = "share_acl_only"

#: The attack-step relations whose source is a principal that could read the file
#: holding the credential, and which therefore carry a verification level. Only
#: these get a label; any other relation is out of scope (no label ever).
SHARE_CREDENTIAL_RELATIONS = (
    "GPPPassword",
    "GPPAutologon",
    "PasswordInShare",
    "PasswordInFile",
)

_SHARE_CREDENTIAL_RELATIONS_LOWER = frozenset(
    r.lower() for r in SHARE_CREDENTIAL_RELATIONS
)

#: Client-facing sentence per level. Authored client-safe: no internal mechanic,
#: no tool or product name, honest about a partial attribution.
_VERIFICATION_LABELS: dict[str, str] = {
    VERIFICATION_SELF_MXAC: (
        "Read access confirmed live for this group, verified with the scanning "
        "identity, which belongs to it. This is a verified floor for the group, "
        "not an exact per-principal mapping."
    ),
    VERIFICATION_NTFS_COMPUTED: (
        "Share and file NTFS permissions were both evaluated for this principal."
    ),
    VERIFICATION_SHARE_ACL_ONLY: (
        "Share-level access only. The file's NTFS permissions could not be "
        "verified, so this attribution is a lead rather than a confirmed read."
    ),
}


def is_share_credential_relation(relation: Any) -> bool:
    """Return whether a relation is a share-file-credential step in scope.

    Only these relations attribute a recovered credential to the principals that
    could read the file it lived in, so only these ever carry a verification
    level. Case-insensitive; a non-string or unknown relation is out of scope.
    """

    return str(relation or "").strip().lower() in _SHARE_CREDENTIAL_RELATIONS_LOWER


def verification_level_label(verification: Any) -> str:
    """Return the client-facing sentence for a verification tag, or ``""``.

    Args:
        verification: The ``notes.verification`` tag stamped on the edge
            (``"self_mxac"`` / ``"ntfs_computed"`` / ``"share_acl_only"``), or a
            missing/unknown value.

    Returns:
        The client-safe sentence for the level, or an empty string when the tag
        is absent or unrecognised. An empty string means the render omits the
        label rather than fabricating a certainty ADscan did not record.
    """

    key = str(verification or "").strip().lower()
    return _VERIFICATION_LABELS.get(key, "")


def _verification_from_step_details(details: Any) -> str:
    """Extract the verification tag from a step's ``details`` (or nested notes)."""

    if not isinstance(details, Mapping):
        return ""
    value = details.get("verification")
    if value:
        return str(value)
    # Some display paths carry the raw edge notes nested under ``details["notes"]``
    # rather than spread into ``details`` directly; look there too.
    nested = details.get("notes")
    if isinstance(nested, Mapping):
        return str(nested.get("verification") or "")
    return ""


def source_verification_label_for_step(step: Any) -> str:
    """Return the source verification label for one attack-path step, or ``""``.

    Reads the step's relation and its ``details`` (where the attack-path SSOT
    spreads the edge notes). Returns the client-facing sentence only when the
    relation is a share-file-credential step AND a recognised verification tag is
    present; otherwise an empty string (out-of-scope relation, or no tag).

    Args:
        step: A raw attack-path step dict with ``action``/``relation`` and an
            optional ``details`` dict.

    Returns:
        The client-safe verification sentence, or ``""``.
    """

    if not isinstance(step, Mapping):
        return ""
    relation = step.get("action") or step.get("relation") or step.get("type") or ""
    if not is_share_credential_relation(relation):
        return ""
    return verification_level_label(_verification_from_step_details(step.get("details")))


__all__ = [
    "SHARE_CREDENTIAL_RELATIONS",
    "VERIFICATION_NTFS_COMPUTED",
    "VERIFICATION_SELF_MXAC",
    "VERIFICATION_SHARE_ACL_ONLY",
    "is_share_credential_relation",
    "source_verification_label_for_step",
    "verification_level_label",
]
