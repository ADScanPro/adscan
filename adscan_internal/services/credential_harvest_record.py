"""HarvestedPrincipal: the shared record every credential-harvest surface
(poisoning, spraying, kerberoasting, AS-REP roasting) builds and renders
through the same panel (see cli/widgets/credential_harvest_panel.py) and
persists through the same artifact (see credential_harvest_store.py).

Per CLAUDE.md § Nomenclature Standard, ``privilege_tier`` and
``compromise_reach`` are the two orthogonal axes — never conflate them.
Both are stored as the underlying SSOT enum ``.value`` strings
(:class:`adscan_internal.services.compromise_class.PrivilegeTier` /
``CompromiseClass``) so this module never duplicates label text; label
rendering happens at the panel layer via ``privilege_tier_label`` /
``compromise_reach_label_short``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# The four harvest surfaces this design standardizes across (spec:
# docs/superpowers/specs/2026-07-07-cracking-job-and-credential-harvest-design.md
# § Sub-project B).
HARVEST_SOURCES: tuple[str, ...] = (
    "poisoning",
    "spraying",
    "kerberoasting",
    "asreproasting",
)

# Mirrors captured_credential_policy.CrackPolicy's status vocabulary plus the
# two states a policy alone cannot express: "captured" (not yet classified /
# spraying's validated-hit case, which has no crack step at all) and
# "cracking" (a background job is in flight).
_DEFAULT_CRACK_STATUS = "captured"
_DEFAULT_ACCOUNT_TYPE = "user"


def _optional_str(value: Any) -> str | None:
    """Normalize a persisted tier/reach field into ``str`` or ``None``.

    ``None`` (UNDETERMINED) round-trips as JSON ``null``; a missing key or an
    empty string is also treated as UNDETERMINED (``None``) so a legacy record
    without the field is not silently forced to a false ``"tier2"`` / ``"none"``.
    A non-empty stored value is preserved verbatim.
    """
    if value is None:
        return None
    text = str(value)
    return text or None


@dataclass(frozen=True)
class HarvestedPrincipal:
    """One classified, harvested principal — the shared cross-surface record.

    Attributes:
        domain: The AD domain this principal belongs to.
        username: The captured/validated principal (sAMAccountName-shaped;
            machine accounts keep the trailing ``$``).
        source: One of :data:`HARVEST_SOURCES` — which surface produced this
            record.
        account_type: ``"user"`` or ``"machine"`` — mirrors
            :func:`captured_credential_policy.classify_principal`.
        ntlm_version: ``"v1"``/``"v2"`` for NTLM captures, ``""`` for
            non-NTLM sources (spraying, kerberoast, AS-REP roast).
        crack_status: ``"captured"`` (spraying — no crack step),
            ``"cracked"``, ``"cracking"`` (a background crack holds the hashcat
            slot — hashcat running), ``"queued"`` (a background crack is alive
            but waiting behind another crack for the single-instance slot),
            ``"rainbow_pending"``, ``"uncrackable_machine"`` (a machine NTLMv2 —
            not wordlist- or rainbow-recoverable, relay-only), or ``"uncracked"``.
        privilege_tier: The ``.value`` of
            :class:`compromise_class.PrivilegeTier` — axis 1, or ``None`` when
            UNDETERMINED (no membership/graph data to classify against — e.g.
            an unauthenticated capture). Renders as "Unknown", NEVER as a false
            "Tier 2: Standard". Re-derived from the current graph at render time.
        compromise_reach: The ``.value`` of
            :class:`compromise_class.CompromiseClass` — axis 2, or ``None`` when
            UNDETERMINED (no attack-graph/path data). Renders as "Not assessed",
            NEVER as a false "Standard reach". Re-derived at render time.
        hash_file: Absolute path to the on-disk hash file backing this
            record, when one exists (empty for spraying, which has no hash
            file — the credential was validated directly). Used by the
            retry-crack / copy-hash actions.
        captured_at: UTC ISO-8601 timestamp of when this record was built.
        mode: The hashcat mode string the crack ran under (``"5500"``/``"5600"``
            NetNTLM, ``"13100"``/AES variants Kerberoast, ``"18200"``/AES
            variants AS-REP). Empty for spraying (no crack) and for legacy
            records. Drives the retry-crack escalation so a roast record
            re-enqueues under the correct mode (not a NetNTLM assumption).
        max_effort: The highest effort tier the crack ladder has already
            attempted for this hash (``"fast"``/``"balanced"``/``"thorough"``;
            empty for a legacy/basic pass or a source with no crack step). The
            escalation selector offers only tiers ABOVE this — ``"thorough"``
            means the ladder is exhausted (``"exhausted (all tiers)"``).
        secret: The recovered plaintext, when this record was produced by a
            BACKGROUND crack that deliberately did NOT auto-add the credential
            (so the operator activates it from the scan-end review). Empty for
            spraying (the credential is already in the store), for uncracked /
            uncrackable / rainbow-pending records, and for foreground cracks
            (which auto-add immediately). Cleartext at rest in the workspace
            artifact, exactly like ``domains_data`` — never rendered redacted.
        method: The cracking method that recovered this hash (for ``cracked``),
            was last attempted (for ``uncracked``/``exhausted``), or is running
            (for ``cracking``) — the wordlist basename, plus the rule name when
            a rules file was applied (e.g. ``"combined_audit_base.txt"`` or
            ``"combined_audit_base.txt + best64"``). Empty for spraying and for
            legacy records. Purely cosmetic — surfaced in the harvest table.
        eta: Human-readable estimated time remaining for a still-running crack
            (e.g. ``"~4m left"``), best-effort from the effort-tier benchmark.
            Empty when not cracking or when no estimate is available.
        progress: Human-readable progress of a still-running crack (e.g.
            ``"33%"``). Empty when not cracking or when no estimate is available.
    """

    domain: str
    username: str
    source: str
    account_type: str
    ntlm_version: str
    crack_status: str
    privilege_tier: str | None
    compromise_reach: str | None
    hash_file: str
    captured_at: str
    mode: str = ""
    max_effort: str = ""
    secret: str = ""
    method: str = ""
    eta: str = ""
    progress: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "username": self.username,
            "source": self.source,
            "account_type": self.account_type,
            "ntlm_version": self.ntlm_version,
            "crack_status": self.crack_status,
            "privilege_tier": self.privilege_tier,
            "compromise_reach": self.compromise_reach,
            "hash_file": self.hash_file,
            "captured_at": self.captured_at,
            "mode": self.mode,
            "max_effort": self.max_effort,
            "secret": self.secret,
            "method": self.method,
            "eta": self.eta,
            "progress": self.progress,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HarvestedPrincipal":
        return cls(
            domain=str(data.get("domain", "")),
            username=str(data.get("username", "")),
            source=str(data.get("source") or ""),
            account_type=str(data.get("account_type") or _DEFAULT_ACCOUNT_TYPE),
            ntlm_version=str(data.get("ntlm_version") or ""),
            crack_status=str(data.get("crack_status") or _DEFAULT_CRACK_STATUS),
            privilege_tier=_optional_str(data.get("privilege_tier")),
            compromise_reach=_optional_str(data.get("compromise_reach")),
            hash_file=str(data.get("hash_file") or ""),
            captured_at=str(data.get("captured_at") or ""),
            mode=str(data.get("mode") or ""),
            max_effort=str(data.get("max_effort") or ""),
            secret=str(data.get("secret") or ""),
            method=str(data.get("method") or ""),
            eta=str(data.get("eta") or ""),
            progress=str(data.get("progress") or ""),
        )
